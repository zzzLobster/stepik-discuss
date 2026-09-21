# 0002 — PWA wrapper + new-comment notifications (Web Push)

Date: 2026-09-21
Status: REFINED 2026-09-21 — ready for D0 spike; D1/D2 gated on D0 verdict (template + VAPID proof). Implements plan 0001 §7.4 hook (`manifest.json` + stub `sw.js` → full PWA + WebPush).
Decisions 2026-09-21 (teacher): notify scope = all members except author; no quiet hours (revisit later); teacher Telegram channel designed but deferred to plan 0003. Refinements 2026-09-21 (teacher): test-version scope (site not used by students yet, webhook-only, no poller); Caddy `/push/*` + `/offline.html` fix ok; SW navigation-fallback frozen; CSRF = admin pattern; author FIO = webhook `User.Name` primary + sessions fallback; subscribe `"all"` for students + teacher, POST-narrow (no PATCH); expanded consent ok; 4 workers / 8 in-flight ok; `webpush-go v1.4.0` + `govulncheck` approved; `id:/` + `start_url:/?source=pwa`; maskable as separate file (pending source choice); grep → unit test.
Test scope: site not used by students yet — D0/P1/P2 may run with test users + ephemeral secrets; no migration compat for old installs required.
Domain: `stepik.study67.fyi` (same-domain, no split — iOS PWA + third-party-cookie safe, per 0001 §3)
Stack delta: Gate (Go 1.27.1) + Caddy `2.11.4-alpine` + remark42 `v1.16.4` + Cloudflare direct (orange-cloud). No new containers.

> Delegation note: Builder performed requirements + architecture directly from repo exploration + remark42/MDN docs + live web sources (remark42 notifications page, `store/comment.go`, `go-pkgz/notify`, Chrome/MDN PWA docs, `webpush-go` releases). Review gates still apply: `go build/vet/test`, `govulncheck`, `caddy-verify.sh`, browser TESTLOG waves.

## 1. Goal

Turn the closed discussion site into an **installable mobile web app** and notify users about **new comments** even when the tab is closed:

1. **PWA installable** on Android (Chrome/Edge/Samsung) + iOS (Safari 16.4+, incl. iOS 26 HS-default) + desktop (Chrome/Edge Add-to-Dock) — `standalone`, own icon, splash, `start_url:/?source=pwa`, stable `id:/`.
2. **Browser push notifications** about new comments via **Web Push (VAPID)** + Service Worker `push` → `showNotification`, deep-link to `/class/<cid>#remark-<comment_id>`.
3. **Mobile-first UX**: class pages usable from Home-Screen icon, offline-safe static shell, RU copy, minors/152-FZ safe (no PII beyond `uid+fio+avatar`, closed threads only).

Non-goal: native App Store / Google Play wrappers (PWABuilder/TWA deferred), email/Telegram push (remark42-native, explicitly rejected for students — see §3), lesson-level threads (Phase 2 in 0001 §7.3 reuses same push plumbing).

## 2. Ground truth (do not re-debate, from 0001 + runbook + live code)

- Gate serves today: `GET /manifest.json` (`standalone, scope:/, start_url:/`, icons `/static/icon-192.png`, `/static/icon-512.png purpose:any maskable` single-file combined), `GET /sw.js` stub (`fetch` passthrough), `apple-touch-icon.png`, `theme-color #3776AB`, `<link rel=manifest>` in `index.html`/`class.html`. Chromium install prompt **will not fire** with stub SW — needs real SW registration + `fetch` handler (MDN install criteria: HTTPS + manifest w/ 192+512 + `display` + registered SW). D1 splits icons into `any` + separate `maskable` file (never `"any maskable"` on one file).
- `gate/handlers/handlers.go:Routes()` is wiring; `privateHeaders` = `Cache-Control: private,no-store` + `noindex` on all HTML/API. SW **must never cache** `/`, `/class/*`, `/auth/*`, `/discuss/*`, `/auth/me`.
- Caddy contracts (enforced by `deploy/caddy-verify.sh`, CI `caddy-contract`): public `handle /discuss/web/* + uri strip_prefix /discuss` (→ `/web/*`); protected `handle_path /discuss/*` strips `/discuss`; gate gets full public URI via `header_up X-Forwarded-Uri /discuss{uri}`; 3-arg `redir`; healthcheck `http://localhost:8081/healthz`. **Any Caddyfile edit must re-run `deploy/caddy-verify.sh`.**
- `forward_auth gate:8081 /auth/check` ONLY on `/discuss/*`, never on `/web/*`. `ExtractCID` fail-closed `403 unknown_thread` without `?url=`/class-`Referer`/iframe-`?url=` unwrap.
- remark42 `v1.16.4` notification matrix (verified in docs `remark42.com/docs/configuration/notifications/` + `parameters` + `store/comment.go` + `go-pkgz/notify`, 2026-09-21):
  - `NOTIFY_ADMINS=email|telegram|slack|webhook` (multi), `NOTIFY_USERS=email|telegram` — **user push via remark42-native requires email/Telegram identity, which our users don't have** (Gate-minted JWT only, `AUTH_ANON=false`, dummy `stepik` provider). So remark42-native user-notify is **unusable** — Gate-owned WebPush is the only per-student path.
  - `NOTIFY_WEBHOOK_URL + NOTIFY_WEBHOOK_TEMPLATE + NOTIFY_WEBHOOK_HEADERS + NOTIFY_WEBHOOK_TIMEOUT (5s) + NOTIFY_QUEUE (100)` — admin webhook fires **HTTP POST per new comment**. Template context is the **`store.Comment` struct** (not plan-draft names): `{{.ID}}`, `{{.ParentID}}` (`pid`), `{{.Text}}`, `{{.User.ID}}` (= `stepik_<uid>`), `{{.User.Name}}`, `{{.Locator.SiteID}}`, `{{.Locator.URL}}`, `{{.Timestamp}}`; filters `escapeJSONString`, `truncate`. Headers format `Header1:Value1,Header2:Value2`. D0 spike freezes the exact working template (see §7.1).
- iOS constraints (MDN + 2026 field reports): push **only after** Add-to-Home-Screen + user-granted permission **in response to tap**; Safari-only install ≤16.3, Share-menu install in any browser ≥16.4; no `beforeinstallprompt` on iOS (manual Share → Add instructions required); WebKit-only, no Bluetooth/USB/NFC (irrelevant here); storage quota large since Safari 17 (no problem for <20 users).
- Scale/privacy: 2–3 classes, <20 users, RU, minors. Store only `uid+fio+avatar_url`. Threads never merge (`page_url` differs per `cid`). Cloudflare cache-bypass rule for `stepik.study67.fyi` must extend to new `/push/*` + `/sw.js` + `/offline.html` versioned URLs (all `BYPASS/DYNAMIC`, never cached).
- Deps: `bbolt, golang-jwt/v5, x/oauth2, x/time/rate` + **approved `github.com/SherClockHolmes/webpush-go v1.4.0`** (teacher-approved 2026-09-21 as interim until a more stable/popular/maintainable lib appears; MIT, 440★, includes CVE-2024-51744 JWT fix + Content-Length fix; ~21 imports, no cgo). Pin via `go.mod` + `go.sum`, `go vet` + `govulncheck` in CI. Alternative hand-rolled VAPID rejected (crypto risk). No other deps.

## 3. Architecture (final)

```
Browser/PWA (SW + manifest)
  ──https──▶ Cloudflare ──https──▶ Caddy :443 ──▶ Gate :8081 (HTML + /push/* + /sw.js + /manifest.json)
  /discuss/* ──forward_auth──▶ Gate check ──allow──▶ remark42 :8080 (comments)
  remark42 ──NOTIFY_WEBHOOK_URL──▶ http://gate:8081/push/webhook (internal docker `app` net only,
                    HMAC/secret header, NOT via Caddy/edge)
  Gate ──WebPush (VAPID)──▶ browser push service (FCM/APNs/Mozilla) ──▶ SW `push` ──▶ Notification
```

- **Gate owns identity + subscriptions + fan-out; remark42 owns comment events; Caddy owns enforcement; push services own delivery.** Same-domain preserves iOS PWA + `__Host-sid` (`Secure, HttpOnly, SameSite=Lax`) semantics.
- **Event source: remark42 admin webhook → Gate internal endpoint** (only source in MVP). Poller fallback (`GET /api/v1/find` every 5m) **dropped from MVP** per 2026-09-21 (test version, webhook-only; outage = log `push_webhook_gap`, next comment re-fires; documented as future, not D2 acceptance).
- **No remark42-native `NOTIFY_USERS`** (would need student emails/Telegram IDs we don't collect and must not collect for minors). **No `NOTIFY_ADMINS=email/telegram`** for MVP either — teacher gets the same WebPush as students (plus existing `/discuss/admin/` moderation). Optional teacher Telegram channel later (Phase 2, needs bot token in VPS `.env` only).
- Volumes/network unchanged: `app` bridge, no `ports:` on backends, only Caddy `80/443`. Volumes `gate-data:/data/gate.db` (new buckets `push_subs`, `push_meta`), `remark-data`, `caddy-data`.

## 4. URL / API map (additive, MVP frozen)

| URL | Auth | Content / contract |
|-----|------|--------------------|
| `GET /manifest.json` | public, `Cache-Control: public,max-age=3600` | Full PWA manifest (see §5). `id:/` (stable, never changes), `start_url:/?source=pwa`, `scope:/`, `display:standalone`, `orientation:portrait-primary`, `lang:ru`, `dir:ltr`, `theme_color/background_color`, icons 192 `any` + 512 `any` + 512 `maskable` separate file + `apple-touch-icon` 180, `categories:[education]`, `screenshots` deferred. |
| `GET /sw.js` | public, `Cache-Control: no-store` in MVP (bare `register('/sw.js')`, no `?v=` query; versioning only via `STATIC_CACHE = "static-"+REV` injected from `buildRevision()`) | Real SW (see §6). Served by Gate (not static file) so `revision` can be injected. Scope `/`. |
| `GET /push/vapid-key` | needs valid `sid` (student or teacher), `Cache-Control: no-store` | `{key: <VAPID-public-base64url>}` for `pushManager.subscribe({userVisibleOnly:true, applicationServerKey})`. 401 anon. |
| `POST /push/subscribe` | needs valid `sid`, Origin-checked (`https://stepik.study67.fyi` via `validSameOrigin`), header CSRF (`X-CSRF-Token` must match readable `__Host-csrf` cookie via `document.cookie`, same pattern as `admin.Admin`; no change to `/auth/me` shape), rate-limited 20/min per `sid` (new `AllowPush`) | Body JSON `{endpoint, keys:{p256dh, auth}, device:{ua, name?}, cids:[<cid…>] \| "all"}`. Validates endpoint URL `https://*` (FCM/WNS/APNs/Mozilla only — reject `http:`), key lengths (p256dh 87-88 chars b64url, auth 22-24), `cids ⊆ session.allowed` OR `"all"` (students + teacher both may send `"all"`; server expands to live `allowed` at **send** time, so revoke takes effect immediately). Upsert into `push_subs[sha256(endpoint)] → {uid, endpoint, p256dh, auth, cids|all, ua, created_at, last_ok_at}`. Returns `{ok:true}`. Per-class disable = `POST` narrowed `cids` array (no `PATCH` method). |
| `POST /push/unsubscribe` | same as subscribe | Body `{endpoint}`. Deletes by hash. Idempotent (200 even if missing). |
| `POST /push/webhook` | **internal only**: Docker-subnet guard + `X-Push-Webhook-Secret: <PUSH_WEBHOOK_SECRET 32B hex>` (from VPS `.env`, shared remark42 `NOTIFY_WEBHOOK_HEADERS` ↔ Gate env). **Never routed via Caddy** (no Caddy handle — direct `http://gate:8081` on `app` net). Fail-closed 404 on bad secret (same pattern as `X-Gate-Auth` Guard). | remark42 POST JSON `{site, page_url, comment:{id, parent_id, user_id, user_name, text_snippet, created_at}}` (template-defined, see §7.1 — fields map to `Locator.SiteID / Locator.URL / ID / ParentID / User.ID / User.Name / Text|truncate|escapeJSONString / Timestamp`). Gate: `ExtractCID(page_url)` → `cid`; drop if `cid` invalid/`site != SITE`; strip `stepik_` prefix for `author_uid`; fan-out async (queue, see §7). Returns `200 {ok:true}` fast (<200ms, enqueue only). |
| `GET /push/health` | shallow public `{ok:true}`; deep `?deep=1` Caddy-only (`X-Gate-Auth` Guard, same pattern as `/healthz`) | Deep returns `{ok:true, subs:<n>, queue:<n>}`. Kept separate from `/healthz` (approved 2026-09-21). |
| Existing `/`, `/class/<cid>`, `/auth/*`, `/discuss/*`, `/healthz`, `/robots.txt`, `/static/*` | unchanged | Class pages add push UI (bell toggle + iOS install hint); no change to `forward_auth` or `ExtractCID`. |

Caddy delta: **no new `handle` for `/push/webhook`** (internal-only by design). Add explicit `handle /push/* { reverse_proxy gate:8081 }` + add `/offline.html` to `@static` (or own handle — otherwise SW `cache.add("/offline.html")` 404s and install fails). Extend `deploy/caddy-verify.sh` with checks for both. Keep CF `BYPASS`. Cloudflare Cache Rule `bypass-private` (hostname `stepik.study67.fyi`) already covers them; verify `cf-cache-status: BYPASS/DYNAMIC` on `/push/*`, `/offline.html` in TESTLOG.

## 5. PWA manifest + installability (D1)

- `handleManifest` extension (Go, `gate/handlers`):
  ```json
  {
    "name": "Обсуждения классов Stepik",
    "short_name": "Stepik Discuss",
    "id": "/",
    "start_url": "/?source=pwa",
    "scope": "/",
    "display": "standalone",
    "orientation": "portrait-primary",
    "lang": "ru",
    "dir": "ltr",
    "theme_color": "#3776AB",
    "background_color": "#ffffff",
    "categories": ["education"],
    "icons": [
      {"src": "/static/icon-192.png", "sizes": "192x192", "type": "image/png", "purpose": "any"},
      {"src": "/static/icon-512.png", "sizes": "512x512", "type": "image/png", "purpose": "any"},
      {"src": "/static/icon-512-maskable.png", "sizes": "512x512", "type": "image/png", "purpose": "maskable"}
    ]
  }
  ```
  `id:/` is stable (never changes → no ghost-install if `start_url` query changes later; both same-origin, `start_url` within `scope:/` per MDN/Chrome). Current repo icon (`icon-512.png`, blue `#3776AB` + yellow bubble, opaque full-bleed) already fits maskable background needs; generate `icon-512-maskable.png` as separate file with logo inside central 80% safe zone (410px of 512, 51px background-only ring per side), opaque, no transparency. Never `"any maskable"` on one file (Chrome warns, logo shrinks 20%). Verify in DevTools Application → Manifest → safe-area preview or maskable.app. 180px `apple-touch-icon.png` already present. No other binary assets beyond re-exported PNGs.
- Templates (`index.html`, `class.html` `<head>`): keep `<link rel=manifest>`, add `<meta name=mobile-web-app-capable content=yes>`, `<meta name=apple-mobile-web-app-capable content=yes>`, `<meta name=apple-mobile-web-app-status-bar-style content=default>`, `<meta name=apple-mobile-web-app-title content="Stepik Discuss">`. Register SW unconditionally (all pages): `<script>if('serviceWorker' in navigator){navigator.serviceWorker.register('/sw.js')}</script>` — deferred, non-blocking.
- Install UX (RU, minimal, no nagging):
  - Android/Desktop Chromium: listen `beforeinstallprompt`, show inline `Установить приложение` button once (dismiss persists in `localStorage`), `appinstalled` hides it.
  - iOS: UA-detect `iPhone|iPad` + `!navigator.standalone` + `!matchMedia('(display-mode: standalone)')` → one-line hint `На iPhone: Поделиться → На экран «Домой», затем откройте с иконки — тогда придут уведомления.` Shown max once per device (localStorage), never blocks content.
  - Lighthouse PWA audit ≥90 (installable + splash + themed) in CI browser check (manual `npx lighthouse` in TESTLOG Wave P1).
- `start_url:/?source=pwa` lets Gate log `source=pwa` launches (analytics-lite, no external tracker — counts only).

## 6. Service Worker (D1, privacy-first)

File: Gate-served `GET /sw.js` (Go handler, `Content-Type: application/javascript`, `Cache-Control: no-store`), version string injected from `buildRevision()`. Bare `register('/sw.js')`, no `?v=` query.

```js
const REV = "<git-rev>"; const STATIC_CACHE = "static-" + REV;
const STATIC_ASSETS = ["/static/style.css", "/static/icon-192.png", "/static/icon-512.png", "/static/icon-512-maskable.png", "/static/apple-touch-icon.png", "/static/favicon.svg", "/offline.html"];
self.addEventListener("install", (e) => { e.waitUntil(caches.open(STATIC_CACHE).then((c) => c.add(new Request("/offline.html", {cache: "reload"}))).then(() => caches.open(STATIC_CACHE).then((c) => c.addAll(STATIC_ASSETS.filter((u) => u !== "/offline.html")))).then(() => self.skipWaiting())); });
self.addEventListener("activate", (e) => { e.waitUntil(caches.keys().then((ks) => Promise.all(ks.filter((k) => k !== STATIC_CACHE).map((k) => caches.delete(k)))).then(() => { if ("navigationPreload" in self.registration) { return self.registration.navigationPreload.enable().catch(() => {}); } }).then(() => self.clients.claim())); });
self.addEventListener("fetch", (e) => {
  const u = new URL(e.request.url);
  if (e.request.method !== "GET" || u.origin !== location.origin) return;
  if (e.request.mode === "navigate") {
    e.respondWith(fetch(e.request).catch(() => caches.open(STATIC_CACHE).then((c) => c.match("/offline.html"))));
    return;
  }
  if (u.pathname.startsWith("/static/") || u.pathname === "/offline.html" || u.pathname === "/favicon.ico") {
    e.respondWith(caches.match(e.request).then((hit) => hit || fetch(e.request).then((res) => res)));
    return;
  }
  // NEVER cache private: /, /class/*, /auth/*, /discuss/*, /push/*, /manifest.json, /sw.js
  return; // network-only passthrough
});
self.addEventListener("push", (e) => {
  let d = {}; try { d = e.data ? e.data.json() : {}; } catch { d = {title: "Новый комментарий"}; }
  const title = d.title || "Новый комментарий";
  e.waitUntil(self.registration.showNotification(title, {
    body: (d.body || "").slice(0, 140),
    icon: "/static/icon-192.png", badge: "/static/icon-192.png",
    tag: d.tag || ("cid-" + d.cid), renotify: true,
    data: {url: d.url || ("/class/" + d.cid), cid: d.cid, comment_id: d.comment_id},
  }));
});
self.addEventListener("notificationclick", (e) => {
  e.notification.close();
  const url = (e.notification.data && e.notification.data.url) || "/";
  e.waitUntil(clients.matchAll({type: "window", includeUncontrolled: true}).then((ws) => {
    for (const w of ws) { if (w.url.includes(new URL(url, location.origin).pathname)) { return w.focus(); } }
    return clients.openWindow(url);
  }));
});
self.addEventListener("pushsubscriptionchange", (e) => { e.waitUntil(resubscribeOnChange()); });
```

- `GET /offline.html`: new Gate-served static shell (generic, **no user data**, `public,max-age=3600`): `Нет соединения. Проверьте интернет — обсуждения появятся, когда сеть вернётся.` + link `/`. SW serves it as `fetch` fallback only for navigations when network throws (never from cache for private HTML — only this generic page).
- No background sync / periodic sync in MVP (iOS weak + unnecessary for <20 users). No `show_rss_subscription` change (already `false` in embed).

## 7. Push pipeline (D2 — the core)

### 7.1 Keys + env (VPS `.env` only, never repo)

| Key | Note |
|-----|------|
| `VAPID_PUBLIC_KEY` / `VAPID_PRIVATE_KEY` / `VAPID_PUBLIC_KEY_OLD` | base64url P-256 pair, generated once via `webpush.GenerateVAPIDKeys()`, helper `go run ./gate/push -gen-vapid`. Public served at `/push/vapid-key`; private never leaves VPS. Rotation: set `VAPID_PUBLIC_KEY` = new, `VAPID_PUBLIC_KEY_OLD` = old, dual-publish both for 7d, then drop old (documented in runbook). Approved 2026-09-21. |
| `VAPID_SUBJECT` | `mailto:mjgavrilov@gmail.com` (RFC8292 contact, sent to push services; teacher-confirmed 2026-09-21). |
| `PUSH_WEBHOOK_SECRET` | 32B hex (`openssl rand -hex 32`), shared: Gate env ↔ remark42 `NOTIFY_WEBHOOK_HEADERS=X-Push-Webhook-Secret:<value>` (headers format `Header1:Value1,Header2:Value2`). |
| remark42 additions | `NOTIFY_ADMINS=webhook`, `NOTIFY_WEBHOOK_URL=http://gate:8081/push/webhook` (internal docker DNS!), `NOTIFY_WEBHOOK_TEMPLATE={"site":"{{.Locator.SiteID}}","page_url":"{{.Locator.URL}}","comment":{"id":"{{.ID}}","parent_id":"{{.ParentID}}","user_id":"{{.User.ID}}","user_name":"{{.User.Name}}","text_snippet":"{{.Text | truncate 300 | escapeJSONString}}","created_at":"{{.Timestamp}}"}}`, `NOTIFY_WEBHOOK_HEADERS=X-Push-Webhook-Secret:${PUSH_WEBHOOK_SECRET}`, `NOTIFY_WEBHOOK_TIMEOUT=5s`, `NOTIFY_QUEUE=200`. `TRUSTED_PROXY` unchanged. Template context = `store.Comment`; D0 spike must prove exact field/filter names before D2. |

Why `http://gate:8081` (not `https://stepik…`): webhook originates inside `app` net; hairpinning via Caddy/edge would need auth + adds latency + leaks secret to edge logs. Internal direct is faster and invisible to CF.

### 7.2 Subscribe UX (per-class, RU)

On `/class/<cid>` (logged-in only): bell button `🔔 Уведомлять о новых комментариях [Вкл/Выкл]` + permission state text. Flow (user gesture → `Notification.requestPermission()` → `pushManager.subscribe` → `POST /push/subscribe` with `cids:[cid]`). On `/` (logged-in): list-level toggle `Уведомлять обо всех моих классах` (`cids:"all"` resolves server-side to `session.allowed` snapshot at send time — not at subscribe time, so left-class revoke takes effect immediately, see §7.4).

RU copy (frozen):
- Enable: `Уведомлять о новых комментариях`
- Granted: `Уведомления включены на этом устройстве.`
- Denied: `Уведомления заблокированы в браузере. Разрешите их в настройках сайта, затем попробуйте снова.`
- iOS-not-installed: `На iPhone уведомления приходят только из приложения на экране «Домой» (Поделиться → На экран «Домой»).`
- Error: `Не удалось включить уведомления. Попробуйте позже.`

Unsubscribe removes endpoint row; disabling one class = `POST /push/subscribe` with narrowed `cids` array (no `PATCH`; server filters `⊆ allowed`).

### 7.3 Fan-out worker (Gate, `gate/push/` new package)

- BoltDB buckets: `push_subs[endpoint_hash] → {uid, endpoint, p256dh, auth, cids|all, ua, created_at, last_ok_at, fail_count}`, `push_meta{vapid_public, vapid_private_ref}` (private key stays in env, never in DB), `push_queue` in-memory channel (cap 512) + worker pool 4 senders, max 8 in-flight WebPush POSTs, **separate limiter from Stepik outbound 4r/s** (Stepik budget untouched; 256M gate fits, measured in Wave P1 via `docker stats`).
- Webhook handler: parse → `cid = ExtractCID(page_url)` → drop if unknown/`site` mismatch → enqueue `{cid, comment_id, author_stepik_id (strip `stepik_` prefix), author_name (from `user_name`, fallback below), snippet, page_url}`. Worker: for each job, list subs where (`cids=="all"` OR `cid ∈ cids`) AND `uid != author_uid` (don't notify self) AND `uid` still allowed for `cid` (check live `sessions` row: `cid ∈ AllowedClassIDs` local read without Stepik call — stale ≤48h accepted, definitive revoke already shrunk `allowed`) → `webpush.SendNotification(payload, sub, {VAPID keys, Subscriber, TTL: 86400, Urgency: normal, Topic: class-<cid>})`. Author FIO = webhook `user_name` primary, sessions-row lookup fallback, else `"Новый комментарий"`.
  - Payload JSON (≤2KB): `{title: "<Class title> — новый комментарий", body: "<Author FIO>: <snippet 120 chars>", cid, comment_id, url: "/class/<cid>#remark-<comment_id>", tag: "cid-<cid>"}`. **No avatar bytes, no tokens.** `Collapse by Topic` so 10 rapid comments → 1 visible notification (renotify).
- Delivery bookkeeping: `410 Gone / 404` from push service → delete sub immediately; transient (429/5xx/timeout) → `fail_count++`, retry with backoff 3× (1s, 30s, 5m), then park until next webhook (don't delete — mobile offline is normal); log `push_send {uid-hash?, cid, endpoint-hash-prefix8, status, latency_ms}` — **never log full endpoint or keys** (endpoint is a bearer secret).
- Rate guard: per-`cid` coalesce window 30s via in-memory `cid → {count, timer}` (10 comments in 30s → 1 push with `body: "N новых комментариев в <Class>"`). First comment arms timer, flush builds single or coalesced body. Prevents spam during lively threads.
- CSRF/rate audit (2026-09-21): push endpoints reuse `admin.Admin` pattern — `validSameOrigin` + `VerifyHeaderCSRF` + per-`sid` limiter. No hole found; no change to `/auth/me` shape needed.

### 7.4 Privacy / isolation (normative)

- Push never bypasses class ACL: send-time check `cid ∈ subscriber_session.allowed` (local read). Left-class/revoked → no push (history stays per 0001 §5, but push stops). `logout-all`/`revoke-user` bumps epoch/version → subs for dead `sid` pruned by uid sweep (hourly, same ticker as session sweeper).
- Webhook payload contains comment snippet — treated as private: Gate logs only `cid, comment_id, author_uid, sub_count`, never snippet text. Push payload snippet truncated 120 chars (same data member would see on page, but new transit via FCM/APNs/Mozilla push services + new copy at rest there — disclosed in consent §9).
- `VAPID_PRIVATE_KEY` + `PUSH_WEBHOOK_SECRET` in VPS `.env` only (`chmod 600`), never in `deploy/.env.example` values (keys only). `docker compose exec gate printenv … | sha256sum` hash-compare debug pattern (runbook §8.3 style), values never leave VPS.
- 152-FZ/minors: no new PII collected (endpoint+p256dh+auth are device keys, not child data; stored per-uid, deletable via Unsubscribe + `deleteme` sweep on logout). Consent line extended (see §9, teacher-approved 2026-09-21).

## 8. Caddy + Cloudflare + compose delta (minimal)

- `deploy/Caddyfile`: add `handle /push/* { reverse_proxy gate:8081 }` (public subscribe/vapid-key/health; webhook NOT here) + serve `/offline.html` via `@static`. Keep `request_header CF-Connecting-IP {client_ip}` + rate-limit IP chain. No change to `/discuss/*` auth, strip rules, or healthcheck listener. After edit: `deploy/caddy-verify.sh` (extended with `/push/*` + `/offline.html` checks) + container `caddy validate` (AGENTS.md exact forms).
- `deploy/compose.yml`: remark42 env += `NOTIFY_ADMINS=webhook`, `NOTIFY_WEBHOOK_URL=http://gate:8081/push/webhook`, `NOTIFY_WEBHOOK_HEADERS=X-Push-Webhook-Secret:${PUSH_WEBHOOK_SECRET}`, `NOTIFY_WEBHOOK_TIMEOUT=5s`, `NOTIFY_QUEUE=200`, `NOTIFY_WEBHOOK_TEMPLATE=<template §7.1>`; gate env += `VAPID_PUBLIC_KEY, VAPID_PRIVATE_KEY, VAPID_PUBLIC_KEY_OLD, VAPID_SUBJECT, PUSH_WEBHOOK_SECRET`. No new services, no `ports:` changes, resource limits unchanged (`gate 256M/128M` — push worker fits; measured separately in Wave P1 via `docker stats`).
- `deploy/.env.example`: keys only (`VAPID_PUBLIC_KEY, VAPID_PRIVATE_KEY, VAPID_PUBLIC_KEY_OLD, VAPID_SUBJECT, PUSH_WEBHOOK_SECRET`, `NOTIFY_*` refs). Secrets never committed.
- Cloudflare: existing hostname Bypass already covers `/push/*`, `/sw.js`, `/manifest.json`, `/offline.html`. Verify `cf-cache-status: BYPASS/DYNAMIC` on each in TESTLOG. No new Page Rules needed.

## 9. Consent + RU strings (amends 0001 §5.2, teacher approves)

Login page consent append (teacher-approved 2026-09-21): `Если включите уведомления, браузер получит технический ключ для доставки оповещений о новых комментариях в ваших классах. Уведомления доставляются через сервис push вашего браузера (Google/Apple/Mozilla) — текст уведомления будет передан ему для показа. Отключить можно в любой момент на странице класса.`

Full RU list (§7.2 + errors): `Сессия истекла…` / `Слишком много запросов…` reuse 0001 §5.3; new push-only strings in §7.2 frozen.

## 10. Browser test plan (Wave P1 — PWA, Wave P2 — push; append to TESTLOG.md)

P1 (installability, no push yet — Gate serves manifest + real SW, webhook disabled):
1. Desktop Chrome `chrome://apps` + DevTools Application→Manifest (no errors, 192+512 present, `standalone`), Lighthouse PWA ≥90.
2. Android Chrome: `beforeinstallprompt` → Install → launches `standalone` (`?source=pwa` in Gate log), icon correct, back button stays in app.
3. iPhone Safari (real device, iOS ≥16.4): Share → Add to Home Screen → opens `standalone`; pre-install push toggle shows iOS-hint string; post-install `Notification.requestPermission()` prompt appears on tap (not on load).
4. Offline: airplane mode → `/static/style.css` loads from SW cache, `/` shows `/offline.html` (generic, no user data), `/class/<cid>` network-only fails safe (no stale private HTML served). `cf-cache-status` recorded for `/manifest.json`, `/sw.js`, `/offline.html`, `/push/vapid-key`.
5. Caddy contracts still green: `deploy/caddy-verify.sh` + §8 items 1–7 from 0001 (teacher/student/outsider/leave/JWT/CF/path) — push must not regress auth.

P2 (push end-to-end, webhook enabled, 2 test users minimum):
6. Student A subscribes on `/class/<cid>` (granted) → Student B posts comment → A receives notification <30s (foreground closed) with correct title/body/deep-link; click focuses/opens `/class/<cid>#remark-<id>`.
7. Self-notify suppressed (B gets nothing for own comment); outsider/revoked user gets nothing (revoke A via `revoke-class`, B posts → no push to A; re-join → push resumes).
8. Multi-device: A subscribes on 2 browsers → both fire; unsubscribe one → only remaining fires.
9. Denied/expired: deny permission → RU denied-string; delete sub via devtools `pushManager.unsubscribe()` → next webhook gets `410` → Gate prunes row (log `push_prune expired`).
10. Burst: 5 comments in 30s → 1 coalesced notification (`N новых комментариев`).
11. Teacher `"all"` sub gets pushes for every owned class; student `"all"` only for own `allowed`.
12. Resource: `docker stats` gate <256M during burst; `go test -count=1 ./...` + `go vet` green.

## 11. Build phases

- **D0 — spike (0.5d, standalone, before Gate changes):** minimal Go sender with `webpush-go v1.4.0` + real browser subscription (manual `vapid-key` dump) → prove VAPID send → notification shows on Android + iOS-HS; plus live remark42 webhook dump (ephemeral secret) to freeze exact `NOTIFY_WEBHOOK_TEMPLATE` field/filter names. Verdict (one paragraph) appended here; split to `plans/0004-push-spike.md` only if >1 page (0003 is teacher Telegram, already exists). Gates D1.
- **D1 — PWA shell (1d):** real `sw.js` (§6 corrected) + `/offline.html` + manifest upgrade (`id:/`, split `any`/`maskable`) + templates install UX + Caddy `/push/*` + `/offline.html` handles + CF verify. Acceptance: Wave P1 green. No webhook yet (subscribe stores rows, fan-out no-op with log `push_noop_no_event`).
- **D2 — push pipeline (2d):** `gate/push/` package (`subscribe/unsubscribe/vapid-key/webhook/worker`), BoltDB buckets, remark42 `NOTIFY_*` compose wiring (frozen template), coalesce + prune + retry, RU strings, consent line. Acceptance: Wave P2 green (items 6–12).
- **D3 — hardening (0.5d):** VAPID rotation doc (`VAPID_PUBLIC_KEY_OLD` dual-publish), `push/health` deep, runbook §, TESTLOG waves, `caddy-verify.sh` re-run, unit test asserting served `sw.js` allowlist (no `caches.add('/')`, no `/class`), `docker stats` evidence. Merge.
- Deferred to later: teacher Telegram channel — design frozen in `plans/0003-teacher-telegram.md`, implementation deferred (needs teacher to create bot via BotFather); lesson-level `…/lesson/<lid>` push (same `cid` fan-out, `url` includes lesson path), email fallback (rejected for minors unless parents request), TWA/Play packaging via PWABuilder.

## 12. Risks

- iOS push requires HS install — students will skip it → mitigate with one-line RU hint + teacher announcement template (`Установите как приложение, иначе уведомления не придут — инструкция на главной`). No auto-prompt (Apple forbids pre-install push).
- remark42 webhook template drift / `Locator.URL` shape change → Gate `ExtractCID` fail-closed drops event + `warn push_webhook_bad_url` + `push_webhook_gap` counter (no crash, no leak). No poller in MVP (dropped 2026-09-21); outage heals on next comment.
- Endpoint churn (browser rotates push URLs) → `410` prune + `pushsubscriptionchange` resubscribe handler; hourly sweep deletes `fail_count>10` + `last_ok>30d`.
- VAPID private leak → rotation via `VAPID_PUBLIC_KEY` + `VAPID_PUBLIC_KEY_OLD` dual-publish 7d (§7.1); old key dies after 7d (subs re-seal on next subscribe — transparent).
- SW cache poisoning private HTML → mitigated by design: SW fetch handler allowlists `/static/*` + `/offline.html` only, navigation-fallback serves only generic `/offline.html`; all else passthrough; `Cache-Control: no-store` on `/sw.js` itself; unit test must assert no `caches.add('/')` or `/class` anywhere (replaces weak `grep -r "caches.*class"`).
- Single VPS SPOF + push queue in-memory → burst loss on restart accepted (comments remain, next comment re-fires; no `down -v` rule from 0001 still holds).
- New dep `webpush-go` review: MIT, `SherClockHolmes/webpush-go v1.4.0` (teacher-approved 2026-09-21 interim), ~21 imports, no cgo; pin via `go.mod` + `go.sum`, `go vet` + `govulncheck` in CI. Approval granted per 0001 §5.3.

## 13. Decisions (resolved 2026-09-21, normative — was open questions + review round)

1. Notify scope: **all class members except the comment author** (no thread-participant-only mode in MVP; coalesced 30s per §7.3).
2. Quiet hours: **none in MVP**. Revisit later only if night spam becomes a problem (then batch into morning digest — deferred, no design frozen here).
3. Teacher Telegram channel: **design frozen in `plans/0003-teacher-telegram.md` (exists), implementation deferred** (needs teacher BotFather bot + VPS `.env` token).
4. Test version: webhook-only MVP, no poller, ephemeral secrets ok (site not used by students yet).
5. Caddy: `handle /push/*` + `/offline.html` via `@static`, extend `caddy-verify.sh`.
6. SW: navigation-only `/offline.html` fallback + cache-first static; bare `register('/sw.js')`, `STATIC_CACHE = "static-"+REV`.
7. CSRF: reuse `admin` pattern (`validSameOrigin` + `VerifyHeaderCSRF` reading `__Host-csrf` via `document.cookie` + `AllowPush` 20/min per `sid`); no `/auth/me` change.
8. Author FIO: webhook `{{.User.Name}}` primary + sessions-row fallback.
9. Subscribe: `"all"` for students + teacher (send-time expand), per-class disable via narrowed `POST`, no `PATCH`.
10. Consent extended with push-service (FCM/APNs/Mozilla) transit sentence.
11. Worker: 4 senders / 8 in-flight, Stepik limiter untouched, in-memory coalesce map.
12. Dep: `webpush-go v1.4.0` approved interim + `govulncheck` in CI.
13. Manifest: `id:/` stable + `start_url:/?source=pwa`; icons split `any` / `maskable` (`icon-512-maskable.png` separate, 80% safe zone, opaque).
14. SW safety: unit test (not grep) asserting allowlist.
