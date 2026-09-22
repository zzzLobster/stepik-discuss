# 0002 — PWA wrapper + new-comment notifications (Web Push)

Date: 2026-09-21
Status: READY FOR IMPLEMENTATION (refined 2026-09-22, security + UX pass)
Implements plan 0001 §7.4 hook (`manifest.json` + stub `sw.js` → full PWA + Web Push).

Domain: `stepik.study67.fyi` (same-domain, no split — iOS PWA + third-party-cookie safe, per 0001 §3).
Stack: Gate (Go 1.27.1) + Caddy `2.11.4-alpine` + remark42 `v1.16.4` + Cloudflare direct (orange-cloud). No new containers.
Test scope: site not used by students yet — D0/P1/P2 run with test users + ephemeral secrets; no migration compat for old installs required.
Test devices: teacher provides real iPhone (iOS ≥16.4, Share → Add to Home Screen, launched from icon) + Android Chrome for P1/P2 — confirmed 2026-09-22.
Priorities: security first, then best UX.

Review gates: `go build ./...`, `go vet ./...`, `go test -count=1 ./...`, `govulncheck ./...`, `deploy/caddy-verify.sh`, container `caddy validate`, browser TESTLOG waves P1/P2.

## 1. Goal

Turn the closed discussion site into an installable mobile web app and notify users about new comments even when the tab is closed:

1. PWA installable on Android (Chrome/Edge/Samsung) + iOS (Safari 16.4+, incl. iOS 26 HS-default) + desktop (Chrome/Edge Add-to-Dock) — `standalone`, own icon, splash, `start_url:/?source=pwa`, stable `id:/`.
2. Browser push about new comments via Web Push (VAPID) + Service Worker `push` → `showNotification`, deep-link to `/class/<cid>#remark-<comment_id>`.
3. Mobile-first UX: class pages usable from Home-Screen icon, offline-safe static shell, RU copy, minors/152-FZ safe (no PII beyond `uid+fio+avatar`, closed threads only).

Non-goals: native App Store / Google Play wrappers (PWABuilder/TWA deferred); email/Telegram student push via remark42-native (rejected — requires emails/Telegram IDs we do not collect); lesson-level threads (Phase 2 in 0001 §7.3 reuses same push plumbing).

## 2. Constraints (do not re-debate)

- Gate serves today: `GET /manifest.json` (standalone, `scope:/`, `start_url:/`, combined `any maskable` icon), `GET /sw.js` stub (fetch passthrough), `apple-touch-icon.png`, `theme-color #3776AB`, `<link rel=manifest>` in `index.html`/`class.html`. Chromium install prompt requires real SW registration + `fetch` handler. D1 splits icons into dedicated `any` + `maskable` files.
- `gate/handlers/handlers.go:Routes()` is wiring; `privateHeaders` = `Cache-Control: private,no-store` + `noindex` on all HTML/API. SW must never cache `/`, `/class/*`, `/auth/*`, `/discuss/*`, `/auth/me`.
- Caddy contracts (enforced by `deploy/caddy-verify.sh`, CI `caddy-contract`): public `handle /discuss/web/* + uri strip_prefix /discuss`; protected `handle_path /discuss/*` strips `/discuss`; gate gets full public URI via `header_up X-Forwarded-Uri /discuss{uri}`; 3-arg `redir`; healthcheck `http://localhost:8081/healthz`. Any Caddyfile edit must re-run `deploy/caddy-verify.sh`.
- `forward_auth gate:8081 /auth/check` only on `/discuss/*`, never on `/web/*`. `ExtractCID` fail-closed `403 unknown_thread` without `?url=` / class-`Referer` / iframe-`?url=` unwrap.
- remark42 `v1.16.4` notification model: `NOTIFY_ADMINS=email|telegram|slack|webhook` (multi), `NOTIFY_USERS=email|telegram`. User push via remark42-native requires email/Telegram identity which our users do not have (Gate-minted JWT only, `AUTH_ANON=false`, dummy `stepik` provider). Gate-owned Web Push is the only per-student path.
- remark42 admin webhook fires HTTP POST per new comment. Template context is the `store.Comment` struct: `{{.ID}}`, `{{.ParentID}}` (empty for top-level), `{{.Text}}` (sanitized HTML via bluemonday), `{{.Orig}}` (raw markdown source), `{{.User.ID}}` (`stepik_<uid>`), `{{.User.Name}}`, `{{.Locator.SiteID}}`, `{{.Locator.URL}}`, `{{.Timestamp.Unix}}` (method call, numeric epoch), `{{.Score}}` (int). Only template function is `escapeJSONString` (returns fully-quoted `json.Marshal` output — use without surrounding quotes). Headers format `Header1:Value1,Header2:Value2` (split on first `:`, `TrimSpace`, no default `Content-Type` — set explicitly).
- iOS constraints: push only after Add-to-Home-Screen + user-granted permission in response to tap; Share-menu install in any browser ≥16.4; no `beforeinstallprompt` on iOS (manual Share → Add instructions required); every `push` handler must end in `showNotification` (no silent push); `pushManager.subscribe({userVisibleOnly:true})` (Apple rejects `false`).
- Scale/privacy: 2–3 classes, <20 users, RU, minors. Store only `uid+fio+avatar_url`. Threads never merge (`page_url` differs per `cid`). Cloudflare bypass covers `/push/*` + `/sw.js` + `/manifest.json` + `/offline.html` (`BYPASS/DYNAMIC`, never cached).
- Deps: `bbolt, golang-jwt/v5, x/oauth2, x/time/rate` + `github.com/SherClockHolmes/webpush-go v1.4.0` (MIT, includes CVE-2024-51744 fix; pin via `go.mod` + `go.sum`, `go vet` + `govulncheck` in CI). No hand-rolled VAPID. No other deps.

## 3. Architecture

```
Browser/PWA (SW + manifest)
  ──https──▶ Cloudflare ──https──▶ Caddy :443 ──▶ Gate :8081 (HTML + /push/* + /sw.js + /manifest.json)
  /discuss/* ──forward_auth──▶ Gate check ──allow──▶ remark42 :8080 (comments)
  remark42 ──NOTIFY_WEBHOOK_URL──▶ http://gate:8081/push/webhook (internal docker `app` net only,
                    secret header, NOT via Caddy/edge)
  Gate ──WebPush (VAPID)──▶ browser push service (FCM/APNs/Mozilla) ──▶ SW `push` ──▶ Notification
```

- Gate owns identity + subscriptions + fan-out; remark42 owns comment events; Caddy owns enforcement; push services own delivery. Same-domain preserves iOS PWA + `__Host-sid` (`Secure, HttpOnly, SameSite=Lax`) semantics.
- Event source: remark42 admin webhook → Gate internal endpoint (only source in MVP). No poller in MVP; outage = log `push_webhook_gap`, next comment re-fires.
- No remark42-native `NOTIFY_USERS`; no `NOTIFY_ADMINS=email/telegram` in MVP — teacher gets the same Web Push as students (plus existing `/discuss/admin/` moderation).
- Volumes/network unchanged: `app` bridge, no `ports:` on backends, only Caddy `80/443`. Volumes `gate-data:/data/gate.db` (new buckets `push_subs`, `push_meta`), `remark-data`, `caddy-data`.
- Ownership to avoid import cycles: `gate/push` owns Store / webhook verification / validation / worker / coalesce / title cache only (imports `sessions`, `config` + stdlib; never `handlers`/`admin`). `gate/handlers` owns all `/push/*` + `/offline.html` HTTP wrappers (reuses `validSameOrigin`, `auth.LoadSession`, `AllowPush`). `gate/admin` imports `push` for prune functions only.

## 4. URL / API contracts

| URL | Auth | Contract |
|-----|------|----------|
| `GET /manifest.json` | public, `Cache-Control: public,max-age=3600` | Full manifest per §5. |
| `GET /sw.js` | public, `Cache-Control: no-store` | Real SW per §6. Served by Gate (not static file) so `REV` from `buildRevision()` can be injected. Scope `/`. Bare `register('/sw.js')`, no `?v=` query. |
| `GET /push/vapid-key` | valid `sid`, `Cache-Control: no-store` | `{key, fp}` for `pushManager.subscribe({userVisibleOnly:true, applicationServerKey})`. `401` anon. Page/SW fetch (never bundle) so rotation needs no release. |
| `POST /push/subscribe` | valid `sid` + `validSameOrigin` + `X-CSRF-Token` matching readable `__Host-csrf` cookie (same pattern as `admin.Admin`) + `AllowPush` per `sid` | Body `{endpoint, keys:{p256dh, auth}, device:{ua, name?}, cids:[cid…] \| "all"}`. Validation per §7.3. Upsert into `push_subs[hex(sha256(endpoint))]`. Returns `{ok:true}`. Per-class disable = `POST` narrowed `cids` array (no `PATCH`). `MaxBytesReader` 64KB. |
| `POST /push/unsubscribe` | same as subscribe | Body `{endpoint}`. Delete by hash. Idempotent (200 even if missing). `MaxBytesReader` 64KB. |
| `POST /push/resubscribe` | valid `sid` + `validSameOrigin` + `AllowPush`; CSRF-exempt (SW has no `document.cookie`/`localStorage`; `SameSite=Lax __Host-sid` + Origin is sufficient; cross-site fetch carries no cookie) | Body `{old_endpoint, endpoint, keys:{p256dh, auth}, device:{ua}}`. Server verifies old row belongs to same `uid` (empty → INSERT fallback), copies `cids`, deletes old hash, upserts new with current `sid` + `key_version`. Returns `{ok:true}`. SW `fetch(...,{credentials:'include'})`. `MaxBytesReader` 64KB. |
| `POST /push/webhook` | internal only: loopback/private peer check + `X-Push-Webhook-Secret` constant-time compare; fail-closed `404` (not `401/403`); `MaxBytesReader` 64KB before parse. Never routed via Caddy (edge has explicit `404` block). | remark42 POST JSON `{site, page_url, comment:{id, parent_id, user_id, user_name, text_html, text_orig, created_unix, score}}`. Gate: `ExtractCID` → `cid`; drop if unknown or `site != SITE`; strip `stepik_` prefix for `author_uid`; snippet server-side; enqueue; return `200 {ok:true}` fast (<200ms, enqueue only). |
| `GET /push/health` | shallow public `{ok:true}`; deep `?deep=1` requires `X-Gate-Auth` Guard (Caddy injects `header_up` only on this handle) | Deep returns `{ok:true, subs:<bolt count>, queue:<len(chan)>}`. Separate from `/healthz`. |
| `GET /offline.html` | public, `Cache-Control: public,max-age=3600` | Generic shell, no user data per §6. Must exist or SW install fails. |
| Existing `/`, `/class/<cid>`, `/auth/*`, `/discuss/*`, `/healthz`, `/robots.txt`, `/static/*` | unchanged | Class pages add push UI (bell + iOS hint) + page-load key migration; no change to `forward_auth` or `ExtractCID`. |

Push API errors are JSON (not HTML): `Content-Type: application/json`, `Cache-Control: private,no-store`, `X-Robots-Tag: noindex`, body `{error:<code>}` with `auth_required|forbidden|transient|rate_limited|bad_request`. `401` anon/expired, `403` Origin/CSRF/ACL fail, `429` + `Retry-After` on `AllowPush` deny. No change to `/auth/me` shape.

## 5. PWA manifest + installability

`handleManifest` (Go, `gate/handlers`):

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

- `id:/` stable (never changes); `start_url` within `scope:/`. Never `"any maskable"` on one file.
- `icon-512-maskable.png` accepted only if: opaque full-bleed, logo inside central 80%-diameter safe-zone circle (410px of 512), no transparency. Verify in DevTools Application → Manifest → safe-area preview + maskable.app shapes; regenerate via Maskable.app Editor if it fails. 180px `apple-touch-icon.png` already present.
- Templates (`index.html`, `class.html` `<head>`): keep `<link rel=manifest>`, add `<meta name=mobile-web-app-capable content=yes>`, `<meta name=apple-mobile-web-app-capable content=yes>`, `<meta name=apple-mobile-web-app-status-bar-style content=default>`, `<meta name=apple-mobile-web-app-title content="Stepik Discuss">`. Register SW unconditionally: `<script>if('serviceWorker' in navigator){navigator.serviceWorker.register('/sw.js')}</script>` (deferred, non-blocking).
- Install UX (RU, minimal, no nagging):
  - Android/Desktop Chromium: listen `beforeinstallprompt`, show inline `Установить приложение` button once (dismiss persists in `localStorage`), `appinstalled` hides it.
  - iOS: `iPhone|iPad` + `!navigator.standalone` + `!matchMedia('(display-mode: standalone)')` → one-line hint `На iPhone: Поделиться → На экран «Домой», затем откройте с иконки — тогда придут уведомления.` Shown max once per device, never blocks content.
  - Lighthouse PWA audit ≥90 in TESTLOG Wave P1.
- `start_url:/?source=pwa` enables launch counting (no external tracker).

## 6. Service Worker + offline + page JS

Gate-served `GET /sw.js` (`Content-Type: application/javascript`, `Cache-Control: no-store`), `REV` injected from `buildRevision()` via new `handlers.Server.Revision` field set from `main.buildRevision()`. `STATIC_CACHE = "static-"+REV`.

```js
function urlBase64ToUint8Array(s){s=s.replace(/-/g,"+").replace(/_/g,"/");const p="=".repeat((4-s.length%4)%4);const b=atob(s+p);const o=new Uint8Array(b.length);for(let i=0;i<b.length;i++)o[i]=b.charCodeAt(i);return o;}
const REV = "<git-rev>"; const STATIC_CACHE = "static-" + REV;
const STATIC_ASSETS = ["/static/style.css", "/static/icon-192.png", "/static/icon-512.png", "/static/icon-512-maskable.png", "/static/apple-touch-icon.png", "/static/favicon.svg", "/offline.html"];
self.addEventListener("install", (e) => { e.waitUntil(caches.open(STATIC_CACHE).then((c) => c.add(new Request("/offline.html", {cache: "reload"}))).then(() => caches.open(STATIC_CACHE).then((c) => c.addAll(STATIC_ASSETS.filter((u) => u !== "/offline.html")))).then(() => self.skipWaiting())); });
self.addEventListener("activate", (e) => { e.waitUntil(caches.keys().then((ks) => Promise.all(ks.filter((k) => k !== STATIC_CACHE).map((k) => caches.delete(k)))).then(() => self.clients.claim())); });
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
  return; // network-only passthrough; never cache /, /class/*, /auth/*, /discuss/*, /push/*, /manifest.json, /sw.js
});
self.addEventListener("push", (e) => {
  let d = {}; try { d = e.data ? e.data.json() : {}; } catch { d = {title: "Новый комментарий"}; }
  const title = d.title || "Новый комментарий";
  e.waitUntil(self.registration.showNotification(title, {
    body: d.body || "",
    icon: "/static/icon-192.png", badge: "/static/icon-192.png",
    tag: d.tag || ("cid-" + d.cid), renotify: true,
    data: {url: d.url || ("/class/" + d.cid), cid: d.cid, comment_id: d.comment_id},
  }));
});
self.addEventListener("notificationclick", (e) => {
  e.notification.close();
  const url = (e.notification.data && e.notification.data.url) || "/";
  e.waitUntil(clients.matchAll({type: "window", includeUncontrolled: true}).then((ws) => {
    for (const w of ws) { try { if (new URL(w.url).pathname === new URL(url, location.origin).pathname) return w.focus(); } catch(_) {} }
    return clients.openWindow(url);
  }));
});
self.addEventListener("pushsubscriptionchange", (e) => {
  e.waitUntil((async () => {
    try {
      const k = await fetch("/push/vapid-key", {credentials: "include"}).then((r) => { if (!r.ok) throw new Error("key"); return r.json(); });
      const sub = await self.registration.pushManager.subscribe({userVisibleOnly: true, applicationServerKey: urlBase64ToUint8Array(k.key)});
      const j = sub.toJSON();
      await fetch("/push/resubscribe", {method: "POST", credentials: "include", headers: {"Content-Type": "application/json"}, body: JSON.stringify({old_endpoint: (e.oldSubscription && e.oldSubscription.endpoint) || "", endpoint: sub.endpoint, keys: j.keys, device: {ua: navigator.userAgent}})});
    } catch (_) { /* next webhook 410-prunes if dead, next page visit heals */ }
  })());
});
```

- `GET /offline.html`: Gate-served from `gate/static/offline.html` (`handlers.handleOffline`, `public,max-age=3600`, `text/html`): generic `Нет соединения. Проверьте интернет — обсуждения появятся, когда сеть вернётся.` + link `/`. No user data, no `{{.FIO}}`. SW serves it as `fetch` fallback only for navigations.
- Page JS: new `gate/static/push.js` (cached `public,max-age=3600`, SW-cached) holds `urlBase64ToUint8Array`, `csrfFromCookie` (page-only, reads `__Host-csrf` via `document.cookie`), bell logic, page-load migration. `class.html`/`index.html` add `<script src="/static/push.js" defer>` + minimal inline `data-*` (cid, uid) + bell button HTML. SW bundle never contains `localStorage`/`document.cookie` (enforced by unit test).
- Page-load logic on logged-in `/` + `/class/*` (silent, no permission prompt unless fresh subscribe):
  1. `GET /push/vapid-key` → `fp`; `sub = await pushManager.getSubscription()`.
  2. If `sub==null` → show bell-Off (needs tap).
  3. If `sub!=null` and `localStorage push_uid != current uid` (shared-computer user change) → `await sub.unsubscribe()` + best-effort `POST /push/unsubscribe(old)` + clear `push_uid/push_cids/vapid_key_fp` + show bell-Off (require explicit tap; never inherit previous user endpoint).
  4. Else if `localStorage vapid_key_fp != fp` (rotation) → `unsubscribe()` → `subscribe(new key)` → `POST /push/unsubscribe(old)` + `POST /push/subscribe(new, same cids from push_cids or "all")` → store new `fp`.
  5. Else (same `uid` + same `fp`): best-effort idempotent `POST /push/subscribe(same endpoint, push_cids or "all")` on every load (no `subscribe()` call, no prompt). Heals server-deleted rows after relog/revoke/restart. Missing `push_cids` → `"all"`.
- No background sync / periodic sync in MVP. iOS hardening: `Notification.requestPermission()` only inside bell-tap handler synchronously; `userVisibleOnly:true`; every `push` ends in `showNotification`.

## 7. Push pipeline

### 7.1 Keys + env (VPS `.env` only, never repo)

| Key | Note |
|-----|------|
| `VAPID_PUBLIC_KEY` / `VAPID_PRIVATE_KEY` / `VAPID_PUBLIC_KEY_OLD` | base64url P-256 pair via `webpush.GenerateVAPIDKeys()`, helper `go run ./gate/cmd/genvapid` (`package main` in `gate/cmd/genvapid/main.go`). `config.Load` fail-fast if `VAPID_PUBLIC_KEY/VAPID_PRIVATE_KEY/VAPID_SUBJECT/PUSH_WEBHOOK_SECRET` missing (no degraded mode). Public validation: base64url decodes to 65B uncompressed point `0x04…`; private to 32B. Fingerprint `fp8 = hex(sha256([]byte(public base64url string)))[:8]` (hash string bytes; helper `config.VapidFP8`). Served at `/push/vapid-key`; private never leaves VPS, never in DB. Rotation: `push_subs` stores `key_version`; sender signs each sub with its row key. MVP single active key (`_OLD` empty → all sends use current; migration paths ship as no-ops). Future: new → current for fresh subscribes, old kept for old rows, clients migrate via unsubscribe-before-resubscribe, retire old when old-version count → 0. No dual-send. Documented in runbook. |
| `VAPID_SUBJECT` | `mailto:mjgavrilov@gmail.com` (RFC 8292 `sub` contact; `mailto:` or `https://` required, bare email rejected). |
| `PUSH_WEBHOOK_SECRET` | 32B hex (`openssl rand -hex 32`, 64 hex chars). Shared Gate env ↔ remark42 `NOTIFY_WEBHOOK_HEADERS`. |
| remark42 | `NOTIFY_ADMINS=webhook`, `NOTIFY_WEBHOOK_URL=http://gate:8081/push/webhook` (internal docker DNS), `NOTIFY_WEBHOOK_TEMPLATE={"site":{{.Locator.SiteID \| escapeJSONString}},"page_url":{{.Locator.URL \| escapeJSONString}},"comment":{"id":{{.ID \| escapeJSONString}},"parent_id":{{.ParentID \| escapeJSONString}},"user_id":{{.User.ID \| escapeJSONString}},"user_name":{{.User.Name \| escapeJSONString}},"text_html":{{.Text \| escapeJSONString}},"text_orig":{{.Orig \| escapeJSONString}},"created_unix":{{.Timestamp.Unix}},"score":{{.Score}}}}`, `NOTIFY_WEBHOOK_HEADERS=Content-Type:application/json,X-Push-Webhook-Secret:${PUSH_WEBHOOK_SECRET}`, `NOTIFY_WEBHOOK_TIMEOUT=5s`, `NOTIFY_QUEUE=200`. `TRUSTED_PROXY` unchanged. `Text` = sanitized HTML, `Orig` = raw markdown (snippet prefers `Orig`). |

Internal `http://gate:8081` avoids Caddy/edge hairpin (faster, secret invisible to CF/edge logs).

### 7.2 Subscribe UX + RU strings + consent

On `/class/<cid>` (logged-in): bell `🔔 Уведомлять о новых комментариях [Вкл/Выкл]` + permission state. Flow: user gesture → `Notification.requestPermission()` synchronously → `GET /push/vapid-key` → `pushManager.subscribe({userVisibleOnly:true, applicationServerKey})` → `POST /push/subscribe` with `cids:[cid]` → store `push_uid/push_cids/vapid_key_fp` in `localStorage`. Pre-flight: if `!('PushManager' in window)` or iOS-not-standalone → show iOS-hint instead of active bell. On `/` (logged-in): list toggle `Уведомлять обо всех моих классах` (`cids:"all"`, expanded server-side at send time). Bell reflects this-device `getSubscription()`, not server-global. Unsubscribe removes endpoint row; disable one class = `POST /push/subscribe` narrowed array.

RU copy:
- Enable: `Уведомлять о новых комментариях`
- Granted: `Уведомления включены на этом устройстве.`
- Denied: `Уведомления заблокированы в браузере. Разрешите их в настройках сайта, затем попробуйте снова.`
- iOS-not-installed: `На iPhone уведомления приходят только из приложения на экране «Домой» (Поделиться → На экран «Домой»).`
- Error: `Не удалось включить уведомления. Попробуйте позже.`
- Bell-Off: `Уведомления выключены на этом устройстве. Выход также отключает их на этом устройстве.`

Login consent (`handlers.RUConsent`, shown above button): existing text + `Если включите уведомления, браузер получит технический ключ для доставки оповещений о новых комментариях в ваших классах. Уведомления доставляются через сервис push вашего браузера (Google/Apple/Mozilla) — текст уведомления будет передан ему для показа. Отключить можно в любой момент на странице класса.`

### 7.3 Fan-out worker (`gate/push` + `gate/handlers` wrappers)

- Storage: BoltDB `push_subs[hex(sha256(endpoint))] → {uid int64, sid string, endpoint, p256dh, auth, cids []int64 + all bool, ua string, key_version fp8, created_at, last_ok_at time.Time, fail_count int}`, `push_meta{vapid_public, fp8}` (private never in DB). `push_queue` in-memory channel cap 512; worker pool 4 senders (in-flight 4), separate from Stepik outbound limiter.
- Sessions: `Store.SessionsForUID(uid)` (full-bucket scan, skip corrupt) + `BestSessionForUID(uid)` (filter `ExpiresAt>now && UserVersion==current && GlobalEpoch==current`, pick freshest `LastVerifiedAt`; `nil` if none). Teacher `IsTeacher` does not bypass expiry.
- Title cache: in-memory `cid → title` mutex map in `gate/push`, set from `session.ClassTitles` at `POST /push/subscribe`, `handleCallback` login, and `resolveHTMLSession` success after `EnsureFresh`. Send path only reads; fallback `Класс <cid>`; lost on restart.
- Webhook handler: `MaxBytesReader` 64KB → parse → `cid = ExtractCIDWithConfig("", page_url, cfg.ClassBase(), cfg.EmbedHost())` → drop if unknown or `site != SITE` (`warn push_webhook_bad_url/site`) → `author_uid` = strip `stepik_` prefix + `ParseInt` (fail → `0`, log `push_webhook_bad_author`) → snippet = `Orig` primary else tag-stripped `Text` (`<[^>]*>` → `` + `html.UnescapeString`, collapse whitespace, trim, 120 runes; empty → `Новый комментарий`) → enqueue `{cid, comment_id, author_uid, author_name, snippet, page_url}`.
- Send: for each job, for each sub: skip if `sub.uid == author_uid`; if `BestSession` present require `IsTeacher || cid ∈ AllowedClassIDs` else `push_skip_revoked`; if absent push only from stored array (`cid ∈ sub.cids`); stored `"all"` + absent → skip, except teacher (`uid == TEACHER_ID`) → push. Subscribe-time `cids ⊆ allowed` + send-time live check (defense in depth). Exactly one send per sub with its row key via `SendNotificationWithContext(ctx10s, payload, sub, {Subscriber: VAPID_SUBJECT, TTL: 86400, Urgency: normal, Topic: class-<cid>})`.
- Author: webhook `user_name` primary, `BestSessionForUID(author_uid).FIO` fallback, else `""` (body = snippet alone). Title: `"<Class title> — новый комментарий"` single, `"<Class title>"` summary. Payload JSON ≤2KB (`len(json)>2048` → cut snippet). No avatar bytes, no tokens.
- Delivery: `410/404` → delete immediately (`push_prune expired`); `403` → `push_403_key_mismatch` (never auto-delete); transient (429/5xx/timeout/`DeadlineExceeded`) → `fail_count++`, non-blocking requeue via `time.AfterFunc(delay, requeue)` with delays `[1s,30s,5m]`, honor `Retry-After` (cap 5m); after 3x park until next webhook. Worker never sleeps inline. Log `push_send {uid_hash8=hex(sha256(uid))[:8], cid, endpoint_hash8=hex(sha256(endpoint))[:8], status, latency_ms}`; never log endpoint/keys/snippet. Webhook log only `cid,comment_id,author_uid,sub_count`.
- Coalesce: per-`cid` `type coalesce struct {count int; latestID string; authorUIDs []int64; timer *time.Timer}` + mutex map. First comment for idle `cid` sends immediately + `count=1` + 30s window; further in window bump `count/latestID/authors`; flush: `count==1` → nothing more; `count>1` → one summary `N=count (total)` with same `tag:cid-<cid>` + `renotify:true` (visible collapses to 1). Author excluded per-sub at immediate + flush. Timers lost on restart.
- Subscribe validation: `endpoint` parses URL, `scheme==https`, `host!=""`, `len<2048`; `p256dh` 87–88 chars base64url decode-check, `auth` 22–24 chars decode-check; `cids` array requires every `cid ∈ session.allowed` (or teacher) else `403` whole request; `"all"` allowed; `device.ua` truncate 256, `device.name` optional 64.
- CSRF/rate: `subscribe|unsubscribe` = `validSameOrigin` + `VerifyHeaderCSRF` + `AllowPush(sid)` (`Every(3s)`, burst 20); `resubscribe` = `validSameOrigin` + `sid` + `AllowPush` only.
- Prune wiring: `handleLogout` deletes rows where `sid==logged-out sid`; `admin.logoutAll` deletes all rows (epoch invalidates all); `admin.revokeUser` deletes rows for target `uid`; `admin.revokeClass` shrinks arrays, deletes single-`[cid]` rows and all `"all"` rows for that `uid` (re-subscribed as new allowed on next heal). Hourly sweep (session sweeper ticker): delete `fail_count>10 && last_ok>30d` + `no live session && last_ok>7d`.

### 7.4 Privacy / isolation

- Push never bypasses class ACL (send-time matrix above). Explicit logout deletes that `sid` rows → logged-out device gets nothing even if same `uid` live elsewhere. Shared-computer user change forces untap, never inherits.
- Webhook snippet treated as private: logs exclude snippet; push transit via FCM/APNs/Mozilla disclosed in consent.
- Secrets in VPS `.env` only (`chmod 600`), keys only in `deploy/.env.example`. Debug via hash-compare (`printenv … | sha256sum`), values never leave VPS.
- 152-FZ/minors: endpoint+p256dh+auth are device keys (not child data), per-uid+sid, deletable via bell-Off + per-device logout + user-change guard.

## 8. Caddy + Cloudflare + compose

`deploy/Caddyfile` (place before final `handle { respond 404 }`, after `/auth/*` block):

```caddy
handle /offline.html {
  reverse_proxy gate:8081
}
handle /push/vapid-key* {
  reverse_proxy gate:8081
}
handle /push/subscribe* {
  reverse_proxy gate:8081
}
handle /push/unsubscribe* {
  reverse_proxy gate:8081
}
handle /push/resubscribe* {
  reverse_proxy gate:8081
}
handle /push/health* {
  reverse_proxy gate:8081 {
    header_up X-Gate-Auth {env.CADDY_GATE_TOKEN}
  }
}
handle /push/webhook* {
  respond "Not found" 404
}
```

Safe: `handle` mutually exclusive, longest-path-first; no overlap with `@static`, `/class/*`, `/auth/*`, `/healthz`, `/discuss/*`. Webhook has no proxy. `CF-Connecting-IP` + rate-limit chain unchanged.

`deploy/compose.yml`: remark42 += `NOTIFY_ADMINS=webhook`, `NOTIFY_WEBHOOK_URL=http://gate:8081/push/webhook`, `NOTIFY_WEBHOOK_HEADERS=Content-Type:application/json,X-Push-Webhook-Secret:${PUSH_WEBHOOK_SECRET}` (double-quoted for expansion), `NOTIFY_WEBHOOK_TIMEOUT=5s`, `NOTIFY_QUEUE=200`, `NOTIFY_WEBHOOK_TEMPLATE='<frozen §7.1>'` (single-quoted, no `$`); gate += `VAPID_PUBLIC_KEY, VAPID_PRIVATE_KEY, VAPID_PUBLIC_KEY_OLD, VAPID_SUBJECT, PUSH_WEBHOOK_SECRET`. No new services, no `ports:` changes.

`deploy/.env.example`: keys only. Secrets never committed.

Cloudflare: hostname Bypass already covers new paths; verify `cf-cache-status: BYPASS/DYNAMIC` on `/push/*`, `/sw.js`, `/manifest.json`, `/offline.html` in TESTLOG.

`caddy-verify.sh` extensions (extend `upstream.py` to emulate: `/push/webhook →404`, `/push/vapid-key` no `__Host-sid` cookie →401 else 200, `/offline.html →200`, `/push/health?deep=1` no `X-Gate-Auth` →404): checks `6: /push/webhook →404`, `7: /push/vapid-key no-cookie →401`, `8: /offline.html →200`, `9: /push/health?deep=1 no-token →404`. After any Caddyfile edit: container `caddy validate` (AGENTS.md exact form) + `deploy/caddy-verify.sh` + `docker compose -f deploy/compose.yml config`.

## 9. Build steps (implement in order D0 → D1 → D2 → D3)

### D0 — spike (0.5d, standalone, before Gate changes)

1. Minimal Go sender with `webpush-go v1.4.0` + real browser subscription (manual vapid-key dump) → prove VAPID send → desktop notification + `201` from push service (iOS-HS proof deferred to P2).
2. Live remark42 webhook dump (ephemeral secret, `spike/` style, never committed) proving frozen §7.1 template: parses, valid JSON on quotes/newlines/emoji, `.Timestamp.Unix` numeric, `.Orig` populated, `Content-Type + secret` headers received.
3. Exit: one-paragraph verdict appended here (split to `plans/0004-push-spike.md` only if >1 page). Template string locked. Gates D1.

### D1 — PWA shell (1d, no webhook yet)

1. `gate/config/config.go`: VAPID_* + secret validation + `VapidFP8` helper (§7.1).
2. `gate/sessions/sessions.go`: create `push_subs`, `push_meta` buckets; push CRUD + `SessionsForUID`/`BestSessionForUID`.
3. `gate/ratelimit/ratelimit.go`: `push` map + `AllowPush(sid)` (`Every(3s)`, burst 20).
4. `gate/push/`: leaf types, `VerifyWebhook`, validation, `TitleCache`.
5. `gate/cmd/genvapid/main.go`: generator (never commit output).
6. `gate/handlers/handlers.go`: `Server.Revision` field + `New` param (set from `main.buildRevision()`); `Routes` `/push/*` + `/offline.html`; manifest upgrade (§5); full `sw.js` (§6); `handleOffline`; JSON errors; `push.js` wiring.
7. `gate/main.go`: pass `Revision`, no worker yet (fan-out no-op `push_noop_no_event`).
8. `gate/static/push.js` + `gate/static/offline.html` + `class.html`/`index.html` (bell + install hint + `push.js` script).
9. `deploy/Caddyfile` + `deploy/caddy-verify.sh` (checks 6–9 + stub) + `docker compose config`; `caddy validate`; CF verify.
10. Acceptance: Wave P1 green (teacher on iPhone + Android) + Lighthouse ≥90 + `/offline.html 200` + `/push/vapid-key 401 anon` + SW bundle unit test (allowlist, no `caches.add('/')`/`/class`, no `localStorage`/`document.cookie`, helper present).

### D2 — push pipeline (2d, core)

1. `gate/push/`: webhook handler, worker + coalesce + retry (§7.3), title cache population.
2. `gate/handlers`: subscribe/unsubscribe/resubscribe/vapid-key/health wrappers + logout prune + consent update.
3. `gate/admin`: `logoutAll`/`revokeUser`/`revokeClass` prune.
4. `deploy/compose.yml`: `NOTIFY_*` wiring (frozen template, no edits without D0 re-verdict).
5. RU strings + consent line live.
6. Acceptance: Wave P2 green (items 6–12 + 7b; item 10 = ≤2 pushes per 30s window, visible 1) + `docker stats gate <256M` + `push_send/push_prune/push_skip_revoked/push_403_key_mismatch` samples.

### D3 — hardening (0.5d)

1. Rotation runbook section (single-key MVP + future overlap, `_OLD` reserved).
2. `push/health` deep evidence; TESTLOG waves; `caddy-verify.sh` re-run.
3. Unit tests: SW allowlist + webhook validation (`http:`/bad keys/oversize rejected) + `BestSessionForUID` ACL matrix + logout-deletes-only-that-sid + user-change guard.
4. `.github/workflows/ci.yml`: `govulncheck` job (`go install golang.org/x/vuln/cmd/govulncheck@latest && govulncheck ./...`).
5. `go build/vet/test -count=1` green + `docker stats` evidence. Then merge.

Deferred: teacher Telegram channel (`plans/0003-teacher-telegram.md`, needs BotFather bot); lesson-level `…/lesson/<lid>` push; email fallback; TWA/Play packaging.

File order: `config` → `sessions` → `ratelimit` → `push` → `genvapid` → `handlers` → `admin` → `main` → `static/push.js` + `templates` + `static/offline.html` → `Caddyfile` + `compose.yml` + `.env.example` + `caddy-verify.sh` → `ci.yml` → `ops-runbook.md` → `TESTLOG.md`.

## 10. Browser test plan (append to TESTLOG.md)

P1 (installability, webhook disabled):
1. Desktop Chrome `chrome://apps` + DevTools Manifest (no errors, 192+512, `standalone`), Lighthouse ≥90.
2. Android Chrome: `beforeinstallprompt` → Install → `standalone` (`?source=pwa` in Gate log), icon correct.
3. iPhone Safari (confirmed device): Share → Add to Home Screen → `standalone`; pre-install toggle shows iOS-hint; post-install tap shows permission prompt (never on load).
4. Offline: airplane mode → `/static/style.css` from SW cache, `/` shows `/offline.html` (generic), `/class/<cid>` fails safe (no stale private HTML). Record `cf-cache-status` for `/manifest.json`, `/sw.js`, `/offline.html`, `/push/vapid-key`.
5. Caddy contracts green: `caddy-verify.sh` + 0001 §8 items 1–7.

P2 (push end-to-end, webhook enabled, ≥2 test users; teacher validates on confirmed iPhone + Android):
6. A subscribes on `/class/<cid>` → B posts → A gets notification <30s (tab closed) with correct title/body/deep-link; click focuses/opens `/class/<cid>#remark-<id>`. Log `push_send`.
7. Self-suppressed (B gets nothing for own); outsider/revoked gets nothing (`push_skip_revoked`; re-join resumes).
7b. Logout silence: A logs out device1 → B posts → device1 nothing, device2 (same A) fires. A re-logs device1 (silent heal) → next post fires without re-tap. Shared-computer: A out, B in same profile without tap → B gets nothing until tap; after tap B gets own only.
8. Multi-device: A on 2 browsers → both fire; unsubscribe one → only remaining fires.
9. Denied/expired: deny → RU denied-string; devtools `unsubscribe()` → next webhook `410` → prune (`push_prune expired`).
10. Burst: 5 comments in 30s → ≤2 pushes (1 immediate + 1 summary `N новых комментариев`), visible 1 (same tag + renotify).
11. Teacher `"all"` gets every owned class; student `"all"` only own `allowed`.
12. Resource: `docker stats` gate <256M; `go test -count=1` + `vet` green.

## 11. Risks

- iOS HS-install skipped → one-line RU hint + teacher announcement (`Установите как приложение, иначе уведомления не придут — инструкция на главной`). No auto-prompt.
- Webhook template drift / `Locator.URL` change → `ExtractCID` fail-closed + `push_webhook_bad_url` + `push_webhook_gap` (no crash/leak). Next comment heals.
- Endpoint churn → `410/404` prune + `pushsubscriptionchange` + page-load migration/heal + user-change guard + hourly sweep. `403` = rotation signal, never auto-delete. Logout deletes only that `sid` rows.
- VAPID leak → per-sub `key_version` rotation; single-key swap safe only in test scope; production must overlap; old dies when old-version count → 0.
- SW cache poisoning → allowlist `/static/*` + `/offline.html` only, generic offline fallback, `no-store` on `sw.js`, unit test allowlist.
- Single VPS SPOF + in-memory queue → burst loss on restart accepted (comments remain; no `down -v`).
- New dep `webpush-go` — pinned + `govulncheck`.

## 12. Decisions

All decisions below are final. Implementation must match; any change requires plan update.

| # | Topic | Decision | Details |
|---|-------|----------|---------|
| D1 | Notify scope | All class members except author | No thread-participant-only mode in MVP. Coalesced per §7.3. |
| D2 | Quiet hours | None in MVP | Revisit only if night spam becomes a problem (morning digest deferred, no design). |
| D3 | Teacher Telegram | Design in `0003`, implementation deferred | Needs teacher BotFather bot + VPS `.env` token. |
| D4 | Test scope | Webhook-only MVP, no poller | Ephemeral secrets ok; outage heals on next comment. |
| D5 | Caddy routing | Enumerated handles + own `/offline.html` + webhook `404` + health `header_up` | `handle /push/vapid-key*`, `/push/subscribe*`, `/push/unsubscribe*`, `/push/resubscribe*` (plain proxy); `handle /push/health*` with `header_up X-Gate-Auth`; `handle /push/webhook* {404}`; own `handle /offline.html` (not `@static` edit). Verify checks 6–9. Compose template single-quoted, headers double-quoted. |
| D6 | Service Worker | Navigation-only offline fallback + cache-first static; bare `register('/sw.js')`; `STATIC_CACHE="static-"+REV` | No `localStorage`/`document.cookie` in SW; `pushsubscriptionchange` best-effort via CSRF-exempt resubscribe; page-load migration/heal/user-change guard; `urlBase64ToUint8Array` in both SW and page; gesture-only permission, `userVisibleOnly:true`, always `showNotification`. No preload, no background/periodic sync. |
| D7 | CSRF | `subscribe|unsubscribe` = Origin + header CSRF + rate limit; `resubscribe` = Origin + sid + rate limit only | `validSameOrigin` + `VerifyHeaderCSRF` (`__Host-csrf` via `document.cookie`) + `AllowPush Every(3s)` burst 20 per `sid`. `resubscribe` CSRF-exempt (SW cannot send header; `SameSite=Lax` + Origin sufficient). SW uses `credentials:'include'`. No `/auth/me` change. |
| D8 | Author name | Webhook `User.Name` primary | Fallback `BestSessionForUID(author_uid).FIO`, else `""` (body = snippet alone). |
| D9 | Subscribe scope | `"all"` for students + teacher; per-class disable via narrowed `POST`; no `PATCH` | Server expands `"all"` at send time via `BestSessionForUID` so revoke takes effect immediately. |
| D10 | Consent | Extended with push-service transit sentence | Verbatim §7.2; login page existing slot; bell-Off text frozen. |
| D11 | Worker | 4 senders (in-flight 4), Stepik limiter untouched, immediate-first coalesce + non-blocking retry, `sid` per row | Queue 512 (gate) / 200 (remark42). `Topic: class-<cid>`, `TTL: 86400`, urgency normal. `SendNotificationWithContext(ctx10s)`. |
| D12 | Dependency | `webpush-go v1.4.0` interim + `govulncheck` in CI | MIT; pin `go.mod`+`go.sum`. No hand-rolled VAPID. |
| D13 | Manifest | `id:/` stable + `start_url:/?source=pwa`; split `any` / `maskable` | Verify-or-regenerate maskable (opaque, 80% safe zone). |
| D14 | SW safety | Unit test (not grep) asserts allowlist | No `caches.add('/')`, no `/class`, no `localStorage`/`document.cookie` in SW, helper present. |
| D15 | Webhook template | Frozen §7.1, no `truncate`, unquoted `escapeJSONString`, `text_html` + `text_orig` + `created_unix` numeric, explicit `Content-Type`, `NOTIFY_QUEUE=200` | D0 proves verbatim; no edits without D0 re-verdict. |
| D16 | Send-time ACL | Present → require allowed else suppress; absent array → push from stored; absent `"all"` → skip except teacher; logout deleted → nothing; revoke prunes synchronously | `push_skip_revoked` on suppress. `revoke-class` deletes `"all"` rows (healed on next visit). Sweep `fail>10 && ok>30d` + `no session && ok>7d`. |
| D17 | VAPID keys | Per-sub `key_version` (`fp8`), single-key MVP, `_OLD` reserved, no dual-send | `fp8 = hex(sha256([]byte(public string)))[:8]`; unsubscribe-before-resubscribe; generator `gate/cmd/genvapid`; fail-fast Load. |
| D18 | Resubscribe | `POST /push/resubscribe` UPDATE-by-`old_endpoint` + page migration/heal/user-change guard | SW best-effort; page primary healer; compat Win/Mac/iOS/Android × Chrome/Chromium/Safari/Firefox. |
| D19 | Titles | In-memory `cid → title` cache, `Класс <cid>` fallback | Set at subscribe + login + `EnsureFresh` success; send only reads; lost on restart; no Stepik hot-path. |
| D20 | Health | `/push/health` shallow public, deep via Caddy `header_up` | Deep `{ok, subs, queue}`; separate from `/healthz`. |
| D21 | Caps | 64KB webhook / 2KB payload / `AllowPush` 20/min/sid / queue 512 / 4 workers / 30s coalesce | Endpoint `https:` any host (log host) + `len<2048`; `p256dh` 87–88, `auth` 22–24 decode-checked; `cids ⊆ allowed` else `403`; `ua` 256, `name` 64. |
| D22 | Logout silence | Per-device (`sid`) delete; relog silent-heal; user-change forces untap; bell per-device | Logged-out device gets nothing even if same `uid` live elsewhere. |
| D23 | Push errors | JSON `{error}` with `private,no-store` + `noindex` | `401/403/429+Retry-After/bad_request`; reuse RU rate-limited text in JSON. |
| D24 | Revision wiring | `Server.Revision` from `main.buildRevision()` injected as `REV` | Bare `register('/sw.js')`, no `?v=`. |
| D25 | Webhook guard | New `VerifyWebhook` (secret constant-time + private peer, `404`) | Never reuse `auth.Guard`; never via Caddy. |
| D26 | Coalesce UX | Immediate-first + 30s tail-batch | Single → <5s; burst 5/30s → 2 sends (total N), visible 1. |
| D27 | Log privacy | Hashes only: `uid_hash8`, `endpoint_hash8` | Never endpoint/keys/snippet; webhook log `cid,comment_id,author_uid,sub_count` only. |
| D28 | Client JS | Separate `static/push.js` + bell HTML | Cached, SW-cached; inline `data-*` only. |
| D29 | Snippet | `Orig` primary else stripped `Text`, 120 runes, ≤2KB | Tag strip + unescape + collapse; empty → `Новый комментарий`. |
| D30 | Test devices | Teacher provides real iPhone + Android — confirmed | Used for P1/P2; not an open question. |

## 13. References

Local (ground truth): `plans/0001-stepik-discussion-site.md` (§§3–8, §7.4, §5.2–5.3, §6.1); `plans/0003-teacher-telegram.md`; `AGENTS.md`; `docs/ops-runbook.md` (§§2/8–9); `deploy/Caddyfile`, `deploy/compose.yml`, `deploy/.env.example`, `deploy/caddy-verify.sh`; `gate/main.go`, `gate/handlers/handlers.go`, `gate/handlers/htmlsession.go` + `util.go`, `gate/config/config.go`, `gate/sessions/sessions.go`, `gate/auth/auth.go`, `gate/admin/admin.go`, `gate/ratelimit/ratelimit.go`, `gate/templates/`, `gate/static/*`, `go.mod`/`go.sum`, `.github/workflows/ci.yml`, `TESTLOG.md`.

Upstream code: `remark42/backend/app/notify/webhook.go`, `remark42/backend/app/store/comment.go`, `remark42/backend/app/store/user.go`, `go-pkgz/notify/webhook.go`, `SherClockHolmes/webpush-go` (`webpush.go`, `v1.4.0` releases, pkg.go.dev).

Docs/standards: `remark42.com/docs/configuration/notifications/` + `/parameters/`; `backend/app/cmd/server.go` (`NotifyGroup`/`Webhook`); RFC 8292 §4.2 + RFC 9749 §5; web-push rotation guides; MDN (`pushsubscriptionchange`, installable, manifest `start_url`/`icons`); Apple Web Push docs + WebKit 13878/13966; Chrome `pwa-manifest-id` + Lighthouse maskable audit + web.dev maskable + maskable.app; Caddy `handle/handle_path/route/reverse_proxy` + matchers.
