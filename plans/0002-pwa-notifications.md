# 0002 — PWA wrapper + new-comment notifications (Web Push)

Date: 2026-09-22
Status: READY FOR IMPLEMENTATION
Implements plan 0001 §7.4 hook (`manifest.json` + stub `sw.js` → full PWA + Web Push).

Domain: `stepik.study67.fyi` (same-domain, no split — iOS PWA + third-party-cookie safe, per 0001 §3).
Stack: Gate (Go 1.27.1) + Caddy `2.11.4-alpine` + remark42 `v1.16.4` + Cloudflare direct (orange-cloud). No new containers.
Test scope: site not used by students yet — D0/P1/P2 run with test users + ephemeral secrets; no migration compat for old installs required.
Test devices: iPhone iOS 26.+ (≥16.4 HS-install push OK) + Android Chrome — confirmed 2026-09-22.
Priorities: security first, then best UX.

Gates: `go build ./...`, `go vet ./...`, `go test -count=1 ./...`, `govulncheck ./...`, `deploy/caddy-verify.sh`, container `caddy validate`, browser TESTLOG waves P1/P2.

Implementation must match this plan; any change requires a plan update.

## 1. Goal

Turn the closed discussion site into an installable mobile web app and notify users about new comments even when the tab is closed:

1. PWA installable on Android (Chrome/Edge/Samsung) + iOS (Safari 16.4+, any browser via Share → Add to Home Screen, launched from icon) + desktop (Chrome/Edge Add-to-Dock) — `standalone`, own icon, splash, `start_url:/?source=pwa`, stable `id:/`.
2. Browser push about new comments via Web Push (VAPID) + Service Worker `push` → `showNotification`, deep-link to `/class/<cid>#remark-<comment_id>` (server-constructed canonical URL, never remark42 `page_url`).
3. Mobile-first UX: class pages usable from Home-Screen icon, offline-safe static shell, RU copy, minors/152-FZ safe (no PII beyond `uid+fio+avatar`, closed threads only).

Non-goals: native App Store / Google Play wrappers (PWABuilder/TWA deferred); email/Telegram student push via remark42-native (rejected — requires emails/Telegram IDs we do not collect); lesson-level threads (Phase 2 in 0001 §7.3 reuses same push plumbing).

## 2. Constraints (do not re-debate)

- Gate serves today: `GET /manifest.json` (standalone, `scope:/`, `start_url:/`, combined `any maskable` icon), `GET /sw.js` stub (fetch passthrough), `apple-touch-icon.png`, `theme-color #3776AB`, `<link rel=manifest>` in `index.html`/`class.html`. Chromium install prompt requires real SW registration + `fetch` handler. D1 splits icons into dedicated `any` + `maskable` files.
- `gate/handlers/handlers.go:Routes()` is wiring; `privateHeaders` = `Cache-Control: private,no-store` + `noindex` on all HTML/API. SW must never cache `/`, `/class/*`, `/auth/*`, `/discuss/*`, `/auth/me`.
- `Server` has no `Revision` field today; `main.buildRevision()` exists but is not injected. D1 adds `Server.Revision` + `New` param (signature break accepted; fallback `"dev"` when VCS info absent — fixes `unknown` default). `Routes()` has no `/push/*` or `/offline.html`; `config.Load()` is fail-fast but has no VAPID/PUSH vars; `sessions` has 4 buckets only (`sessions`, `user_versions`, `teacher_token`, `meta`), no `SessionsForUID`/`BestSessionForUID`; `ratelimit` has no `AllowPush`/`AllowPushByIP`; `static/push.js` + `static/offline.html` missing; `webpush-go` absent from `go.mod`; CI has no `govulncheck`; Caddyfile has no `/push/*` or `/offline.html`; compose has no `NOTIFY_*`/`VAPID_*`; `caddy-verify.sh` checks 1–5 only. `icon-512-maskable.png` file exists but is unused. `handleStatic` today lacks `.js → application/javascript` and `.html → text/html` mappings. Bolt has no `push_subs`/`push_meta` buckets and no `SchemaVersion` bump for them. All of the above are D1–D3 work, not assumptions.
- Caddy contracts (enforced by `deploy/caddy-verify.sh`, CI `caddy-contract`): public `handle /discuss/web/* + uri strip_prefix /discuss`; protected `handle_path /discuss/*` strips `/discuss`; gate gets full public URI via `header_up X-Forwarded-Uri /discuss{uri}`; 3-arg `redir`; healthcheck `http://localhost:8081/healthz`. Any Caddyfile edit must re-run `deploy/caddy-verify.sh`. `handle` blocks are mutually exclusive, first match wins; same-named `handle` directives sort longest-path-first. Insertion point for §8 block: after `/auth/*` block, before `/discuss/*` blocks and before final `handle { respond 404 }` (the file has `/discuss` blocks between — "before final handle" alone is wrong).
- `forward_auth gate:8081 /auth/check` only on `/discuss/*`, never on `/web/*`. `ExtractCID` fail-closed `403 unknown_thread` without `?url=` / class-`Referer` / iframe-`?url=` unwrap. Webhook path reuses `ExtractCIDWithConfig("", page_url, cfg.ClassBase(), cfg.EmbedHost())` — signature already supports it.
- remark42 `v1.16.4` notification model: `NOTIFY_ADMINS=email|telegram|slack|webhook` (multi), `NOTIFY_USERS=email|telegram`. User push via remark42-native requires email/Telegram identity which our users do not have (Gate-minted JWT only, `AUTH_ANON=false`, dummy `stepik` provider). Gate-owned Web Push is the only per-student path.
- remark42 admin webhook fires HTTP POST per new comment. Verified upstream (`backend/app/notify/webhook.go`, `backend/app/store/comment.go`, docs `configuration/notifications` + `parameters`): default template `{"text": {{.Text | escapeJSONString}}}`, headers format `Header1:Value1,Header2:Value2` (split on first `:`, `TrimSpace`, no default `Content-Type` — set explicitly), `NOTIFY_QUEUE` default `100` (plan uses `200`), `NOTIFY_WEBHOOK_TIMEOUT` default `5s`. Template context is the `store.Comment` struct: `{{.ID}}`, `{{.ParentID}}` (empty for top-level), `{{.Text}}` (sanitized HTML via bluemonday `UGCPolicy`), `{{.Orig}}` (raw markdown source, never render as HTML), `{{.User.ID}}` (`stepik_<uid>`), `{{.User.Name}}`, `{{.Locator.SiteID}}`, `{{.Locator.URL}}`, `{{.Timestamp.Unix}}` (method call, numeric epoch), `{{.Score}}` (int). Only template function is `escapeJSONString` (returns fully-quoted `json.Marshal` output — use without surrounding quotes).
- iOS constraints (verified Apple/WebKit docs): push only after Add-to-Home-Screen + user-granted permission in response to tap; Share-menu install in any browser ≥16.4; no `beforeinstallprompt` on iOS (manual Share → Add instructions required); every `push` handler must end in `showNotification` (Safari revokes permission on silent push); `pushManager.subscribe({userVisibleOnly:true})` (Apple rejects `false`).
- Scale/privacy: 2–3 classes, <20 users, RU, minors. Store only `uid+fio+avatar_url`. Threads never merge (`page_url` differs per `cid`). Cloudflare Bypass rule `(http.host eq "stepik.study67.fyi") → Bypass cache` covers `/push/*` + `/sw.js` + `/manifest.json` + `/offline.html` (`BYPASS/DYNAMIC`, never cached) — confirmed 2026-09-22.
- Deps: `bbolt, golang-jwt/v5, x/oauth2, x/time/rate` + `github.com/SherClockHolmes/webpush-go v1.4.0` (MIT, published 2025-01-02, after CVE-2024-51744; pin via `go.mod` + `go.sum`, `go vet` + `govulncheck` in CI). API verified: `GenerateVAPIDKeys() (private, public string, err error)` (base64 `RawURLEncoding`), `SendNotificationWithContext(ctx, message, sub, options)` with `Options{Subscriber, VAPIDPublicKey, VAPIDPrivateKey, TTL, Topic, Urgency, VapidExpiration}`. No hand-rolled VAPID. No other deps. `bluemonday.StrictPolicy()` is preferred over regex for HTML stripping if HTML strip is needed (already an indirect dep via remark42 model; no new dep if already present, else regex + `html.UnescapeString` path in §7.3 is acceptable).
- Single `:8081` in MVP (no `:8082` second listener) — intentional. Extra listener = compose/healthcheck/complexity for <20 users; header-deny + secret + edge 404 block is sufficient. `:8082` documented as future option only.
- Push endpoint allowlist is intentional (D34) — zero UX cost, legit browsers only use known push hosts.

## 3. Architecture

```
Browser/PWA (SW + manifest)
  ──https──▶ Cloudflare ──https──▶ Caddy :443 ──▶ Gate :8081 (HTML + /push/* + /sw.js + /manifest.json)
  /discuss/* ──forward_auth──▶ Gate check ──allow──▶ remark42 :8080 (comments)
  remark42 ──NOTIFY_WEBHOOK_URL──▶ http://gate:8081/push/webhook (internal docker `app` net only,
                    secret header, NOT via Caddy/edge, single :8081)
  Gate ──WebPush (VAPID)──▶ browser push service (FCM/APNs/Mozilla) ──▶ SW `push` ──▶ Notification
```

- Gate owns identity + subscriptions + fan-out; remark42 owns comment events; Caddy owns enforcement; push services own delivery. Same-domain preserves iOS PWA + `__Host-sid` (`Secure, HttpOnly, SameSite=Lax`) semantics.
- Event source: remark42 admin webhook → Gate internal endpoint (only source in MVP). No poller in MVP; outage = log `push_webhook_gap`, next comment re-fires.
- No remark42-native `NOTIFY_USERS`; no `NOTIFY_ADMINS=email/telegram` in MVP — teacher gets the same Web Push as students (plus existing `/discuss/admin/` moderation). `NOTIFY_ADMINS=webhook` stays extensible to `webhook,telegram` for plan 0003.
- Volumes/network unchanged: `app` bridge, no `ports:` on backends, only Caddy `80/443`. Volumes `gate-data:/data/gate.db` (new buckets `push_subs`, `push_meta` + `SchemaVersion` bump / create-if-missing), `remark-data`, `caddy-data`.
- Ownership to avoid import cycles: `gate/push` owns Store / webhook verification / validation / worker / coalesce / title cache only (imports `sessions`, `config` + stdlib; never `handlers`/`admin`). `gate/handlers` owns all `/push/*` + `/offline.html` HTTP wrappers (reuses `validSameOrigin`, `auth.LoadSession`, `AllowPush`, `AllowPushByIP`). `gate/admin` imports `push` for prune functions only. `admin` cannot import `handlers.validSameOrigin` (cycle — `handlers` already imports `admin`); `handlers`-side push code reuses it directly.
- Atomic session+push mutation (no two-tx): `sessions` owns the buckets and exposes single-`Update` APIs — `DeleteSessionAndPushSubs(sid)`, `StripClassAndPrunePush(uid,cid)`, `BumpVersionAndPrunePush(uid)` — and `push` exposes only pure row-mutators (or `sessions` owns all logic). Two separate Bolt transactions for one logical revoke/logout is forbidden (a stale `BestSession` in the gap would re-authorize a revoked `cid`).

## 4. URL / API contracts

| URL | Auth | Contract |
|-----|------|----------|
| `GET /manifest.json` | public, `Cache-Control: public,max-age=3600`, `Content-Type: application/manifest+json` | Full manifest per §5. |
| `GET /sw.js` | public, `Cache-Control: no-store`, `Content-Type: application/javascript` | Real SW per §6. Served by Gate (not static file) so `REV` from `buildRevision()` can be injected. Scope `/`. Bare `register('/sw.js')`, no `?v=` query. |
| `GET /push/vapid-key` | `AllowPushByIP(ClientIP)` before `LoadSession`, then valid `sid`, `Cache-Control: no-store`. Per-sid `AllowPush` also checked after auth (same bucket — fetched on every page load). | `{key, fp}` for `pushManager.subscribe({userVisibleOnly:true, applicationServerKey})`. `401` anon. Page/SW fetch (never bundle) so rotation needs no release. |
| `POST /push/subscribe` | `AllowPushByIP(ClientIP)` before `LoadSession`, then valid `sid` + `validSameOrigin` + `X-CSRF-Token` matching readable `__Host-csrf` cookie (same pattern as `admin.Admin`) + per-sid `AllowPush` after auth | Body `{endpoint, keys:{p256dh, auth}, device:{ua, name?}, cids:[cid…] \| "all"}`. Validation per §7.3 incl. endpoint allowlist (D34). Upsert into `push_subs[hex(sha256(endpoint))]`. Returns `{ok:true}`. Per-class disable = `POST` narrowed `cids` array (no `PATCH`). `MaxBytesReader` 64KB. |
| `POST /push/unsubscribe` | `AllowPushByIP(ClientIP)` before `LoadSession`, then valid `sid` + `validSameOrigin` + `X-CSRF-Token` + per-sid `AllowPush` after auth | Body `{endpoint}`. Ownership-scoped delete: delete rows for this `uid` first; cross-`uid` delete only if `BestSessionForUID(row.uid)==nil` (orphan / shared-computer). Prevents a member silencing a teacher while still healing shared-computer orphans. Idempotent (200 even if missing). `MaxBytesReader` 64KB. |
| `POST /push/resubscribe` | `AllowPushByIP(ClientIP)` before `LoadSession`, then valid `sid` + **require-present `Origin` exact match** (no `Referer` fallback — SW JSON POST always sends `Origin`) + per-sid `AllowPush` after auth; CSRF-exempt (SW has no `document.cookie`/`localStorage`; `SameSite=Lax __Host-sid` + required Origin is sufficient; cross-site fetch carries no cookie) | Body `{old_endpoint, endpoint, keys:{p256dh, auth}, device:{ua}}` (no `cids`). Server: if `old_endpoint==""` → `400` (no INSERT; SW expiry is rare and the page-load full subscribe with `cids` + CSRF is the healer). Else row must exist and belong to same `uid`, otherwise `403` (never steal/overwrite foreign row). Copy `cids`, re-validate `cids ⊆ allowed` at resubscribe time, delete old hash, upsert new with current `sid` + `key_version`. Returns `{ok:true}`. SW `fetch(...,{credentials:'include'})`. `MaxBytesReader` 64KB. |
| `POST /push/webhook` | internal only, single `:8081` (no `:8082` in MVP): `RemoteAddr`-only loopback/private peer check (`net.ParseIP`, loopback + private incl. docker `172.16/12`; parse fail → deny; never read `X-Forwarded-*`/`CF-Connecting-IP` on this route) + deny if any of `X-Forwarded-Uri` / `X-Forwarded-For` / `CF-Ray` / `CF-Connecting-IP` / `X-Gate-Auth` present (proves the request came via Caddy/edge, not docker-internal) + `X-Push-Webhook-Secret` constant-time compare + require `Content-Type: application/json` + fail-closed `404` if configured secret is empty; fail-closed `404` (not `401/403`); `MaxBytesReader` 64KB before parse. Never routed via Caddy (edge has explicit `404` block). Never reuse `auth.Guard` (different secret + no `X-Gate-Auth` semantics). | remark42 POST JSON `{site, page_url, comment:{id, parent_id, user_id, user_name, text_html, text_orig, created_unix, score}}`. Gate: `ExtractCID` → `cid`; drop if unknown or `site != SITE`; strip `stepik_` prefix for `author_uid`; `comment_id` allowlist `^[A-Za-z0-9_-]{1,64}$` else drop; snippet server-side; enqueue non-blocking; return `200 {ok:true}` fast (<200ms, enqueue only). Queue-full → `push_queue_drop` + `200` (never `503`, avoids remark42 retry storm). Never log body/snippet/`user_name` on any failure path — log only `remote_hash8, bytes, reason`. |
| `GET /push/health` | shallow public `{ok:true}` rate-limited via `AllowPushByIP` only (no session). Deep `?deep=1` requires `auth.Guard` (`X-Gate-Auth`); Caddy sends NO `header_up X-Gate-Auth` on this handle (unlike `/healthz`), so via edge deep is always `404` (no injection path); via docker/caddy-net with token it works (localhost-only ops). | Deep returns `{ok:true, subs:<push_subs count via Bucket.Stats()>, queue:<len(chan)>}` — counts only, no subscriber PII. Deep without token → `404` (not `401`). Separate from `/healthz`. |
| `GET /offline.html` | public, `Cache-Control: public,max-age=3600`, `text/html` | Generic shell, no user data per §6. Must exist or SW install fails. Own Caddy `handle` (not `@static` edit). |
| Existing `/`, `/class/<cid>`, `/auth/*`, `/discuss/*`, `/healthz`, `/robots.txt`, `/static/*` | unchanged | `/` ignores `?source=pwa` (launch counting via Gate log only). Class pages add push UI (bell + iOS hint) + page-load key migration; no change to `forward_auth` or `ExtractCID`. |

Push API errors are JSON (not HTML): `Content-Type: application/json`, `Cache-Control: private,no-store`, `X-Robots-Tag: noindex`, body `{error:<code>}`. Mapping: `401 anon/expired → auth_required`; `403 Origin/CSRF/ACL/uid-mismatch → forbidden`; `429 AllowPush/AllowPushByIP deny → rate_limited + Retry-After`; `400 validation → bad_request`; `502 send-transient surfaced only in logs, never to browser`. Reuse RU rate-limited text in JSON for `429`. No change to `/auth/me` shape. Parity note: `/auth/check` + `/auth/admin` JSON lack `X-Robots-Tag` today — push JSON adds it per this mapping; no change to old routes in MVP.

### 4.1 Frozen JSON schemas (Go structs are source of truth)

```go
// GET /push/vapid-key → 200
type VapidKeyResp struct { Key string `json:"key"`; FP string `json:"fp"` }
// key: base64url unpadded P-256 public (65B uncompressed 0x04…); fp: fp8 hex (8 chars).

// POST /push/subscribe
type SubscribeReq struct {
  Endpoint string `json:"endpoint"`
  Keys struct { P256dh string `json:"p256dh"`; Auth string `json:"auth"` } `json:"keys"`
  Device struct { UA string `json:"ua"`; Name string `json:"name,omitempty"` } `json:"device"`
  Cids CidsOrAll `json:"cids"` // custom UnmarshalJSON: JSON array of int64 OR string "all"
}
// POST /push/unsubscribe
type UnsubscribeReq struct { Endpoint string `json:"endpoint"` }
// POST /push/resubscribe (no cids — copied from old row)
type ResubscribeReq struct {
  OldEndpoint string `json:"old_endpoint"`
  Endpoint string `json:"endpoint"`
  Keys struct { P256dh string `json:"p256dh"`; Auth string `json:"auth"` } `json:"keys"`
  Device struct { UA string `json:"ua"` } `json:"device"`
}
// POST /push/webhook (from remark42 template §7.1)
type WebhookReq struct {
  Site string `json:"site"`; PageURL string `json:"page_url"`
  Comment struct {
    ID string `json:"id"`; ParentID string `json:"parent_id"`
    UserID string `json:"user_id"`; UserName string `json:"user_name"`
    TextHTML string `json:"text_html"`; TextOrig string `json:"text_orig"`
    CreatedUnix int64 `json:"created_unix"`; Score int `json:"score"`
  } `json:"comment"`
}
// Gate → push service payload (≤2048B after marshal)
type PushPayload struct {
  Title string `json:"title"`; Body string `json:"body"`
  Tag string `json:"tag"`; URL string `json:"url"`
  Cid int64 `json:"cid"`; CommentID string `json:"comment_id"`
}
```

`comment_id` allowlist: `^[A-Za-z0-9_-]{1,64}$` (fail-closed drop on mismatch). Push `url` is always server-constructed `/class/<cid>#remark-<comment_id>` and Gate asserts `strings.HasPrefix(url, "/class/")`; SW asserts `url.startsWith("/class/")` else falls back to `"/"`. `page_url` is used only for `ExtractCID`, never flows into `clients.openWindow()`.

### 4.2 Header / cache table (who sets: Gate unless noted)

| Route | `Content-Type` | `Cache-Control` | Notes |
|-------|----------------|-----------------|-------|
| `/manifest.json` | `application/manifest+json` | `public,max-age=3600` | Gate sets both. |
| `/sw.js` | `application/javascript` | `no-store` | Gate sets both. |
| `/push/vapid-key` | `application/json` | `no-store` | + `privateHeaders` (`private,no-store` + `noindex`) — `no-store` wins. |
| `/push/subscribe`, `/unsubscribe`, `/resubscribe` | `application/json` | `private,no-store` + `X-Robots-Tag: noindex` | Errors follow §4 mapping. |
| `/push/webhook` | `application/json` | none (internal) | `200 {ok:true}` on accept and on queue-full drop. Requires `Content-Type: application/json`. |
| `/push/health` shallow | `application/json` | `no-store` | `AllowPushByIP` only. Deep adds Guard; Caddy injects no `X-Gate-Auth` here. |
| `/offline.html` | `text/html; charset=utf-8` | `public,max-age=3600` | No `{{.FIO}}`, no user data. |
| `/static/push.js` | `application/javascript; charset=utf-8` | `public,max-age=3600` (via existing static handler) | SW-cached. |
| `/static/*.html` | `text/html; charset=utf-8` | `public,max-age=3600` (via existing static handler) | `handleStatic` mapping fixed in D1 (D41). |

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
  - Android/Desktop Chromium: listen `beforeinstallprompt`, show inline `Установить приложение` button once (dismiss persists in `localStorage` key `pwa_install_dismissed=1`), `appinstalled` hides it.
  - iOS: `iPhone|iPad` + `!navigator.standalone` + `!matchMedia('(display-mode: standalone)')` → one-line hint `На iPhone: Поделиться → На экран «Домой», затем откройте с иконки — тогда придут уведомления.` Shown max once per device (`localStorage pwa_ios_hint=1`), never blocks content. iPad desktop-mode (`Macintosh` UA + touch) gap accepted for <20 users; optionally add `navigator.maxTouchPoints>1` check.
  - Lighthouse PWA audit ≥90 in TESTLOG Wave P1.
- `start_url:/?source=pwa` enables launch counting (Gate `/` handler ignores the query; count in access log; no external tracker).

## 6. Service Worker + offline + page JS

Gate-served `GET /sw.js` (`Content-Type: application/javascript`, `Cache-Control: no-store`), `REV` injected from `buildRevision()` via new `handlers.Server.Revision` field set from `main.buildRevision()` (fallback `"dev"` when VCS info absent; rollback changes `REV` → old cache deleted on activate). `STATIC_CACHE = "static-"+REV`.

```js
function urlBase64ToUint8Array(s){s=s.replace(/-/g,"+").replace(/_/g,"/");const p="=".repeat((4-s.length%4)%4);const b=atob(s+p);const o=new Uint8Array(b.length);for(let i=0;i<b.length;i++)o[i]=b.charCodeAt(i);return o;}
const REV = "<git-rev>"; const STATIC_CACHE = "static-" + REV;
const STATIC_ASSETS = ["/static/style.css", "/static/push.js", "/static/icon-192.png", "/static/icon-512.png", "/static/icon-512-maskable.png", "/static/apple-touch-icon.png", "/static/favicon.svg", "/offline.html"];
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
  let url = (e.notification.data && e.notification.data.url) || "/";
  if (typeof url !== "string" || !url.startsWith("/class/")) url = "/";
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
    } catch (_) { /* 400 on empty old_endpoint is fine; next page visit heals via full subscribe */ }
  })());
});
```

- `STATIC_ASSETS` includes `/static/push.js` (omitting it would leave bell logic network-dependent offline). Every URL in `STATIC_ASSETS` must `200` with correct `Content-Type` — unit test asserts status + type per D41. If any listed asset 404s, `addAll` rejects and the whole install fails, so verify `/static/apple-touch-icon.png` path exactly (file is `gate/static/apple-touch-icon.png`, served under `/static/`).
- `GET /offline.html`: Gate-served from `gate/static/offline.html` (`handlers.handleOffline`, `public,max-age=3600`, `text/html; charset=utf-8`): generic `Нет соединения. Проверьте интернет — обсуждения появятся, когда сеть вернётся.` + link `/`. No user data, no `{{.FIO}}`. SW serves it as `fetch` fallback only for navigations.
- Page JS: new `gate/static/push.js` (cached `public,max-age=3600`, SW-cached, served `application/javascript; charset=utf-8`) holds `urlBase64ToUint8Array`, `csrfFromCookie` (page-only, reads `__Host-csrf` via `document.cookie`), bell logic, page-load migration. `class.html`/`index.html` add `<script src="/static/push.js" defer>` + minimal inline `data-*` (`data-cid`, `data-uid`) + bell button HTML. SW bundle never contains `localStorage`/`document.cookie` (enforced by unit test, not grep).
- `localStorage` keys (frozen): `push_uid` (string uid), `push_cids` (`"all"` or JSON array string), `vapid_key_fp` (fp8), `pwa_install_dismissed`, `pwa_ios_hint`. On logout keep keys (rely on server-side `sid` delete + user-change guard); never inherit previous user endpoint.
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
| `VAPID_PUBLIC_KEY` / `VAPID_PRIVATE_KEY` / `VAPID_PUBLIC_KEY_OLD` | base64url P-256 pair via `webpush.GenerateVAPIDKeys()` (returns `RawURLEncoding`: public 65B uncompressed `0x04…`, private 32B), helper `go run ./gate/cmd/genvapid` (`package main` in `gate/cmd/genvapid/main.go`). `config.Load` fail-fast if `VAPID_PUBLIC_KEY/VAPID_PRIVATE_KEY/VAPID_SUBJECT/PUSH_WEBHOOK_SECRET` missing (no degraded mode; `_OLD` empty-string allowed in MVP). Public validation: base64url decodes to 65B uncompressed point `0x04…`; private to 32B. Fingerprint `fp8 = hex(sha256([]byte(public base64url string)))[:8]` (hash string bytes; helper `config.VapidFP8`). Served at `/push/vapid-key`; private never leaves VPS, never in DB. Rotation: `push_subs` stores `key_version`; sender maps `row.fp8 → private key` and signs each sub with its row key; unknown `fp8` → `push_skip_unknown_key` + skip (never fallback to current — would cause `403` storm). MVP single active key (`_OLD` empty → all sends use current; migration paths ship as no-ops). Future: new → current for fresh subscribes, old kept for old rows, clients migrate via unsubscribe-before-resubscribe, retire old when old-version count → 0. No dual-send. Documented in runbook. |
| `VAPID_SUBJECT` | `mailto:mjgavrilov@gmail.com` — frozen 2026-09-22 (RFC 8292 `sub` contact; `mailto:` or `https://` required, bare email rejected; `webpush-go` auto-prefixes `mailto:` but always store full form). |
| `PUSH_WEBHOOK_SECRET` | 32B hex (`openssl rand -hex 32`, 64 hex chars). Shared Gate env ↔ remark42 `NOTIFY_WEBHOOK_HEADERS`. Empty value = fail-closed `404` on every webhook call (never accept). Rotation requires simultaneous restart window (both sides read env at boot); document hash-compare debug. |
| remark42 | `NOTIFY_ADMINS=webhook`, `NOTIFY_WEBHOOK_URL=http://gate:8081/push/webhook` (internal docker DNS, single port — no `:8082` in MVP), `NOTIFY_WEBHOOK_TEMPLATE={"site":{{.Locator.SiteID \| escapeJSONString}},"page_url":{{.Locator.URL \| escapeJSONString}},"comment":{"id":{{.ID \| escapeJSONString}},"parent_id":{{.ParentID \| escapeJSONString}},"user_id":{{.User.ID \| escapeJSONString}},"user_name":{{.User.Name \| escapeJSONString}},"text_html":{{.Text \| escapeJSONString}},"text_orig":{{.Orig \| escapeJSONString}},"created_unix":{{.Timestamp.Unix}},"score":{{.Score}}}}`, `NOTIFY_WEBHOOK_HEADERS=Content-Type:application/json,X-Push-Webhook-Secret:${PUSH_WEBHOOK_SECRET}`, `NOTIFY_WEBHOOK_TIMEOUT=5s`, `NOTIFY_QUEUE=200`. `TRUSTED_PROXY` unchanged. `Text` = sanitized HTML, `Orig` = raw markdown (snippet prefers `Orig`). Gate queue `512` vs remark42 `200` is intentional (gate absorbs bursts + retries; remark42 smaller is upstream backpressure). |
| Send options (frozen) | `TTL: 86400`, `Urgency: "normal"` (low/high only with explicit plan change), `Topic: "class-<cid>"`, `ctx` 10s timeout per send, `VapidExpiration` unset = library default (never set custom expiry in MVP). |

Internal `http://gate:8081` avoids Caddy/edge hairpin (faster, secret invisible to CF/edge logs).

Deploy ordering (fail-fast breaks old deploys otherwise): add secrets to VPS `.env` + `compose.yml` first, then deploy gate. `VAPID_PUBLIC_KEY_OLD` may be empty in MVP.

### 7.2 Subscribe UX + RU strings + consent

On `/class/<cid>` (logged-in): bell `🔔 Уведомлять о новых комментариях [Вкл/Выкл]` + permission state. Flow: user gesture → `Notification.requestPermission()` synchronously → `GET /push/vapid-key` → `pushManager.subscribe({userVisibleOnly:true, applicationServerKey})` → `POST /push/subscribe` with `cids:[cid]` → store `push_uid/push_cids/vapid_key_fp` in `localStorage`. Pre-flight: if `!('PushManager' in window)` or iOS-not-standalone → show iOS-hint instead of active bell. On `/` (logged-in): list toggle `Уведомлять обо всех моих классах` (`cids:"all"`, expanded server-side at send time via live `BestSessionForUID`, so future classes are included automatically and revoke takes effect immediately). Bell reflects this-device `getSubscription()`, not server-global. Unsubscribe removes endpoint row; disable one class = `POST /push/subscribe` narrowed array.

RU copy:
- Enable: `Уведомлять о новых комментариях`
- Granted: `Уведомления включены на этом устройстве.`
- Denied: `Уведомления заблокированы в браузере. Разрешите их в настройках сайта, затем попробуйте снова.`
- iOS-not-installed: `На iPhone уведомления приходят только из приложения на экране «Домой» (Поделиться → На экран «Домой»).`
- Error: `Не удалось включить уведомления. Попробуйте позже.`
- Bell-Off: `Уведомления выключены на этом устройстве. Выход также отключает их на этом устройстве.`

Login consent (`handlers.RUConsent`, shown above button): existing text + `Если включите уведомления, браузер получит технический ключ для доставки оповещений о новых комментариях в ваших классах. Уведомления доставляются через сервис push вашего браузера (Google/Apple/Mozilla) — текст уведомления будет передан ему для показа. Отключить можно в любой момент на странице класса.`

### 7.3 Fan-out worker (`gate/push` + `gate/handlers` wrappers)

- Storage: BoltDB `push_subs[hex(sha256(endpoint))] → {uid int64, sid string, endpoint, p256dh, auth, cids []int64 + all bool, ua string, key_version fp8, created_at, last_ok_at time.Time, fail_count int}`, `push_meta{vapid_public, fp8}` (private never in DB). Bump/create-if-missing Bolt `SchemaVersion` for the new buckets. `push_queue` in-memory channel cap 512; worker pool 4 senders (in-flight 4), separate from Stepik outbound limiter. Bolt tx never spans network: read snapshot → release → `SendNotificationWithContext` → short update tx (`last_ok_at`/`fail_count`/delete). Queue depth exposed via `/push/health` deep; `push_queue_drop` logged on full.
- Sessions: `Store.SessionsForUID(uid)` (full-bucket scan, skip corrupt) + `BestSessionForUID(uid)` (filter `ExpiresAt>now && UserVersion==current && GlobalEpoch==current` where currents come from `GetUserVersion`/`GetGlobalEpoch` store globals, UTC clock; pick freshest `LastVerifiedAt`; `nil` if none). Teacher `IsTeacher` does not bypass expiry (static `uid==TEACHER_ID` exception in send matrix is config-based, not session-based, and stays). Atomic mutators (single `Update`, two-tx forbidden): `DeleteSessionAndPushSubs(sid)`, `StripClassAndPrunePush(uid,cid)`, `BumpVersionAndPrunePush(uid)` — `sessions` owns buckets, `push` exposes pure row-mutators only.
- Title cache: in-memory `cid → title` mutex map in `gate/push`, set from `session.ClassTitles` at `POST /push/subscribe`, `handleCallback` login, and `resolveHTMLSession` success after `EnsureFresh`. Send path only reads; fallback `Класс <cid>`; lost on restart (accepted). No eviction (N small). No Stepik hot-path. Title rendered plain-text only via `html/template`; strip `Cc`+`Cf` (incl. bidi `U+202A–E`, `U+2066–9`, `U+200E/F`), collapse whitespace, rune-boundary truncate ≤100 runes.
- Webhook handler: `MaxBytesReader` 64KB → parse → `cid = ExtractCIDWithConfig("", page_url, cfg.ClassBase(), cfg.EmbedHost())` → drop if unknown or `site != SITE` (log `push_webhook_bad_url/site` with `remote_hash8, bytes` only) → `author_uid` = strip `stepik_` prefix + `ParseInt` (fail → `0`, log `push_webhook_bad_author` with `author_parse_fail`, never raw `user_id`) → `comment_id` allowlist `^[A-Za-z0-9_-]{1,64}$` else drop → snippet = `Orig` primary else stripped `Text` (prefer `bluemonday.StrictPolicy()`; fallback `<[^>]*>` → `` + `html.UnescapeString`; then strip `Cc`+`Cf` incl. bidi, collapse whitespace, trim, 120 runes rune-boundary; empty → `Новый комментарий`; snippet/name/title plain-text only via `html/template`, never raw HTML) → non-blocking enqueue `{cid, comment_id, author_uid, author_name, snippet}`.
- Send: for each job, for each sub: skip if `sub.uid == author_uid`; if `BestSession` present require `IsTeacher || cid ∈ AllowedClassIDs` else `push_skip_revoked`; if absent: push from stored array only if `max(created_at,last_ok_at) <24h` (`cid ∈ sub.cids`); stored `"all"` + absent → skip, except teacher (`uid == TEACHER_ID` from config) → push. Teacher `"all"` covers future classes. Subscribe-time `cids ⊆ allowed` + send-time live check + resubscribe-time re-validate (defense in depth). Exactly one send per sub with its row key via `SendNotificationWithContext(ctx10s, payload, sub, {Subscriber: VAPID_SUBJECT, TTL: 86400, Urgency: normal, Topic: class-<cid>, VapidExpiration: default})`. Unknown `key_version` → `push_skip_unknown_key` + skip. Title truncated to ≤100 runes before marshal; `len(json)>2048` → cut snippet loop until fit.
- Author: webhook `user_name` primary (plain-text sanitized as snippet), `BestSessionForUID(author_uid).FIO` fallback, else `""` (body = snippet alone). Title: `"<Class title> — новый комментарий"` single, `"<Class title>"` summary. Payload JSON ≤2KB. No avatar bytes, no tokens. Payload `url` asserted `strings.HasPrefix(url, "/class/")`.
- Delivery: `410/404` → delete immediately (`push_prune expired`); `400/413/415` → delete (bad subscription, avoids infinite retry); `403` → `push_403_key_mismatch` (never auto-delete — rotation signal); transient (429/5xx/timeout/`DeadlineExceeded`) → `fail_count++`, non-blocking requeue via explicit `select { case q <- job: default: push_queue_drop }` (never block worker) with `time.AfterFunc(delay, requeue)` delays `[1s,30s,5m]`, honor `Retry-After` (cap 5m); after 3x park until next webhook. Re-check ACL + row-exists + `fail_count` at each retry tick; drop if revoked/deleted. Worker never sleeps inline. Log `push_send {uid_hash8=hex(sha256(uid))[:8], cid, endpoint_hash8=hex(sha256(endpoint))[:8], status, latency_ms}`; never log endpoint/keys/snippet. Webhook accept log only `cid,comment_id,author_hash8,sub_count`.
- Coalesce: per-`cid` `type coalesce struct {count int; latestID string; authorUIDs []int64; timer *time.Timer}` + mutex map. First comment for idle `cid` sends immediately + `count=1` + 30s window; further in window bump `count/latestID/authors`; flush: `count==1` → nothing more; `count>1` → one summary with same `tag:cid-<cid>` + `renotify:true` (visible collapses to 1). Summary `N` is per-sub excluding own (`N = count - ownCount`; author excluded at immediate + flush). Timers + `AfterFunc` retries lost on restart (accepted; `push_webhook_gap` logged).
- Subscribe validation: `endpoint` parses URL, `scheme==https`, `host!=""`, `userinfo==""`, `len<2048` + allowlist (D34): host must equal `fcm.googleapis.com`, `updates.push.services.mozilla.com`, or `web.push.apple.com`, or have suffix `.push.apple.com`, or suffix `.notify.windows.com` (Edge); else `400`. IP safety: if host parses via `net.ParseIP` → deny `IsLoopback/IsPrivate/IsLinkLocalUnicast/IsUnspecified`; else resolve host → deny if any resolved IP matches those predicates. `p256dh` 87–88 chars base64url decode-check with `len(decode)==65 && [0]==0x04`, `auth` 22–24 chars decode-check with `len(decode)==16`; `cids` array requires every `cid ∈ session.allowed` (or teacher) else `403` whole request; empty `cids:[]` rejected (use `unsubscribe` instead); `"all"` allowed; `device.ua` truncate 256 + strip `Cc`+`Cf`/controls, `device.name` optional 64 + strip `Cc`+`Cf`/controls, plain-text only (never render as HTML in admin).
- CSRF/rate: `AllowPushByIP(ClientIP)` (`Every(1s)`, burst 30) checked before `LoadSession` on all `/push/*` incl. shallow `/push/health`; then `subscribe|unsubscribe` = `validSameOrigin` + `VerifyHeaderCSRF` + per-sid `AllowPush` (`Every(3s)`, burst 20 — ~20/min sustained; stale `sid` entries cleaned by existing 3-min sweep in `allow()`); `vapid-key` also per-sid `AllowPush` after auth; `resubscribe` = require-present-`Origin` exact match + `sid` + per-sid `AllowPush` only (no `Referer` fallback). `429` returns `Retry-After` seconds.
- Prune wiring (atomic, single `Update` each): `handleLogout` → `DeleteSessionAndPushSubs(logged-out sid)`; `admin.logoutAll` → epoch bump + `BumpVersionAndPrunePush` for all affected (deletes all rows; epoch invalidates all); `admin.revokeUser` → `BumpVersionAndPrunePush(target uid)` (deletes rows for target `uid`); `admin.revokeClass` → `StripClassAndPrunePush(uid,cid)` per affected `uid` (shrinks arrays, deletes single-`[cid]` rows and all `"all"` rows for that `uid`, re-subscribed as new allowed on next heal) **and synchronously rewrites affected sessions' `AllowedClassIDs` (or bumps per-user `UserVersion`) in the same Bolt tx** so a stale `BestSession` (6h `VerifyTTL`) cannot re-authorize the revoked `cid`. Unit test: revoke → immediate send suppressed before next `EnsureFresh`. Hourly sweep (session sweeper ticker, shared): delete `fail_count>10 && last_ok>30d` + `no live session && max(created_at,last_ok_at)>24h`.

### 7.4 Privacy / isolation

- Push never bypasses class ACL (send-time matrix above). 24h `max(created,last_ok)` cap closes the ex-student leak window and fixes fresh-sub-never-fires. Explicit logout deletes that `sid` rows → logged-out device gets nothing even if same `uid` live elsewhere. Shared-computer user change forces untap, never inherits (orphan cross-`uid` delete only when old `uid` has no live session, without leaking).
- Webhook snippet treated as private: logs exclude snippet/body/`user_name`; push transit via FCM/APNs/Mozilla disclosed in consent.
- Secrets in VPS `.env` only (`chmod 600`), keys only in `deploy/.env.example`. Debug via hash-compare (`printenv … | sha256sum`), values never leave VPS.
- 152-FZ/minors: endpoint+p256dh+auth are device keys (not child data), per-uid+sid, deletable via bell-Off + per-device logout + user-change guard. Stable Stepik `uid` never logged in clear (hashes only — `hex(sha256(uid))[:8]` is anti-PII hygiene, not anonymity: 32-bit prefix is reversible for <20 uids by brute force; documented as such). Migrate old clear-`uid` log lines later (no change in MVP beyond push paths); compose `config` test path uses dummy env only.

## 8. Caddy + Cloudflare + compose

`deploy/Caddyfile` (insert after `/auth/*` block, before `/discuss/*` blocks and before final `handle { respond 404 }`):

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
  reverse_proxy gate:8081
}
handle /push/webhook* {
  respond "Not found" 404
}
```

Safe: `handle` mutually exclusive, longest-path-first among same directive; listed paths have no overlap with `@static`, `/class/*`, `/auth/*`, `/healthz`, `/discuss/*`. Webhook has no proxy (edge always 404). `/push/health` has NO `header_up X-Gate-Auth` (unlike `/healthz`) — deep `?deep=1` via edge is always 404; with token via docker/caddy-net it works. `CF-Connecting-IP` + rate-limit chain unchanged. Covers `/push/webhook?x` and trailing slash via `*`.

`deploy/compose.yml`: remark42 += `NOTIFY_ADMINS=webhook`, `NOTIFY_WEBHOOK_URL=http://gate:8081/push/webhook` (internal docker DNS, single port), `NOTIFY_WEBHOOK_HEADERS=Content-Type:application/json,X-Push-Webhook-Secret:${PUSH_WEBHOOK_SECRET}` (double-quoted for expansion), `NOTIFY_WEBHOOK_TIMEOUT=5s`, `NOTIFY_QUEUE=200`, `NOTIFY_WEBHOOK_TEMPLATE='<frozen §7.1>'` (single-quoted, no `$`); gate += `VAPID_PUBLIC_KEY, VAPID_PRIVATE_KEY, VAPID_PUBLIC_KEY_OLD, VAPID_SUBJECT, PUSH_WEBHOOK_SECRET`. No new services, no `ports:` changes. No `:8082` listener in MVP (future option documented in runbook only).

`deploy/.env.example`: keys only (`VAPID_PUBLIC_KEY=`, `VAPID_PRIVATE_KEY=`, `VAPID_PUBLIC_KEY_OLD=` (may be empty), `VAPID_SUBJECT=mailto:mjgavrilov@gmail.com`, `PUSH_WEBHOOK_SECRET=` + generation comments `go run ./gate/cmd/genvapid` / `openssl rand -hex 32`). Secrets never committed.

Cloudflare: rule `(http.host eq "stepik.study67.fyi") → Bypass cache` confirmed 2026-09-22 and already covers new paths; verify `cf-cache-status: BYPASS/DYNAMIC` on `/push/*`, `/sw.js`, `/manifest.json`, `/offline.html` in TESTLOG. WAF/Bot-mode must not challenge `POST /push/subscribe` (verify in P2).

`caddy-verify.sh` extensions (extend `upstream.py` to emulate: `/push/webhook →404`, `/push/vapid-key` no `__Host-sid` cookie →401 else 200, `/offline.html →200`, `/push/health?deep=1` no `X-Gate-Auth` →404): checks `6: /push/webhook →404`, `7: /push/vapid-key no-cookie →401`, `8: /offline.html →200`, `9: /push/health?deep=1 no-token →404`. After any Caddyfile edit: container `caddy validate` (AGENTS.md exact form) + `deploy/caddy-verify.sh` + `docker compose -f deploy/compose.yml config`.

## 9. Build steps (implement in order D0 → D1 → D2 → D3)

### D0 — spike (0.5d, standalone, before Gate changes)

1. Minimal Go sender with `webpush-go v1.4.0` + real browser subscription (manual vapid-key dump) → prove VAPID send → desktop notification + `201` from push service (iOS-HS proof deferred to P2).
2. Live remark42 webhook dump (ephemeral secret, `spike/` style, never committed) proving frozen §7.1 template: parses, valid JSON on quotes/newlines/emoji, `.Timestamp.Unix` numeric, `.Orig` populated, `Content-Type + secret` headers received.
3. Exit: one-paragraph verdict appended here (split to `plans/0004-push-spike.md` only if >1 page). Template string locked. Gates D1.

### D1 — PWA shell (1d, no webhook yet)

1. `gate/config/config.go`: VAPID_* + secret validation + `VapidFP8` helper (§7.1). Fail-fast; `_OLD` empty allowed. `VAPID_SUBJECT` must be full `mailto:` form.
2. `gate/sessions/sessions.go`: create `push_subs`, `push_meta` buckets + `SchemaVersion` bump/create-if-missing; push CRUD + `SessionsForUID`/`BestSessionForUID` + atomic mutators `DeleteSessionAndPushSubs(sid)`, `StripClassAndPrunePush(uid,cid)`, `BumpVersionAndPrunePush(uid)` (single `Update` each; `push` exposes pure row-mutators only).
3. `gate/ratelimit/ratelimit.go`: `push` map + `AllowPush(sid) (bool, time.Duration)` (`Every(3s)`, burst 20) + `AllowPushByIP(ip) (bool, time.Duration)` (`Every(1s)`, burst 30, pre-auth).
4. `gate/push/`: leaf types (§4.1 structs + `CidsOrAll.UnmarshalJSON`), `VerifyWebhook` (secret constant-time + empty-secret `404` + RemoteAddr-only private peer + deny if `X-Forwarded-Uri`/`X-Forwarded-For`/`CF-Ray`/`CF-Connecting-IP`/`X-Gate-Auth` present + require `Content-Type: application/json`, `404`, never-log-body), validation (`IsValidEndpoint` incl. allowlist + resolve-then-IP-check per D34 / `IsValidKeys` / `IsValidCids`, `comment_id` allowlist `^[A-Za-z0-9_-]{1,64}$`), `TitleCache`.
5. `gate/cmd/genvapid/main.go`: generator (never commit output).
6. `gate/handlers/handlers.go`: `Server.Revision` field + `New` param (set from `main.buildRevision()`, fallback `"dev"` when VCS info absent); `Routes` `/push/*` + `/offline.html`; manifest upgrade (§5, `application/manifest+json`); full `sw.js` (§6, incl. `startsWith("/class/")` guard); `handleOffline`; `handleStatic` MIME fix (`.js → application/javascript; charset=utf-8`, `.html → text/html; charset=utf-8`); JSON errors (§4 mapping + `X-Robots-Tag`); `push.js` wiring; `AllowPushByIP` before `LoadSession` on every `/push/*` + shallow health; deep health via `auth.Guard`.
7. `gate/main.go`: pass `Revision`, no worker yet (fan-out no-op `push_noop_no_event`).
8. `gate/static/push.js` + `gate/static/offline.html` + `class.html`/`index.html` (bell + install hint + `push.js` script + `data-cid/data-uid`).
9. `deploy/Caddyfile` + `deploy/caddy-verify.sh` (checks 6–9 + stub, insertion after `/auth/*` before `/discuss` blocks, no `header_up` on `/push/health`) + `docker compose config`; `caddy validate`; CF `BYPASS/DYNAMIC` verify.
10. Acceptance: Wave P1 green (teacher on iPhone iOS 26.+ + Android) + Lighthouse ≥90 + `/offline.html 200 text/html` + `/static/push.js 200 application/javascript` + `/push/vapid-key 401 anon` + SW bundle unit test (allowlist, no `caches.add('/')`/`/class`, no `localStorage`/`document.cookie`, helper present, every `STATIC_ASSETS` URL `200` + correct type).

### D2 — push pipeline (2d, core)

1. `gate/push/`: webhook handler, worker + coalesce + retry (§7.3: snapshot-outside-tx, queue-full drop+`200`, `400/413/415→delete`, `403→retain`, explicit non-blocking `select` requeue + `AfterFunc` retries with ACL/row/`fail_count` re-check each tick + `Retry-After` cap 5m, per-sub summary `N`, `TTL/Topic/Urgency/ctx10s/VapidExpiration-default`, `max(created,last_ok)<24h` absent cap, `comment_id` allowlist + `HasPrefix` URL assert, `bluemonday.StrictPolicy` snippet + `Cc`/`Cf` strip + rune-boundary + 2048 loop), title cache population.
2. `gate/handlers`: subscribe/unsubscribe/resubscribe/vapid-key/health wrappers (§4 + §7.3: uid-scoped unsubscribe + orphan rule, resubscribe `400` on empty old + `cids` re-validate, endpoint allowlist `400`) + logout prune via `DeleteSessionAndPushSubs` + consent update.
3. `gate/admin`: `logoutAll`/`revokeUser`/`revokeClass` via `BumpVersionAndPrunePush`/`StripClassAndPrunePush` + synchronous session rewrite in same tx (§7.3).
4. `deploy/compose.yml`: `NOTIFY_*` wiring (frozen template, no edits without D0 re-verdict).
5. RU strings + consent line live (verbatim §7.2).
6. Acceptance: Wave P2 green (items 6–12 + 7b; item 10 = ≤2 pushes per 30s window, visible 1) + `docker stats gate <256M` + `push_send/push_prune/push_skip_revoked/push_403_key_mismatch/push_skip_unknown_key/push_queue_drop` samples.

### D3 — hardening (0.5d)

1. Rotation runbook section (single-key MVP + future overlap, `_OLD` reserved; `PUSH_WEBHOOK_SECRET` simultaneous-restart window; hash-compare debug; `:8082` future option noted).
2. `push/health` deep evidence (via docker/caddy-net with token; edge deep always 404); TESTLOG waves; `caddy-verify.sh` re-run.
3. Unit tests: SW allowlist + `STATIC_ASSETS` 200 + correct `Content-Type` + webhook validation (`http:`/bad keys/oversize/allowlist-miss/never-log-body rejected) + endpoint-SSRF (`169.254.169.254`/`gate:8081`/`http:` rejected `400`) + `VerifyWebhook` RemoteAddr-only (XFF spoof rejected) + header-deny (`X-Forwarded-Uri`/`CF-Ray`/etc. → `404`) + empty-secret `404` + non-JSON `Content-Type` `404` + `BestSessionForUID` ACL matrix + revoke-immediate-suppress + absent-`max(created,last_ok)`-24h-skip + logout-deletes-only-that-sid + user-change guard + resubscribe-`400`-on-empty-old + resubscribe-403-on-mismatch + unsubscribe-ownership (same-uid delete, foreign-with-live-session kept, orphan deleted) + unknown-fp8-skip + `comment_id` allowlist (`/`, `<`, space rejected) + `Retry-After` cap.
4. `.github/workflows/ci.yml`: `govulncheck` job (`go install golang.org/x/vuln/cmd/govulncheck@latest && govulncheck ./...`).
5. `go build/vet/test -count=1` green + `docker stats` evidence. Then merge.

Deferred: teacher Telegram channel (`plans/0003-teacher-telegram.md`, needs BotFather bot); lesson-level `…/lesson/<lid>` push; email fallback; TWA/Play packaging.

File order: `config` → `sessions` → `ratelimit` → `push` → `genvapid` → `handlers` → `admin` → `main` → `static/push.js` + `templates` + `static/offline.html` → `Caddyfile` + `compose.yml` + `.env.example` + `caddy-verify.sh` → `ci.yml` → `ops-runbook.md` → `TESTLOG.md`.

## 10. Browser test plan (append to TESTLOG.md)

P1 (installability, webhook disabled):
1. Desktop Chrome `chrome://apps` + DevTools Manifest (no errors, 192+512, `standalone`), Lighthouse ≥90.
2. Android Chrome: `beforeinstallprompt` → Install → `standalone` (`?source=pwa` in Gate log), icon correct.
3. iPhone iOS 26.+ (confirmed device): Share → Add to Home Screen → `standalone`; pre-install toggle shows iOS-hint; post-install tap shows permission prompt (never on load).
4. Offline: airplane mode → `/static/style.css` + `/static/push.js` from SW cache, `/` shows `/offline.html` (generic), `/class/<cid>` fails safe (no stale private HTML). Record `cf-cache-status` (`BYPASS`/`DYNAMIC`, never `HIT`) for `/manifest.json`, `/sw.js`, `/offline.html`, `/push/vapid-key`, `/push/subscribe`, `/static/push.js`.
5. Caddy contracts green: `caddy-verify.sh` + 0001 §8 items 1–7.

P2 (push end-to-end, webhook enabled, ≥2 test users; teacher validates on confirmed iPhone iOS 26.+ + Android):
6. A subscribes on `/class/<cid>` → B posts → A gets notification <30s (tab closed) with correct title/body/deep-link; click focuses/opens `/class/<cid>#remark-<id>`. Log `push_send`.
7. Self-suppressed (B gets nothing for own); outsider/revoked gets nothing (`push_skip_revoked`; re-join resumes). Revoke takes effect immediately (no 6h lag).
7b. Logout silence: A logs out device1 → B posts → device1 nothing, device2 (same A) fires. A re-logs device1 (silent heal) → next post fires without re-tap. Shared-computer: A out, B in same profile without tap → B gets nothing until tap; after tap B gets own only. Ex-student with no re-auth >24h (`max(created,last_ok)>24h`) gets nothing. Unsubscribe ownership: A cannot silence teacher endpoint (foreign live-session row kept, `403`-class path covered by unit test + manual spot-check).
8. Multi-device: A on 2 browsers → both fire; unsubscribe one → only remaining fires.
9. Denied/expired: deny → RU denied-string; devtools `unsubscribe()` → next webhook `410` → prune (`push_prune expired`). `403` (rotation) → retained (`push_403_key_mismatch`).
10. Burst: 5 comments in 30s → ≤2 pushes (1 immediate + 1 summary `N новых комментариев`), visible 1 (same tag + renotify). Summary `N` excludes own comments per-sub.
11. Teacher `"all"` gets every owned class incl. future classes; student `"all"` only own `allowed`.
12. Resource: `docker stats` gate <256M; `go test -count=1` + `vet` + `govulncheck` green.
13. Security spot-checks (record in TESTLOG): endpoint-SSRF (`169.254.169.254`, `http://gate:8081/`, non-allowlist host → `400`); webhook header-deny (with `X-Forwarded-For`/`CF-Ray`/`X-Gate-Auth` → `404`); `comment_id` allowlist (`../../`, `<img>`, space → dropped, no push); WAF/Bot check (`POST /push/subscribe` not challenged, `cf-cache-status` recorded); `/push/health?deep=1` via edge → `404`, via internal token → `200` counts-only.

## 11. Risks

- iOS HS-install skipped → one-line RU hint + teacher announcement (`Установите как приложение, иначе уведомления не придут — инструкция на главной`). No auto-prompt.
- Webhook template drift / `Locator.URL` change → `ExtractCID` fail-closed + `push_webhook_bad_url` + `push_webhook_gap` (no crash/leak, never log body). Next comment heals.
- Endpoint churn → `410/404/400/413` prune + `pushsubscriptionchange` (400-tolerant) + page-load migration/heal + user-change guard + hourly sweep. `403` = rotation signal, never auto-delete. Logout deletes only that `sid` rows via atomic `DeleteSessionAndPushSubs`.
- VAPID leak → per-sub `key_version` rotation; single-key swap safe only in test scope; production must overlap; old dies when old-version count → 0. Unknown `fp8` → skip, never fallback.
- SW cache poisoning → allowlist `/static/*` + `/offline.html` only, generic offline fallback, `no-store` on `sw.js`, unit test allowlist + `STATIC_ASSETS` 200 + correct type.
- Single VPS SPOF + in-memory queue/timers → burst loss on restart accepted (comments remain; no `down -v`). `push_queue_drop` + `push_webhook_gap` make loss visible.
- New dep `webpush-go` — pinned + `govulncheck`.
- `X-Gate-Auth` overwrite — plain `header_up` overwrites (no append); consistent with `/healthz`. `/push/health` intentionally has no `header_up`, so deep via edge → `404`.
- Authenticated SSRF via endpoint allowlist miss → closed by D34 allowlist + resolve-then-IP-check (worker POSTs VAPID JWT to attacker host, floods/scans — blocked at subscribe `400`).
- Pre-auth flood on `/push/*` → closed by D35 `AllowPushByIP` before session load.

## 12. Decisions

All decisions below are final. Implementation must match; any change requires plan update.

| # | Topic | Decision | Details |
|---|-------|----------|---------|
| D1 | Notify scope | All class members except author | No thread-participant-only mode in MVP. Coalesced per §7.3, per-sub `N` excludes own. |
| D2 | Quiet hours | None in MVP | Revisit only if night spam becomes a problem (morning digest deferred, no design). |
| D3 | Teacher Telegram | Design in `0003`, implementation deferred | Needs teacher BotFather bot + VPS `.env` token. `NOTIFY_ADMINS=webhook` stays extensible to `webhook,telegram`. |
| D4 | Test scope | Webhook-only MVP, no poller | Ephemeral secrets ok; outage heals on next comment (`push_webhook_gap`). |
| D5 | Caddy routing | Enumerated handles + own `/offline.html` + webhook `404`, NO `header_up` on `/push/health` | `handle /push/vapid-key*`, `/push/subscribe*`, `/push/unsubscribe*`, `/push/resubscribe*` (plain proxy); `handle /push/health*` plain proxy with NO `header_up X-Gate-Auth` (unlike `/healthz`, so edge deep is always 404); `handle /push/webhook* {404}`; own `handle /offline.html` (not `@static` edit). Insert after `/auth/*` block, before `/discuss/*` blocks and before final `handle {404}`. Verify checks 6–9. Compose template single-quoted, headers double-quoted. `*` covers query + trailing slash. CF Bypass rule covers new paths (see Assumptions 2026-09-22). See D36/D39. |
| D6 | Service Worker | Navigation-only offline fallback + cache-first static; bare `register('/sw.js')`; `STATIC_CACHE="static-"+REV` | No `localStorage`/`document.cookie` in SW; `pushsubscriptionchange` best-effort via resubscribe (400-tolerant); page-load migration/heal/user-change guard; `urlBase64ToUint8Array` in both SW and page; gesture-only permission, `userVisibleOnly:true`, always `showNotification`. `STATIC_ASSETS` includes `push.js`; every entry must `200` + correct type. No preload, no background/periodic sync. `notificationclick` asserts `startsWith("/class/")` else `"/"`. |
| D7 | CSRF + rate | `subscribe\|unsubscribe` = IP + Origin + header CSRF + per-sid rate; `resubscribe` = IP + required-Origin + sid + per-sid rate only | `AllowPushByIP Every(1s)` burst 30 before `LoadSession` on all `/push/*` + shallow health; then `validSameOrigin` + `VerifyHeaderCSRF` (`__Host-csrf` via `document.cookie`) + per-sid `AllowPush Every(3s)` burst 20. `resubscribe` CSRF-exempt but requires present `Origin` exact match (no `Referer` fallback; SW cannot send header; `SameSite=Lax` + required Origin sufficient). SW uses `credentials:'include'`. `vapid-key` also per-sid `AllowPush` after IP check. `429` + `Retry-After`. No `/auth/me` change. See D35. |
| D8 | Author name | Webhook `User.Name` primary | Fallback `BestSessionForUID(author_uid).FIO`, else `""` (body = snippet alone). Plain-text only. |
| D9 | Subscribe scope | `"all"` for students + teacher; per-class disable via narrowed `POST`; no `PATCH` | Server expands `"all"` at send time via live `BestSessionForUID` so revoke + future classes take effect immediately. Empty `cids:[]` rejected (use `unsubscribe`). |
| D10 | Consent | Extended with push-service transit sentence | Verbatim §7.2; login page existing slot; bell-Off text frozen. |
| D11 | Worker | 4 senders (in-flight 4), Stepik limiter untouched, immediate-first coalesce + non-blocking retry, `sid` per row | Queue 512 (gate) / 200 (remark42, intentional backpressure). `Topic: class-<cid>`, `TTL: 86400`, urgency normal, `VapidExpiration` default, `ctx` 10s. Bolt snapshot-outside-tx. Queue-full → `push_queue_drop` + `200`. Requeue explicit non-blocking `select`, `Retry-After` cap 5m, ACL/row/`fail_count` re-checked each tick. |
| D12 | Dependency | `webpush-go v1.4.0` interim + `govulncheck` in CI | MIT; pin `go.mod`+`go.sum`. `GenerateVAPIDKeys` = `RawURLEncoding`. `Options{Subscriber mailto:, TTL, Topic, Urgency}`. `VAPID_SUBJECT=mailto:mjgavrilov@gmail.com` frozen §7.1. No hand-rolled VAPID. `bluemonday.StrictPolicy` preferred for HTML strip if needed. |
| D13 | Manifest | `id:/` stable + `start_url:/?source=pwa`; split `any` / `maskable` | `Content-Type: application/manifest+json`. Verify-or-regenerate maskable (opaque, 80% safe zone). `/` ignores `?source=pwa`. |
| D14 | SW safety | Unit test (not grep) asserts allowlist + `STATIC_ASSETS` 200 + type | No `caches.add('/')`, no `/class`, no `localStorage`/`document.cookie` in SW, helper present. |
| D15 | Webhook template | Frozen §7.1, no `truncate`, unquoted `escapeJSONString`, `text_html` + `text_orig` + `created_unix` numeric, explicit `Content-Type`, `NOTIFY_QUEUE=200` | D0 proves verbatim; no edits without D0 re-verdict. Never log body/snippet/`user_name` on any path. |
| D16 | Send-time ACL | Present → require allowed else suppress; absent array + `max(created,last_ok)<24h` → push from stored; absent `"all"` → skip except teacher; logout deleted → nothing; revoke prunes atomically | `push_skip_revoked` on suppress. `revoke-class` deletes `"all"` rows + synchronously rewrites sessions `AllowedClassIDs` (or bumps `UserVersion`) in same tx via `StripClassAndPrunePush` (healed on next visit). Sweep `fail>10 && ok>30d` + `no session && max(created,last_ok)>24h`. Ex-student >24h without re-auth gets nothing. See D40. |
| D17 | VAPID keys | Per-sub `key_version` (`fp8`), single-key MVP, `_OLD` reserved, no dual-send, unknown → skip | `fp8 = hex(sha256([]byte(public string)))[:8]`; unsubscribe-before-resubscribe; generator `gate/cmd/genvapid`; fail-fast Load (`_OLD` empty allowed). Unknown `fp8` → `push_skip_unknown_key`, never fallback. |
| D18 | Resubscribe | `POST /push/resubscribe` UPDATE-by-`old_endpoint`; empty old → `400` | `old==""` → `400` (no INSERT; page-load full subscribe with `cids` + CSRF is the healer); foreign `old` → `403`; copied `cids` re-validated. SW best-effort (400-tolerant); page primary healer; compat Win/Mac/iOS/Android × Chrome/Chromium/Safari/Firefox. See D37. |
| D19 | Titles | In-memory `cid → title` cache, `Класс <cid>` fallback | Set at subscribe + login + `EnsureFresh` success; send only reads; lost on restart; no Stepik hot-path. Truncate ≤100 runes, plain-text via `html/template`. |
| D20 | Health | Shallow public via IP limiter; deep localhost-only via Guard, no Caddy injection | Shallow `{ok:true}` via `AllowPushByIP` only. Deep `?deep=1` requires `X-Gate-Auth` Guard; Caddy sends no `header_up` so edge deep always 404; via docker/caddy-net with token works. Deep = counts only (`Bucket.Stats()`, `len(chan)`), no PII. Deep without token → `404`. Separate from `/healthz`. See D39. |
| D21 | Caps | 64KB webhook / 2KB payload / per-sid `AllowPush` 20/min + pre-auth IP 30/s-burst / queue 512 / 4 workers / 30s coalesce | Endpoint `https:` + allowlist + no userinfo + `len<2048` (D34); `p256dh` 87–88 + `65B/0x04` decode-check, `auth` 22–24 + `16B` decode-check; `cids ⊆ allowed` else `403`; `comment_id ^[A-Za-z0-9_-]{1,64}$`; `ua` 256, `name` 64, strip `Cc`/`Cf`; `400/413/415 → delete`; `403 → retain`; `429/5xx/timeout → retry [1s,30s,5m]` + `Retry-After` cap 5m, max 3x. |
| D22 | Logout silence | Per-device (`sid`) atomic delete; relog silent-heal; user-change forces untap; bell per-device | `unsubscribe` uid-scoped first, cross-`uid` only if `BestSessionForUID(row.uid)==nil` (orphan/shared-computer). Idempotent 200. Logged-out device gets nothing even if same `uid` live elsewhere. `localStorage` kept on logout. See D38. |
| D23 | Push errors | JSON `{error}` with `private,no-store` + `noindex` | `401 auth_required / 403 forbidden / 429 rate_limited+Retry-After / 400 bad_request`; reuse RU rate-limited text in JSON. `/auth/*` parity unchanged in MVP. |
| D24 | Revision wiring | `Server.Revision` from `main.buildRevision()` injected as `REV`; `New` signature break; fallback `"dev"` | Fixes `unknown` default. Bare `register('/sw.js')`, no `?v=`. See D41. |
| D25 | Webhook guard | New `VerifyWebhook` (secret constant-time + empty-secret `404` + RemoteAddr-only private peer + header-deny + JSON-only, `404`) | Parse `RemoteAddr` only, reject parse fail, never read `X-*`/`CF-Connecting-IP`. Deny if `X-Forwarded-Uri`/`X-Forwarded-For`/`CF-Ray`/`CF-Connecting-IP`/`X-Gate-Auth` present. Require `Content-Type: application/json`. Never reuse `auth.Guard`; never via Caddy. See D36. |
| D26 | Coalesce UX | Immediate-first + 30s tail-batch | Single → <5s; burst 5/30s → 2 sends (total N per-sub excl. own), visible 1. Same `tag:cid-<cid>` + `renotify:true`. |
| D27 | Log privacy | Hashes only: `uid_hash8`, `endpoint_hash8`, `author_hash8`, `remote_hash8` | Anti-PII hygiene, not anonymity (32-bit prefix brute-forcible for <20 uids — documented). Never endpoint/keys/snippet/body/`user_name`/clear `uid`; webhook log `cid,comment_id,author_hash8,sub_count` only. Old clear-`uid` lines migrated later. |
| D28 | Client JS | Separate `static/push.js` + bell HTML | Cached, SW-cached; inline `data-cid/data-uid` only. Keys frozen §6. |
| D29 | Snippet | `Orig` primary else stripped `Text`, 120 runes, ≤2KB, plain-text only | Prefer `bluemonday.StrictPolicy()`; strip `Cc`+`Cf` incl. bidi `U+202A–E`/`U+2066–9`/`U+200E/F`, collapse ws, rune-boundary cut, `html/template` render; empty → `Новый комментарий`. Cut loop until `len(json)≤2048`. |
| D30 | Test devices | iPhone iOS 26.+ + Android Chrome — confirmed 2026-09-22 | Used for P1/P2; not an open question. |
| D31 | Payload URL | Server-constructed `/class/<cid>#remark-<comment_id>` only | `page_url` only for `ExtractCID`. `comment_id` allowlist enforced; Gate `HasPrefix(url,"/class/")`, SW `startsWith("/class/")` else `"/"`. |
| D32 | Deploy order | Secrets first, then gate | VPS `.env` + compose before gate deploy; hash-compare debug; `PUSH_WEBHOOK_SECRET` simultaneous-restart window. |
| D33 | State loss | In-memory queue/timers/titles lost on restart accepted | `push_queue_drop` + `push_webhook_gap` make loss visible; comments remain. Sweep shares session ticker. |
| D34 | Endpoint allowlist | YES restrict — authenticated SSRF closed at subscribe `400` | Allow: `fcm.googleapis.com`, `updates.push.services.mozilla.com`, `web.push.apple.com`, `*.push.apple.com`, `*.notify.windows.com` (Edge). Deny `IsLoopback/IsPrivate/IsLinkLocalUnicast/IsUnspecified` after `ParseIP` + resolve-then-check every IP. Reject outside list `400`. Zero UX cost (legit browsers only use known hosts). Unit test with `169.254.169.254` / `gate:8081` / `http:` in D3. |
| D35 | Pre-auth IP limiter | `AllowPushByIP(ClientIP)` `Every(1s)` burst 30 before `LoadSession` on all `/push/*` + shallow health | Keeps per-`sid` `Every(3s)` burst 20 after auth. `429` + `Retry-After`. Closes pre-auth flood without touching Stepik limiter. |
| D36 | Webhook header-deny + single-port | KEEP single `:8081` in MVP (no `:8082`); deny proxied webhook | Extra listener = compose/healthcheck/complexity for <20 users; header-deny + secret + edge 404 sufficient. `:8082` is future option (runbook note only). `VerifyWebhook` denies if `X-Forwarded-Uri`/`X-Forwarded-For`/`CF-Ray`/`CF-Connecting-IP`/`X-Gate-Auth` present + requires `Content-Type: application/json` + fail-closed `404` if secret empty. |
| D37 | Resubscribe empty old | `old_endpoint==""` → `400` (not INSERT) | SW best-effort (400-tolerant); page-load full subscribe (has `cids` + CSRF) is the healer. Safe + UX-neutral (SW expiry rare, next page visit heals silently). |
| D38 | Unsubscribe ownership | `uid`-scoped delete first; cross-`uid` only if `BestSessionForUID(row.uid)==nil` | Idempotent 200 kept. Prevents member silencing teacher; shared-computer orphans still healed. |
| D39 | Health localhost-only | Shallow public via IP limiter; deep via Guard only, no Caddy injection | Caddy `handle /push/health*` plain proxy with NO `header_up X-Gate-Auth` (unlike `/healthz`). Shallow rate-limited via `AllowPushByIP`. Deep `?deep=1` via edge always 404; via docker/caddy-net with token works. Deep = subs count + queue len only, no PII. |
| D40 | Absent cap | `max(created_at,last_ok_at)<24h` for stored-array push; sweep `max(...)>24h` | Closes ex-student leak and fixes fresh-sub-never-fires (pure `last_ok` would suppress a fresh sub that never fired). |
| D41 | Static MIME + Revision dev | `handleStatic`: `.js → application/javascript; charset=utf-8`, `.html → text/html; charset=utf-8`; `Revision` fallback `"dev"` | Test every `STATIC_ASSETS` entry `200` + correct type. `New` signature break noted. Fixes `unknown` buildRevision default. |

## 13. References

Local (ground truth): `plans/0001-stepik-discussion-site.md` (§§3–8, §7.4, §5.2–5.3, §6.1); `plans/0003-teacher-telegram.md`; `AGENTS.md`; `docs/ops-runbook.md` (§§2/8–9); `deploy/Caddyfile`, `deploy/compose.yml`, `deploy/.env.example`, `deploy/caddy-verify.sh`; `gate/main.go`, `gate/handlers/handlers.go`, `gate/handlers/htmlsession.go` + `util.go`, `gate/config/config.go`, `gate/sessions/sessions.go`, `gate/auth/auth.go`, `gate/admin/admin.go`, `gate/ratelimit/ratelimit.go`, `gate/templates/`, `gate/static/*`, `go.mod`/`go.sum`, `.github/workflows/ci.yml`, `TESTLOG.md`.

Upstream code (verified 2026-09-22): `remark42/backend/app/notify/webhook.go` (`escapeJSONString` = quoted `json.Marshal`, default template, `NewWebhook` parse), `remark42/backend/app/store/comment.go` (`Comment{ID, ParentID/pid, Text, Orig, User, Locator{SiteID, URL}, Score, Timestamp}`, `Sanitize` bluemonday), `go-pkgz/notify/webhook.go` (headers/timeout), `SherClockHolmes/webpush-go v1.4.0` (`GenerateVAPIDKeys` `RawURLEncoding`, `SendNotificationWithContext`, `Options{Subscriber, TTL, Topic, Urgency}`, pkg.go.dev).

Docs/standards: `remark42.com/docs/configuration/notifications/` + `/parameters/` (`NOTIFY_ADMINS/WEBHOOK_URL/TEMPLATE/HEADERS/TIMEOUT/QUEUE`); RFC 8292 §4.2 (`mailto:`/`https://` `sub`) + RFC 9749 §5; MDN (`pushsubscriptionchange`, installable, manifest `start_url`/`icons`); Apple Web Push docs + WebKit 13878/13966 (16.4+ HS-install, tap-gesture permission, always `showNotification`, Badging); Caddy `handle/handle_path/route/reverse_proxy/header_up` (mutually exclusive, longest-path-first, `header_up` overwrites without `+`).

## 14. Assumptions

Assumptions lists only env/edge/device assumptions; D35/D37/D38/D39/D40/D41 are normative in §12, not repeated here.

- Quiet-hours none in MVP (D2) — acceptable for school use; revisit on night-spam complaint.
- Teacher `"all"` auto-includes future classes (live `BestSession` expansion) — desired; no extra setting.
- Gate `512` vs remark42 `200` queue mismatch intentional (gate absorbs bursts + retries).
- iPad desktop-mode UA gap accepted (<20 users); optional `maxTouchPoints` check noted.
- `VAPID_SUBJECT=mailto:mjgavrilov@gmail.com` — frozen 2026-09-22, no new contact needed.
- Cloudflare Bypass rule `(http.host eq "stepik.study67.fyi")` — confirmed 2026-09-22, covers `/push/*`, `/sw.js`, `/manifest.json`, `/offline.html`; `BYPASS`/`DYNAMIC` recorded in TESTLOG P1/P2; WAF/Bot not challenging `POST /push/subscribe` verified in P2.
- iPhone iOS 26.+ + Android Chrome test devices — confirmed 2026-09-22.
- Endpoint allowlist (D34) intentional — zero UX cost, closes authenticated SSRF.
- Single `:8081` for webhook (D36) intentional — `:8082` is future option only.
