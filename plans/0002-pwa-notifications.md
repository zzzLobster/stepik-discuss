# 0002 — PWA wrapper + new-comment notifications (Web Push)

Date: 2026-09-22
Status: FINAL
Implements plan 0001 §7.4 hook (`manifest.json` + stub `sw.js` → full PWA + Web Push).

Consolidation pass: structure + wording only. All prior freezes preserved (see `git log -- plans/0002-pwa-notifications.md`); no frozen decision reopened.

Domain: `stepik.study67.fyi` (same-domain, no split — iOS PWA + third-party-cookie safe, per 0001 §3).
Stack: Gate (Go 1.27.1) + Caddy `2.11.4-alpine` + remark42 `v1.16.4` + Cloudflare direct (orange-cloud). No new containers.
Test scope: site not used by students yet — D0/P1/P2 run with test users + ephemeral secrets; no migration compat for old installs required.
Test devices: iPhone iOS 26.+ (≥16.4 HS-install push OK) + Android Chrome.
Priorities: security first, then best UX.

Gates: `go build ./...`, `go vet ./...`, `go test -count=1 ./...`, `govulncheck ./...`, `deploy/caddy-verify.sh`, container `caddy validate`, browser TESTLOG waves P1/P2.

Implementation must match this plan; any change requires a plan update.

## 1. Goal

Turn the closed discussion site into an installable mobile web app and notify users about new comments even when the tab is closed:

1. PWA installable on Android (Chrome/Edge/Samsung) + iOS (Safari 16.4+, any browser via Share → Add to Home Screen, launched from icon) + desktop (Chrome/Edge Add-to-Dock) — `standalone`, own icon, splash, `start_url:/?source=pwa`, stable `id:/`.
2. Browser push about new comments via Web Push (VAPID) + Service Worker `push` → `showNotification`, deep-link to `/class/<cid>#remark-<comment_id>` (server-constructed canonical URL, never remark42 `page_url`).
3. Mobile-first UX: class pages usable from Home-Screen icon, offline-safe static shell, RU copy, minors/152-FZ safe (no PII beyond `uid+fio+avatar`, closed threads only).

Non-goals: native App Store / Google Play wrappers (PWABuilder/TWA deferred); email/Telegram student push via remark42-native (requires emails/Telegram IDs we do not collect); lesson-level threads (Phase 2 in 0001 §7.3 reuses same push plumbing).

## 2. Constraints (do not re-debate)

- Gate serves today: `GET /manifest.json` (standalone, `scope:/`, `start_url:/`, combined `any maskable` icon), `GET /sw.js` stub (fetch passthrough), `apple-touch-icon.png`, `theme-color #3776AB`, `<link rel=manifest>` in `index.html`/`class.html`. Chromium install prompt requires real SW registration + `fetch` handler. §5 splits icons into dedicated `any` + `maskable` files.
- `gate/handlers/handlers.go:Routes()` is wiring; `privateHeaders` = `Cache-Control: private,no-store` + `noindex` on all HTML/API. SW must never cache `/`, `/class/*`, `/auth/*`, `/discuss/*`, `/auth/me`.
- Current-state gaps closed by §9: `Server` has no `Revision` field (`main.buildRevision()` exists but is not injected; D1 adds `var revision = "dev"` in `main` + ldflags stamp + `Server.Revision` + `New` param); `Routes()` has no `/push/*` or `/offline.html`; `config.Load()` is fail-fast but has no VAPID/PUSH vars; `sessions` has 4 buckets only (`sessions`, `user_versions`, `teacher_token`, `meta`), current `SchemaVersion` is `"1"`, no `SessionsForUID`/`BestSessionForUID`; `ratelimit` has no `AllowPush`/`AllowPushByIP` and `ClientIP` still has the `X-Forwarded-For` first-entry fallback (D1 removes it); `static/push.js` + `static/offline.html` missing; `webpush-go` absent from `go.mod`; CI has no `govulncheck`; Caddyfile has no `/push/*` or `/offline.html`; compose has no `NOTIFY_*`/`VAPID_*`; `caddy-verify.sh` checks 1–5 only. `icon-512-maskable.png` file exists but is unused. `handleStatic` lacks `.js → application/javascript` and `.html → text/html` mappings. Bolt has no `push_subs`/`push_meta` buckets. `cfg.Origin` exists (`GATE_ORIGIN`, absolute URL); D1 adds canonicalization (trim trailing `/`). `//go:embed` does not yet include `offline.html`. Unit tests construct config with dummy env only.
- Caddy contracts (enforced by `deploy/caddy-verify.sh`, CI `caddy-contract`): public `handle /discuss/web/* + uri strip_prefix /discuss`; protected `handle_path /discuss/*` strips `/discuss`; gate gets full public URI via `header_up X-Forwarded-Uri /discuss{uri}`; 3-arg `redir`; healthcheck `http://localhost:8081/healthz`. Any Caddyfile edit must re-run `deploy/caddy-verify.sh`. `handle` blocks are mutually exclusive, first match wins; same-named `handle` directives sort longest-path-first. Insertion point for §8 block: after `/auth/*` block, before `/discuss/*` blocks and before final `handle { respond 404 }`.
- `forward_auth gate:8081 /auth/check` only on `/discuss/*`, never on `/web/*`. `ExtractCID` fail-closed `403 unknown_thread` without `?url=` / class-`Referer` / iframe-`?url=` unwrap. Webhook path reuses `ExtractCIDWithConfig("", page_url, cfg.ClassBase(), cfg.EmbedHost())` — signature already supports it.
- remark42 `v1.16.4` notification model: `NOTIFY_ADMINS=email|telegram|slack|webhook` (multi), `NOTIFY_USERS=email|telegram`. User push via remark42-native requires email/Telegram identity which our users do not have (Gate-minted JWT only, `AUTH_ANON=false`, dummy `stepik` provider). Gate-owned Web Push is the only per-student path.
- remark42 admin webhook fires HTTP POST per new comment. Verified upstream (`backend/app/notify/webhook.go`, `backend/app/store/comment.go`, docs `configuration/notifications` + `parameters`): default template `{"text": {{.Text | escapeJSONString}}}`, headers format `Header1:Value1,Header2:Value2` (split on first `:`, `TrimSpace`, no default `Content-Type` — set explicitly), `NOTIFY_QUEUE` default `100` (plan uses `200`), `NOTIFY_WEBHOOK_TIMEOUT` default `5s`. Template context is the `store.Comment` struct: `{{.ID}}`, `{{.ParentID}}` (empty for top-level), `{{.Text}}` (sanitized HTML via bluemonday `UGCPolicy`), `{{.Orig}}` (raw markdown source, never render as HTML), `{{.User.ID}}` (`stepik_<uid>`), `{{.User.Name}}`, `{{.Locator.SiteID}}`, `{{.Locator.URL}}`, `{{.Timestamp.Unix}}` (method call, numeric epoch), `{{.Score}}` (int). Only template function is `escapeJSONString` (returns fully-quoted `json.Marshal` output — use without surrounding quotes).
- iOS constraints (verified Apple/WebKit docs): push only after Add-to-Home-Screen + user-granted permission in response to tap; Share-menu install in any browser ≥16.4; no `beforeinstallprompt` on iOS (manual Share → Add instructions required); every `push` handler must end in `showNotification` (Safari revokes permission on silent push); `pushManager.subscribe({userVisibleOnly:true})` (Apple rejects `false`).
- Scale/privacy: 2–3 classes, <20 users, RU, minors. Store only `uid+fio+avatar_url`. Threads never merge (`page_url` differs per `cid`). Cloudflare Bypass rule `(http.host eq "stepik.study67.fyi") → Bypass cache` covers `/push/*` + `/sw.js` + `/manifest.json` + `/offline.html` (`BYPASS/DYNAMIC`, never cached).
- Deps: `bbolt, golang-jwt/v5, x/oauth2, x/time/rate` + `github.com/SherClockHolmes/webpush-go v1.4.0` (MIT, published 2025-01-02, after CVE-2024-51744; pin via `go.mod` + `go.sum`, `go vet` + `govulncheck` in CI). API: `GenerateVAPIDKeys() (private, public string, err error)` (base64 `RawURLEncoding`), `SendNotificationWithContext(ctx, message, sub, options)` with `Options{Subscriber, VAPIDPublicKey, VAPIDPrivateKey, TTL, Topic, Urgency, VapidExpiration}`. No hand-rolled VAPID. No other deps. HTML stripping uses `bluemonday.StrictPolicy()` only.
- Single `:8081` in MVP (no `:8082` second listener).
- Push endpoint allowlist is intentional (authenticated SSRF closed at subscribe time, zero UX cost).
- `auth.Allowed(sess, cid)` returns true for teacher (`IsTeacher`) or `cid ∈ AllowedClassIDs`. `Checker.EnsureFresh(ctx, sid, sess)` fresh window is `VerifyTTL + verifyJitter(sid)` (`verifyJitter` ∈ −15m…+15m); send path uses the `+15m` upper bound (see §7.3). `sessions.SetSID/SetCSRF` use `SameSite=Lax` + `Secure` (`sessions.go`).

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
- Event source: remark42 admin webhook → Gate internal endpoint (only source in MVP). No poller in MVP; outage = log `push_webhook_gap`, next comment re-fires. Hourly `ReconcilePushSubs` (§7.3, D47) bounds direct-Stepik-UI-removal leak; it is a pruner, not an event source.
- No remark42-native `NOTIFY_USERS`; no `NOTIFY_ADMINS=email/telegram` in MVP — teacher gets the same Web Push as students (plus existing `/discuss/admin/` moderation). `NOTIFY_ADMINS=webhook` stays extensible to `webhook,telegram` for plan 0003.
- Volumes/network unchanged: `app` bridge, no `ports:` on backends, only Caddy `80/443`. Volumes `gate-data:/data` (DB file `/data/gate.db` per `config.DBPath`; new buckets `push_subs`, `push_meta` + `SchemaVersion` `"1"`→`"2"`), `remark-data`, `caddy-data`.
- Ownership (frozen, avoids import cycles): `sessions` owns `push_subs`/`push_meta` buckets and all Bolt CRUD + atomic single-`Update` mutators (`DeleteSessionAndPushSubs`, `StripClassAndPrunePush`, `BumpVersionAndPrunePush`, `DeletePushSubsForUID`). `push` owns `VerifyWebhook`, validation, worker, coalesce, `TitleCache`, `ReconcilePushSubs` (imports `sessions`, `config`, `auth` + stdlib; never `handlers`/`admin`). `handlers` owns all `/push/*` + `/offline.html` HTTP wrappers (reuses `validSameOrigin`, `auth.LoadSession`, `AllowPush`, `AllowPushByIP`). `admin` calls `sessions` mutators directly for prune. Two separate Bolt transactions for one logical revoke/logout is forbidden.
- Build is two-pass by design (not single-pass): D1 creates types + `VerifyWebhook` + PWA shell + stubs; D2 fills worker + push HTTP wrappers + `NOTIFY_*`. §9 lists the exact files per pass; no other revisits.

## 4. URL / API contracts

| URL | Auth | Contract |
|-----|------|----------|
| `GET /manifest.json` | public, `Cache-Control: public,max-age=3600`, `Content-Type: application/manifest+json` | Full manifest per §5. |
| `GET /sw.js` | public, `Cache-Control: no-store`, `Content-Type: application/javascript` | Real SW per §6. Served by Gate (not static file) so `REV` from `main.revision` can be injected. Scope `/`. Bare `register('/sw.js')`, no `?v=` query. |
| `GET /push/vapid-key` | `AllowPushByIP(ClientIP)` before `LoadSession`, then valid `sid`; per-sid `AllowPush` after auth; `Cache-Control: no-store` | `{key, fp}` for `pushManager.subscribe({userVisibleOnly:true, applicationServerKey})`. `401` anon. Page/SW fetch (never bundle) so rotation needs no release. |
| `POST /push/subscribe` | `AllowPushByIP(ClientIP)` before `LoadSession`, then valid `sid` + `validSameOrigin` + `X-CSRF-Token` matching readable `__Host-csrf` cookie (same pattern as `admin.Admin`) + per-sid `AllowPush` after auth | Body `{endpoint, keys:{p256dh, auth}, device:{ua, name?}, cids:[cid…] \| "all"}` (missing/null `cids` → `400`; only explicit non-empty array or `"all"`). Validation per §7.3 incl. endpoint allowlist + normalization + port. Upsert into `push_subs[hex(sha256(endpoint))]`. Returns `{ok:true}`. Per-class disable = `POST` narrowed `cids` array (no `PATCH`). `MaxBytesReader` 64KB. Wrong method → `405`. |
| `POST /push/unsubscribe` | `AllowPushByIP(ClientIP)` before `LoadSession`, then valid `sid` + `validSameOrigin` + `X-CSRF-Token` + per-sid `AllowPush` after auth | Body `{endpoint}`. Ownership-scoped: missing row → `200 {ok:true}`; own-`uid` row → delete + `200`; foreign row with live `BestSessionForUID(row.uid)` → `403 forbidden` (no delete — prevents silencing teacher); foreign orphan (`BestSession==nil`) → delete + `200` (shared-computer heal). `MaxBytesReader` 64KB. Wrong method → `405`. |
| `POST /push/resubscribe` | `AllowPushByIP(ClientIP)` before `LoadSession`, then valid `sid` + require-present `Origin` exact match against canonical `cfg.Origin` (no `Referer` fallback; missing/`"null"`/mismatch → `403`) + per-sid `AllowPush` after auth; CSRF-exempt (SW has no `document.cookie`/`localStorage`; `SameSite=Lax __Host-sid` + required Origin is sufficient; if ever `None`, re-add CSRF) | Body `{old_endpoint, endpoint, keys:{p256dh, auth}, device:{ua}}` (no `cids`). Server: if `old_endpoint==""` → `400` (no INSERT; page-load full subscribe with `cids` + CSRF is the healer). Else row must exist and belong to same `uid`, otherwise `403` (never steal/overwrite foreign row). New `endpoint` re-runs full `IsValidEndpoint` + `IsValidKeys` (`400` on fail) before `cids` check. Copy `cids`, re-validate `cids ⊆ allowed` at resubscribe time, delete old hash, upsert new with current `sid` + `key_version`. Returns `{ok:true}`. SW `fetch(...,{credentials:'include'})`. `MaxBytesReader` 64KB. Wrong method → `405`. |
| `POST /push/webhook` | internal only, single `:8081`: `r.Method==POST` else `404` (empty body) + `RemoteAddr`-only loopback/private peer check (`SplitHostPort` then `TrimSpace` + `net.ParseIP`; `ip.IsLoopback() \|\| ip.IsPrivate()` else deny; parse fail → deny; never read `X-Forwarded-*`/`CF-*` on this route) + deny if any of `X-Forwarded-Uri/For/Proto/Host`, `Forwarded`, `Via`, `CF-Ray/CF-Connecting-IP/CF-Visitor/CF-IPCountry`, `X-Gate-Auth` present + `X-Push-Webhook-Secret` constant-time compare + require `Content-Type` via `mime.ParseMediaType==application/json` (allow `; charset=`) + fail-closed `404` (empty body, not `401/403`) if configured secret is empty; `MaxBytesReader` 64KB before parse. Never routed via Caddy (edge has explicit `404` block). Never reuse `auth.Guard`. | remark42 POST JSON `{site, page_url, comment:{id, parent_id, user_id, user_name, text_html, text_orig, created_unix, score}}`. Gate: `ExtractCID` → `cid`; drop if unknown or `site != SITE` (log `push_webhook_bad_url/site` with `remote_hash8, bytes` only) → `author_uid` = strip `stepik_` prefix + `ParseInt` (fail → `0`, log `push_webhook_bad_author`, never raw `user_id`) → `comment_id` allowlist `^[A-Za-z0-9_-]{1,64}$` else drop → snippet server-side → non-blocking enqueue `{cid, comment_id, author_uid, author_name, snippet}`. Return `200 {ok:true}` fast (<200ms, enqueue only). Queue-full → `push_queue_drop` + `200` (never `503`). Never log body/snippet/`user_name` on any failure path — log only `remote_hash8, bytes, reason`. |
| `GET /push/health` | shallow public `{ok:true}` rate-limited via `AllowPushByIP` only (no session). Deep `?deep=1` requires `auth.Guard` (`X-Gate-Auth`); Caddy strips inbound `X-Gate-Auth` (`request_header -X-Gate-Auth`) and sends NO `header_up X-Gate-Auth` (unlike `/healthz`), so via edge deep is unconditionally `404` (empty body); ops deep works via direct `http://gate:8081/push/health?deep=1` with token from docker/caddy-net (bypasses Caddy). | Deep returns `{ok:true, subs:<push_subs count via Bucket.Stats()>, queue:<len(chan)>}` — counts only, no subscriber PII. Deep without token → `404` (not `401`). Separate from `/healthz`. |
| `GET /offline.html` | public, `Cache-Control: public,max-age=3600`, `text/html` | Generic shell, no user data per §6. Must exist or SW install fails. Own Caddy `handle` (not `@static` edit). |
| Existing `/`, `/class/<cid>`, `/auth/*`, `/discuss/*`, `/healthz`, `/robots.txt`, `/static/*` | unchanged | `/` ignores `?source=pwa` (launch counting via Gate log only). Class pages add push UI (bell + iOS hint) + page-load key migration; no change to `forward_auth` or `ExtractCID`. |

Push API errors are JSON (not HTML): `Content-Type: application/json`, `Cache-Control: private,no-store`, `X-Robots-Tag: noindex`, body `{error:<code>}`. Mapping: `401 anon/expired → auth_required`; `403 Origin/CSRF/ACL/uid-mismatch → forbidden`; `429 AllowPush/AllowPushByIP deny → rate_limited + Retry-After`; `400 validation → bad_request`; `502 send-transient surfaced only in logs, never to browser`. Reuse RU rate-limited text in JSON for `429`. No change to `/auth/me` shape. Parity note: `/auth/check` + `/auth/admin` JSON lack `X-Robots-Tag` today — push JSON adds it per this mapping; no change to old routes in MVP.

### 4.1 Frozen JSON schemas (Go structs are source of truth)

```go
// GET /push/vapid-key → 200
type VapidKeyResp struct { Key string `json:"key"`; FP string `json:"fp"` }
// key: base64url unpadded P-256 public (65B uncompressed 0x04…); fp: fp8 hex (8 chars).

// CidsOrAll: JSON array of int64 OR string "all". Missing/null/empty → Unmarshal error.
type CidsOrAll struct { All bool; List []int64 }
func (c *CidsOrAll) UnmarshalJSON(b []byte) error // "all" → {All:true}; array → {List};
// MarshalJSON mirrors the same two shapes.

// POST /push/subscribe
type SubscribeReq struct {
  Endpoint string `json:"endpoint"`
  Keys struct { P256dh string `json:"p256dh"`; Auth string `json:"auth"` } `json:"keys"`
  Device struct { UA string `json:"ua"`; Name string `json:"name,omitempty"` } `json:"device"`
  Cids CidsOrAll `json:"cids"`
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
// RU plural for summary body (frozen):
// func plural(n int) string {
//   if n%10==1 && n%100!=11 { return "новый комментарий" }
//   if n%10>=2 && n%10<=4 && (n%100<12 || n%100>14) { return "новых комментария" }
//   return "новых комментариев"
// }
```

`comment_id` allowlist: `^[A-Za-z0-9_-]{1,64}$` (fail-closed drop on mismatch). Push `url` is always server-constructed `/class/<cid>#remark-<comment_id>` and Gate asserts `strings.HasPrefix(url, "/class/")`; SW asserts `url.startsWith("/class/")` else falls back to `"/"`. `page_url` is used only for `ExtractCID`, never flows into `clients.openWindow()`.

### 4.2 Header / cache table (who sets: Gate unless noted)

| Route | `Content-Type` | `Cache-Control` | Notes |
|-------|----------------|-----------------|-------|
| `/manifest.json` | `application/manifest+json` | `public,max-age=3600` | Gate sets both. |
| `/sw.js` | `application/javascript` | `no-store` | Gate sets both. |
| `/push/vapid-key` | `application/json` | `no-store` | Authenticated; never cached. Errors follow §4 mapping. |
| `/push/subscribe`, `/unsubscribe`, `/resubscribe` | `application/json` | `private,no-store` + `X-Robots-Tag: noindex` | Errors follow §4 mapping. |
| `/push/webhook` accept + queue-full drop | `application/json` | none (internal) | `200 {ok:true}`. Requires `Content-Type: application/json`. |
| `/push/webhook` deny | none | none (internal) | `404` empty body (not `401/403`). |
| `/push/health` shallow | `application/json` | `no-store` | `AllowPushByIP` only. Deep adds Guard; Caddy injects no `X-Gate-Auth` here. |
| `/offline.html` | `text/html; charset=utf-8` | `public,max-age=3600` | No `{{.FIO}}`, no user data. |
| `/static/push.js` | `application/javascript; charset=utf-8` | `public,max-age=3600` (via existing static handler) | SW-cached. |
| `/static/*.html` | `text/html; charset=utf-8` | `public,max-age=3600` (via existing static handler) | `handleStatic` mapping fixed in D1. |

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
- `icon-512-maskable.png` accepted only if: opaque full-bleed, logo inside central 80%-diameter safe-zone circle (410px of 512), no transparency. Verify in DevTools Application → Manifest → safe-area preview + maskable.app shapes; regenerate via Maskable.app Editor if it fails. Record final verification in TESTLOG P1. 180px `apple-touch-icon.png` already present.
- Templates (`gate/templates/index.html`, `gate/templates/class.html`, `<head>` near existing lines 11–13): keep `<link rel=manifest>`, add `<link rel=apple-touch-icon href=/static/apple-touch-icon.png>`, `<meta name=mobile-web-app-capable content=yes>`, `<meta name=apple-mobile-web-app-capable content=yes>`, `<meta name=apple-mobile-web-app-status-bar-style content=default>`, `<meta name=apple-mobile-web-app-title content="Stepik Discuss">`. Register SW unconditionally: `<script>if('serviceWorker' in navigator){navigator.serviceWorker.register('/sw.js')}</script>` (deferred, non-blocking).
- Install UX (RU, minimal, no nagging):
  - Android/Desktop Chromium: `e.preventDefault(); deferredPrompt=e;` on `beforeinstallprompt`, show inline `Установить приложение` button once (dismiss persists in `localStorage` key `pwa_install_dismissed=1`), `appinstalled` hides it. Persistent footer link `Установить приложение` re-opens prompt/hint even if dismissed; dismiss re-arms after 7d or REV change.
  - iOS: `iPhone|iPad|iPod` or (`Macintosh` UA + `navigator.maxTouchPoints>1`) + `!navigator.standalone` + `!matchMedia('(display-mode: standalone)')` → one-line hint `На iPhone/iPad уведомления приходят только из значка на экране «Домой» (Поделиться → На экран «Домой»), а не из Safari. Откройте с иконки — тогда придут уведомления.` Shown max once per device (`localStorage pwa_ios_hint=1`), re-arms after 7d or REV change like the Android dismiss; never blocks content.
  - Lighthouse PWA audit ≥90 (mobile) in TESTLOG Wave P1.
- `orientation: portrait-primary` is frozen; verify iPad landscape not letterboxed in P1, drop only with a plan update.
- `start_url:/?source=pwa` enables launch counting (Gate `/` handler ignores the query; count in access log; no external tracker).

## 6. Service Worker + offline + page JS

Gate-served `GET /sw.js` (`Content-Type: application/javascript`, `Cache-Control: no-store`), `REV` injected from `main.revision` via new `handlers.Server.Revision` field (precedence: ldflags-stamped `main.revision` → `debug.ReadBuildInfo vcs.revision[:12]+-dirty` → `"dev"` for `go run`; `handleSW` injects via `%q`; bare `register('/sw.js')`, no `?v=`). `STATIC_CACHE = "static-"+REV` (rollback changes `REV` → old cache deleted on activate).

```js
function urlBase64ToUint8Array(s){s=s.replace(/-/g,"+").replace(/_/g,"/");const p="=".repeat((4-s.length%4)%4);const b=atob(s+p);const o=new Uint8Array(b.length);for(let i=0;i<b.length;i++)o[i]=b.charCodeAt(i);return o;}
const REV = "<git-rev>"; const STATIC_CACHE = "static-" + REV;
const STATIC_ASSETS = ["/static/style.css", "/static/push.js", "/static/icon-192.png", "/static/icon-512.png", "/static/icon-512-maskable.png", "/static/apple-touch-icon.png", "/static/favicon.svg", "/favicon.ico", "/offline.html"];
self.addEventListener("install", (e) => { e.waitUntil(caches.open(STATIC_CACHE).then((c) => c.add(new Request("/offline.html", {cache: "reload"})).then(() => c.addAll(STATIC_ASSETS.filter((u) => u !== "/offline.html")))).then(() => self.skipWaiting())); });
self.addEventListener("activate", (e) => { e.waitUntil(caches.keys().then((ks) => Promise.all(ks.filter((k) => k.startsWith("static-") && k !== STATIC_CACHE).map((k) => caches.delete(k)))).then(() => self.clients.claim())); });
self.addEventListener("fetch", (e) => {
  const u = new URL(e.request.url);
  if (e.request.method !== "GET" || u.origin !== location.origin) return;
  if (e.request.mode === "navigate") {
    e.respondWith(fetch(e.request).catch(() => caches.open(STATIC_CACHE).then((c) => c.match("/offline.html"))));
    return;
  }
  if (u.pathname.startsWith("/static/") || u.pathname === "/offline.html" || u.pathname === "/favicon.ico") {
    e.respondWith(caches.open(STATIC_CACHE).then((c) => c.match(e.request).then((hit) => hit || fetch(e.request).then((res) => res))));
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
    for (const w of ws) { try { if (new URL(w.url).pathname === new URL(url, location.origin).pathname) { return w.focus().then((cw) => { const t = cw || w; const send = () => { try { t.postMessage({type: "push-click", url: url}); } catch(_) {} }; if ("navigate" in t) { return t.navigate(url).then(send, send); } send(); }); } } catch(_) {} }
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

- `STATIC_ASSETS` includes `/static/push.js` and `/favicon.ico` (precache; omitting either leaves bell logic or icon network-dependent offline). Every URL in `STATIC_ASSETS` must `200` with correct `Content-Type` — unit test asserts status + type. All files: `gate/static/style.css, push.js (new), icon-192.png, icon-512.png, icon-512-maskable.png, apple-touch-icon.png, favicon.svg` + `favicon.ico` (served by `handleFavicon`) + Gate-served `/offline.html`. `badge: /static/icon-192.png` reuse is frozen for MVP; verify legibility on Android in P1, add dedicated monochrome `badge-72.png` only with a plan update.
- `GET /offline.html`: Gate-served from `gate/static/offline.html` (`handlers.handleOffline`, `public,max-age=3600`, `text/html; charset=utf-8`, wired into `//go:embed`): generic `Нет соединения. Проверьте интернет — обсуждения появятся, когда сеть вернётся.` + link `/`. No user data, no `{{.FIO}}`. SW serves it as `fetch` fallback only for navigations.
- Page JS: new `gate/static/push.js` (cached `public,max-age=3600`, SW-cached, served `application/javascript; charset=utf-8`) holds `urlBase64ToUint8Array`, `csrfFromCookie` (page-only, reads `__Host-csrf` via `document.cookie`), bell logic, page-load migration, plus a `serviceWorker` `message` listener for `{type:"push-click"}` that `location.reload()`s when already on that class pathname (else `location.assign(url)`) so notification tap always shows a fresh thread (P2 fix: same-pathname hash navigation never reloads, and remark42 has no live thread refresh). `class.html`/`index.html` add `<script src="/static/push.js" defer>` + minimal inline `data-*` (`data-cid`, `data-uid`, `data-allowed` for all-minus-one) + bell button HTML. SW bundle never contains `localStorage`/`document.cookie` (enforced by unit test).
- `localStorage` keys (frozen): `push_uid` (string uid), `push_cids` (`"all"` or JSON array string), `vapid_key_fp` (fp8), `pwa_install_dismissed`, `pwa_ios_hint`. On logout keep keys (rely on server-side `sid` delete + user-change guard); never inherit previous user endpoint.
- Page-load logic on logged-in `/` + `/class/*` (silent, no permission prompt unless fresh subscribe):
  1. `GET /push/vapid-key` → `fp`; `sub = await pushManager.getSubscription()`. On `429` from vapid-key: skip heal this load, keep current bell state, retry next load.
  2. If `sub==null` → show bell-Off (needs tap).
  3. If `sub!=null` and `localStorage push_uid != current uid` (shared-computer user change) → `await sub.unsubscribe()` + best-effort `POST /push/unsubscribe(old)` + clear `push_uid/push_cids/vapid_key_fp` + show bell-Off (require explicit tap; never inherit previous user endpoint).
  4. Else if `localStorage vapid_key_fp != fp` (rotation) → `unsubscribe()` → `subscribe(new key)` → `POST /push/unsubscribe(old)` + `POST /push/subscribe(new, same cids from push_cids or "all")` → store new `fp`.
  5. Else (same `uid` + same `fp`): best-effort idempotent `POST /push/subscribe(same endpoint, push_cids or "all")` on every load (no `subscribe()` call, no prompt). Heals server-deleted rows after relog/revoke/restart. Missing `push_cids` → `"all"`.
- No background sync / periodic sync in MVP. iOS hardening: `Notification.requestPermission()` only inside bell-tap handler synchronously; `userVisibleOnly:true`; every `push` ends in `showNotification`.

## 7. Push pipeline

### 7.1 Keys + env (VPS `.env` only, never repo)

| Key | Note |
|-----|------|
| `VAPID_PUBLIC_KEY` / `VAPID_PRIVATE_KEY` / `VAPID_PUBLIC_KEY_OLD` | base64url P-256 pair via `webpush.GenerateVAPIDKeys()` (returns `RawURLEncoding`: public 65B uncompressed `0x04…`, private 32B), helper `go run ./gate/cmd/genvapid` (`package main` in `gate/cmd/genvapid/main.go`). `config.Load` fail-fast if `VAPID_PUBLIC_KEY/VAPID_PRIVATE_KEY/VAPID_SUBJECT/PUSH_WEBHOOK_SECRET` missing (no degraded mode; `_OLD` empty-string allowed in MVP). Public validation: base64url decodes to 65B uncompressed point `0x04…`; private to 32B. Fingerprint `fp8 = hex(sha256([]byte(public base64url string)))[:8]` (hash string bytes; helper `config.VapidFP8`). Served at `/push/vapid-key`; private never leaves VPS, never in DB. `config.CanonicalOrigin` trims trailing `/` from `GATE_ORIGIN` at Load (exact-match basis for resubscribe `Origin`). Rotation: `push_subs` stores `key_version`; sender maps `row.fp8 → private key` and signs each sub with its row key; unknown `fp8` → `push_skip_unknown_key` + skip (never fallback to current). MVP single active key (`_OLD` empty → all sends use current; migration paths ship as no-ops). Future: new → current for fresh subscribes, old kept for old rows, clients migrate via unsubscribe-before-resubscribe, retire old when old-version count → 0. No dual-send. Documented in runbook. |
| `VAPID_SUBJECT` | `mjgavrilov@gmail.com` (RFC 8292 `sub` contact; bare email or `https://` accepted, `mailto:`-prefixed rejected fail-fast — `webpush-go` prepends `mailto:` unless the value starts with `https:`, so a stored prefix would double to `mailto:mailto:…` and Apple 403s. P2 fix.) |
| `PUSH_WEBHOOK_SECRET` | 32B hex (`openssl rand -hex 32`, 64 hex chars). `config.Load` rejects `len!=64` hex or non-hex (fail-fast). Shared Gate env ↔ remark42 `NOTIFY_WEBHOOK_HEADERS`. Empty value = fail-closed `404` on every webhook call (never accept). Rotation requires simultaneous `compose up -d --force-recreate gate remark42` window (both sides read env at boot); debug via hash-compare (`printenv … | sha256sum`), values never leave VPS, never log headers. |
| remark42 | `NOTIFY_ADMINS=webhook`, `NOTIFY_WEBHOOK_URL=http://gate:8081/push/webhook` (internal docker DNS, single port), `NOTIFY_WEBHOOK_TEMPLATE={"site":{{.Locator.SiteID \| escapeJSONString}},"page_url":{{.Locator.URL \| escapeJSONString}},"comment":{"id":{{.ID \| escapeJSONString}},"parent_id":{{.ParentID \| escapeJSONString}},"user_id":{{.User.ID \| escapeJSONString}},"user_name":{{.User.Name \| escapeJSONString}},"text_html":{{.Text \| escapeJSONString}},"text_orig":{{.Orig \| escapeJSONString}},"created_unix":{{.Timestamp.Unix}},"score":{{.Score}}}}`, `NOTIFY_WEBHOOK_HEADERS=Content-Type:application/json,X-Push-Webhook-Secret:${PUSH_WEBHOOK_SECRET}`, `NOTIFY_WEBHOOK_TIMEOUT=5s`, `NOTIFY_QUEUE=200`. `TRUSTED_PROXY` unchanged. `Text` = sanitized HTML, `Orig` = raw markdown (snippet prefers `Orig`). Gate queue `512` vs remark42 `200` is intentional (gate absorbs bursts + retries; remark42 smaller is upstream backpressure). |
| Send options (frozen) | `TTL: 86400`, `Urgency: "normal"` (low/high only with explicit plan change), `Topic: "class-<cid>"`, `ctx` 10s timeout per send, `VapidExpiration` unset = library default (never set custom expiry in MVP). |

Internal `http://gate:8081` avoids Caddy/edge hairpin (faster, secret invisible to CF/edge logs).

Deploy ordering (fail-fast breaks old deploys otherwise): add secrets to VPS `.env` + `compose.yml` first, then deploy gate. `VAPID_PUBLIC_KEY_OLD` may be empty in MVP.

### 7.2 Subscribe UX + RU strings + consent

On `/class/<cid>` (logged-in): bell `🔔 Уведомлять о новых комментариях [Вкл/Выкл]` + permission state. Flow: user gesture → `Notification.requestPermission()` synchronously → `GET /push/vapid-key` → `pushManager.subscribe({userVisibleOnly:true, applicationServerKey})` → `POST /push/subscribe` with `cids:[cid]` → store `push_uid/push_cids/vapid_key_fp` in `localStorage`. Pre-flight: if `!('PushManager' in window)` or iOS-not-standalone → show iOS-hint instead of active bell. On `/` (logged-in): list toggle `Уведомлять обо всех моих классах на этом устройстве` (`cids:"all"`, expanded server-side at send time via live `BestSessionForUID`, so future classes are included automatically and revoke takes effect immediately). Bell reflects this-device `getSubscription()`, not server-global. Unsubscribe removes endpoint row. Per-class disable: if stored `push_cids=="all"`, class bell shows On (inherited); tapping Off on `cid` X sends `cids = live AllowedClassIDs minus X` (client reads `data-allowed` from page; if result empty → `POST /push/unsubscribe` instead of `[]`); tapping On when stored==array sends `array ∪ {cid}`.

RU copy (state → string, frozen):

- Enable: `Уведомлять о новых комментариях`
- Granted: `Уведомления включены на этом устройстве.`
- Denied: `Уведомления заблокированы в браузере. Разрешите их в настройках сайта, затем попробуйте снова.`
- iOS-not-installed: `На iPhone/iPad уведомления приходят только из значка на экране «Домой» (Поделиться → На экран «Домой»), а не из Safari.`
- Error: `Не удалось включить уведомления. Попробуйте позже.`
- Bell-Off: `Уведомления выключены на этом устройстве. Выход из аккаунта на этом устройстве также отключает их здесь.`

Login consent (`handlers.RUConsent`, shown above button): existing text + `Если включите уведомления, браузер получит технический ключ для доставки оповещений о новых комментариях в ваших классах. Уведомления доставляются через сервис push вашего браузера (Google/Apple/Mozilla) — текст уведомления будет передан ему для показа. Отключить можно в любой момент на странице класса или на главной, а также выходом из аккаунта на этом устройстве.`

Holiday semantics (frozen, also in consent-adjacent help): push is best-effort notification; threads retain all comments. A device offline >24h without re-auth stops receiving pushes until the next page visit silently re-subscribes with the stored `cids` (per-class disables preserved). Revoke/logout take effect immediately.

### 7.3 Fan-out worker (`gate/push` + `gate/handlers` wrappers)

- Storage: BoltDB `push_subs[hex(sha256(endpoint))] → {uid int64, sid string, endpoint, p256dh, auth, cids []int64 + all bool, ua string, key_version fp8, created_at, last_ok_at time.Time, fail_count int}`, `push_meta{vapid_public, fp8}` (private never in DB). Bump/create-if-missing Bolt `SchemaVersion`: fresh DB → create all buckets + `Put("2")`; `version=="1"` → create `push_subs`/`push_meta` + `Put("2")`; `version=="2"` → no-op; else error. `Ping` asserts `"2"`; unit test open-v1→open-v2. `push_queue` in-memory channel cap 512; worker pool 4 senders (in-flight 4), separate from Stepik outbound limiter. Bolt tx never spans network: read snapshot → release → `SendNotificationWithContext` → short update tx (`last_ok_at`/`fail_count`/delete). Queue depth exposed via `/push/health` deep; `push_queue_drop` logged on full.
- Sessions: `Store.SessionsForUID(uid)` (full-bucket scan, skip corrupt) + `BestSessionForUID(uid) (*SessionRecord, string sid)` (one `View` snapshot; filter `ExpiresAt>now` AND `time.Since(LastVerifiedAt) <= VerifyTTL+15m` (jitter-aligned upper bound, UTC) AND `UserVersion==current` AND `GlobalEpoch==current` where currents come from `GetUserVersion`/`GetGlobalEpoch`; pick freshest `LastVerifiedAt`; `nil,""` if none). `IsTeacher` does not bypass expiry. Atomic mutators (single `Update` each, two-tx forbidden): `DeleteSessionAndPushSubs(sid)`, `StripClassAndPrunePush(uid,cid)`, `BumpVersionAndPrunePush(uid)`, `DeletePushSubsForUID(uid)` — `sessions` owns `push_subs`/`push_meta` buckets and all CRUD + mutators; `push` owns validation/worker/coalesce/title-cache/reconcile and calls `sessions` methods (never `sessions→push`; import cycle forbidden).
- Title cache: in-memory `cid → title` mutex map in `gate/push`, set from `session.ClassTitles` at `POST /push/subscribe`, `handleCallback` login, and `resolveHTMLSession` success after `EnsureFresh` (only when titles non-empty and changed; §9 wires these three hooks). Send path only reads; fallback `Класс <cid>`; lost on restart (accepted). No eviction (N small). No Stepik hot-path. Title rendered plain-text only via `html/template`; strip `Cc`+`Cf` (incl. bidi `U+202A–E`, `U+2066–9`, `U+200E/F`), collapse whitespace, rune-boundary truncate ≤100 runes.
- Webhook handler: `MaxBytesReader` 64KB → parse → `cid = ExtractCIDWithConfig("", page_url, cfg.ClassBase(), cfg.EmbedHost())` → drop if unknown or `site != SITE` → `author_uid` = strip `stepik_` prefix + `ParseInt` (fail → `0`) → `comment_id` allowlist `^[A-Za-z0-9_-]{1,64}$` else drop → snippet = `Orig` primary else `bluemonday.StrictPolicy()`-stripped `Text` (then strip `Cc`+`Cf` incl. bidi, collapse whitespace, trim, 120 runes rune-boundary; empty → `Новый комментарий`; snippet/name/title plain-text only via `html/template`, never raw HTML) → non-blocking enqueue `{cid, comment_id, author_uid, author_name, snippet}`.
- Send: for each job, for each sub: skip if `sub.uid == author_uid`; if `BestSession` present require `IsTeacher || cid ∈ AllowedClassIDs` else `push_skip_revoked`; if absent: push from stored array only if `max(created_at,last_ok_at) <24h` (`cid ∈ sub.cids`); stored `"all"` + absent → skip (no teacher exempt — uniform rule). Subscribe-time `cids ⊆ allowed` + send-time live check + resubscribe-time re-validate (defense in depth). Exactly one send per sub with its row key via `SendNotificationWithContext(ctx10s, payload, sub, {Subscriber: VAPID_SUBJECT, TTL: 86400, Urgency: normal, Topic: class-<cid>, VapidExpiration: default})`. Unknown `key_version` → `push_skip_unknown_key` + skip. Title truncated to ≤100 runes before marshal; `len(json)>2048` → cut snippet loop until fit. `last_ok_at` is updated only when `BestSession` was present at send time; absent-path success never touches `last_ok_at` — otherwise daily comments would self-refresh the 24h window and ex-students would never expire.
- Author: webhook `user_name` primary (plain-text sanitized as snippet), `BestSessionForUID(author_uid).FIO` fallback, else `""` (body = snippet alone). Title: `"<Class title> — новый комментарий"` single, `"<Class title>"` summary. Summary body: `N + plural(N)` via frozen `plural` (§4.1; covers 11–14, 111); per-sub `N = count - ownCount` where `count` counts unique comment IDs in the window and `ownCount` counts the sub's own comments among them (`authorUIDs` deduplicated per comment); same `tag:cid-<cid>` + `renotify:true`; summary deep-link uses `latestID`. Payload JSON ≤2KB. No avatar bytes, no tokens. Payload `url` asserted `strings.HasPrefix(url, "/class/")`.
- Delivery: `410/404` → delete immediately (`push_prune expired`); `400/413/415` → delete (bad subscription, avoids infinite retry); `403` → `push_403_key_mismatch` (never auto-delete — rotation signal); transient (429/5xx/timeout/`DeadlineExceeded`) → `fail_count++`, non-blocking requeue via explicit `select { case q <- job: default: push_queue_drop }` (never block worker) with `time.AfterFunc(delay, requeue)` delays `[1s,30s,5m]`, honor `Retry-After` (cap 5m); after 3x park until next webhook. Re-check ACL + row-exists + `fail_count` at each retry tick; drop if revoked/deleted. Worker never sleeps inline. Log `push_send {uid_hash8=hex(sha256(uid))[:8], cid, endpoint_hash8=hex(sha256(endpoint))[:8], status, latency_ms}`; never log endpoint/keys/snippet/body/`user_name`/headers (`X-Push-Webhook-Secret`, `X-Gate-Auth` never logged; hash-compare debug only). Webhook accept log only `cid,comment_id,author_hash8,sub_count`.
- Coalesce: per-`cid` `type coalesce struct {count int; latestID string; authorUIDs []int64; timer *time.Timer}` + mutex map (`authorUIDs` unique per comment; `count` = unique comments in window). First comment for idle `cid` sends immediately + `count=1` + 30s window; further in window bump `count/latestID/authors`; flush: `count==1` → nothing more; `count>1` → one summary with same `tag:cid-<cid>` + `renotify:true` (visible collapses to 1). Summary `N` is per-sub excluding own (`N = count - ownCount`; author excluded at immediate + flush). Timers + `AfterFunc` retries lost on restart (accepted; `push_webhook_gap` logged).
- Subscribe validation: `endpoint` parses URL, `scheme==https`, `host!=""`, `userinfo==""`, `len<2048` + allowlist: host must equal `fcm.googleapis.com`, `updates.push.services.mozilla.com`, or `web.push.apple.com`, or have suffix `.push.apple.com`, or suffix `.notify.windows.com` (Edge); else `400`. Normalization: `strings.ToLower(strings.TrimSuffix(host,"."))`, reject empty after trim, IDNA ToASCII, require `port==""||port=="443"` (deny explicit non-443); suffix match only on dot-boundary (`host==base || HasSuffix(host,"."+base)`). IP safety: if host parses via `net.ParseIP` → deny `IsLoopback/IsPrivate/IsLinkLocalUnicast/IsUnspecified`; else resolve host → deny if any resolved IP matches those predicates. `p256dh` 87–88 chars base64url decode-check with `len(decode)==65 && [0]==0x04`, `auth` 22–24 chars decode-check with `len(decode)==16`; `cids` array requires every `cid ∈ session.allowed` (or teacher) else `403` whole request; missing/null `cids` → `400` (only explicit non-empty array or `"all"` accepted); empty `cids:[]` rejected (use `unsubscribe` instead); `"all"` allowed; `device.ua` truncate 256 + strip `Cc`+`Cf`/controls, `device.name` optional 64 + strip `Cc`+`Cf`/controls, plain-text only (never render as HTML in admin). Resubscribe re-runs full `IsValidEndpoint` + `IsValidKeys` on the new `endpoint` before `cids` check; worker re-resolves host before send and applies same IP-deny (`push_skip_ssrf_rebind` + delete on match) as defense-in-depth for DNS rebind.
- CSRF/rate: `ClientIP` = Caddy-authoritative `CF-Connecting-IP` when from trusted peer (loopback/private docker net), else `RemoteAddr` peer (Caddy strips inbound `X-Forwarded-For` via `request_header -X-Forwarded-For` + sets `CF-Connecting-IP {client_ip}` from trusted `trusted_proxies`; Gate ignores `X-Forwarded-For` entirely — D1 removes the `XFF` first-entry fallback from `ratelimit.ClientIP`, keep only `CF-Connecting-IP` + `RemoteAddr`). `AllowPushByIP(ClientIP)` (`Every(1s)`, burst 30) checked before `LoadSession` on all `/push/*` incl. shallow `/push/health`; then `subscribe|unsubscribe` = `validSameOrigin` + `VerifyHeaderCSRF` + per-sid `AllowPush` (`Every(3s)`, burst 20; stale `sid` entries cleaned by existing 3-min sweep in `allow()`); `vapid-key` also per-sid `AllowPush` after auth; `resubscribe` = require-present-`Origin` exact match against canonical `cfg.Origin` (reject missing/`"null"`/mismatch; `cfg.Origin` canonicalized at Load) + `sid` + per-sid `AllowPush` only (no `Referer` fallback). Unit test asserts `SetSID/SetCSRF` use `SameSite=Lax` (if ever `None`, re-add CSRF). `429` returns `Retry-After` seconds. All JSON POST `Content-Type` checks use `mime.ParseMediaType==application/json` (allow `; charset=`), not prefix-match.
- Prune wiring (atomic, single `Update` each): `handleLogout` → `DeleteSessionAndPushSubs(logged-out sid)` (delete `where row.sid==sid`, not by `uid`; idempotent double-logout keeps same-`uid` other-device rows); `admin.logoutAll` → epoch bump + delete all `push_subs` in same `Update` (no per-session iteration; epoch already invalidates all); `admin.revokeUser` → `BumpVersionAndPrunePush(target uid)` (deletes rows for target `uid`); `admin.revokeClass` → `StripClassAndPrunePush(uid,cid)` per affected `uid` (shrinks arrays, deletes single-`[cid]` rows and all `"all"` rows for that `uid`, re-subscribed as new allowed on next heal) **and synchronously rewrites affected sessions' `AllowedClassIDs` in the same Bolt tx (never bump `UserVersion` for class revoke — that would log the user out and break 0001 §5.5)** so a stale `BestSession` (6h `VerifyTTL`) cannot re-authorize the revoked `cid`. Revoke only via `/discuss/admin/revokeClass` — direct Stepik-UI removal bypasses prune and is bounded only by VerifyTTL-freshness + 24h absent cap + hourly reconciler (see below); it is forbidden in ops. Unit test: revoke → immediate send suppressed before next `EnsureFresh`. Hourly sweep (session sweeper ticker, shared): delete `fail_count>10 && last_ok>30d` + `no live session && max(created_at,last_ok_at)>24h` (uniform for all uids including teacher; explicit logout/delete still removes immediately). Known gap (documented, no code in MVP): logout requires network; offline logout leaves rows until next online logout/sweep/24h cap — note in TESTLOG.
- Reconciler (H2 backstop, D47): `push.ReconcilePushSubs(ctx, store, checker)` hourly, sharing the session sweeper ticker. For each distinct `sid` referenced by `push_subs` rows whose session exists and `time.Since(LastVerifiedAt) > VerifyTTL`: call `checker.EnsureFresh(ctx, sid, sess)` (reuses Stepik outbound limiter; Bolt tx never spans network). On `left`/`outsider`/`expired` → prune that `uid` via `StripClassAndPrunePush`/`BumpVersionAndPrunePush`/`DeletePushSubsForUID` in a single `Update`. On success with changed `AllowedClassIDs` → `StripClassAndPrunePush` for removed `cid`s in the same `Update` as the session rewrite. On transient → keep rows, log `push_reconcile_transient`. Stepik outage never deletes. Unit test: direct-Stepik-remove → reconciler prunes within one tick; transient → rows kept.

### 7.4 Privacy / isolation

- Push never bypasses class ACL (send-time matrix above). Uniform 24h `max(created,last_ok)` cap bounds the ex-student window; `VerifyTTL+15m` freshness bounds the present window; reconciler bounds direct-UI removal to ~1h. Explicit logout deletes that `sid` rows → logged-out device gets nothing even if same `uid` live elsewhere. Shared-computer user change forces untap, never inherits (orphan cross-`uid` delete only when old `uid` has no live session, without leaking).
- Webhook snippet treated as private: logs exclude snippet/body/`user_name`; push transit via FCM/APNs/Mozilla disclosed in consent.
- Secrets in VPS `.env` only (`chmod 600`), keys only in `deploy/.env.example`. Debug via hash-compare (`printenv … | sha256sum`), values never leave VPS.
- 152-FZ/minors: endpoint+p256dh+auth are device keys (not child data), per-uid+sid, deletable via bell-Off + per-device logout + user-change guard. No parental gate in MVP nor production — push transit via FCM/APNs/Mozilla disclosed in login consent (§7.2) is sufficient. Stable Stepik `uid` never logged in clear (hashes only — `hex(sha256(uid))[:8]` is anti-PII hygiene, not anonymity: 32-bit prefix is reversible for <20 uids by brute force; documented as such). Migrate old clear-`uid` log lines later (no change in MVP beyond push paths); compose `config` test path uses dummy env only.

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
  request_header -X-Gate-Auth
  reverse_proxy gate:8081
}
handle /push/webhook* {
  respond "Not found" 404
}
```

Safe: `handle` mutually exclusive, longest-path-first among same directive; listed paths have no overlap with `@static`, `/class/*`, `/auth/*`, `/healthz`, `/discuss/*`. Webhook has no proxy (edge always 404). `/push/health` strips inbound `X-Gate-Auth` (`request_header -X-Gate-Auth`) and sends NO `header_up X-Gate-Auth` (unlike `/healthz`) — deep `?deep=1` via edge is unconditionally `404` even with a guessed token; ops deep works via direct `http://gate:8081/push/health?deep=1` with token from docker/caddy-net (bypasses Caddy). `CF-Connecting-IP` + rate-limit chain unchanged. Covers `/push/webhook?x` and trailing slash via `*`.

`deploy/compose.yml`: remark42 += `NOTIFY_ADMINS=webhook`, `NOTIFY_WEBHOOK_URL=http://gate:8081/push/webhook` (internal docker DNS, single port), `NOTIFY_WEBHOOK_HEADERS=Content-Type:application/json,X-Push-Webhook-Secret:${PUSH_WEBHOOK_SECRET}` (double-quoted for expansion), `NOTIFY_WEBHOOK_TIMEOUT=5s`, `NOTIFY_QUEUE=200`, `NOTIFY_WEBHOOK_TEMPLATE='<frozen §7.1>'` (single-quoted, no `$`); gate += `VAPID_PUBLIC_KEY, VAPID_PRIVATE_KEY, VAPID_PUBLIC_KEY_OLD, VAPID_SUBJECT, PUSH_WEBHOOK_SECRET`. No new services, no `ports:` changes. No `:8082` listener in MVP (future option documented in runbook only).

`deploy/.env.example`: keys only (`VAPID_PUBLIC_KEY=`, `VAPID_PRIVATE_KEY=`, `VAPID_PUBLIC_KEY_OLD=` (may be empty), `VAPID_SUBJECT=mjgavrilov@gmail.com` (bare — library prepends `mailto:`), `PUSH_WEBHOOK_SECRET=` + generation comments `go run ./gate/cmd/genvapid` / `openssl rand -hex 32`). Secrets never committed.

Cloudflare: rule `(http.host eq "stepik.study67.fyi") → Bypass cache` already covers new paths; verify `cf-cache-status: BYPASS/DYNAMIC` on `/push/*`, `/sw.js`, `/manifest.json`, `/offline.html` in TESTLOG. Bot Fight Mode is OFF for the host — `POST /push/subscribe` must not be challenged (verify in P2 with `cf-cache-status` evidence).

`caddy-verify.sh` extensions (extend `upstream.py` to emulate Gate for new paths; keep checks 1–5 unchanged): stub behavior: `GET /auth/check` → log `X-Forwarded-Uri` + `200 ok` (existing); `GET|POST /push/vapid-key` → if no `Cookie: __Host-sid` → `401 {error:auth_required}` else `200 {key,fp}`; `GET /offline.html` → `200 text/html`; `GET /push/health?deep=1` → if no `X-Gate-Auth` header (Caddy strips + never injects) → `404` else `200 {ok:true}`; any `POST /push/webhook` reaching upstream is a failure (Caddy must 404 before proxy — assert upstream logs contain zero `/push/webhook` hits). Checks: `6: POST /push/webhook →404` + upstream-never-hit, `7: GET /push/vapid-key no-cookie →401` + with-cookie `→200`, `8: GET /offline.html →200 text/html`, `9: GET /push/health?deep=1` without token `→404` and with forged `X-Gate-Auth: <any>` `→404` (proves strip). After any Caddyfile edit: container `caddy validate` (AGENTS.md exact form) + `deploy/caddy-verify.sh` + `docker compose -f deploy/compose.yml config`.

## 9. Build steps (implement in order D0 → D1 → D2 → D3)

Two-pass by design: D1 creates types + `VerifyWebhook` + PWA shell + stubs; D2 fills worker + push HTTP wrappers + `NOTIFY_*`. Files are revisited only where the pass column says D1→D2.

### D0 — spike (0.5d, standalone, before Gate changes; gates D1)

Precondition: no Gate code changes yet.

| # | Do | Done |
|---|----|------|
| D0.1 | Minimal Go sender with `webpush-go v1.4.0` + real browser subscription (manual vapid-key dump) → prove VAPID send → desktop notification + `201` from push service (iOS-HS proof deferred to P2). | `201` + visible notification recorded. |
| D0.2 | Live remark42 webhook dump (ephemeral secret, `spike/` style, never committed) proving frozen §7.1 template: parses, valid JSON on quotes/newlines/emoji, `.Timestamp.Unix` numeric, `.Orig` populated, `Content-Type + secret` headers received. Additionally dump 3+ real `comment.ID` values to confirm `comment_id` allowlist `^[A-Za-z0-9_-]{1,64}$`, and screenshot remark42 `v1.16.4` DOM anchor to confirm `/#remark-<comment_id>` deep-link shape. | Verdict paragraph appended here (split to `plans/0004-push-spike.md` only if >1 page). Template string locked. |
| D0.3 | Record D0 verdict (one paragraph). No D1 without this verdict. | Gates D1. |

### D1 — PWA shell (1d, no webhook yet)

Precondition: D0 verdict recorded. Deploy order: VPS `.env` (`VAPID_*`, `PUSH_WEBHOOK_SECRET`, `chmod 600`) + `deploy/compose.yml` gate `VAPID_*` + `deploy/.env.example` keys first, then gate code (`config.Load` fail-fast breaks old deploys otherwise).

| # | Files (pass) | Do (refs only) | Done |
|---|--------------|----------------|------|
| D1.1 | `gate/config/config.go` (D1) | Add VAPID_*/secret validation + `VapidFP8` + `CanonicalOrigin` per §7.1/D17. Fail-fast; `_OLD` empty allowed. | `Load` rejects bad/missing secrets. |
| D1.2 | `gate/sessions/sessions.go` (D1) | Create `push_subs`, `push_meta` buckets + `SchemaVersion` `"1"`→`"2"` per §7.3/D40; add push CRUD + `SessionsForUID`/`BestSessionForUID` (freshness `VerifyTTL+15m`, D16/D48) + atomic mutators `DeleteSessionAndPushSubs`, `StripClassAndPrunePush`, `BumpVersionAndPrunePush`, `DeletePushSubsForUID` (single `Update` each). | Unit: open-v1→open-v2; `Ping` asserts `"2"`. |
| D1.3 | `gate/ratelimit/ratelimit.go` (D1) | Add `push` + `push_ip` maps + `AllowPush(sid)` (`Every(3s)`, burst 20) + `AllowPushByIP(ip)` (`Every(1s)`, burst 30, pre-auth); `ClientIP` = `CF-Connecting-IP` when from trusted peer else `RemoteAddr` peer — remove `X-Forwarded-For` fallback per §7.3/D35. | Pre-auth flood closed; XFF ignored. |
| D1.4 | `gate/push/` types + verify (D1 stub) | Add §4.1 structs + `CidsOrAll.UnmarshalJSON` + `plural` + `VerifyWebhook` (§4/D25: `POST`-only + secret constant-time + empty-secret `404` + `IsLoopback\|\|IsPrivate` predicate + extended header-deny + `mime.ParseMediaType` JSON, `404` empty body, never-log-body) + validation (`IsValidEndpoint`/`IsValidKeys`/`IsValidCids`, `comment_id` allowlist) + `TitleCache` type. Deps (pin in `go.mod`+`go.sum`): `github.com/SherClockHolmes/webpush-go v1.4.0` + `github.com/microcosm-cc/bluemonday` (latest 1.x, `StrictPolicy` only) + `golang.org/x/net/idna` (`ToASCII` for endpoint normalization). No worker yet. | Unit: webhook validation matrix (D3 list). |
| D1.5 | `gate/cmd/genvapid/main.go` (D1) | Generator per §7.1. | Never commit output. |
| D1.6 | `gate/handlers/handlers.go` (D1 PWA) | Add `Server.Revision` + `New` param (D24) + update all `handlers.New(...)` call sites in tests (`handlers_test.go`, `callback_test.go`, `htmlsession_test.go`, `teacher_*_test.go`); `Routes` `/push/*` + `/offline.html` stubs (wrong-method `405`); manifest upgrade (§5); full `sw.js` (§6 with `%q` REV, named-cache match, `startsWith("/class/")` guard + hash-preserving `notificationclick`); `handleOffline` + `//go:embed offline.html`; `handleStatic` MIME fix (`.js`, `.html`); JSON errors (§4 mapping + `X-Robots-Tag`); `push.js` wiring (+ `maxTouchPoints` iPad check, vapid-key `429` → silent skip); `AllowPushByIP` before `LoadSession` on every `/push/*` + shallow health; deep health via `auth.Guard`; `CanonicalOrigin` exact-match helper for resubscribe. | Manifest/SW/offline served with §4.2 headers. |
| D1.7 | `gate/main.go` + `gate/Dockerfile` (D1) | `main.go`: `var revision = "dev"` + pass to `New`; fail-fast `if !cfg.Placeholder && (revision=="dev"\|\|"unknown"\|\|"") → log.Error + os.Exit(1)`. `Dockerfile`: `ARG REV` + `RUN CGO_ENABLED=0 go build -ldflags "-X main.revision=$REV" -o /gate ./gate`, built via `--build-arg REV=$(git rev-parse --short=12 HEAD)`. No worker yet (fan-out no-op `push_noop_no_event`). | Prod REV enforced; `go run` placeholder allows `dev`. |
| D1.8 | `gate/static/push.js` + `gate/static/offline.html` + `gate/templates/class.html`/`index.html` (D1) | Bell + install hint + `push.js` script + `data-cid/data-uid/data-allowed` + `apple-touch-icon` link per §5/§6/§7.2. | P1 shell renders. |
| D1.9 | `deploy/Caddyfile` + `deploy/caddy-verify.sh` + `deploy/compose.yml` gate `VAPID_*` + `deploy/.env.example` (D1) | Caddy §8 block (insert after `/auth/*` before `/discuss` blocks, strip on `/push/health`, no `header_up`); `caddy-verify.sh` checks 6–9 + stub; `docker compose config`; `caddy validate`; CF `BYPASS/DYNAMIC` verify. | `caddy-verify.sh` green. |
| D1.10 | Acceptance | Wave P1 green (§10 items 1–5) + Lighthouse mobile ≥90 + `/offline.html 200 text/html` + `/static/push.js 200 application/javascript` + `/push/vapid-key 401 anon` + `govulncheck ./...` clean locally + SW bundle unit test (allowlist, no `caches.add('/')`/`/class`, no `localStorage`/`document.cookie`, helper present, every `STATIC_ASSETS` URL `200` + correct type, `navigate`-on-focus). | TESTLOG P1. |

### D2 — push pipeline (2d, core)

| # | Files (pass) | Do (refs only) | Done |
|---|--------------|----------------|------|
| D2.1 | `gate/push/` worker (D1→D2 fill) | Add webhook handler, worker + coalesce + retry + `ReconcilePushSubs` per §7.3/D11/D47 (snapshot-outside-tx, queue-full drop+`200`, `400/413/415→delete`, `403→retain`, non-blocking `select` requeue + `AfterFunc` retries with ACL/row/`fail_count` re-check each tick + `Retry-After` cap 5m, per-sub summary `N`, `TTL/Topic/Urgency/ctx10s/VapidExpiration-default`, uniform `max(created,last_ok)<24h` absent cap (no teacher exempt, D40), `comment_id` allowlist + `HasPrefix` URL assert, `bluemonday.StrictPolicy` snippet + `Cc`/`Cf` strip + rune-boundary + 2048 loop); wire title-cache population hooks (§7.3). | Unit: send/ACL/coalesce/retry matrix (D3 list). |
| D2.2 | `gate/handlers` push wrappers (D1→D2 fill) | Add subscribe/unsubscribe/resubscribe/vapid-key/health wrappers (§4 + §7.3: uid-scoped unsubscribe + orphan rule, resubscribe `400` on empty old + `cids` re-validate, endpoint allowlist `400`, Origin exact + `null`-reject) + logout prune via `DeleteSessionAndPushSubs` + consent update (§7.2) + title-cache hooks in `handleCallback` + `resolveHTMLSession` after `EnsureFresh`. | Wrappers match §4.1/§4.2. |
| D2.3 | `gate/admin` (D2) | Wire `logoutAll`/`revokeUser`/`revokeClass` via `sessions` mutators + synchronous session rewrite in same tx (§7.3). | Revoke → immediate suppress (unit). |
| D2.4 | `deploy/compose.yml` (D1→D2 fill) | Add `NOTIFY_*` wiring (frozen §7.1 template, no edits without D0 re-verdict). | Compose parses. |
| D2.5 | RU strings + consent (D2) | Verbatim §7.2 live. | Copy verified. |
| D2.6 | Acceptance | Wave P2 green (§10 items 6–12 + 7b; item 10 = ≤2 pushes per 30s window, visible 1) + `docker stats gate <256M` + `push_send/push_prune/push_skip_revoked/push_403_key_mismatch/push_skip_unknown_key/push_queue_drop` samples. | TESTLOG P2. |

### D3 — hardening (0.5d)

| # | Files | Do (refs only)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                  | Done |
|---|-------|----------------|------|
| D3.1 | `docs/ops-runbook.md` | Add rotation section (single-key MVP + future overlap, `_OLD` reserved; `PUSH_WEBHOOK_SECRET` simultaneous-restart window; hash-compare debug; `:8082` future option noted; direct Stepik-UI removal forbidden — only `/discuss/admin/revokeClass` revokes, reconciler bounds bypass to ~1h; Cloudflare Bypass + Bot Fight Mode OFF verification; holiday semantics §7.2).                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                      | Runbook merged. |
| D3.2 | `TESTLOG.md` + verify | `push/health` deep evidence (direct `http://gate:8081/push/health?deep=1` with token from docker/caddy-net; edge deep unconditionally 404); TESTLOG waves; `caddy-verify.sh` re-run.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            | Evidence recorded. |
| D3.3 | Unit tests (grouped; exact names in code) | Webhook: `http:`/bad keys/oversize/allowlist-miss/never-log-body rejected; `VerifyWebhook` RemoteAddr-only (XFF spoof rejected) + header-deny (`X-Forwarded-Uri`/`Forwarded`/`Via`/`CF-Ray`/`CF-Visitor`/etc. → `404`) + `GET-webhook-404` + `charset-200` + empty-secret `404` + short-secret `404` + non-JSON `Content-Type` `404`. Endpoint-SSRF: `169.254.169.254`/`gate:8081`/`http:`/uppercase/trailing-dot/non-443 rejected `400`; send-time rebind `push_skip_ssrf_rebind`. Sessions/ACL: `BestSessionForUID` matrix (expiry + `VerifyTTL+15m` freshness + version/epoch) + revoke-immediate-suppress + absent-`max(created,last_ok)`-24h-skip (uniform, teacher included) + absent-no-refresh + ex-student-daily-suppressed + logout-deletes-only-that-sid + user-change guard + `DeletePushSubsForUID`. Resubscribe: `400`-on-empty-old + attacker-endpoint-`400` + `403`-on-mismatch + Origin missing/`null`/mismatch `403` + Lax-assertion. Unsubscribe ownership: own delete 200, foreign-live 403 no-delete, orphan delete 200. Keys: unknown-fp8-skip. Comment: `comment_id` allowlist (`/`, `<`, space rejected). Schema: v1→v2. Queue: `Retry-After` cap + queue-full-`200`+`push_queue_drop` + single-`Update` atomicity. SW: allowlist + `STATIC_ASSETS` 200 + correct `Content-Type` + hash-preserving `notificationclick` (`focus()+navigate`, hash kept) + no `localStorage`/`document.cookie` in bundle. Coalesce/snippet: plural `11–14/111` + all-minus-one narrow + summary `N` per-sub + `latestID` link + `bluemonday` snippet + 2048 loop. Reconciler: direct-remove pruned within one tick; transient keeps rows. | `go test -count=1` green. |
| D3.4 | `.github/workflows/ci.yml` | Add `govulncheck` job (pinned 1.x version from pkg.go.dev, never `@latest`, e.g. `go install golang.org/x/vuln/cmd/govulncheck@v1.8.0 && govulncheck ./...`).                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   | CI green. |
| D3.5 | Merge | `go build/vet/test -count=1` green + `docker stats` evidence.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   | Merge. |

Deferred: teacher Telegram channel (`plans/0003-teacher-telegram.md`, needs BotFather bot); lesson-level `…/lesson/<lid>` push; email fallback; TWA/Play packaging.

## 10. Browser test plan (append to TESTLOG.md)

Gates per phase:

| Phase | Items | Evidence |
|-------|-------|----------|
| P1 (installability, webhook disabled) | §10 items 1–5 | TESTLOG P1 + Lighthouse + `cf-cache-status` + `caddy-verify.sh` log |
| P2 (push end-to-end, webhook enabled, ≥2 test users) | §10 items 6–12 + 7b + 13 | TESTLOG P2 + Gate logs (`push_send` etc.) + `docker stats` |
| Merge | Gates (§1) + D3.3–D3.5 | CI + `govulncheck` + `docker stats` |

P1 (installability, webhook disabled):
1. Desktop Chrome `chrome://apps` + DevTools Manifest (no errors, 192+512, `standalone`), Lighthouse ≥90.
2. Android Chrome: `beforeinstallprompt` → Install → `standalone` (`?source=pwa` in Gate log), icon correct.
3. iPhone iOS 26.+: Share → Add to Home Screen → `standalone`; pre-install toggle shows iOS-hint; post-install tap shows permission prompt (never on load).
4. Offline: airplane mode → `/static/style.css` + `/static/push.js` from SW cache, `/` shows `/offline.html` (generic), `/class/<cid>` fails safe (no stale private HTML). Record `cf-cache-status` (`BYPASS`/`DYNAMIC`, never `HIT`) for `/manifest.json`, `/sw.js`, `/offline.html`, `/push/vapid-key`, `/push/subscribe`, `/static/push.js`.
5. Caddy contracts green: `caddy-verify.sh` + 0001 §8 items 1–7.

P2 (push end-to-end, webhook enabled, ≥2 test users; teacher validates on iPhone iOS 26.+ + Android):
6. A subscribes on `/class/<cid>` → B posts → A gets notification (single <5s, end-to-end <30s even with tab closed) with correct title/body/deep-link; click focuses/opens `/class/<cid>#remark-<id>` preserving hash. Log `push_send`.
7. Self-suppressed (B gets nothing for own); outsider/revoked gets nothing (`push_skip_revoked`; re-join resumes). Revoke takes effect immediately (no 6h lag).
7b. Logout silence: A logs out device1 → B posts → device1 nothing, device2 (same A) fires. A re-logs device1 (silent heal) → next post fires without re-tap. Shared-computer: A out, B in same profile without tap → B gets nothing until tap; after tap B gets own only. Ex-student with no re-auth >24h (`max(created,last_ok)>24h`) gets nothing (uniform incl. teacher). Unsubscribe ownership: A cannot silence teacher endpoint (foreign live-session row kept, `403` path covered by unit test + manual spot-check).
8. Multi-device: A on 2 browsers → both fire; unsubscribe one → only remaining fires.
9. Denied/expired: deny → RU denied-string; devtools `unsubscribe()` → next webhook `410` → prune (`push_prune expired`). `403` (rotation) → retained (`push_403_key_mismatch`).
10. Burst: 5 comments in 30s → ≤2 pushes (1 immediate + 1 summary with frozen RU plural), visible 1 (same tag + renotify; assert via upstream push-service log count + device-visible single notification). Summary `N` excludes own comments per-sub.
11. Teacher `"all"` gets every owned class incl. future classes; student `"all"` only own `allowed` (live expansion; absent `"all"` → skip for all uids).
12. Resource: `docker stats` gate <256M; `go test -count=1` + `vet` + `govulncheck` green.
13. Security spot-checks (record in TESTLOG): endpoint-SSRF (`169.254.169.254`, `http://gate:8081/`, non-allowlist host, uppercase/trailing-dot/non-443 → `400`); webhook header-deny (with `X-Forwarded-For`/`Forwarded`/`Via`/`CF-Ray`/`CF-Visitor`/`X-Gate-Auth` → `404`; `GET /push/webhook` → `404`; `charset` CT → `200`); `comment_id` allowlist (`../../`, `<img>`, space → dropped, no push); Bot check (Bot Fight Mode OFF; `POST /push/subscribe` not challenged, `cf-cache-status` recorded); `/push/health?deep=1` via edge (even with token) → `404`, via direct `gate:8081` with token → `200` counts-only; `Retry-After` on `429`; `push_send/push_prune/push_skip_revoked/push_403_key_mismatch/push_skip_unknown_key/push_queue_drop/push_skip_ssrf_rebind` samples; revoke→immediate-suppress; resubscribe empty-old `400` → page heal; `410` prune vs `403` retain; reconciler tick evidence (`push_reconcile_prune` / `push_reconcile_transient`).

## 11. Risks

- iOS HS-install skipped → one-line RU hint + teacher announcement (`Установите как приложение, иначе уведомления не придут — инструкция на главной`). No auto-prompt.
- Webhook template drift / `Locator.URL` change → `ExtractCID` fail-closed + `push_webhook_bad_url` + `push_webhook_gap` (no crash/leak, never log body). Next comment heals.
- Endpoint churn → `410/404/400/413` prune + `pushsubscriptionchange` (400-tolerant) + page-load migration/heal + user-change guard + hourly sweep + reconciler. `403` = rotation signal, never auto-delete. Logout deletes only that `sid` rows via atomic `DeleteSessionAndPushSubs`.
- VAPID leak → per-sub `key_version` rotation; single-key swap safe only in test scope; production must overlap; old dies when old-version count → 0. Unknown `fp8` → skip, never fallback.
- SW cache poisoning → allowlist `/static/*` + `/offline.html` + `/favicon.ico` only, generic offline fallback, `no-store` on `sw.js`, unit test allowlist + `STATIC_ASSETS` 200 + correct type.
- Single VPS SPOF + in-memory queue/timers → burst loss on restart accepted (comments remain; no `down -v`). `push_queue_drop` + `push_webhook_gap` make loss visible.
- New dep `webpush-go` — pinned + `govulncheck`.
- `X-Gate-Auth` overwrite — plain `header_up` overwrites (no append); consistent with `/healthz`. `/push/health` strips inbound (`request_header -X-Gate-Auth`) and has no `header_up`, so deep via edge is unconditionally `404`.
- Authenticated SSRF via endpoint allowlist miss → closed by allowlist + resolve-then-IP-check (subscribe `400` + send-time rebind check).
- Pre-auth flood on `/push/*` → closed by `AllowPushByIP` before session load.
- Direct Stepik-UI class removal (bypasses `admin.revokeClass`) → bounded by `VerifyTTL+15m` present window + uniform 24h absent cap + hourly reconciler (~1h typical); forbidden in ops, only admin revoke revokes. Reconciler transient (Stepik outage) keeps rows and logs `push_reconcile_transient`.
- Holiday offline >24h → pushes stop until next visit heals (threads retain comments; per-class disables preserved via stored `cids`). Documented in §7.2; accepted for security-first.
- Caddy/Gate header logging → never log `X-Push-Webhook-Secret` / `X-Gate-Auth` / full `r.Header`; hash-compare debug only; verify `Caddyfile` has no `log … headers`.

## 12. Decisions

All decisions below are final. Implementation must match; any change requires plan update. History lives in `git log` only.

| # | Topic | Decision | Details |
|---|-------|----------|---------|
| D1 | Notify scope | All class members except author | No thread-participant-only mode in MVP. Coalesced per §7.3, per-sub `N` excludes own. |
| D2 | Quiet hours | None in MVP | Revisit only if night spam becomes a problem (morning digest deferred, no design). |
| D3 | Teacher Telegram | Design in `0003`, implementation deferred | Needs teacher BotFather bot + VPS `.env` token. `NOTIFY_ADMINS=webhook` stays extensible to `webhook,telegram`. |
| D4 | Test scope | Webhook-only MVP, no poller | Ephemeral secrets ok; outage heals on next comment (`push_webhook_gap`). Reconciler (D47) is a pruner, not a poller. |
| D5 | Caddy routing | Enumerated handles + own `/offline.html` + webhook `404`, strip on `/push/health` | `handle /push/vapid-key*`, `/push/subscribe*`, `/push/unsubscribe*`, `/push/resubscribe*` (plain proxy); `handle /push/health*` with `request_header -X-Gate-Auth` + NO `header_up X-Gate-Auth` (unlike `/healthz`, so edge deep is unconditionally 404); `handle /push/webhook* {404}`; own `handle /offline.html` (not `@static` edit). Insert after `/auth/*` block, before `/discuss/*` blocks and before final `handle {404}`. Verify checks 6–9. Compose template single-quoted, headers double-quoted. `*` covers query + trailing slash. CF Bypass rule covers new paths. |
| D6 | Service Worker | Navigation-only offline fallback + cache-first static; bare `register('/sw.js')`; `STATIC_CACHE="static-"+REV` | No `localStorage`/`document.cookie` in SW; `pushsubscriptionchange` best-effort via resubscribe (400-tolerant, page-load is primary healer); page-load migration/heal/user-change guard; `urlBase64ToUint8Array` in both SW and page; gesture-only permission, `userVisibleOnly:true`, always `showNotification`. `STATIC_ASSETS` includes `push.js` + `/favicon.ico`; every entry must `200` + correct type. No preload, no background/periodic sync. `notificationclick` asserts `startsWith("/class/")` else `"/"` and preserves `#remark-<id>` on focus path via `focus()+navigate(url)` + `postMessage({type:"push-click"})`; the page listener reloads same-pathname windows (fresh thread, hash kept) per §6. iPad includes `navigator.maxTouchPoints>1` alongside `Macintosh` UA check. Cache reads use the named `STATIC_CACHE` (`caches.open(STATIC_CACHE).then(match)`). `REV` injected via `%q`; byte-change drives SW update → new `STATIC_CACHE`, old deleted on activate. |
| D7 | CSRF + rate | `subscribe\|unsubscribe` = IP + Origin + header CSRF + per-sid rate; `resubscribe` = IP + required-Origin + sid + per-sid rate only | `ClientIP` = Caddy `CF-Connecting-IP` when from trusted peer (loopback/private), else `RemoteAddr` peer (Gate ignores `X-Forwarded-For` entirely; Caddy strips it; D1 removes the XFF fallback). `AllowPushByIP Every(1s)` burst 30 before `LoadSession` on all `/push/*` + shallow health; then `validSameOrigin` + `VerifyHeaderCSRF` (`__Host-csrf` via `document.cookie`) + per-sid `AllowPush Every(3s)` burst 20. `resubscribe` CSRF-exempt but requires present `Origin` exact match against canonical `cfg.Origin` (reject missing/`"null"`/mismatch; no `Referer` fallback; SW always sends `Origin`; `SameSite=Lax` + required Origin sufficient; unit test asserts `Lax`; if ever `None`, re-add CSRF). SW uses `credentials:'include'`. `vapid-key` also per-sid `AllowPush` after IP check. `429` + `Retry-After`. No `/auth/me` change. |
| D8 | Author name | Webhook `User.Name` primary | Fallback `BestSessionForUID(author_uid).FIO`, else `""` (body = snippet alone). Plain-text only. |
| D9 | Subscribe scope | `"all"` for students + teacher; per-class disable via narrowed `POST`; no `PATCH` | Server expands `"all"` at send time via live `BestSessionForUID` so revoke + future classes take effect immediately. Empty `cids:[]` and missing/null `cids` rejected `400` (only explicit non-empty array or `"all"`; use `unsubscribe` to stop). All-minus-one: stored `"all"` + Off on X → `cids = AllowedClassIDs − X` (via `data-allowed`; empty → `unsubscribe`); stored array + On → `array ∪ {cid}`. Absent `"all"` → skip for all uids (D40). |
| D10 | Consent | Extended with push-service transit sentence | Verbatim §7.2; login page existing slot; bell-Off text frozen; holiday semantics documented alongside. |
| D11 | Worker | 4 senders (in-flight 4), Stepik limiter untouched, immediate-first coalesce + non-blocking retry, `sid` per row | Queue 512 (gate) / 200 (remark42, intentional backpressure). `Topic: class-<cid>`, `TTL: 86400`, urgency normal, `VapidExpiration` default, `ctx` 10s. Bolt snapshot-outside-tx. Queue-full → `push_queue_drop` + `200`. Requeue explicit non-blocking `select`, `Retry-After` cap 5m, ACL/row/`fail_count` re-checked each tick. |
| D12 | Dependency | `webpush-go v1.4.0` + `bluemonday` + `x/net/idna` + `govulncheck` in CI | MIT; pin `go.mod`+`go.sum`. `GenerateVAPIDKeys` = `RawURLEncoding`. `Options{Subscriber bare-email, TTL, Topic, Urgency}`. `VAPID_SUBJECT=mjgavrilov@gmail.com` per §7.1 (bare — library prepends `mailto:`; prefixed form 403s on Apple). No hand-rolled VAPID. `bluemonday.StrictPolicy` for HTML strip. `idna.ToASCII` for endpoint normalization. |
| D13 | Manifest | `id:/` stable + `start_url:/?source=pwa`; split `any` / `maskable` | `Content-Type: application/manifest+json`. Verify-or-regenerate maskable (opaque, 80% safe zone); record in TESTLOG P1. `/` ignores `?source=pwa`. |
| D14 | SW safety | Unit test asserts allowlist + `STATIC_ASSETS` 200 + type | No `caches.add('/')`, no `/class`, no `localStorage`/`document.cookie` in SW, helper present. |
| D15 | Webhook template | Frozen §7.1, no `truncate`, unquoted `escapeJSONString`, `text_html` + `text_orig` + `created_unix` numeric, explicit `Content-Type`, `NOTIFY_QUEUE=200` | D0 proves verbatim; no edits without D0 re-verdict. Never log body/snippet/`user_name` on any path. |
| D16 | Send-time ACL | Present (freshness-gated) → require allowed else suppress; absent array + `max(created,last_ok)<24h` → push from stored; absent `"all"` → skip (uniform); logout deleted → nothing; revoke prunes atomically; reconciler backstops direct-UI removal | Present = `BestSessionForUID != nil` where freshness is `ExpiresAt>now && time.Since(LastVerifiedAt) <= VerifyTTL+15m (UTC)` + version/epoch match (D48). `push_skip_revoked` on suppress. `revoke-class` deletes `"all"` rows + synchronously rewrites sessions `AllowedClassIDs` in same tx via `StripClassAndPrunePush` (never version-bump; healed on next visit). Sweep `fail>10 && ok>30d` + `no session && max(created,last_ok)>24h` (uniform). Ex-student >24h without re-auth gets nothing. `last_ok_at` only on present-session sends. |
| D17 | VAPID keys | Per-sub `key_version` (`fp8`), single-key MVP, `_OLD` reserved, no dual-send, unknown → skip | `fp8 = hex(sha256([]byte(public string)))[:8]`; unsubscribe-before-resubscribe; generator `gate/cmd/genvapid`; fail-fast Load (`_OLD` empty allowed). Unknown `fp8` → `push_skip_unknown_key`, never fallback. `CanonicalOrigin` trimmed at Load. |
| D18 | Resubscribe | `POST /push/resubscribe` UPDATE-by-`old_endpoint`; empty old → `400` (not INSERT) + full endpoint re-validation | `old==""` → `400` (page-load full subscribe with `cids` + CSRF is the healer); foreign `old` → `403`; new `endpoint` re-runs full `IsValidEndpoint`+`IsValidKeys` then `cids` re-check (`403` on fail). SW best-effort (400-tolerant); page primary healer. Origin exact + `null`-reject per D7. |
| D19 | Titles | In-memory `cid → title` cache, `Класс <cid>` fallback | Set at subscribe + login (`handleCallback`) + `resolveHTMLSession` after `EnsureFresh` (only when non-empty and changed; §9 wires all three); send only reads; lost on restart; no Stepik hot-path. Truncate ≤100 runes, plain-text via `html/template`. |
| D20 | Health | Shallow public via IP limiter; deep via Guard + Caddy strip, no injection | Shallow `{ok:true}` via `AllowPushByIP` only. Deep `?deep=1` requires `X-Gate-Auth` Guard; Caddy strips inbound `X-Gate-Auth` and sends no `header_up`, so edge deep is unconditionally 404; ops deep via direct `http://gate:8081/...` with token (bypasses Caddy). Deep = counts only (`Bucket.Stats()`, `len(chan)`), no PII. Deep without token → `404`. Separate from `/healthz`. |
| D21 | Caps | 64KB webhook / 2KB payload / per-sid `AllowPush` 20/min + pre-auth IP 30/s-burst / queue 512 / 4 workers / 30s coalesce | Endpoint `https:` + allowlist + normalization + port `""`/`443` + no userinfo + `len<2048`; `p256dh` 87–88 + `65B/0x04` decode-check, `auth` 22–24 + `16B` decode-check; `cids` explicit non-empty or `"all"` else `400`; `cids ⊆ allowed` else `403`; `comment_id ^[A-Za-z0-9_-]{1,64}$`; `ua` 256, `name` 64, strip `Cc`/`Cf`; `400/413/415 → delete`; `403 → retain`; `429/5xx/timeout → retry [1s,30s,5m]` + `Retry-After` cap 5m, max 3x. Wrong method → `405`. All JSON `Content-Type` via `mime.ParseMediaType`. |
| D22 | Logout silence | Per-device (`sid`) atomic delete; relog silent-heal; user-change forces untap; bell per-device; offline-logout gap documented | `unsubscribe`: missing→`200`, own→delete+`200`, foreign-live→`403` (no delete), orphan→delete+`200`. Logged-out device (`row.sid==sid` delete) gets nothing even if same `uid` live elsewhere. `localStorage` kept on logout. Offline logout leaves rows until online logout/sweep/24h cap (known gap, TESTLOG note, no code). |
| D23 | Push errors | JSON `{error}` with `private,no-store` + `noindex` | `401 auth_required / 403 forbidden / 429 rate_limited+Retry-After / 400 bad_request`; reuse RU rate-limited text in JSON. `/auth/*` parity unchanged in MVP. |
| D24 | Revision wiring | `Server.Revision` from `main.revision` (`var revision="dev"` + ldflags stamp); `New` signature break; prod fail-fast via `!Placeholder` | Precedence: ldflags `-X main.revision=$REV` (from `ARG REV`, built via `--build-arg REV=$(git rev-parse --short=12 HEAD)`) → `debug.ReadBuildInfo vcs.revision[:12]+-dirty` → `"dev"`. Prod = `!cfg.Placeholder` (real Stepik creds, no new env var); `if prod && rev in (dev,unknown,"") → fatal`. `go run` with placeholder allows `dev`. `handleSW` injects via `%q`; bare `register('/sw.js')`, no `?v=` (byte-change drives SW update → new `STATIC_CACHE`, old deleted on activate). |
| D25 | Webhook guard | `VerifyWebhook` (`POST`-only + secret constant-time + empty-secret `404` + RemoteAddr-only `IsLoopback\|\|IsPrivate` peer + extended header-deny + `mime.ParseMediaType` JSON, `404` empty body) | `SplitHostPort` then `TrimSpace` + `ParseIP`, reject parse fail, never read `X-*`/`CF-*`. Deny if `X-Forwarded-Uri/For/Proto/Host`, `Forwarded`, `Via`, `CF-Ray/CF-Connecting-IP/CF-Visitor/CF-IPCountry`, `X-Gate-Auth` present + `r.Method==POST` else `404` + `mime.ParseMediaType==application/json` + fail-closed `404` if secret empty. Never reuse `auth.Guard`; never via Caddy. Predicate `IsLoopback()\|\|IsPrivate()` covers `127/8`, `10/8`, `172.16/12`, `192.168/16`, `::1`; denies link-local/public/unspecified/multicast. |
| D26 | Coalesce UX | Immediate-first + 30s tail-batch, frozen RU summary + plural fn | Single → <5s; burst 5/30s → 2 sends (total N per-sub excl. own, `authorUIDs` unique per comment, summary link = `latestID`), visible 1. Same `tag:cid-<cid>` + `renotify:true`. Summary body: `N + plural(N)` per §4.1. |
| D27 | Log privacy | Hashes only: `uid_hash8`, `endpoint_hash8`, `author_hash8`, `remote_hash8` | Anti-PII hygiene, not anonymity (32-bit prefix brute-forcible for <20 uids — documented). Never endpoint/keys/snippet/body/`user_name`/clear `uid`/headers (`X-Push-Webhook-Secret`, `X-Gate-Auth` never logged; hash-compare only); webhook log `cid,comment_id,author_hash8,sub_count` only. Old clear-`uid` lines migrated later. |
| D28 | Client JS | Separate `static/push.js` + bell HTML | Cached, SW-cached; inline `data-cid/data-uid/data-allowed` only. Keys frozen §6. |
| D29 | Snippet | `Orig` primary else `bluemonday.StrictPolicy()`-stripped `Text`, 120 runes, ≤2KB, plain-text only | Strip `Cc`+`Cf` incl. bidi `U+202A–E`/`U+2066–9`/`U+200E/F`, collapse ws, rune-boundary cut, `html/template` render; empty → `Новый комментарий`. Cut loop until `len(json)≤2048`. No regex alternative. |
| D30 | Test devices | iPhone iOS 26.+ + Android Chrome | Used for P1/P2; not an open question. |
| D31 | Payload URL | Server-constructed `/class/<cid>#remark-<comment_id>` only | `page_url` only for `ExtractCID`. `comment_id` allowlist enforced; Gate `HasPrefix(url,"/class/")`, SW `startsWith("/class/")` else `"/"`. |
| D32 | Deploy order | Secrets first, then gate; `PUSH_WEBHOOK_SECRET` 64-hex enforce | VPS `.env` + compose before gate deploy; `config.Load` rejects non-64-hex; hash-compare debug; `PUSH_WEBHOOK_SECRET` simultaneous `compose up -d --force-recreate gate remark42` window. |
| D33 | State loss | In-memory queue/timers/titles lost on restart accepted | `push_queue_drop` + `push_webhook_gap` make loss visible; comments remain. Sweep shares session ticker; reconciler shares it too. |
| D34 | Endpoint allowlist | Restrict — authenticated SSRF closed at subscribe `400` + normalization + send-time rebind | Allow: `fcm.googleapis.com`, `updates.push.services.mozilla.com`, `web.push.apple.com`, `*.push.apple.com`, `*.notify.windows.com` (Edge). Normalize `ToLower+TrimSuffix(".")+IDNA`, port `""`/`443` only, dot-boundary suffix. Deny `IsLoopback/IsPrivate/IsLinkLocalUnicast/IsUnspecified` after `ParseIP` + resolve-then-check every IP. Reject outside list `400`. Worker re-resolves before send (`push_skip_ssrf_rebind`+delete). Zero UX cost (legit browsers only use known hosts). |
| D35 | Pre-auth IP limiter | `AllowPushByIP(ClientIP)` `Every(1s)` burst 30 before `LoadSession` on all `/push/*` + shallow health | Keeps per-`sid` `Every(3s)` burst 20 after auth. `429` + `Retry-After`. Closes pre-auth flood without touching Stepik limiter. |
| D38 | Unsubscribe ownership | `uid`-scoped delete first; cross-`uid` only if `BestSessionForUID(row.uid)==nil` | Idempotent 200 kept. Prevents member silencing teacher; shared-computer orphans still healed. |
| D39 | Health localhost-only | Strip + no inject; edge deep unconditionally 404 | Caddy `handle /push/health*` with `request_header -X-Gate-Auth` + NO `header_up X-Gate-Auth` (unlike `/healthz`). Shallow rate-limited via `AllowPushByIP`. Deep `?deep=1` via edge unconditionally 404 even with token; ops via direct `gate:8081`. Deep = subs count + queue len only, no PII. |
| D40 | Absent cap | Uniform `max(created_at,last_ok_at)<24h` for stored-array push; sweep `max(...)>24h`; no self-refresh; no teacher exempt | Closes ex-student leak. `last_ok_at` only on present-session sends. Sweep uniform for all uids. Holiday semantics per §7.2. Tests: `absent-no-refresh`, `ex-student-daily-suppressed`. |
| D41 | Static MIME (REV part see D24) | `handleStatic`: `.js → application/javascript; charset=utf-8`, `.html → text/html; charset=utf-8` | Test every `STATIC_ASSETS` entry `200` + correct type. |
| D44 | Endpoint normalization | Lower + trailing-dot trim + IDNA + port + dot-boundary | `ToLower(TrimSuffix(host,"."))`, IDNA ToASCII, `port==""\|\|"443"`, suffix only on `"." + base`. Tests: uppercase/trailing-dot/non-443 `400`. |
| D47 | Reconciler | Hourly `ReconcilePushSubs` sharing session sweeper ticker; Stepik outage never deletes | For each distinct `sid` in `push_subs` with stale session (`LastVerifiedAt > VerifyTTL`): `EnsureFresh`; `left`/`outsider`/`expired` → prune uid in single `Update`; changed `AllowedClassIDs` → `StripClassAndPrunePush` removed `cid`s; transient → keep + `push_reconcile_transient`. Bounds direct-Stepik-UI-removal leak to ~1h. Unit + TESTLOG evidence required. |
| D48 | Freshness predicate | `BestSessionForUID` requires `VerifyTTL+15m` (jitter-aligned upper bound, UTC) | `ExpiresAt>now && time.Since(LastVerifiedAt) <= VerifyTTL+15m && UserVersion==current && GlobalEpoch==current`; pick freshest `LastVerifiedAt`; else `nil`. Returns `(rec, sid)`. Aligns worker with the most permissive `EnsureFresh` fresh decision; fail-closed beyond it. |

## 13. References

Local (ground truth): `plans/0001-stepik-discussion-site.md` (§§3–8, §7.4, §5.2–5.3, §6.1); `plans/0003-teacher-telegram.md`; `AGENTS.md`; `docs/ops-runbook.md` (§§2/8–9); `deploy/Caddyfile`, `deploy/compose.yml`, `deploy/.env.example`, `deploy/caddy-verify.sh`; `gate/main.go`, `gate/handlers/handlers.go`, `gate/handlers/htmlsession.go` + `util.go`, `gate/config/config.go`, `gate/sessions/sessions.go` (`SetSID` Lax, `SchemaVersion "1"`, `SIDMaxAge 2592000`), `gate/auth/auth.go` (`Allowed`, `EnsureFresh`, `verifyJitter −15m…+15m`, `LoadSession`), `gate/admin/admin.go`, `gate/ratelimit/ratelimit.go` (`ClientIP`, `trustedPeer`), `gate/templates/`, `gate/static/*`, `go.mod`/`go.sum`, `.github/workflows/ci.yml`, `TESTLOG.md`.

Upstream code (verified): `remark42/backend/app/notify/webhook.go` (`escapeJSONString` = quoted `json.Marshal`, default template, `NewWebhook` parse), `remark42/backend/app/store/comment.go` (`Comment{ID, ParentID/pid, Text, Orig, User, Locator{SiteID, URL}, Score, Timestamp}`, `Sanitize` bluemonday), `go-pkgz/notify/webhook.go` (headers/timeout), `SherClockHolmes/webpush-go v1.4.0` (`GenerateVAPIDKeys` `RawURLEncoding`, `SendNotificationWithContext`, `Options{Subscriber, TTL, Topic, Urgency}`, pkg.go.dev).

Docs/standards: `remark42.com/docs/configuration/notifications/` + `/parameters/` (`NOTIFY_ADMINS/WEBHOOK_URL/TEMPLATE/HEADERS/TIMEOUT/QUEUE`); RFC 8292 §4.2 (`mailto:`/`https://` `sub`) + RFC 9749 §5; MDN (`pushsubscriptionchange`, installable, manifest `start_url`/`icons`); Apple Web Push docs + WebKit 13878/13966 (16.4+ HS-install, tap-gesture permission, always `showNotification`, Badging); Caddy `handle/handle_path/route/reverse_proxy/header_up` (mutually exclusive, longest-path-first, `header_up` overwrites without `+`).

## 14. Assumptions

Env/edge/device assumptions only; normative caps/keys/limits live in §12.

- `VAPID_SUBJECT=mjgavrilov@gmail.com` (bare — library prepends `mailto:`) — no new contact needed (see D17).
- Cloudflare Bypass rule `(http.host eq "stepik.study67.fyi")` covers new paths; `BYPASS`/`DYNAMIC` recorded in TESTLOG P1/P2; Bot Fight Mode OFF verified in P2 (see D5).
- iPhone iOS 26.+ + Android Chrome test devices (see D30).
- D0 gates D1: no Gate changes without `ID` charset + `Locator.URL` shape + `Orig`/`Unix` + anchor screenshot verdict (see §9 D0).
