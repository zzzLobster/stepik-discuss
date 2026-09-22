# TESTLOG — stepik-discuss browser waves

Append one section per wave. Paste `docker compose logs gate` excerpts + `cf-cache-status` evidence.

## Wave 1 — date, tester, browser

| # | Step | Expected | Actual+code | log(uid,cid,auth_path,cf_ray) | Pass |
|---|------|----------|-------------|-------------------------------|------|
| 1 | Teacher login | sees all owned classes | | | |
| 2 | Student login + post/reply | only own class(es), Stepik name/avatar | | | |
| 4 | Leave-class / re-join | 403 left-class on next login or ≤6h, history kept | | | |
| 5 | JWT attribution | `stepik_<id>`, tampered→401, anon API→401 | | | |
| 6 | Cloudflare | `cf-cache-status: BYPASS/DYNAMIC`, Full(strict) | | | |
| 7 | Auth path | B vs B+detail vs A-fallback in logs | | | |

`cf-cache-status` evidence:

```
# paste curl -I https://stepik.study67.fyi/class/<cid> headers here
```

## Wave 2 — date, tester, browser (outsider, post-merge pre-announce)

| # | Step | Expected | Actual+code | log(uid,cid,auth_path,cf_ray) | Pass |
|---|------|----------|-------------|-------------------------------|------|
| 3 | Outsider login | 403 outsider-string, no leak (HTML + /discuss API 401) | | | |

## Refresh renewal — Wave 1 (live gate, 2026-09-20)

Pre-req: deploy with refresh renewal; `docker compose logs gate` shows
`oauth exchange ok has_refresh=true` on each login.

| # | Step | Expected | Actual+code | log evidence | Pass |
|---|------|----------|-------------|--------------|------|
| R1 | Fresh login (student + teacher) | `oauth exchange ok has_refresh=true`; session row holds encrypted refresh | | `oauth exchange ok has_refresh=true` per uid | |
| R2 | Force-expire access (expire `TokenExpiresAt` / wait out ~10h, keep refresh) → open `/class/<cid>` | Silent renew, `200`, no `302` to Stepik, no re-login banner | | `teacher_renew_demand_start` → `teacher_renew_demand_success rotated=true/false` + `reason=student_401` (or `teacher_401`), then `check allow` | |
| R3 | Rotation single-chain (concurrent hits during R2, or two rapid re-checks) | Exactly one redeem; loser logs `teacher_renew_demand_superseded`, no `invalid_grant` | | one `demand_start`, one `demand_success`, ≥0 `demand_superseded`, zero `demand_invalid_grant` | |
| R4 | Teacher restart → wait ~15s | One jittered (5–15s) background check, then 15m ticks; expiring/dead teacher token renewed without teacher re-login | | `teacher_background_alive` or `teacher_background_renew_ok reason=background_expiry|background_probe` within ~15s of boot | |
| R5 | Outsider login (still) | 403 outsider-string, no content; no renew events for that uid | | `check deny … auth_path=deny`, no `teacher_renew_demand_*` for outsider uid | |

## Refresh renewal — Wave 2 (live gate, 2026-09-20)

| # | Step | Expected | Actual+code | log evidence | Pass |
|---|------|----------|-------------|--------------|------|
| R6 | Revoked refresh (revoke app at Stepik / use dead refresh) → open `/class/<cid>` | `302` to login (HTML) / `401 auth_required` (`/auth/check`), re-login banner; stored refresh cleared | | `teacher_renew_demand_invalid_grant` (+ `teacher_background_parked reason=invalid_grant` if teacher record) | |
| R7 | After R6, teacher `/` banner | `"Проверка студентов приостановлена…"` while parked; clears after teacher re-login; parked loop escapes on 6h tick even without restart | | `teacher_background_parked` → (re-login) → `teacher_background_renew_ok` / `teacher_background_alive` | |

## 0002 P1 — PWA shell (2026-09-22, unit + contract)

Gates: `go build ./...`, `go vet ./...`, `go test -count=1 ./...` green; `govulncheck ./...` clean; `deploy/caddy-verify.sh` checks 1–9 green; container `caddy validate`; `docker compose -f deploy/compose.yml config` parses.

| # | Step | Expected | Actual+code | Evidence | Pass |
|---|------|----------|-------------|----------|------|
| P1.1 | Manifest/SW/offline/headers | `/manifest.json 200 application/manifest+json public,max-age=3600` full §5 (id:/, start_url:/?source=pwa, split any/maskable, no any maskable); `/sw.js 200 application/javascript no-store` full §6 (%q REV, named cache, startsWith guard, focus+navigate); `/offline.html 200 text/html`; `/static/push.js 200 application/javascript` | unit `TestManifest_full`, `TestSW_bundle`, `TestSW_staticAssets200`, `TestOffline_public` green | `go test ./gate/handlers/ -run TestManifest_full|TestSW_bundle|TestSW_staticAssets200|TestOffline_public -v` | ✅ |
| P1.2 | Push auth | `/push/vapid-key 401 anon {error:auth_required}`; wrong-method 405; `AllowPushByIP` before session; shallow `/push/health 200 {ok:true}`; deep `?deep=1` without token 404 | unit `TestVapidKey_401anon`, `TestPush_wrongMethod405`, `TestPushHealth_deep` green | `go test ./gate/handlers/ -run TestVapidKey_401anon|TestPush_wrongMethod405|TestPushHealth_deep -v` | ✅ |
| P1.3 | Caddy contracts | `caddy-verify.sh` checks 1–5 (0001) + 6–9 (push: webhook 404 + upstream-never-hit, vapid-key 401/200, offline 200 text/html, deep 404 + forged 404) | to be run on VPS/CI with pinned `caddy:2.11.4-alpine@sha256:de23…` | `deploy/caddy-verify.sh` log (see CI `caddy-contract`) | ⏳ CI |
| P1.4 | Lighthouse + maskable | Mobile ≥90, DevTools Manifest no errors (192+512, standalone), maskable safe-zone verified via maskable.app | manual (iPhone iOS 26.+ + Android Chrome) | TESTLOG P1 device evidence | ⏳ manual |
| P1.5 | Cache headers | `cf-cache-status: BYPASS/DYNAMIC` (never HIT) for `/manifest.json`, `/sw.js`, `/offline.html`, `/push/vapid-key`, `/push/subscribe`, `/static/push.js` | manual edge curl | `curl -I https://stepik.study67.fyi/...` | ✅ live 2026-09-22 (evidence below) |

`cf-cache-status` evidence (VPS live, 2026-09-22 — DYNAMIC, never HIT):

```
manifest.json: cf-cache-status: DYNAMIC
sw.js: cf-cache-status: DYNAMIC
offline.html: cf-cache-status: DYNAMIC
static/push.js: cf-cache-status: DYNAMIC
```

Full edge smoke (same run):

```
manifest:200
sw.js: HTTP/2 200, content-type: application/javascript
offline.html: HTTP/2 200, content-type: text/html; charset=utf-8
vapid-anon:401
webhook-edge:404
push/health shallow: {"ok":true}
deep-edge (even with token):404
```

## 0002 P2 — push end-to-end (webhook enabled, ≥2 test users)

| # | Step | Expected | Actual+code | Evidence | Pass |
|---|------|----------|-------------|----------|------|
| 6 | A subscribes → B posts → A notifies | Single <5s, e2e <30s, title/body/deep-link correct, click focuses/opens `/class/<cid>#remark-<id>` hash-preserved | unit `TestUnsubscribe_ownership`, `TestSubscribe_validation`, `TestResubscribe_matrix` + worker `push_send` | `go test ./gate/handlers/ ./gate/push/ -v` + `docker compose logs gate \| grep push_send` | ✅ unit, ⏳ live |
| 7 | Self/outsider/revoked suppressed | B nothing own; outsider/revoked nothing (`push_skip_revoked`; re-join resumes); revoke immediate (no 6h lag) | unit `TestStripClassAndPrunePush_revokeImmediate`, `TestBestSessionForUID_matrix` | `go test ./gate/sessions/ -v` | ✅ unit, ⏳ live |
| 7b | Logout/device/user-change/ex-student | Device1 logout → nothing, device2 fires; relog heals; shared-computer untap; >24h `max(created,last_ok)` nothing (uniform); orphan 200, foreign-live 403 | unit `TestLogout_prunesPush`, `TestDeleteSessionAndPushSubs_onlyThatSid`, `TestUnsubscribe_ownership` | `go test ./gate/handlers/ ./gate/sessions/ -v` | ✅ unit, ⏳ live |
| 8 | Multi-device | Both fire; unsubscribe one → remaining fires | live (2 browsers) | `push_send` ×2 then ×1 | ⏳ live |
| 9 | Denied/expired | Deny → RU denied-string; `unsubscribe()` → next webhook `410` → prune (`push_prune expired`); `403` retained (`push_403_key_mismatch`) | unit + live devtools | logs | ⏳ live |
| 10 | Burst | 5/30s → ≤2 pushes (1 immediate + 1 summary RU plural), visible 1 (same tag + renotify) | unit `TestPlural`, `TestCoalesceN`, `TestPayload2048` | `go test ./gate/push/ -v` + push-service log count + device-visible single | ✅ unit, ⏳ live |
| 11 | All scope | Teacher `all` every owned incl. future; student `all` only own `allowed` (live expansion; absent `all` → skip) | unit `TestAllMinusOne`, `TestIsValidCids` | `go test ./gate/push/ -v` | ✅ unit, ⏳ live |
| 12 | Resource | `docker stats gate <256M`; `go test -count=1` + `vet` + `govulncheck` green | `go build/vet/test -count=1` green (see below); `docker stats --no-stream` | ✅ stats VPS 2026-09-22 (gate 6.75MiB/256MiB), ⏳ govulncheck |
| 13 | Security spot-checks | Endpoint-SSRF 400; webhook header-deny 404 + GET 404 + charset 200; comment_id drop; Bot OFF; `/push/health?deep=1` edge 404 even with token, direct `gate:8081` 200 counts-only; Retry-After 429; `push_*` samples; revoke→suppress; resubscribe empty-old 400; 410 prune vs 403 retain; reconciler tick | unit `TestEndpoint`, `TestVerifyWebhook`, `TestCommentID`, `TestRetryAfterCap`, `TestSweep`, `TestPushHealth_deep` green | `go test ./gate/push/ ./gate/handlers/ -v` + edge curl + direct `http://gate:8081/push/health?deep=1` with token (from docker/caddy-net) | ✅ unit, ⏳ live edge/direct |

`push/health` deep evidence (D3.2, VPS live 2026-09-22):

```
# edge deep with forged token → 404 (Caddy strips X-Gate-Auth, no header_up — proves strip):
deep-edge:404
# direct gate:8081 with token (bypasses Caddy, from docker/caddy-net) → 200 counts-only, no PII:
{"ok":true,"queue":0,"subs":1}
# subs:1 = one live subscription (test device already tapped bell — subscribe path works at API level)
```

Known gap (documented, no code in MVP): logout requires network; offline logout leaves rows until next online logout/sweep/24h cap.
