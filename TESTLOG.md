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
