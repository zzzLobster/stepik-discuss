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
