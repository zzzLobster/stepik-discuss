# Spike D0 — remark42 JWT shape (Deliverable 0)

Goal: prove stock `remark42 v1.16.4` verifies Gate-minted HS256 JWTs passed as
`X-JWT` + `X-XSRF-TOKEN` headers, before building the full Gate.

## Procedure

```sh
cd spike
docker compose up -d
go run ./minter -secret <REMARK_JWT_SECRET> -base http://127.0.0.1:8080/discuss
docker compose logs remark42
docker compose down   # never down -v on prod; spike volume is disposable
```

The minter mints 4 tokens (`iss=remark42`, `aud=stepik-discuss`,
`exp=now+300s`, `user={id,name,picture}`, no `admin/sub/email`):

1. valid teacher (`stepik_1182644732`)
2. valid student (`stepik_1190530325`)
3. tampered (student token, last char flipped)
4. expired (`exp=now-60s`)

…then calls `GET /api/v1/user` with each (plus a no-header call) and posts
one probe comment per valid identity.

## Expected matrix

| # | Call | Want |
|---|------|------|
| 1 | valid teacher `GET /user?site=` | 200, `stepik_1182644732`, `admin:true` |
| 2 | valid student `GET /user?site=` | 200, `stepik_<id>`, `admin:false` |
| 3 | tampered `GET /user?site=` | 401 |
| 4 | expired `GET /user?site=` | 401 |
| 5 | no-cookie `GET /user?site=` | 401 |
| 6 | teacher + student `POST /comment?site=` | 201, each attributed to own `stepik_<id>` |
| 7 | teacher `GET /admin/blocked?site=` | 200 (functional admin probe) |
| 8 | student `GET /admin/blocked?site=` | 403 |

`?site=` is mandatory on protected calls (remark42 `matchSiteID` → 403
without it; bundled frontend always sends it).

Admin mapping check: teacher `GET /user` must report `admin=true`
(`ADMIN_SHARED_ID=stepik_1182644732` + `user.attrs.admin=true` in
Gate-minted claims, D0 finding); functional proof is row 7 vs 8.

The minter exits 0 only if every row passes, then prints
`SPIKE VERDICT: JWT shape (b) works with stock remark42.`
Any other outcome is a written verdict that stock image can't do it →
fallback (c), Gate posts via remark42 admin API.

## After green

Freeze the digest on the VPS (needs docker there):

```sh
docker buildx imagetools inspect ghcr.io/umputun/remark42:v1.16.4 --format '{{json .Manifest}}' | grep -o '"digest":"[^"]*"'
```

Commit the digest into `deploy/compose.yml`
(`v1.16.4@sha256:980e0e76a6f241cd181f44c5b4d686f0d8cd7f552e11deb3bdcba223b2c3b866`, frozen 2026-09-17) and `plans/0001-stepik-discussion-site.md` §6.
