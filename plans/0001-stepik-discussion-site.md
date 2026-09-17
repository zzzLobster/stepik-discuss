# 0001 — Discussion site for Stepik classes at `stepik.study67.fyi`

Date: 2026-09-17
Status: REFINED 2026-09-17 — P0 resolved, ready for D0+scaffold
Defaults approved, TESTLOG.md decided, spike verdict placement deferred.
Domain: `study67.fyi` bought (reg.ru, `.fyi` renew 1403 ₽/yr). Site host: **`stepik.study67.fyi`**.
DNS: Cloudflare (you manage it), proxy (orange cloud) **ON** confirmed.
TLS origin email: `mjgavrilov@gmail.com`.
Stack: Gate in **Go 1.27.1** (`github.com/zzzLobster/stepik-discuss`, you maintain),
Ubuntu 24, Docker + docker compose, Caddy `2.11.4-alpine`, you deploy.
Auth: **hybrid C** (user-token primary, teacher-token fallback).
Consent text: **approved** (see §5.2). Backups: deferred. Prod `client_id`: pending.
Secrets: **never in repo, only VPS `.env`** (agreed). VPS IP: to be provided later.

## 1. Goal

Standalone companion discussion site for Stepik teacher's classes. Stepik has
classes but no private in-class discussion. The site allows discussions **only**
for the teacher + his current class students, login **via Stepik OAuth only**.

## 2. Ground truth (verified, do not re-debate)

- Teacher: `https://stepik.org/users/1182644732/profile` → **TEACHER_ID=1182644732**
  (Михаил Гаврилов, verified via `GET /api/users/1182644732`).
- Course: **58852** (from `GET /api/classes/82866` and `/87566` → `course: 58852`).
- Classes (verified live with teacher token):
  - `82866` "2025-26", `students_count: 5`, `owner: 1182644732`
  - `87566` "2026-27", `students_count: 13`, `owner: 1182644732`
  - Discovered extra: `82491` "Супер класс", `students_count: 2`, `owner: 1182644732`
- Decision 2026-09-17: **all my classes, no pinned IDs**. Gate discovers classes
  dynamically via `GET /api/classes?owner_or_assistant=1182644732`
  (paginate `meta.has_next`); new classes appear automatically, deleted/left
  classes disappear on next re-check. `82866/87566/82491` are just examples.
- Scale: 1 course, 2–3 classes, <20 students total. Low load.
- Stepik OAuth: prod app registered by you as **Confidential / Authorization
  code** with exact redirect `https://stepik.study67.fyi/auth/callback`
  (confirmed secure: exact-redirect + server-side code exchange + Gate `state`
  CSRF + `next`, secret never leaves VPS). Endpoints:
  - authorize: `https://stepik.org/oauth2/authorize/`
  - token: `https://stepik.org/oauth2/token/`
  - Token lifetime ~10h (`expires_in: 36000`), scope all-or-nothing `read write`.
- Whoami: `GET /api/stepics/1` with user Bearer → `stepics[0].user = LOGGED_USER_ID`
  (verified: returns `user: 1182644732` for teacher token).
- Membership check (verified with teacher token):
  - `GET /api/classes/82866`, `/87566` → `owner`, `course`, `students_count`.
  - `GET /api/classes?student=<uid>` **works with teacher token for arbitrary
    student IDs** (verified: `?student=1190530325` returned classes
    `82491 + 87566` owned by teacher). `?student=<teacher>` returns `[]`
    (owner is not a student of own class — expected).
  - `GET /api/classes?owner_or_assistant=1182644732` returns full owned list.
    Plain `GET /api/classes` returns `[]` — Gate must always use filtered queries.
  - All list responses paginated (`meta.has_next`); never hardcode page size.
- Access rule agreed: **`owner == 1182644732` is enough, evaluated dynamically**
  (no pinned allowlist; log class IDs on every decision).
  Teacher's class list = `GET /api/classes?owner_or_assistant=1182644732`.
- remark42 (umputun/remark42): single Go binary/Docker, embedded BoltDB,
  ~80MB RAM, 1 URL = 1 thread. Has no whitelist/SSO and Stepik userinfo is
  nested (`{"stepics":[...]}`), so remark42 **alone cannot enforce**
  "only my students". Decision: remark42 as comment store **behind custom
  Auth-Gate** (proxy-gate variant A1), never exposed directly.
- Hosting: remark42 needs always-on + persistent volume → VPS wins.
  VPS: RU region, 2 CPU / 2 GB RAM / 40 GB disk. Fits (<600MB total).
  Render Free / Vercel / Netlify / HF Spaces unsuitable (ephemeral/sleep).

## 3. Architecture (final)

Single domain, three containers behind reverse proxy. Gate owns identity;
remark42 owns comments; proxy owns enforcement. Canonical ports — Gate
`:8081`, remark42 `:8080` (never `:3000`).

```
Browser ──https──▶ Cloudflare (free: DNS + edge TLS + DDoS/CDN, proxy ON)
  ──https──▶ Caddy :443 (origin TLS + forward_auth ONLY on /discuss/*)
  / , /class/*, /auth/*, /manifest.json, /healthz ──▶ Gate :8081 (Go, BoltDB;
                  HTML does Gate-internal check + 302, avoids self-loop,
                  shares allowed() func — never forward_auth on HTML)
  /discuss/* ──▶ remark42 :8080 (internal docker network only,
                 only if Gate check passes; Gate-minted JWT, §6.1)
Gate ──▶ Stepik API (oauth2 + /api/stepics/1 + /api/users + /api/classes)
Gate sessions ──▶ BoltDB file `/data/gate.db` (same engine as remark42, separate
                 file — BoltDB allows one writer per file, so two processes
                 can never share one file)
remark42 comments ──▶ BoltDB file `/srv/var/remark.db`
```

- Single bridge network `app`. Backends expose no `ports:` — only Caddy
  publishes `80/443`. Upstreams: `gate:8081`, `remark42:8080`.
- Volumes (named): `gate-data:/data/gate.db`, `remark-data:/srv/var/remark.db`,
  `caddy-data:/data`.
- Same-domain proxy (not subdomain split) to avoid CORS/third-party-cookie
  issues on iOS PWA and to gate HTML + API with one policy.
- Gate trust to remark42: internal network only + Gate-minted JWT verified by
  remark42 via shared secret (decided §6.1 — most secure option). Caddy strips
  any client-sent identity headers. Firewall denies direct `:8080`.
  (Plain `X-Auth-*` header trust alone rejected: headers are spoofable if the
  backend is ever reachable directly; JWT is cryptographically verified.)
- `robots.txt: Disallow: /` + `X-Robots-Tag: noindex` on all responses.

## 4. URL map (MVP frozen)

| URL | Auth | Content |
|-----|------|---------|
| `GET /` | public (shows login state) | RU landing: cards for own classes only (dynamic list, not pinned). No session → "Войти через Stepik". Student sees only own classes; teacher sees all owned. |
| `GET /class/<cid>` (e.g. `/class/82866`, `/class/87566`; any owned class works, including future ones) | `sid.valid && (cid in session.allowed \|\| is_teacher)` else 302 login / 403 | RU shell: class title, link to `https://stepik.org/class/<cid>`, remark42 embed with `site=stepik-discuss`, `url=https://stepik.study67.fyi/class/<cid>`. |
| `GET /auth/login?next=…`, `GET /auth/callback?code=…`, `POST /auth/logout`, `GET /auth/check` (Caddy-internal), `GET /auth/me` | `check` internal only; `me` needs valid sid | OAuth start/callback/logout. `check` is Caddy's "ask Gate first" hook (plain words: before serving any private page, Caddy asks Gate "is this visitor allowed here?"; Gate answers yes/no — header names are internal detail, no action needed from you). `check` never 302: `200`+JWT allow, `401 {auth_required}`, `403 {forbidden}` (outsider/left/unknown_thread/teacher_only), `404` on bad `X-Gate-Auth`. |
| `GET /discuss/*` | same `forward_auth` as HTML; `cid` extracted from `?url=` / `Referer`; deny if page class not in `allowed` | remark42 JS + API under the renamed route (was `/remark42/*`, renamed per 2026-09-17). Never linked directly. `cid` extract: parse `X-Forwarded-Uri` `?url=` first then `Referer` fallback, require `https://stepik.study67.fyi/class/<cid>` with `cid=^[0-9]{1,10}$`, one decode reject `%25` double-encode, trim `/`, exact host. Missing/unparseable → `403 unknown_thread` fail-closed + warn. |
| `POST /auth/admin/logout-all` | teacher-only, Origin-checked | Bumps `meta.global_epoch` (logout-all). `revoke-user` bumps `user_versions[uid]`; `revoke-class` strips `cid`. |
| `GET /manifest.json`, `GET /sw.js` (stub), `GET /healthz`, `GET /robots.txt` | public | PWA hook (deferred push), health for monitoring. |
| Phase 2 only: `GET /class/<cid>/lesson/<lid>` | same per-class rule | Auto-generated shell: lesson title + link to Stepik + own remark thread. No lesson body copy. |

No `/admin` in MVP — moderation via remark42 admin UI at `/discuss/admin/`
(gated, teacher-only: `/discuss/admin/*` requires `is_teacher` else
`403 teacher_only`). Phase 2 `lesson/<lid>` checks parent `cid` only.

Proxy hardening (normative): `forward_auth` ONLY on `/discuss/*`. Caddy
sends `X-Gate-Auth` (Caddy-only token `CADDY_GATE_TOKEN`, 16B hex) + Docker-
subnet guard; Gate returns `404` on bad `X-Gate-Auth`. Caddy strips inbound
`X-JWT,X-XSRF-TOKEN,Remote-User,X-Auth-*`. `ufw` allow `22,80,443` only.

## 5. Auth + access policy

1. `GET /auth/login?next=/class/87566` → validate `next` (after one decode
   must equal `/` or `/class/<digits>[/]` else `400 "Некорректная ссылка для
   возврата."`; never send `next` to Stepik, bind to `state`) → 302 to
   `https://stepik.org/oauth2/authorize?client_id=<PROD_ID>&redirect_uri=https://stepik.study67.fyi/auth/callback&response_type=code&state=<state>`.
   `state`: 32B CSPRNG base64url, server record
   `{hash,next,binder,created,ip_hash}` TTL 10m single-use, replay → 403.
   Binder cookie `__Host-oa` 16B `HttpOnly Secure SameSite=Lax Path=/auth
   Max-Age=600`. PKCE skipped.
2. Callback: `code → POST /oauth2/token/` → `access_token` (~10h). Mismatch /
   missing `code` / `error=access_denied` → `403 "Вход через Stepik отменён
   или не удался. Попробуйте ещё раз."` Then:
   - `GET /api/stepics/1` → `LOGGED_ID`
   - `GET /api/users/<LOGGED_ID>` → `first_name, last_name, avatar` (real
     Stepik name only, fallback to `id`)
   - If `LOGGED_ID == 1182644732` → `is_teacher=true`; `allowed` = fresh list
     from `GET /api/classes?owner_or_assistant=1182644732` (dynamic, all owned).
     Auto-capture teacher token on every teacher login (overwrite
     `teacher_token/current` — see §5.1; no `STEPIK_TEACHER_TOKEN` in `.env`).
   - Else hybrid C per §5.1 order B → B+detail → A-fallback → stale/503.
     Grant `cid` iff `class.owner == 1182644732`. Log
     `(uid, cid, owner, decision, auth_path=B|B+detail|A-fallback|A-expired|transient|deny)`.
3. Mint opaque `sid` (32B random hex), cookie `__Host-sid, HttpOnly, Secure,
   SameSite=Lax, Path=/, Max-Age=2592000`. Server BoltDB at `/data/gate.db`
   (dir `0700`, file `0600`) buckets:
   `sessions[sid_hex] → SessionRecord{stepik_user_id,fio,avatar_url,
   allowed_class_ids[],is_teacher,created_at,last_verified_at,next_retry_at,
   expires_at(now+30d),last_seen_at,user_version,global_epoch,
   token_ciphertext AES-256-GCM key GATE_TOKEN_KEY 32B from .env only,
   token_nonce,token_obtained_at,token_expires_at(obtained+expires_in-300s)}`,
   `user_versions[uid]`, `teacher_token[current] →
   {ciphertext,nonce,obtained_at,expires_at,expires_in,
   owner_uid=1182644732}`, `meta{global_epoch,schema_version}`.
   Stepik access tokens never reach browser (encrypted at rest). Sliding:
   re-issue `Set-Cookie` only if `now > expires_at-29d` or re-verify
   succeeded. Sweeper every 1h deletes `expires_at < now-7d`.
4. Re-check: full check on every login; lazy re-check if
   `now - last_verified_at > 6h` (`GATE_VERIFY_TTL=6h`, verify jitter ±15m,
   skew 300s) on Gate-internal HTML check / `forward_auth`. `GATE_RETRY_AFTER
   =15m+jitter(fnv(sid)%5m)`, `GATE_MAX_STALE=48h`. FRESH: serve cache, no
   Stepik call. DUE: try hybrid (§5.1). Transient `429/5xx`/timeout →
   `next_retry=now+15m`, serve stale if `≤48h` + `X-Gate-Stale:1` (stripped
   at edge), else `503` transient RU. Definitive `200` with `cid ∉ list` or
   `owner != 1182644732` → shrink `allowed` immediately → `403` left-class
   (history kept). Satisfies "revoke immediately, re-check each login".
5. Revoke semantics: revoked = `cid ∉ allowed` → `403` on HTML **and**
   remark42 API (`Нет доступа. Вы больше не состоите в классе.`). **History
   stays** — remark42 rows untouched; re-join restores read/write on next login.
   `logout-all`: `POST /auth/admin/logout-all` (teacher, Origin-checked)
   bumps `meta.global_epoch`; `revoke-user` bumps `user_versions[uid]`;
   `revoke-class` strips `cid`.
6. Isolation: student in N classes gets `allowed=[…]` (dynamic) → sees N
   cards on `/`, but each page/API call checks one `cid`; threads never merge
   (`page_url` differs).
7. `POST /auth/logout` only (`405` else), `Origin` must equal
   `https://stepik.study67.fyi` else `403`, clears row + cookie + `302 /`.
   Form: "Выйти из аккаунта? [Да, выйти]". `GET /auth/me` →
   `{id,fio,avatar,allowed,is_teacher}` only, `Cache-Control: no-store`,
   never tokens.

### 5.1 Teacher-token bootstrap + Hybrid C (DECIDED — normative order)

Stepik access tokens live ~10h, no documented refresh token. No
`STEPIK_TEACHER_TOKEN` in `.env`. Auto-capture on every teacher login
(`uid == 1182644732`): overwrite `teacher_token/current`
`{ciphertext,nonce,obtained_at,expires_at,expires_in,
owner_uid=1182644732}` (token encrypted with `GATE_TOKEN_KEY`).

`valid = exists && now < expires_at-60s`.

Order per DUE (never A before B):

- **B** — user-token self-check: `GET /api/classes?student=<self>` with the
  student's own token → own memberships.
- **B+detail** — only if owner missing or new `cid`: `GET
  /api/classes/<id>` to verify `owner == 1182644732`.
- **A-fallback** — server-held teacher token
  `GET /api/classes?student=<uid>` (verified working for arbitrary student
  IDs). Downside: expires ~10h → needs teacher re-login.
- **stale/503** — transient `429/5xx`/timeout → serve stale in grace
  (`≤48h` + `X-Gate-Stale:1`) else `503` transient RU
  `"Не удалось проверить состав класса. Попробуйте позже."`

Expired teacher token during student re-check: never `403` the student —
serve stale in grace + warn `teacher_token_valid=false`; beyond grace `503`
transient RU. Teacher banner on `/` when `!valid`: `"Проверка студентов
приостановлена: токен преподавателя истёк. Войдите через Stepik ещё раз,
чтобы возобновить её."`

Log every decision `(uid,cid,owner,decision,
auth_path=B|B+detail|A-fallback|A-expired|transient|deny)`. Pure user-token
(B) is primary (zero secret rotation); teacher token is fallback only.
Detail `403`-anon readability confirmed path: member readability verified
in browser wave (see §8 item 7 — which auth path fired).

### 5.2 Consent notice (APPROVED 2026-09-17)

Login page (RU, mandatory, above the "Войти через Stepik" button):

> Входя через Stepik, вы соглашаетесь, что ваше имя и аватар Stepik будут
> видны участникам вашего класса. Обсуждения закрыты, не индексируются и
> доступны только вашему классу и преподавателю.

Stored PII: only `stepik user_id + first/last name + avatar URL`. Shown only
to members of the same class + teacher. No export.

### 5.3 Defaults (APPROVED 2026-09-17 — frozen) + P0 limits/edge (normative)

Rate limits (Gate `x/time/rate` in-memory, MVP values, tunable via env):
- Login start `/auth/login`: 10 req/min per IP, burst 5.
- Callback `/auth/callback`: 20 req/min per IP, burst 10.
- Proxied `/discuss/*` API: 100 req/min per session, burst 20 → `429`
  `"Слишком много запросов. Подождите минуту и попробуйте снова."` +
  `Retry-After`.
- IP = `CF-Connecting-IP` → leftmost `XFF` → socket;
  `trusted_proxies` = Cloudflare ranges only.
- Outbound Stepik API client: max 4 req/s shared, burst 8, honor
  `Retry-After` cap 30s, `500ms×2+jitter250ms` max 4 attempts.
  (We make ~2 calls per login + 1 per 6h re-check; well under limits.)

Log format (structured JSON to stdout → `docker compose logs`):
- Fields: `ts, level, msg, uid (stepik id, numbers only), cid, auth_path
  (B|B+detail|A-fallback|A-expired|transient|deny), latency_ms, cf_ray (if present)`.
- Levels: `info` (login allow/deny), `warn` (Stepik 429/5xx, JWT fail),
  `error` (5xx, BoltDB errors). No message bodies, no tokens, no secrets.
- Retention: Docker default json-file `max-size=10m max-file=5` (local only);
  no external log shipper in MVP.

RU copy (frozen unless you amend):
- Login button: `Войти через Stepik`.
- Consent: §5.2 text (approved).
- Outsider 403: `Доступ запрещён. Этот сайт только для учеников моих классов
  на Stepik. Если вы мой ученик — напишите мне, проверим состав класса.`
- Transient failure: `Не удалось проверить состав класса. Попробуйте позже.`
- Left-class 403: `Нет доступа. Вы больше не состоите в классе.` (history kept;
  re-join restores access).
- New RU (P0 frozen): expired session `"Сессия истекла. Войдите через Stepik
  снова."`, rate-limited `"Слишком много запросов. Подождите минуту и
  попробуйте снова."`, next-invalid `"Некорректная ссылка для возврата."`,
  OAuth-deny `"Вход через Stepik отменён или не удался. Попробуйте ещё раз."`,
  teacher-token banner (see §5.1).

Resource limits (compose, normative): `gate 256M/128M`, `remark42 512M/256M`,
`caddy 128M/64M`. Deps only: `bbolt`, `golang-jwt/v5`, `x/oauth2`,
`x/time/rate` — no other deps without approval.

Edge/security headers (all private responses):
`Cache-Control: private,no-store`, `HSTS 63072000 preload`, `nosniff`,
`DENY`, `strict-origin`, `noindex` (`robots.txt: Disallow: /` +
`X-Robots-Tag: noindex`).

Health: `GET /healthz → {ok:true}` shallow; `?deep=1` Caddy-only checks
BoltDB + DNS.

PWA: `manifest {standalone, scope:/, start_url:/}` + `sw.js` passthrough,
never caching private.

Boot with `STEPIK_CLIENT_ID=placeholder` → `/auth/login` `503` `"Вход
временно недоступен. Попробуйте позже."`, rest works.

## 6. remark42 config (this scale)

- Image (pinned): `ghcr.io/umputun/remark42:v1.16.4@sha256:980e0e76a6f241cd181f44c5b4d686f0d8cd7f552e11deb3bdcba223b2c3b866`
  (resolve via `imagetools inspect` at spike, commit digest, never `:latest`).
  Caddy `2.11.4-alpine`, Go `1.27.1`.
- Single secret: `.env REMARK_JWT_SECRET=<64hex>` → `remark42.SECRET=
  ${REMARK_JWT_SECRET}` + `gate.REMARK_JWT_SECRET` same value.
- `SITE=stepik-discuss` (single; threads distinguished by `page_url`).
  `REMARK_URL=https://stepik.study67.fyi/discuss`.
- Public route **`/discuss/*`** (renamed from `/remark42/*` per 2026-09-17);
  Embed snippet uses `host: "https://stepik.study67.fyi/discuss"`.
- `AUTH_ANON=false`, no providers (no google/github/telegram) — only
  Gate-minted identity.
- Admin: `ADMIN_SHARED_ID=stepik_1182644732`, `AUTH_TTL_JWT=5m`.
  No co-teachers. No scope-explainer note on login page (decided: consent +
  button only).
- Custom provider placeholder `stepik` (D0-mandatory, see §6.1 verdict):
  `AUTH_CUSTOM_NAME=stepik`, dummy `CID/CSEC`
  (`spike-placeholder-never-completes`, non-secrets), real Stepik
  auth/token/info URLs. Login via remark42 can never complete (dummy
  client); the provider exists only to satisfy the allowlist.
- `AVATAR_PROXY=true`; avatars hotlinked from Stepik CDN via Gate-cached URL.
- `MAX_COMMENT_SIZE=2000`, `EDIT_TIME=10m`, locale `ru`.
- Storage: same engine as Gate (BoltDB), separate files/volumes
  (`remark.db` vs `gate.db`; BoltDB = one writer per file, so sharing one
  file between two processes is impossible — "same storage if possible" is
  satisfied as same engine + same backup procedure). Backup deferred.

### 6.1 Attribution (DECIDED 2026-09-17: most secure option, SPIKE-FIRST)

Chosen: **(b) Gate-minted JWT verified by remark42 via shared secret**,
defense in depth with proxy-gate (Caddy `forward_auth` ONLY on `/discuss/*` +
internal-only remark42 port + header stripping).

JWT (normative, HS256): claims `{iss:remark42,aud:stepik-discuss,
exp:now+300,iat:now,jti:16B rand,user:{id:stepik_<id>,
name:First Last|Stepik <id>,picture:avatar|"",attrs:{admin:true}|∅}}`.
Teacher sessions mint `attrs:{admin:true}` (D0: required for `AdminOnly` +
`/user` admin flag); students mint no `attrs`. Never `admin:true/sub/email`
as top-level claims.

Transport (normative): mint fresh on every `GET /auth/check → 200`. Return
`200 {"ok":true}` + `X-JWT` + `X-XSRF-TOKEN:<jti>`. Caddy `copy_headers
X-JWT X-XSRF-TOKEN` + `header_up` to remark42. Browser never sees JWT.
Rotation: new `.env` + `up -d` both, old dies ≤5m (matches `AUTH_TTL_JWT`).

**Deliverable 0 — JWT shape spike (separate, BEFORE full Gate):**
minimal `compose.yml` (caddy 2.11.4-alpine + stock remark42 v1.16.4
`DEBUG=true`) + tiny Go helper (minter, not the full Gate) that mints 4
tokens: valid teacher / valid student / tampered / expired, and calls
remark42. Verdict placement **deferred to spike time** (decided 2026-09-17):
default = append short verdict to §6.1; split to `plans/0002-jwt-spike.md`
only if it grows beyond a page. Questions answered: which env/claim shape
does stock remark42 verify, exact 401/200 matrix, admin mapping for
`stepik_1182644732`. Exit criteria: teacher+student posts attributed
correctly, tampered JWT → 401, no-cookie → 401 — or written verdict that
stock image can't do it → fallback (c). Freeze digest
`sha256:980e0e76a6f241cd181f44c5b4d686f0d8cd7f552e11deb3bdcba223b2c3b866` here after `imagetools inspect`.

**D0 VERDICT 2026-09-17 (local docker, `spike/`): GREEN — (b) works with
stock `v1.16.4@sha256:980e…`, no fallback needed.** Matrix:
teacher/student `GET /user?site=` → `200` attributed (`stepik_1182644732`
`admin:true` / `stepik_1190530325` `admin:false`); tampered/expired/
no-cookie → `401`; teacher+student `POST /comment?site=` → `201` each
attributed; teacher `GET /admin/blocked?site=` → `200`, student → `403`.
Four integration findings (all implemented in `spike/`, `deploy/`, `gate/`):
(a) proxy must `strip_prefix /discuss` (`handle_path`) — remark42 serves
API+web at root, prefixed `/user` → `404`; (b) custom `stepik` placeholder
provider mandatory — zero providers ⇒ every JWT rejected
(`provider is not allowed`), dummy `cid/csec` so remark42-login never
completes; (c) `?site=` mandatory on protected calls (`matchSiteID` → `403`
without); (d) teacher claims need `user.attrs.admin=true` (`AdminOnly`
checks claims, not `ADMIN_SHARED_ID` alone). Non-blocking note: remark42
`failed to set title, domain not allowed` WARN in spike (title extractor
allowlist) — harmless, Gate renders its own shells.

- Why most secure: identity is cryptographically verified (HMAC with
  `REMARK_JWT_SECRET` from VPS `.env`), not a spoofable plain header; even if
  someone reached remark42 directly, forged requests fail verification.
  Rejected: (a) anon+proxy (all users share backend identity — impersonation
  and false attribution); plain unsigned `X-Auth-*` trust (spoofable).
- Fallback if JWT shape spike fails on drafted compose: (c) Gate posts via
  remark42 admin API on users' behalf (heavier, but attribution stays
  server-side and secure). Decision on fallback after spike, before MVP merge.
- Spike (on drafted compose, teacher+student accounts): teacher posts +
  student posts → each attributed to own `stepik_<id>`; tampered JWT → 401;
  no-cookie API → 401.

## 7. Deployment

### 7.1 DNS + TLS (Cloudflare ON confirmed, `study67.fyi`)

Decision 2026-09-17: DNS managed by **Cloudflare** (you do the changes),
proxy (orange cloud) **ON**. Origin TLS email: `mjgavrilov@gmail.com`.
Cloudflare proxy (orange cloud, free plan) = edge TLS + DDoS/CDN protection.
Origin (Caddy on VPS) still needs its own TLS cert — Cloudflare does not
replace it; it terminates client TLS at edge and re-encrypts to origin.
Use **SSL mode "Full (strict)"**, never "Flexible" (Flexible sends HTTP to
origin and breaks `Secure` cookies + OAuth redirect).

Step-by-step (Cloudflare dashboard → domain `study67.fyi` → DNS → Records):

1. Add record: Type `A`, Name `stepik`, IPv4 address `<VPS_IP>`,
   Proxy status **Proxied** (orange cloud ON), TTL Auto. Result:
   `stepik.study67.fyi → <VPS_IP>` (clients see Cloudflare IPs).
2. SSL/TLS → Overview → Encryption mode → **Full (strict)**.
3. SSL/TLS → Edge Certificates → Always Use HTTPS **ON**,
   Automatic HTTPS Rewrites **ON** (optional but harmless).
4. Wait for DNS propagation: `dig +short stepik.study67.fyi` returns
   Cloudflare IPs; `https://stepik.study67.fyi` loads edge cert.
5. Caddy on VPS keeps origin TLS via Let's Encrypt
   (`stepik.study67.fyi { reverse_proxy …; tls mjgavrilov@gmail.com }`,
   HTTP-01 auto-renew). Cloudflare must be able to reach origin on
   443; keep `ufw allow 80,443/tcp` (plus `22`). Alternatively Cloudflare Origin
   Certificate on Caddy is possible, but Let's Encrypt default is simpler
   and you maintain it.
6. Cloudflare caching — WHY + HOW (you asked to explain; action required).
   WHY: Cloudflare caches by URL by default for static assets, and with
   "Cache Everything" it could cache `/class/*` HTML — then student A could
   be served student B's page from edge, leaking closed discussions. Our
   pages carry `Cookie: __Host-sid` + per-user `allowed` lists, so they must
   NEVER be cached at edge. remark42 API (`/discuss/*`) likewise.
   HOW (free plan, 5 min): Cloudflare dashboard → `study67.fyi` → Caching →
   Cache Rules → Create rule: name `bypass-private`; if Hostname equals
   `stepik.study67.fyi` → Bypass cache. (Tighter alternative: two rules for
   paths `/class/*`, `/auth/*`, `/discuss/*` — same effect; single hostname
   rule is simpler and safe since the whole host is private.) Verify:
   logged-in page returns `cf-cache-status: BYPASS` (or `DYNAMIC`). Please
   confirm once set.

Direct-origin test (bypass Cloudflare) via `/etc/hosts` entry
`stepik.study67.fyi → <VPS_IP>` before switching DNS, or `tls internal`
staging only. Register prod Stepik OAuth app only after public HTTPS works:
redirect URI `https://stepik.study67.fyi/auth/callback`.

### 7.2 Compose (Ubuntu 24, Docker + docker compose, you deploy)

Pinned: Go `1.27.1` (builder + `go.mod`), Caddy `2.11.4-alpine`, remark42
`v1.16.4@sha256:980e0e76a6f241cd181f44c5b4d686f0d8cd7f552e11deb3bdcba223b2c3b866`.
Repo layout (this repo): `gate/` (Go module
`github.com/zzzLobster/stepik-discuss`), `deploy/Caddyfile`,
`deploy/compose.yml`, `deploy/.env.example` (keys only, no values).
Secrets live **only in VPS `deploy/.env`, never committed** (agreed absolute
rule). `client_id`/`client_secret` arrive via runtime env — does not block
code start. Boot with `STEPIK_CLIENT_ID=placeholder` → `/auth/login` `503`,
rest works.

Env table (canonical; see `deploy/.env.example`):

| Key | Value / note |
|-----|--------------|
| `STEPIK_CLIENT_ID` | `placeholder` until prod app registered; runtime env |
| `STEPIK_CLIENT_SECRET` | VPS `.env` only |
| `STEPIK_REDIRECT_URL` | `https://stepik.study67.fyi/auth/callback` |
| `TEACHER_ID` | `1182644732` |
| `GATE_TOKEN_KEY` | 32B from `.env` only (`openssl rand -hex 32`), AES-256-GCM |
| `REMARK_JWT_SECRET` | `<64hex>` (`openssl rand -hex 32`); maps to `remark42.SECRET` + `gate.REMARK_JWT_SECRET` same value |
| `CADDY_GATE_TOKEN` | 16B hex (`openssl rand -hex 16`), Caddy-only |
| `GATE_VERIFY_TTL` | `6h` |
| `GATE_RETRY_AFTER` | `15m` + jitter |
| `GATE_MAX_STALE` | `48h` |
| `SITE` / `REMARK_URL` | `stepik-discuss` / `https://stepik.study67.fyi/discuss` |

- `caddy`: `caddy:2.11.4-alpine`, volumes `caddy-data:/data`, `Caddyfile:ro`.
- `gate`: **Go 1.27.1** multi-stage image you maintain (static binary),
  volume `gate-data:/data` (BoltDB `/data/gate.db` — same engine as remark42,
  separate file/volume; see §3). `GATE_TOKEN_KEY` required at boot.
- `remark42`: `ghcr.io/umputun/remark42:v1.16.4@sha256:980e0e76a6f241cd181f44c5b4d686f0d8cd7f552e11deb3bdcba223b2c3b866`,
  volume `remark-data:/srv/var` (BoltDB `remark.db`).
- One docker bridge network `app`; no `ports:` on backends; only Caddy
  `80/443`. `docker compose up -d`.
- D0 spike steps (normative): compose `caddy+remark42 v1.16.4 DEBUG=true` +
  minter helper minting 4 tokens (valid teacher / valid student / tampered /
  expired); matrix expectations `200/200/401/401`; admin mapping check
  `stepik_1182644732`; freeze digest via `imagetools inspect`.
- Backups: **deferred to later** per 2026-09-17 (plan later).
  Minimum safety net until then: named volumes; do not
  `docker compose down -v`. Runbook to be designed later.
- VPS IP: **provided later** by you at DNS time; compose/Caddy contain no
  hardcoded IP (only `stepik.study67.fyi`).

### 7.3 Phase 2 auto-import (not MVP, design frozen)

Importer cron (6h + manual teacher-only reimport):
`GET /api/classes/<cid>` → `course` (expect 58852) →
`GET /api/sections?course=` (paginate) → units →
`GET /api/lessons/<lid>` → `{title}`. Gate stores
`lesson_index {cid, lid, title, stepik_url, position}` in its BoltDB and
renders index + `/class/<cid>/lesson/<lid>` shells. remark42 thread
auto-created on first comment. Never store lesson body. Deleted lesson →
"Урок скрыт на Stepik", old comments remain.

### 7.4 PWA / push (deferred, hook now)

Gate serves RU `manifest.json` (`display:standalone`, `scope:/`,
`start_url:/`) + stub `sw.js` (passthrough, never caching private, must not
break remark42 caching). Future: `VAPID_*` env +
`POST /push/subscribe` + remark42 new-comment webhook → WebPush. No MVP cost.

## 8. Browser test plan (D0 spike + Wave 1 green gates merge)

D0 spike (on drafted compose, before Gate): caddy + remark42 v1.16.4
`DEBUG=true` + minter helper (4 tokens: valid teacher / valid student /
tampered / expired); expectations `200/200/401/401`; admin mapping check
`stepik_1182644732`; freeze digest.

Gate implements hybrid C with path logging
(`auth_path=B|B+detail|A-fallback|A-expired|transient|deny` per login), and
we verify end-to-end in browser on the drafted site. Merge on Wave 1 green
(§8 items 1,2,4,5,6,7); Wave 2 outsider may land post-merge but before
announce.

**Who drives (you asked to explain):** you do — recommended option (a):
you hold teacher + student accounts (wave 1) and later the outsider account
(wave 2), so no credential sharing is needed. I never see passwords/tokens.
You click through the checklist below in Chrome/Firefox (+ one mobile Safari
pass for PWA), then paste results + relevant `docker compose logs gate`
excerpts. Results live in **`TESTLOG.md`** in this repo (decided 2026-09-17;
GitHub issues only if/when the module repo gains tracking). Append one
section per test wave (`## Wave 1 — teacher+student`, `## Wave 2 — outsider`).
I triage failures from the log.

Matrix (normative):

1. Teacher login → sees all owned classes (dynamic list).
2. Student login (1–2 real students) → sees only own class(es); post + reply
   works; name/avatar = Stepik.
3. Outsider (non-student Stepik user, Wave 2) → login succeeds at Stepik, Gate
   shows 403 outsider-string `Доступ запрещён. Этот сайт только для учеников
   моих классов на Stepik. Если вы мой ученик — напишите мне, проверим состав
   класса.`; no content leaked (check HTML + direct `/discuss/api` without
   cookie → 401).
4. Leave-class / ex / deleted → next login (or ≤6h lazy re-check) revokes
   read/write, `403` left-class `Нет доступа. Вы больше не состоите в
   классе.`, history stays; re-join restores. New class appears on next login
   or ≤6h. Assistant-only class (`owner != 1182644732` even if in
   `owner_or_assistant` list) → 403 even if member.
5. remark42 JWT attribution (§6.1): comments attributed to `stepik_<id>`;
   teacher has admin (delete/pin/block); tampered JWT → 401; anon API
   without cookie → 401. Anon HTML → 302 login; anon API → 401;
   non-numeric cid → 404 HTML / 403 API.
6. Cloudflare: `cf-cache-status: BYPASS/DYNAMIC` on `/class/*`; Full (strict)
   green lock; Always Use HTTPS on. Record `cf-cache-status` evidence in
   TESTLOG.
7. Check Gate logs which auth path fired (B vs B+detail vs A-fallback) →
   confirms whether student-token detail reads work; keep or simplify
   accordingly.

Session timings frozen: cookie 30d sliding, lazy Stepik re-check 6h
(`GATE_VERIFY_TTL=6h`).

New RU strings under test: expired `"Сессия истекла. Войдите через Stepik
снова."`, rate-limited `"Слишком много запросов. Подождите минуту и
попробуйте снова."`, next-invalid `"Некорректная ссылка для возврата."`,
OAuth-deny `"Вход через Stepik отменён или не удался. Попробуйте ещё раз."`

## 9. Build phases

- **Deliverable 0 — JWT spike (first, standalone):** minimal compose
  (caddy 2.11.4-alpine + remark42 v1.16.4 `DEBUG=true`) + minter helper
  (4 tokens: valid teacher / valid student / tampered / expired) + written
  verdict (b works with exact env/claims, or fallback c) + digest freeze.
  Gates Phase 1.
- **Phase 0 (0.5d):** prod OAuth app (you) + DNS `stepik` A-record (you) +
  cache-bypass rule (you: hostname Bypass for `stepik.study67.fyi`, verify
  `cf-cache-status: BYPASS/DYNAMIC`) + `.env` on VPS (secrets only there).
- **Phase 1 MVP:** Go Gate (`/`, `/class/:cid`, `/auth/*`, `/healthz`,
  RU templates incl. §5.2 consent, no scope note) + Caddyfile 2.11.4
  (`forward_auth` ONLY on `/discuss/*`, strip identity headers, `/discuss/`
  proxy, `copy_headers X-JWT X-XSRF-TOKEN`) + `compose.yml` +
  `.env.example` (keys only). No backup runbook (deferred). Acceptance:
  §8 Wave 1 green (items 1,2,4,5,6,7); outsider Wave 2 post-merge
  pre-announce.
- **Phase 2:** lesson importer + `/class/:cid/lesson/:lid`, backup design,
  optional WebPush.

## 10. Risks (this setup)

- No instant webhook on leave → up to 6h read window; accepted for <20 users;
  teacher can force logout-all (`POST /auth/admin/logout-all` bumps
  `global_epoch`).
- Stepik `?student=` / schema drift → Gate logs raw responses, fail-closed
  403 + retry.
- Identity spoofing if remark42 exposed → mitigated by design: internal-only
  port + Caddy strips client identity headers + JWT verification (§6.1);
  firewall denies direct `:8080`. Anon mode rejected.
- Single VPS SPOF → backups deferred (your call); until designed, no `down -v`.
- 152-FZ/minors → store only `uid+fio+avatar_url`, RU VPS, closed registration,
  no export. Login page shows a short notice (see §11 Q8) — not legal advice.
- `read write` scope: Stepik offers no finer scope; decided **no explainer note**
  on login page (consent + button only). Risk accepted: a student may ask why
  "read write" — answer: we only read class list + profile.

## 11. P0 resolved (2026-09-17 refinement — normative) + remaining non-blockers

P0 resolved, now normative in §§3–8 (supersedes round-7 "nothing blocks" /
FINAL claim):

- Q1 auth storage: `/data/gate.db` (`0700` dir, `0600` file), buckets
  `sessions/user_versions/teacher_token/meta`, `SessionRecord` + AES-256-GCM
  `GATE_TOKEN_KEY`, sliding `__Host-sid` 30d, sweeper 1h (see §5.3).
- Q2 teacher bootstrap + Hybrid C: no `STEPIK_TEACHER_TOKEN` in `.env`,
  auto-capture on teacher login, order B → B+detail → A-fallback →
  stale/503, never A before B, banner + logging (see §5.1).
- Q8 revocation: `GATE_VERIFY_TTL=6h` (canonical — no stale TTL remains),
  `GATE_RETRY_AFTER=15m+jitter`, `GATE_MAX_STALE=48h`, stale + `X-Gate-Stale:1`
  else 503, definitive shrink + history kept (see §5).
- Q3 remark42 pin: `v1.16.4@sha256:980e0e76a6f241cd181f44c5b4d686f0d8cd7f552e11deb3bdcba223b2c3b866`, single secret
  `REMARK_JWT_SECRET`, `SITE/REMARK_URL/AUTH_ANON/ADMIN_SHARED_ID/
  AUTH_TTL_JWT=5m/AVATAR_PROXY/MAX_COMMENT_SIZE/EDIT_TIME` + placeholder
  custom provider `stepik` (D0-mandatory, see §6/§6.1).
- Q4 JWT transport: fresh mint on `/auth/check→200`, `X-JWT+X-XSRF-TOKEN`,
  Caddy `copy_headers`, rotation ≤5m (see §6.1).
- Q5/Q6 proxy: `forward_auth` ONLY on `/discuss/*`, Gate `:8081` canonical
  (no `:3000`), bridge `app`, volumes, `check` never 302, `cid` extract +
  `unknown_thread` fail-closed, `/discuss/admin/*` teacher-only,
  `X-Gate-Auth` + subnet guard + strip + `ufw 22,80,443` (see §§3–4).
- Q7 OAuth: `next` validation + `state` 32B + `__Host-oa` binder + 403
  deny-copy, PKCE skipped, `POST /auth/logout` Origin-checked,
  `/auth/me` no-store (see §5).
- Q9/Q11 limits/edge: `x/time/rate`, IP chain, outbound 4r/s, compose
  log/limits, deps-only list, Full(strict) + LE `mjgavrilov@gmail.com`
  HTTP-01 + hostname Bypass, private headers, `/healthz`, PWA, placeholder
  boot (see §§5.3/7.2).
- Q10 QA: Wave 1 green gates merge, Wave 2 outsider post-merge pre-announce,
  matrix + new RU strings (see §8).

Remaining non-blocking pendings (each documented where it lands): prod
`client_id` (runtime env, Phase 0), VPS IP (DNS time), outsider Wave 2
account (pre-announce), backups (later phase), spike digest freeze
(`sha256:980e0e76a6f241cd181f44c5b4d686f0d8cd7f552e11deb3bdcba223b2c3b866` at D0).
