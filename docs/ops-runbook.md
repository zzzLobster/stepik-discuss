# Ops Runbook — Cloudflare Slowness + Discuss Embed (2026-09-19)

> Concise, copy-paste ready. Keys / IDs only, no secret values.

## 1. Incident Timeline (2026-09-19 UTC)

1. `discuss.stepik.org` slow via Cloudflare: page timeouts, TTFB seconds.
2. `remark.mjs` / `remark.css` → `403 application/json + nosniff` (browser blocks).
3. After auth bypass → `404` from remark42 (`File not found`).
4. `/api/v1/config` → `403` (ExtractCID reject).
5. `/` and `/class` TTFB ~8.5s via CF; direct-to-origin instant.
6. Direct vs CF (same minute):
   - `/` direct ~0.06s vs CF ~8.5s; `/class` ~0.05s vs ~2.7s; `/discuss/web/remark.mjs` ~0.05s vs ~16.5s.
7. Caddy access log: `duration ~3ms`; gate handler `latency_ms 0ms` → proves stall is pre-accept (edge/network), not app.
8. Host net: `TCPSynRetrans 326`, dual IPs `5.181`/`6.148` on same NIC, `speed-ix` jitter, `mtr` loss to `1.1.1.1`.
9. Decision: cut over to Cloudflare Tunnel (outbound-only, no inbound 80/443).

## 2. Root Causes + Fixes

### 2.1 `forward_auth` blocked static web → 403 JSON
- `handle /discuss/* forward_auth gate:8080` ran for `/discuss/web/*`.
- `ExtractCID` needs `?url=` or `Referer: /class`; iframe `Referer` is `iframe.html` → reject.
- Fix: public bypass before auth:
```caddy
handle /discuss/web/* {
  uri strip_prefix /discuss
  reverse_proxy remark42:8080
}
handle /discuss/* {
  forward_auth gate:8080 { uri /auth/check; header_up X-Forwarded-Uri {uri} }
  reverse_proxy remark42:8080
}
```

### 2.2 `handle_path` stripped too much → 404
- `handle_path /discuss/web/*` strips full prefix → upstream `/remark.mjs`, want `/web/remark.mjs`.
- Fix: `handle` + `uri strip_prefix /discuss` (strip one level only).

### 2.3 `ExtractCID` missed iframe unwrap → `/api/v1/config` 403
- Embed flow: `iframe.html?url=<encoded /class>`; API `Referer` is iframe URL.
- Fix: unwrap one level — parse Referer, take inner `?url=` if path is `iframe.html` (gate).
```go
// unwrapIframeURL: if Referer path ends with iframe.html, return inner ?url= value
```

### 2.4 `trusted_proxies cloudflare` invalid on stock image
- `caddy:2.11.4-alpine` has no `http.ip_sources.cloudflare` module → adapt error.
- Fix: global block, static ranges:
```caddy
{
  servers {
    trusted_proxies static private_ranges 173.245.48.0/20 103.21.244.0/22 103.22.200.0/22 103.31.4.0/22 141.101.64.0/18 108.162.192.0/18 190.93.240.0/20 188.114.96.0/20 197.234.240.0/22 198.41.128.0/17 162.158.0.0/15 104.16.0.0/13 104.24.0.0/14 172.64.0.0/13 131.0.72.0/22
  }
}
```
- Direct edge: full list above. Tunnel-only: `private_ranges` is enough (edge → `127.0.0.6` via `cloudflared`).
- Validate via container (no local binary needed) — see §3.

### 2.5 Tunnel `308` loop
- `auto_https` + `http://caddy:80` ingress → redirect loop.
- Fix: `auto_https disable_redirects` when behind tunnel.

### 2.6 Logout button unstyled
- `<button>` with no class. Fix: `class="button"` + `button.button` CSS.

### 2.7 Missing observability
- Added `index`/`class` latency logs (`check`, `allow`, `latency_ms`, `cf_ray`) + Caddy JSON access log joinable on `cf-ray` / `cf_ray`.

### 2.8 Flaky `TestMint_tamperedRejected`
- Pre-existing: flips last char (base64 padding, often `=`) → signature unchanged → pass.
- Fix needed: flip first payload/sig char instead.

## 3. Ways to Test

### Timing + headers (TTFB, edge cache, ray)
```bash
curl -sS -o /dev/null -w 'tls:%{time_appconnect} ttfb:%{time_starttransfer} total:%{time_total} code:%{http_code}\n' https://discuss.stepik.org/
curl -sSI https://discuss.stepik.org/discuss/web/remark.mjs | grep -iE 'HTTP/|content-type|cf-ray|cf-cache-status|x-nosniff'
curl -sS -D - -o /dev/null https://discuss.stepik.org/class | head -20
```

### Bypass CF (isolate origin vs edge)
```bash
ORIGIN_IP=<vps-ip>  # key only, no value in repo
curl -sS -o /dev/null -w 'ttfb:%{time_starttransfer} total:%{time_total}\n' --resolve discuss.stepik.org:443:$ORIGIN_IP https://discuss.stepik.org/
curl -sS -o /dev/null -w 'ttfb:%{time_starttransfer} total:%{time_total}\n' --resolve discuss.stepik.org:443:$ORIGIN_IP https://discuss.stepik.org/class
```

### Embed paths: Referer variants + sid cookie
```bash
curl -sSI https://discuss.stepik.org/discuss/web/remark.mjs
curl -sSI -e https://discuss.stepik.org/class https://discuss.stepik.org/discuss/web/remark.mjs
curl -sS -b 'sid=<sid-key-only>' -e https://discuss.stepik.org/iframe.html?url=https%3A%2F%2Fdiscuss.stepik.org%2Fclass https://discuss.stepik.org/discuss/api/v1/config | head -c 300; echo
```

### Logs (gate + caddy)
```bash
docker logs gate 2>&1 | grep -E 'check|allow|index|class|latency_ms|cf_ray' | tail -30
docker logs caddy 2>&1 | grep -E 'duration|cf-ray|cf_ray' | tail -30
docker stats --no-stream
```

### Host network
```bash
ss -s; netstat -s | grep -i -A2 retrans
iptables -L -n -v; iptables -t nat -L -n -v
ip addr; ip route
ping -c4 1.1.1.1; mtr -rwc 20 1.1.1.1
echo | openssl s_client -connect discuss.stepik.org:443 -servername discuss.stepik.org 2>/dev/null | grep -E 'Verify|Chain|Certificate'
curl -s https://speed-ix.stepik.org/ | head -c 200
```

### Caddy validate / fmt / adapt (container, pinned)
```bash
docker run --rm -v $PWD/deploy/Caddyfile:/etc/caddy/Caddyfile caddy:2.11.4-alpine caddy validate --config /etc/caddy/Caddyfile --adapter caddyfile
docker run --rm -v $PWD/deploy/Caddyfile:/etc/caddy/Caddyfile caddy:2.11.4-alpine caddy fmt --overwrite /etc/caddy/Caddyfile
docker run --rm -v $PWD/deploy/Caddyfile:/etc/caddy/Caddyfile caddy:2.11.4-alpine caddy adapt --config /etc/caddy/Caddyfile --adapter caddyfile | head -100
docker compose config
```

### Go
```bash
go test ./... -count=1   # -count=1 avoids cache masking flake
go vet ./...
go build ./...
```

### Cloudflare token (for WAF/Logs/DNS checks)
- Scopes: `Zone:Read Analytics:Read DNS:Read WAF:Read Logs:Read`, zone-scoped, 7d TTL. Never Global Key. Revoke after use.

## 4. Tunnel Cutover Runbook

1. Zero Trust → Networks → Tunnels → Create → `cloudflared` token → VPS `.env` (`CLOUDFLARED_TOKEN=<ref>`), `chmod 600 .env`.
2. Ingress: `discuss.stepik.org → http://caddy:80`.
3. DNS: CNAME `discuss → <tunnel-id>.cfargotunnel.com` (orange cloud).
4. SSL: `Full (strict)` if origin TLS else `Full`; `Always Use HTTPS + HSTS` ON.
5. Up:
```bash
docker compose up -d tunnel; docker logs tunnel 2>&1 | tail -20
docker logs tunnel 2>&1 | grep -c 'Registered tunnel connection'  # want 4x QUIC
```
6. Verify:
```bash
for i in 1 2 3; do curl -sS -o /dev/null -w 'ttfb:%{time_starttransfer} total:%{time_total}\n' https://discuss.stepik.org/; done
curl -sSI https://discuss.stepik.org/discuss/web/remark.mjs | grep -iE 'HTTP/|cf-ray'
```
   Want `ttfb < 1.5s`, no `308` loop.
7. Lock firewall (only after tunnel healthy):
```bash
iptables -P INPUT DROP; iptables -P FORWARD DROP
iptables -A INPUT -i lo -j ACCEPT; iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
iptables -A INPUT -p tcp --dport 22 -j ACCEPT; iptables -A INPUT -p icmp -j ACCEPT
# no ACCEPT 80/443 from anywhere; origin reachable only via outbound tunnel
```
8. Caveat: with 80/443 closed, ACME HTTP-01 fails → use DNS-01 (CF API token, `DNS:Edit` zone-scoped) for renewals.
9. Rollback: open 80/443, DNS CNAME back to `A <vps-ip>` (orange still ON), `docker compose stop tunnel`.

## 5. Current State

Commits `2026-09-19` (newest first):
```text
769e035 tunnel ingress + private trust + firewall docs
fe5a9e6 latency logs + Caddy access log + logout style
78565fe ExtractCID unwrap iframe referer
b6c4046 web path handle + strip_prefix
e5a7afa trusted_proxies global static + container validate
2057193 public web assets + framing + favicon + redirects
83dd93a referrer policy + framing + trusted proxy
```

Open:
- [ ] Fix flaky `TestMint_tamperedRejected` (flip first sig char, not last padding).
- [ ] DNS-01 for ACME after firewall lock (HTTP-01 will fail).
- [ ] Fallback net tuning if tunnel still jitters: `rp_filter`, TCP `mss`, single primary IP.

## 6. Tunnel evaluated 2026-09-19 — rolled back, direct retained

- Zero Trust tunnel cutover (§4) rolled back: Cloudflare Zero Trust Free plan requires a credit card, user has none → tunnel not usable. Direct orange-cloud (`CF edge → Caddy 80/443`) retained; no `tunnel` service, no `TUNNEL_TOKEN`.
- §4 kept as alternative design if a card becomes available later (re-add `tunnel` service, `private_ranges`-only trust, `disable_redirects`, firewall `DROP 80/443` + DNS-01 note).
- Current direct mitigations: `trusted_proxies static private_ranges + explicit CF ranges`, `auto_https` default (no `disable_redirects`), origin firewall CF-only (`ufw allow 22,80,443`; 80/443 preferably Cloudflare-only, no `DROP`-all).

## 7. MSS 1380 resolution 2026-09-19 — CF AMS/LHR tails fixed

- Before: 4x timeout 30s + 8s tails p95 30s; clamp-to-PMTU still 30% bad (ServerHello/cert frag PMTUD blackhole on AMS path).
- After `--set-mss 1380`: 20/20 edge 200 zero timeouts, all AMS; ttfb median 0.309 p95 0.438 max 0.526, total median 0.312 p95 0.439; direct 0.136 median.
- Verify: `iptables -t mangle -S POSTROUTING | grep -E 'TCPMSS.*1380'`
- Measure: `for i in $(seq 1 20); do curl -sS -o /dev/null -w 'ttfb:%{time_starttransfer} total:%{time_total} code:%{http_code}\n' https://discuss.stepik.org/; done`
- Apply: `deploy/network-tune.sh` (idempotent; removes legacy clamp rule).
- Persist (root on Linux, runs automatically at the end of `network-tune.sh`):
  `netfilter-persistent save` when `iptables-persistent` is installed
  (else `iptables-save > /etc/iptables/rules.v4` snapshot). No systemd unit.
- Persistence verification (after `reboot`):
```bash
iptables -t mangle -S POSTROUTING | grep 1380
```

## 8. remark42 Gate-JWT auth — pitfalls + debug runbook (2026-09-19)

### 8.1 Design recap

- Remark native `Sign In → Stepik` with `AUTH_CUSTOM_CID=spike-placeholder-never-completes` is dead by design: go-pkgz/auth needs ≥1 provider (plan §6.1 D0), dummy `cid/csec` can never complete.
- Real login is Gate `/auth/login → /auth/callback`; per-request Gate-minted `X-JWT + X-XSRF-TOKEN` via Caddy `forward_auth ... copy_headers`, browser never sees JWT.
- Callback URL proof: remark native is `/discuss/auth/stepik/callback` vs Gate `/auth/callback`. Testing the former tests nothing.

### 8.2 Two Caddy pitfalls fixed in `4c17b02`/`b9eeb29`

- (a) Redundant `header_up X-JWT {http.request.header.X-JWT}` re-set after copy: canonical Go header is `X-Jwt` vs `X-JWT`, plus empty-clear risk on some adapts. Removed; rely on `copy_headers X-JWT X-XSRF-TOKEN` only.
- (b) `request_header -X-JWT/-X-XSRF-TOKEN` in protected `handle_path /discuss/*` adapts AFTER the copy and deletes the Gate JWT. Removed there only. Kept in public `handle /discuss/web/*`; kept `-Remote-User/-X-Auth-*` everywhere.
- Spoof still safe: on allow `copy_headers` overwrites any client value; on deny Caddy never proxies.

### 8.3 Debug runbook (keys only, `<placeholders>`, no values)

```bash
# 1. Secret match (hash-compare, values never leave VPS)
docker compose exec gate printenv REMARK_JWT_SECRET | sha256sum
docker compose exec remark42 printenv SECRET | sha256sum
# want identical hashes

# 2. SITE / REMARK_URL match
docker compose exec gate printenv SITE REMARK_URL
docker compose exec remark42 printenv SITE REMARK_URL
# want SITE=<site> on both, REMARK_URL=https://<host>/discuss on both

# 3. No manual X-JWT re-set in adapted JSON
docker run --rm -v $PWD/deploy/Caddyfile:/etc/caddy/Caddyfile:ro caddy:2.11.4-alpine \
  caddy adapt --config /etc/caddy/Caddyfile --adapter caddyfile | grep -c 'http.request.header.X'
# want 0

# 4. Gate mint check (from caddy net, want 200 + both headers)
docker compose exec caddy wget -qSO- \
  --header="Cookie: __Host-sid=<sid>" \
  --header="X-Forwarded-Uri: /discuss/api/v1/find?site=<site>&url=https://<host>/class/<cid>" \
  --header="Referer: https://<host>/class/<cid>" \
  http://gate:8081/auth/check 2>&1 | grep -iE '^  HTTP/|X-JWT|X-XSRF-TOKEN'

# 5. Direct-to-remark replay (inside container, status only — no JWT leak)
docker compose exec caddy sh -c \
  'curl -sS -o /dev/null -w "direct:%{http_code}\n" \
  -H "X-JWT: <jwt-from-step-4>" -H "X-XSRF-TOKEN: <xsrf-from-step-4>" \
  "http://remark42:8080/api/v1/find?site=<site>&url=https://<host>/class/<cid>"'
# want direct:200

# 6. Edge check (__Host-sid from devtools Application→Cookies, HttpOnly; Referer = class URL)
curl -sS -o /dev/null -w 'edge:%{http_code}\n' \
  -b '__Host-sid=<sid>' -e 'https://<host>/class/<cid>' \
  'https://<host>/discuss/api/v1/find?site=<site>&url=https://<host>/class/<cid>'
# want edge:200

# 7. remark DEBUG one-repro tail (run one edge curl, then immediately)
docker compose logs remark42 2>&1 | grep -iE '401|jwt|app-name|auth' | tail -20
```

- `/discuss/auth/list` without `Referer` → Gate `403 forbidden` is expected (`ExtractCID` fail-closed on missing `?url=`/class `Referer`), not a remark bug. Retest with `-e https://<host>/class/<cid>`.
- Two dirs on VPS (`/opt/git` vs `/opt/stepik-discuss`): always `pwd; git log --oneline -3` in the compose dir before debugging, and `docker compose up -d caddy` after every pull — otherwise you test a stale Caddyfile.

### 8.4 Symptom table

| Gate `check` | remark | Meaning |
|---|---|---|
| `check allow` + remark `401 app-name: remark42` | `direct:200` untested | Downstream of Gate: secret/claims/Caddy copy — run §8.3 steps 1–5 |
| `direct:200` + edge `401` | Caddy copy/strip | `forward_auth copy_headers` or `request_header -X-JWT` regression — run step 3 |
| `direct:401` | secret/claims/clock | `SECRET` mismatch, `aud/iss/exp` drift, or `SITE`/`REMARK_URL` mismatch — run steps 1–2 |

## 9. Refresh-token ops (hybrid renewal, 2026-09-20)

Capture: `ExchangeCode` (`Scopes: read`, cut from `read+write` in `f16b899`) stores access + refresh
encrypted (AES-256-GCM) in the session row and, for the teacher, in
`teacher_token/current`. Renew: silent `RedeemRefresh` on `401` or
probe-mismatch (`teacher_401`/`teacher_probe`/`student_401`/`student_probe`
reasons), rotation-aware (empty `refreshOut` keeps the old refresh),
single-flight per `sid:<sid>` / `teacher:current` with `ObtainedAt` fencing
(loser reuses the winner, never double-redeems).

### 9.1 Event names

- Demand: `session_renew_demand_*` (`scope=session`, student SIDs) +
  `teacher_renew_demand_*` (`scope=teacher_session`, teacher SIDs + dual-write) +
  same names with `scope=teacher_record` (background loop). Verbs: `start`,
  `success` (`rotated=true/false`), `invalid_grant`, `transient`, `superseded`.
  `reason` is
  `teacher_401`/`teacher_probe`/`student_401`/`student_probe` on demand,
  `background_expiry`/`background_probe` in the loop.
- Background loop (`gate/auth/teacher_refresh.go`): `teacher_background_alive`,
  `teacher_background_renew_ok` (`reason=background_expiry|background_probe`),
  `teacher_background_transient`, `teacher_background_transient_skip`,
  `teacher_background_no_record`, `teacher_background_parked`
  (`reason=no_record|still_dead|invalid_grant|no_refresh`).

### 9.2 Pager: invalid_grant rate

- `session_renew_demand_invalid_grant` / `teacher_renew_demand_invalid_grant` at `info` = one dead refresh chain
  (user revoked at Stepik / rotation loser) → re-login, not a page. Split pager by `scope=session` vs `scope=teacher_session`.
- Page when the rate spikes across many uids or the teacher record parks with
  `reason=invalid_grant` (shared fallback dead): check
  `teacher_background_parked` + teacher banner on `/`, ask the teacher to
  re-login via Stepik (re-seeds both records unconditionally).
- `session_renew_demand_transient` / `teacher_renew_demand_transient` / `teacher_background_transient` at `warn`
  = Stepik 429/5xx/transport → stale-in-grace, no action unless sustained.

### 9.3 Parked / unparked + 6h escape

- Background parks (no Stepik calls while parked) on: missing record,
  `invalid_grant`, or still-dead-after-renew. Single `warn` on first park,
  quiet after.
- Unpark: any successful renew/probe (`markAlive`), or the 6h escape hatch —
  a parked loop older than 6h retries on the next tick instead of returning
  `parked`, so a false park (e.g. stale-record race healed by a demand
  dual-write) self-heals without a restart.

### 9.4 Restart behavior

- yes, teacher token is checked once 5-15s after (re)start and renewed if expiring/dead, then every 15m — students always renew lazily on demand.
- Concretely: `StartTeacherRefresh` fires one jittered (5–15s) immediate check
  on boot, then a `15m±3m` ticker. Expiring-within-1h renews without probing;
  otherwise one `GetLoggedID` probe decides (uid mismatch / empty stepics /
  401 → renew; transient → back off up to two ticks; alive → no-op).
- Students never tick: renewal happens only inside `EnsureFresh` on the 6h
  lazy re-check path (401/probe-mismatch → redeem → retry verify once).

### 9.5 Presence: has_refresh

- Both `oauth exchange ok` and `stepik refresh ok` log `has_refresh=<bool>`.
- `has_refresh=false` on exchange = pre-feature Stepik response without a
  refresh (row keeps working, legacy path: expiry → re-login). Absence of a
  stored refresh (`renewNone`) is normal for old rows, not an error.

### 9.6 Scope note (plan §10 decision stands)

Scope is now `read`-only. `AuthCodeURL`/`ExchangeCode` send `Scopes: ["read"]`; `RedeemRefresh` posts no `scope` param so each chain keeps whatever it was granted. **Mixed-scope rollout:** pre-cut sessions and the shared `teacher_token/current` row keep their `read+write` bundle until the teacher re-logins (refresh never narrows scope); post-cut logins are `read`-only. Both work — Gate only ever reads (`GetLoggedID`, `GetProfile`, `ListOwned`, `VerifyStudent`). If a student asks why an old consent screen said "read write", answer: we only read class list + profile; new logins ask read only. No login-page explainer per plan §10.
