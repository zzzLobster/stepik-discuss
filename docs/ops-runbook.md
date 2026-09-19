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
