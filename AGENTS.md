# AGENTS.md — stepik-discuss

Go 1.27.1 gate (`gate/main.go` → `:8081`) + Caddy `2.11.4-alpine` + remark42 + Cloudflare direct (orange-cloud, no tunnel). No README; normative spec `plans/0001-stepik-discussion-site.md`, ops runbook `docs/ops-runbook.md`, browser QA `TESTLOG.md`.

## Commands (use these exact forms)

- `go build ./...`, `go vet ./...`, `go test -count=1 ./...` — CI uses `-count=1`; cached `go test` masks flaky `TestMint_tamperedRejected`.
- Single: `go test ./gate/auth/ -run TestExtractCID -v`, `go test ./gate/handlers/ -v`.
- No local caddy binary — validate via container (same image as deploy):
  `docker run --rm -e CADDY_GATE_TOKEN=dummy... -v ./deploy/Caddyfile:/etc/caddy/Caddyfile:ro caddy:2.11.4-alpine caddy validate --config /etc/caddy/Caddyfile --adapter caddyfile`
  `docker compose -f deploy/compose.yml config` — must parse after any compose edit.
- Proxy/gate contract checks (CI job `caddy-contract`): `deploy/caddy-verify.sh` — boots the pinned caddy image on the real Caddyfile and asserts the three contracts below. Run it after any Caddyfile edit; Go unit tests call the gate directly and cannot see these.
- Spike (live remark42 JWT, ephemeral secret, no testcontainers): see `.github/workflows/ci.yml` + `spike/`; never commit secret.

## Architecture that bites

- `gate/handlers/handlers.go:Routes()` is the wiring; templates/static embedded via `//go:embed`. `/` never calls Stepik; `/class/*` calls `EnsureFresh` only on `VerifyTTL 6h` expiry.
- Caddy `handle_path` strips the **full matched prefix**: public web must be `handle /discuss/web/* + uri strip_prefix /discuss` (→ `/web/*`), protected is `handle_path /discuss/*` (strips `/discuss`). Swapping them 404s remark assets. The strip happens BEFORE the `forward_auth` subrequest, so the gate must be given the full public URI via `header_up X-Forwarded-Uri /discuss{uri}` — the gate's teacher-only admin branch matches `/discuss/admin/...` and `ExtractCID` parses `?url=` from that header. `{uri}` alone sends `/admin/...` and silently kills the admin check.
- 2-arg `redir /discuss/ 308` adapts to a bogus Location (blank 200, no redirect) — use the 3-arg form `redir /discuss /discuss/ 308`.
- Container healthcheck hits `http://localhost:8081/healthz` (dedicated plain-HTTP listener in the Caddyfile); the main site 308s HTTP→HTTPS and has no cert for `localhost`, so port-80 healthchecks can never pass.
- `forward_auth gate:8081 /auth/check` only on `/discuss/*`, never on `/web/*`. `ExtractCID` needs `?url=` or class `Referer` or iframe `?url=` unwrap; else `unknown_thread` 403 JSON (browser shows MIME/nosniff block).
- Stock caddy has no `http.ip_sources.cloudflare`: use global `{ servers { trusted_proxies static private_ranges + explicit CF ranges [...] } }`. Direct orange-cloud keeps the full CF range list; `auto_https` default (redirects on, no `disable_redirects`).
- Direct origin: `CF edge → Caddy 80/443`; `CF-Connecting-IP` trusted via `trusted_proxies`. Direct-to-origin forgery mitigated by CF-only firewall (`ufw allow 22,80,443`, 80/443 preferably Cloudflare-only, no `DROP`-all). No `tunnel` service in compose.

## Secrets / deploy

- Never commit `deploy/.env`, `*.db`, real tokens. `deploy/.env.example` keys only. Images pinned by digest (`caddy`, `remark42`), never `:latest`.
- Debug slowness by `cf-ray`: gate `index/class` logs (`latency_ms,cf_ray`) + Caddy json `duration` join on ray. `curl --resolve ...:45.12.6.148` bypasses CF to isolate origin vs edge. `cf-cache-status: DYNAMIC` is correct for HTML/API.
