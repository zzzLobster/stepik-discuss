#!/bin/sh
# Caddy contract regression checks (bug-1/2/3 fixes, 2026-09-21).
#
# Proves the three proxy/gate contracts against the PINNED caddy image and
# the REAL deploy/Caddyfile (tls swapped to internal so no ACME is needed):
#
#   1. forward_auth sends the gate the FULL public URI: /discuss{uri}.
#      handle_path strips /discuss before the auth subrequest; the gate's
#      teacher-only branch matches "/discuss/admin/..." and ExtractCID
#      parses ?url= from the same header. If this regresses, admin requests
#      fall through to cid extraction and 403 the teacher (fail-visible but
#      wrong), and tests calling the gate directly stay green — this script
#      is the only check that covers the Caddy->gate header contract.
#   2. redir uses the 3-arg form: `redir /discuss /discuss/ 308`.
#      The 2-arg `redir /discuss/ 308` adapts to a bogus Location (blank 200).
#   3. the healthcheck listener answers on localhost:8081 with exit 0.
#
# Usage: deploy/caddy-verify.sh   (needs docker; used in CI and locally)
set -eu

cd "$(dirname "$0")/.."
# Same digest-pinned image as compose.yml — a mutable tag here would let an
# upstream tag move change what is actually tested in CI.
IMAGE=caddy:2.11.4-alpine@sha256:de23def33b17fb5d1290b0f6c2add1d70780e52341896c00a4c8a2a2fe9d355e
NET=caddy-verify-$$
TOKEN=dummy0123456789abcdef
TMPD=$(mktemp -d)
cleanup() { rm -rf "$TMPD"; docker rm -f cv-upstream cv-caddy >/dev/null 2>&1 || true; docker network rm "$NET" >/dev/null 2>&1 || true; }
trap cleanup EXIT

sed 's/tls mjgavrilov@gmail.com/tls internal/' deploy/Caddyfile > "$TMPD/Caddyfile"
sed 's/gate:8081/cv-upstream:8081/; s/remark42:8080/cv-upstream:8081/' "$TMPD/Caddyfile" > "$TMPD/Caddyfile.test"

docker network create "$NET" >/dev/null

# Stand-in for gate+remark42: logs the X-Forwarded-Uri the gate would see.
cat > "$TMPD/upstream.py" <<'PY'
from http.server import BaseHTTPRequestHandler, HTTPServer
import json
class H(BaseHTTPRequestHandler):
    def vapid_key(self):
        cookie = self.headers.get('Cookie', '')
        if '__Host-sid' not in cookie:
            body = b'{"error":"auth_required"}'
            self.send_response(401); self.send_header('Content-Type', 'application/json'); self.send_header('Content-Length', str(len(body))); self.end_headers(); self.wfile.write(body)
        else:
            body = b'{"key":"k","fp":"fp123456"}'
            self.send_response(200); self.send_header('Content-Type', 'application/json'); self.send_header('Content-Length', str(len(body))); self.end_headers(); self.wfile.write(body)
    def do_GET(self):
        p = self.path.split('?')[0]
        if p == '/auth/check':
            print(json.dumps({'seen': self.headers.get('X-Forwarded-Uri', 'MISSING')}), flush=True)
            self.send_response(200); self.send_header('Content-Length', '2'); self.end_headers(); self.wfile.write(b'ok')
        elif p == '/push/vapid-key':
            self.vapid_key()
        elif p == '/offline.html':
            body = b'<html>offline</html>'
            self.send_response(200); self.send_header('Content-Type', 'text/html'); self.send_header('Content-Length', str(len(body))); self.end_headers(); self.wfile.write(body)
        elif p == '/push/health':
            if 'deep=1' in self.path:
                if self.headers.get('X-Gate-Auth'):
                    body = b'{"ok":true}'
                    self.send_response(200); self.send_header('Content-Type', 'application/json'); self.send_header('Content-Length', str(len(body))); self.end_headers(); self.wfile.write(body)
                else:
                    self.send_response(404); self.send_header('Content-Length', '0'); self.end_headers()
            else:
                body = b'{"ok":true}'
                self.send_response(200); self.send_header('Content-Type', 'application/json'); self.send_header('Content-Length', str(len(body))); self.end_headers(); self.wfile.write(body)
        elif p == '/push/webhook':
            print(json.dumps({'webhook_hit': self.path}), flush=True)
            self.send_response(200); self.send_header('Content-Length', '2'); self.end_headers(); self.wfile.write(b'ok')
        else:
            self.send_response(200); self.send_header('Content-Length', '2'); self.end_headers(); self.wfile.write(b'ok')
    def do_POST(self):
        p = self.path.split('?')[0]
        if p == '/push/vapid-key':
            self.vapid_key()
        elif p == '/push/webhook':
            print(json.dumps({'webhook_hit': self.path}), flush=True)
            self.send_response(200); self.send_header('Content-Length', '2'); self.end_headers(); self.wfile.write(b'ok')
        else:
            self.send_response(200); self.send_header('Content-Length', '2'); self.end_headers(); self.wfile.write(b'ok')
    def log_message(self, *a): pass
HTTPServer(('0.0.0.0', 8081), H).serve_forever()
PY

docker run -d --name cv-upstream --network "$NET" -v "$TMPD/upstream.py":/up.py:ro python:3.12-alpine python -u /up.py >/dev/null
docker run -d --name cv-caddy --network "$NET" -p 127.0.0.1:18443:443 -e CADDY_GATE_TOKEN="$TOKEN" \
  -v "$TMPD/Caddyfile.test":/etc/caddy/Caddyfile:ro "$IMAGE" >/dev/null

fail() { echo "FAIL: $1" >&2; exit 1; }

# Wait for caddy to start listening (internal TLS generation can take a
# moment on loaded runners); a bare sleep here makes check 1 fail with a
# confusing empty-grep message when caddy is not up yet.
i=0
until curl -sk -o /dev/null --max-time 2 --resolve stepik.study67.fyi:18443:127.0.0.1 https://stepik.study67.fyi:18443/ 2>/dev/null; do
  i=$((i + 1))
  [ "$i" -ge 30 ] && fail "caddy did not become ready on :18443 within 30s"
  sleep 1
done

req() { # req <path-with-optional-query> — curl against the pinned caddy via --resolve
  curl -sk -o /dev/null --max-time 15 --resolve stepik.study67.fyi:18443:127.0.0.1 "https://stepik.study67.fyi:18443$1"
}

# --- check 1: gate sees the full public URI (admin path)
req /discuss/admin/api/v1/comments
SAW=$(docker logs cv-upstream 2>&1 | grep '"seen"' | tail -1)
echo "$SAW" | grep -q '"/discuss/admin/api/v1/comments"' || fail "gate saw $SAW, want /discuss/admin/api/v1/comments"

# --- check 2: gate sees the full public URI (cid-extract path with query)
req "/discuss/api/v1/find?site=s&url=https%3A%2F%2Fstepik.study67.fyi%2Fclass%2F82866"
SAW=$(docker logs cv-upstream 2>&1 | grep '"seen"' | tail -1)
echo "$SAW" | grep -q '"/discuss/api/v1/find?site=s&url=https%3A%2F%2Fstepik.study67.fyi%2Fclass%2F82866"' \
  || fail "gate saw $SAW, want full /discuss URI with query"

# --- check 3: /discuss exact redirects 308 (2-arg redir regression)
CODE=$(curl -sk -o /dev/null -w '%{http_code}' --max-time 15 --resolve stepik.study67.fyi:18443:127.0.0.1 https://stepik.study67.fyi:18443/discuss)
[ "$CODE" = "308" ] || fail "/discuss returned $CODE, want 308 (2-arg redir regression)"

CODE=$(curl -sk -o /dev/null -w '%{http_code}' --max-time 15 --resolve stepik.study67.fyi:18443:127.0.0.1 https://stepik.study67.fyi:18443/discuss/web)
[ "$CODE" = "308" ] || fail "/discuss/web returned $CODE, want 308"

# --- check 4: slash paths still proxied, not redirected
CODE=$(curl -sk -o /dev/null -w '%{http_code}' --max-time 15 --resolve stepik.study67.fyi:18443:127.0.0.1 https://stepik.study67.fyi:18443/discuss/)
[ "$CODE" = "200" ] || fail "/discuss/ returned $CODE, want 200 (proxied)"

# --- check 5: healthcheck command succeeds inside the container
docker exec cv-caddy wget -qO- http://localhost:8081/healthz >/dev/null || fail "healthcheck wget failed (localhost:8081 listener regression)"

# --- check 6: POST /push/webhook →404 + upstream-never-hit
CODE=$(curl -sk -o /dev/null -w '%{http_code}' --max-time 15 -X POST --resolve stepik.study67.fyi:18443:127.0.0.1 https://stepik.study67.fyi:18443/push/webhook)
[ "$CODE" = "404" ] || fail "POST /push/webhook returned $CODE, want 404 (edge must 404 before proxy)"
docker logs cv-upstream 2>&1 | grep -q '"webhook_hit"' && fail "upstream saw /push/webhook hit, want zero (Caddy must 404 before proxy)"

# --- check 7: GET /push/vapid-key no-cookie →401 + with-cookie →200
CODE=$(curl -sk -o /dev/null -w '%{http_code}' --max-time 15 --resolve stepik.study67.fyi:18443:127.0.0.1 https://stepik.study67.fyi:18443/push/vapid-key)
[ "$CODE" = "401" ] || fail "GET /push/vapid-key no-cookie returned $CODE, want 401"
CODE=$(curl -sk -o /dev/null -w '%{http_code}' --max-time 15 -b '__Host-sid=test' --resolve stepik.study67.fyi:18443:127.0.0.1 https://stepik.study67.fyi:18443/push/vapid-key)
[ "$CODE" = "200" ] || fail "GET /push/vapid-key with-cookie returned $CODE, want 200"

# --- check 8: GET /offline.html →200 text/html
CODE=$(curl -sk -o /dev/null -w '%{http_code}' --max-time 15 --resolve stepik.study67.fyi:18443:127.0.0.1 https://stepik.study67.fyi:18443/offline.html)
[ "$CODE" = "200" ] || fail "GET /offline.html returned $CODE, want 200"
CTYPE=$(curl -sk -o /dev/null -w '%{content_type}' --max-time 15 --resolve stepik.study67.fyi:18443:127.0.0.1 https://stepik.study67.fyi:18443/offline.html)
echo "$CTYPE" | grep -q 'text/html' || fail "GET /offline.html Content-Type $CTYPE, want text/html"

# --- check 9: GET /push/health?deep=1 without token →404 and with forged X-Gate-Auth →404 (proves strip)
CODE=$(curl -sk -o /dev/null -w '%{http_code}' --max-time 15 --resolve stepik.study67.fyi:18443:127.0.0.1 "https://stepik.study67.fyi:18443/push/health?deep=1")
[ "$CODE" = "404" ] || fail "GET /push/health?deep=1 without token returned $CODE, want 404"
CODE=$(curl -sk -o /dev/null -w '%{http_code}' --max-time 15 -H 'X-Gate-Auth: forged' --resolve stepik.study67.fyi:18443:127.0.0.1 "https://stepik.study67.fyi:18443/push/health?deep=1")
[ "$CODE" = "404" ] || fail "GET /push/health?deep=1 with forged X-Gate-Auth returned $CODE, want 404 (proves strip)"

echo "caddy-verify: all contract checks passed"
