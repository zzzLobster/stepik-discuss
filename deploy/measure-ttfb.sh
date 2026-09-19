#!/usr/bin/env bash
# Before/after TTFB probe: 10x curl via edge, optional direct-origin compare.
# Usage: ./measure-ttfb.sh [URL]   (default https://stepik.study67.fyi/)
#        ORIGIN_IP=45.12.6.148 ./measure-ttfb.sh [URL]
# Needs only curl + awk (+ sort/date, base on Mac and Ubuntu).
set -euo pipefail

URL="${1:-https://stepik.study67.fyi/}"
N="${TTFB_COUNT:-10}"
LOG="/tmp/ttfb-$(date +%s).log"

stats() {
  sort -n "$1" | awk '
    { v[NR] = $1; n = NR }
    END {
      if (n == 0) { print "no samples"; exit }
      if (n % 2 == 1) med = v[int(n/2)+1]
      else med = (v[n/2] + v[n/2+1]) / 2
      p95i = int(0.95*n + 0.999999)
      if (p95i < 1) p95i = 1
      if (p95i > n) p95i = n
      printf "n=%d median=%.3f p95=%.3f min=%.3f max=%.3f\n", n, med, v[p95i], v[1], v[n]
    }'
}

phase() {
  label="$1"
  url="$2"
  shift 2
  vals_tls=$(mktemp /tmp/ttfb-tls.XXXXXX)
  vals_ttfb=$(mktemp /tmp/ttfb-ttfb.XXXXXX)
  vals_total=$(mktemp /tmp/ttfb-total.XXXXXX)
  {
    echo "## $label: $url (n=$N)"
    i=0
    while [ "$i" -lt "$N" ]; do
      i=$((i + 1))
      hdr=$(mktemp /tmp/ttfb-hdr.XXXXXX)
      out=$(curl -s --max-time 30 -o /dev/null -D "$hdr" \
        -w "%{time_appconnect} %{time_starttransfer} %{time_total} %{http_code}" \
        "$@" "$url" 2>/dev/null || echo "0 0 0 000")
      ray=$(grep -i '^cf-ray:' "$hdr" 2>/dev/null | tr -d '\r' | awk '{print $2}' || true)
      cache=$(grep -i '^cf-cache-status:' "$hdr" 2>/dev/null | tr -d '\r' | awk '{print $2}' || true)
      rm -f "$hdr"
      tls=$(echo "$out" | awk '{print $1}')
      ttfb=$(echo "$out" | awk '{print $2}')
      total=$(echo "$out" | awk '{print $3}')
      code=$(echo "$out" | awk '{print $4}')
      echo "try=$i tls=$tls ttfb=$ttfb total=$total code=${code:-000} cf_ray=${ray:- -} cf_cache=${cache:- -}"
      echo "$tls" >> "$vals_tls"
      echo "$ttfb" >> "$vals_ttfb"
      echo "$total" >> "$vals_total"
    done
    echo "-- $label tlss  : $(stats "$vals_tls")"
    echo "-- $label ttfb  : $(stats "$vals_ttfb")"
    echo "-- $label total : $(stats "$vals_total")"
  } | tee -a "$LOG"
  rm -f "$vals_tls" "$vals_ttfb" "$vals_total"
}

echo "raw log: $LOG"
phase "edge" "$URL"

if [ -n "${ORIGIN_IP:-}" ]; then
  host=$(printf '%s' "$URL" | sed -e 's#^https\?://##' -e 's#/.*$##' -e 's#:.*$##')
  case "$URL" in
    https://*) port=443 ;;
    *) port=80 ;;
  esac
  # shellcheck disable=SC2086
  phase "direct" "$URL" --resolve "$host:$port:$ORIGIN_IP"
else
  echo "skip direct: ORIGIN_IP env not set (e.g. ORIGIN_IP=45.12.6.148 $0 $URL)" | tee -a "$LOG"
fi
echo "saved: $LOG"
