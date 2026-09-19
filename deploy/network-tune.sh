#!/usr/bin/env bash
# MSS 1380 + SYN-backlog tuning for direct Cloudflare origin.
# Proven 2026-09-19: --set-mss 1380 fixed CF AMS/LHR tails (20/20 edge 200
# zero timeouts); --clamp-mss-to-pmtu insufficient (ServerHello/cert frag
# PMTUD blackhole on AMS path).
# Idempotent: safe to re-run, never flushes existing rules.
# Linux-only actions are skipped gracefully on other OSes.
set -euo pipefail

SUDO=""
if [ "$(id -u)" -ne 0 ] && command -v sudo >/dev/null 2>&1; then
  SUDO="sudo"
fi

# Persist the runtime mangle rule across reboot. Prefers netfilter-persistent
# when installed, falls back to a plain iptables-save snapshot. Idempotent.
persist_netfilter() {
  if [ "$(id -u)" -ne 0 ]; then
    echo "skip: not root, mangle rule will not persist across reboot (re-run as root to persist)"
    return 0
  fi
  if command -v netfilter-persistent >/dev/null 2>&1; then
    if netfilter-persistent save; then
      echo "persisted: netfilter-persistent save"
    else
      echo "warn: netfilter-persistent save failed"
    fi
  elif command -v iptables-save >/dev/null 2>&1; then
    mkdir -p /etc/iptables
    if iptables-save > /etc/iptables/rules.v4; then
      echo "persisted: iptables-save > /etc/iptables/rules.v4 (install iptables-persistent to auto-restore)"
    else
      echo "warn: iptables-save failed"
    fi
  else
    echo "skip: neither netfilter-persistent nor iptables-save found"
  fi
}

echo "== iptables mangle: TCPMSS set-mss 1380 =="
if ! command -v iptables >/dev/null 2>&1; then
  echo "skip: iptables not found (non-Linux host?)"
else
  # Remove legacy clamp rule if present to avoid duplicate MSS rules.
  # shellcheck disable=SC2086
  if $SUDO iptables -t mangle -C POSTROUTING -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu 2>/dev/null; then
    # shellcheck disable=SC2086
    $SUDO iptables -t mangle -D POSTROUTING -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu
    echo "removed: legacy POSTROUTING TCPMSS clamp-mss-to-pmtu"
  fi
  # shellcheck disable=SC2086
  if $SUDO iptables -t mangle -C POSTROUTING -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --set-mss 1380 2>/dev/null; then
    echo "present: POSTROUTING TCPMSS set-mss 1380 already applied"
  else
    # shellcheck disable=SC2086
    $SUDO iptables -t mangle -A POSTROUTING -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --set-mss 1380
    echo "applied: POSTROUTING TCPMSS set-mss 1380"
  fi
  echo "-- current mangle POSTROUTING rules --"
  # shellcheck disable=SC2086
  $SUDO iptables -t mangle -S POSTROUTING 2>/dev/null || $SUDO iptables -t mangle -L POSTROUTING -n -v
fi

echo "== iptables persistence =="
if [ "$(uname -s)" != "Linux" ]; then
  echo "skip: iptables persistence is Linux-only"
elif ! command -v iptables >/dev/null 2>&1; then
  echo "skip: iptables not found, nothing to persist"
else
  persist_netfilter
fi

echo "== sysctl runtime =="
if ! command -v sysctl >/dev/null 2>&1; then
  echo "skip: sysctl not found"
else
  for kv in net.ipv4.tcp_max_syn_backlog=4096 net.core.somaxconn=4096 net.ipv4.tcp_syncookies=1; do
    # shellcheck disable=SC2086
    if $SUDO sysctl -w "$kv" 2>/dev/null; then
      true
    else
      echo "skip: cannot set $kv on this host"
    fi
  done
  sysctl net.ipv4.tcp_max_syn_backlog net.core.somaxconn net.ipv4.tcp_syncookies 2>/dev/null || true
fi

echo "== sysctl persistence =="
CONF="/etc/sysctl.d/99-stepik-discuss.conf"
WANT="# stepik-discuss origin tuning (direct Cloudflare, MSS clamp companion)
net.ipv4.tcp_max_syn_backlog = 4096
net.core.somaxconn = 4096
net.ipv4.tcp_syncookies = 1"
if [ "$(id -u)" -eq 0 ]; then
  if [ -f "$CONF" ] && [ "$(cat "$CONF")" = "$WANT" ]; then
    echo "present: $CONF already up to date"
  else
    mkdir -p /etc/sysctl.d
    printf '%s\n' "$WANT" > "$CONF"
    echo "wrote: $CONF"
  fi
else
  echo "skip: not root, would write $CONF with:"
  printf '%s\n' "$WANT"
fi

echo "== SYN-RECV backlog =="
if command -v ss >/dev/null 2>&1; then
  COUNT=$(ss -tnp state syn-recv 2>/dev/null | tail -n +2 | wc -l | tr -d ' ')
  echo "syn-recv count (ss): $COUNT"
  ss -tnp state syn-recv 2>/dev/null | head -n 20 || true
elif command -v netstat >/dev/null 2>&1; then
  COUNT=$(netstat -an 2>/dev/null | grep -c SYN_RCVD || true)
  echo "syn-recv count (netstat): $COUNT"
else
  echo "skip: neither ss nor netstat found"
fi

echo "== conntrack =="
if command -v conntrack >/dev/null 2>&1; then
  conntrack -C 2>/dev/null || conntrack -L 2>/dev/null | wc -l
elif [ -r /proc/sys/net/netfilter/nf_conntrack_count ]; then
  echo -n "count: "; cat /proc/sys/net/netfilter/nf_conntrack_count
  echo -n "max: "; cat /proc/sys/net/netfilter/nf_conntrack_max 2>/dev/null || true
else
  echo "skip: conntrack tool and /proc counters unavailable"
fi
