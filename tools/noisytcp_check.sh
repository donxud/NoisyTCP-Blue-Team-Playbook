#!/usr/bin/env bash
# noisytcp_check.sh - read-only exposure check for NoisyTCP (CVE-2026-99288)
#
# Reports, for this host: booted kernel, whether the fix is recorded in the
# package changelog (Debian/Ubuntu) or kernel RPM changelog (RHEL family),
# TCP listeners, RX queue / RPS precondition, and tcp_syncookies.
# It changes nothing and sends no network traffic.
#
# Output: one JSON line (for SIEM/SOAR ingestion) unless --text is given.
# Exit codes: 0 = FIXED or NOT_EXPOSED (no listener, or single queue and no RPS;
#                 still patch in the normal window), 1 = EXPOSED or MITIGATED,
#             2 = UNKNOWN (needs manual review)
#
# Usage: sudo ./noisytcp_check.sh [--text] [interface ...]
#        Interfaces default to every non-loopback interface.

set -u
CVE="CVE-2026-99288"
TEXT=0
IFACES=()
for arg in "$@"; do
  case "$arg" in
    --text) TEXT=1 ;;
    -h|--help) sed -n '2,16p' "$0"; exit 0 ;;
    *) IFACES+=("$arg") ;;
  esac
done
if [ ${#IFACES[@]} -eq 0 ]; then
  for d in /sys/class/net/*; do
    n=$(basename "$d"); [ "$n" = "lo" ] && continue
    [ -d "$d/queues" ] && IFACES+=("$n")
  done
fi

KERNEL=$(uname -r)
HOST=$(hostname)

# --- 1. Is the fix recorded for the booted kernel? -------------------------
FIX="unknown"
deb_log=$(ls /usr/share/doc/linux-image-"$KERNEL"/changelog*.gz 2>/dev/null | head -n1)
if [ -n "$deb_log" ]; then
  if zgrep -q "$CVE" "$deb_log" 2>/dev/null; then FIX="yes"; else FIX="not_in_changelog"; fi
elif command -v rpm >/dev/null 2>&1 && rpm -q "kernel-$KERNEL" >/dev/null 2>&1; then
  if rpm -q --changelog "kernel-$KERNEL" 2>/dev/null | grep -q "$CVE"; then FIX="yes"; else FIX="not_in_changelog"; fi
fi
# RHEL 6/7 and CentOS 7 kernels predate the vulnerable code.
case "$KERNEL" in
  2.6.*|3.10.*) FIX="not_affected" ;;
esac

# --- 2. Reachable TCP listeners (non-loopback) ------------------------------
if command -v ss >/dev/null 2>&1; then
  LISTENERS=$(ss -Hltn 2>/dev/null | awk '{print $4}' \
    | grep -vE '^(127\.|\[::1\]|::1)' | sort -u | tr '\n' ' ' | sed 's/ $//')
elif [ -r /proc/net/tcp ]; then
  # Fallback without iproute2: state 0A = LISTEN; skip IPv4/IPv6 loopback.
  LISTENERS=$(cat /proc/net/tcp /proc/net/tcp6 2>/dev/null \
    | awk '$4 == "0A" { split($2, a, ":"); if (a[1] != "0100007F" && a[1] != "00000000000000000000000001000000") print a[2] }' \
    | while read -r h; do printf '*:%d\n' "0x$h"; done | sort -u | tr '\n' ' ' | sed 's/ $//')
else
  LISTENERS="?"
fi

# --- 3. Multi-queue / RPS precondition --------------------------------------
MULTIQ="no"
DETAIL=""
for i in "${IFACES[@]}"; do
  rxq=$(ls -d /sys/class/net/"$i"/queues/rx-* 2>/dev/null | wc -l)
  rps_on=0
  for f in /sys/class/net/"$i"/queues/rx-*/rps_cpus; do
    [ -r "$f" ] || continue
    v=$(tr -d ',0\n' < "$f")
    [ -n "$v" ] && rps_on=1
  done
  DETAIL="$DETAIL$i:rxq=$rxq,rps=$rps_on "
  if [ "$rxq" -gt 1 ] || [ "$rps_on" -eq 1 ]; then MULTIQ="yes"; fi
done
DETAIL=$(echo "$DETAIL" | sed 's/ $//')

SYNCOOKIES=$(sysctl -n net.ipv4.tcp_syncookies 2>/dev/null || echo "?")

# --- 4. Verdict --------------------------------------------------------------
if [ "$FIX" = "yes" ] || [ "$FIX" = "not_affected" ]; then
  STATUS="FIXED"; RC=0
elif [ "$LISTENERS" = "?" ]; then
  STATUS="UNKNOWN"; RC=2
elif [ -z "$LISTENERS" ] || [ "$MULTIQ" = "no" ]; then
  # No reachable listener, or one RX queue with RPS off: precondition absent.
  # Still patch in the normal window and re-check after NIC/kernel tuning.
  STATUS="NOT_EXPOSED"; RC=0
elif [ "$SYNCOOKIES" = "0" ]; then
  STATUS="MITIGATED"; RC=1
elif [ "$FIX" = "unknown" ]; then
  STATUS="UNKNOWN"; RC=2
else
  STATUS="EXPOSED"; RC=1
fi

if [ "$TEXT" -eq 1 ]; then
  printf 'host:        %s\nkernel:      %s\nfix_logged:  %s\nlisteners:   %s\nmultiqueue:  %s (%s)\nsyncookies:  %s\nSTATUS:      %s\n' \
    "$HOST" "$KERNEL" "$FIX" "${LISTENERS:-none}" "$MULTIQ" "$DETAIL" "$SYNCOOKIES" "$STATUS"
  [ "$STATUS" = "UNKNOWN" ] && echo "note: compare the kernel package with your vendor advisory."
  [ "$STATUS" = "MITIGATED" ] && echo "note: SYN cookies are off as a workaround; the kernel still needs the fix."
  [ "$STATUS" = "NOT_EXPOSED" ] && echo "note: precondition absent today; patch in the normal window and re-check after NIC changes."
else
  printf '{"check":"noisytcp","cve":"%s","host":"%s","kernel":"%s","fix_logged":"%s","listeners":"%s","multiqueue":"%s","queues":"%s","syncookies":"%s","status":"%s"}\n' \
    "$CVE" "$HOST" "$KERNEL" "$FIX" "$LISTENERS" "$MULTIQ" "$DETAIL" "$SYNCOOKIES" "$STATUS"
fi
exit $RC
