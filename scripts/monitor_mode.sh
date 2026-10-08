#!/usr/bin/env bash
set -euo pipefail

action="${1:-}"
interface="${2:-}"

if [[ -z "$action" || -z "$interface" ]]; then
  echo "usage: sudo $0 {up|down} <interface>" >&2
  exit 64
fi

case "$action" in
  up)
    nmcli device set "$interface" managed no 2>/dev/null || true
    ip link set "$interface" down
    iw dev "$interface" set type monitor
    ip link set "$interface" up
    echo "$interface is in monitor mode"
    ;;
  down)
    ip link set "$interface" down
    iw dev "$interface" set type managed
    ip link set "$interface" up
    nmcli device set "$interface" managed yes 2>/dev/null || true
    echo "$interface restored to managed mode"
    ;;
  *)
    echo "unknown action: $action" >&2
    exit 64
    ;;
esac
