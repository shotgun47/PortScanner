#!/bin/sh
set -u

LOCK_DIR="/tmp/host_presence_drift.lock"
PID_FILE="$LOCK_DIR/pid"
STATE_FILE="$LOCK_DIR/state"
IFACE="${IFACE:-eth0}"

log() {
  echo "[host_presence_drift] $1"
}

cleanup() {
  ip link set "$IFACE" up >/dev/null 2>&1 || true
  rm -rf "$LOCK_DIR"
}

trap cleanup EXIT INT TERM

if ! command -v ip >/dev/null 2>&1; then
  log "ip command not found"
  exit 1
fi

if ! ip link show "$IFACE" >/dev/null 2>&1; then
  log "interface not found: $IFACE"
  exit 1
fi

if mkdir "$LOCK_DIR" >/dev/null 2>&1; then
  echo $$ > "$PID_FILE"
else
  if [ -f "$PID_FILE" ]; then
    OLD_PID="$(cat "$PID_FILE" 2>/dev/null || true)"
    if [ -n "${OLD_PID:-}" ] && kill -0 "$OLD_PID" >/dev/null 2>&1; then
      log "already running pid=$OLD_PID"
      exit 0
    fi
  fi
  rm -rf "$LOCK_DIR"
  mkdir "$LOCK_DIR" || exit 1
  echo $$ > "$PID_FILE"
fi

rand_sleep() {
  min="$1"
  max="$2"
  span=$((max - min + 1))
  r="$(od -An -N2 -tu2 /dev/urandom 2>/dev/null | tr -d ' ')"
  [ -z "$r" ] && r=7
  echo $((min + (r % span)))
}

host_down() {
  ip link set "$IFACE" down
  echo "down" > "$STATE_FILE"
  log "$IFACE down -> host should disappear from inventory"
}

host_up() {
  ip link set "$IFACE" up
  echo "up" > "$STATE_FILE"
  log "$IFACE up -> host should reappear in inventory"
}

host_up

while true; do
  sleep "$(rand_sleep 20 40)"
  host_down
  sleep "$(rand_sleep 15 25)"
  host_up
done