#!/bin/sh
# redis_drift: random service/port drift inside the target container.
# This script must run inside the container and avoid killing PID 1.

set -u

STATE_DIR="/tmp/redis_drift"
LOCK_DIR="$STATE_DIR/.lock"
PID_FILE="$STATE_DIR/scenario.pid"
LOG_PREFIX="[redis_drift]"
MIN_SLEEP="${MIN_SLEEP:-60}"
MAX_SLEEP="${MAX_SLEEP:-180}"
REDIS_PID_FILE="$STATE_DIR/redis.pid"
REDIS_MODE="managed"
ENABLE_REDIS_DRIFT=1
ENABLE_TCP_DRIFT=1
NC_MODE="none"
BUSYBOX_BIN="${BUSYBOX_BIN:-/tmp/busybox}"

mkdir -p "$STATE_DIR"

log() {
  printf '%s %s %s\n' "$(date '+%Y-%m-%d %H:%M:%S')" "$LOG_PREFIX" "$*"
}

rand_between() {
  min="$1"
  max="$2"
  range=$((max - min + 1))

  if [ -r /dev/urandom ] && command -v od >/dev/null 2>&1; then
    raw="$(od -An -N2 -tu2 /dev/urandom 2>/dev/null | tr -d '[:space:]')"
  else
    raw="$(date +%s)"
  fi
  [ -n "$raw" ] || raw=0
  echo $(( (raw % range) + min ))
}

coin_flip() {
  [ "$(rand_between 0 1)" -eq 1 ]
}

pid_alive() {
  pid_file="$1"
  [ -f "$pid_file" ] || return 1
  pid="$(cat "$pid_file" 2>/dev/null || true)"
  [ -n "$pid" ] || return 1
  kill -0 "$pid" 2>/dev/null
}

kill_pid_file() {
  pid_file="$1"
  if ! pid_alive "$pid_file"; then
    rm -f "$pid_file"
    return 0
  fi
  pid="$(cat "$pid_file")"
  if [ "$pid" -eq 1 ] 2>/dev/null; then
    log "skip kill for PID 1 ($pid_file)"
    return 0
  fi
  kill "$pid" >/dev/null 2>&1 || true
  sleep 1
  kill -9 "$pid" >/dev/null 2>&1 || true
  rm -f "$pid_file"
}

acquire_lock() {
  if mkdir "$LOCK_DIR" 2>/dev/null; then
    echo "$$" > "$PID_FILE"
    return 0
  fi

  old_pid=""
  if [ -f "$PID_FILE" ]; then
    old_pid="$(cat "$PID_FILE" 2>/dev/null || true)"
  fi
  if [ -n "$old_pid" ] && kill -0 "$old_pid" 2>/dev/null; then
    log "another instance already running (pid=$old_pid); exiting"
    exit 0
  fi

  rm -rf "$LOCK_DIR" >/dev/null 2>&1 || true
  if mkdir "$LOCK_DIR" 2>/dev/null; then
    echo "$$" > "$PID_FILE"
    return 0
  fi

  log "ERROR: failed to acquire scenario lock"
  exit 1
}

release_lock() {
  rm -f "$PID_FILE" >/dev/null 2>&1 || true
  rm -rf "$LOCK_DIR" >/dev/null 2>&1 || true
}

detect_nc_mode() {
  if command -v nc >/dev/null 2>&1; then
    nc_help="$(nc -h 2>&1 || true)"
    if printf '%s' "$nc_help" | grep -q -- "-p "; then
      echo "with-port-flag"
      return
    fi
    echo "plain"
    return
  fi

  if [ -x "$BUSYBOX_BIN" ] && "$BUSYBOX_BIN" nc 2>&1 | grep -q "Usage: nc"; then
    echo "busybox"
    return
  fi

  if ! command -v nc >/dev/null 2>&1; then
    echo "none"
    return
  fi
}

is_pid1_redis() {
  if [ ! -r /proc/1/cmdline ]; then
    return 1
  fi
  pid1_cmd="$(tr '\000' ' ' < /proc/1/cmdline 2>/dev/null || true)"
  case "$pid1_cmd" in
    *redis-server*)
      return 0
      ;;
    *)
      return 1
      ;;
  esac
}

preflight() {
  case "$MIN_SLEEP" in
    ''|*[!0-9]*)
      log "ERROR: MIN_SLEEP must be a positive integer"
      exit 1
      ;;
  esac
  case "$MAX_SLEEP" in
    ''|*[!0-9]*)
      log "ERROR: MAX_SLEEP must be a positive integer"
      exit 1
      ;;
  esac
  if [ "$MIN_SLEEP" -lt 1 ] || [ "$MAX_SLEEP" -lt 1 ] || [ "$MIN_SLEEP" -gt "$MAX_SLEEP" ]; then
    log "ERROR: sleep bounds must satisfy 1 <= MIN_SLEEP <= MAX_SLEEP"
    exit 1
  fi

  acquire_lock

  if ! command -v redis-server >/dev/null 2>&1; then
    log "ERROR: redis-server not found; cannot run redis_drift"
    exit 1
  fi

  if is_pid1_redis; then
    REDIS_MODE="pid1-locked"
    ENABLE_REDIS_DRIFT=0
    log "INFO: redis-server is PID 1; 6379 start/stop drift disabled to protect main process"
  fi

  NC_MODE="$(detect_nc_mode)"
  if [ "$NC_MODE" = "none" ]; then
    ENABLE_TCP_DRIFT=0
    log "INFO: nc not found; tcp/22 and tcp/80 drift disabled (no busybox fallback)"
  fi

  if [ "$ENABLE_REDIS_DRIFT" -eq 0 ] && [ "$ENABLE_TCP_DRIFT" -eq 0 ]; then
    log "ERROR: no drift actions available in this container; exiting"
    exit 1
  fi

  log "preflight: redis_drift=$ENABLE_REDIS_DRIFT tcp_drift=$ENABLE_TCP_DRIFT nc_mode=$NC_MODE redis_mode=$REDIS_MODE"
}

start_tcp_listener() {
  port="$1"
  pid_file="$STATE_DIR/nc_${port}.pid"

  if [ "$NC_MODE" = "none" ]; then
    log "nc is not installed; cannot simulate tcp/$port"
    return 0
  fi

  if pid_alive "$pid_file"; then
    return 0
  fi

  case "$NC_MODE" in
    with-port-flag)
      listen_cmd="nc -l -p $port"
      ;;
    plain)
      listen_cmd="nc -l $port"
      ;;
    busybox)
      listen_cmd="$BUSYBOX_BIN nc -l -p $port"
      ;;
    *)
      log "unsupported nc mode: $NC_MODE"
      return 1
      ;;
  esac

  # Use a loop to keep the listener alive after each client disconnect.
  nohup sh -c "while true; do $listen_cmd >/dev/null 2>&1; done" >/dev/null 2>&1 &
  echo "$!" > "$pid_file"
}

stop_tcp_listener() {
  port="$1"
  pid_file="$STATE_DIR/nc_${port}.pid"
  kill_pid_file "$pid_file"
}

start_redis() {
  if [ "$ENABLE_REDIS_DRIFT" -eq 0 ]; then
    return 1
  fi

  if pid_alive "$REDIS_PID_FILE"; then
    return 1
  fi

  redis-server \
    --daemonize yes \
    --bind 0.0.0.0 \
    --protected-mode no \
    --port 6379 \
    --pidfile "$REDIS_PID_FILE" >/dev/null 2>&1 || return 1

  sleep 1
  pid_alive "$REDIS_PID_FILE"
}

stop_redis() {
  if [ "$ENABLE_REDIS_DRIFT" -eq 0 ]; then
    return 1
  fi

  if ! pid_alive "$REDIS_PID_FILE"; then
    rm -f "$REDIS_PID_FILE"
    return 1
  fi

  redis_pid="$(cat "$REDIS_PID_FILE")"
  if [ "$redis_pid" -eq 1 ] 2>/dev/null; then
    log "skip redis stop for PID 1"
    return 0
  fi

  if command -v redis-cli >/dev/null 2>&1; then
    redis-cli -p 6379 shutdown nosave >/dev/null 2>&1 || true
  fi
  kill "$redis_pid" >/dev/null 2>&1 || true
  sleep 1
  kill -9 "$redis_pid" >/dev/null 2>&1 || true
  rm -f "$REDIS_PID_FILE"

  if pid_alive "$REDIS_PID_FILE"; then
    return 1
  fi
  return 0
}

cleanup() {
  stop_tcp_listener 22
  stop_tcp_listener 80
  release_lock
}
trap cleanup INT TERM EXIT

preflight

log "scenario loop started (random interval ${MIN_SLEEP}-${MAX_SLEEP}s)"

while true; do
  sleep_time="$(rand_between "$MIN_SLEEP" "$MAX_SLEEP")"
  log "drift tick started"

  if [ "$ENABLE_REDIS_DRIFT" -eq 1 ]; then
    if coin_flip; then
      if start_redis; then
        log "redis: open (6379)"
      else
        log "redis: open attempt skipped/failed (6379)"
      fi
    else
      if stop_redis; then
        log "redis: close (6379)"
      else
        log "redis: close attempt skipped/failed (6379)"
      fi
    fi
  fi

  if [ "$ENABLE_TCP_DRIFT" -eq 1 ]; then
    if coin_flip; then
      start_tcp_listener 22
      log "ssh simulation: open (22)"
    else
      stop_tcp_listener 22
      log "ssh simulation: close (22)"
    fi

    if coin_flip; then
      start_tcp_listener 80
      log "http simulation: open (80)"
    else
      stop_tcp_listener 80
      log "http simulation: close (80)"
    fi
  fi

  log "sleep ${sleep_time}s before next drift tick"
  sleep "$sleep_time"
done
