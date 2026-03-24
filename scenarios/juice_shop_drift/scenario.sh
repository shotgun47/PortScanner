#!/bin/sh
# juice_shop_drift: random port drift simulation inside target container.
# This script only controls helper listeners started by itself.

set -u

SCENARIO_NAME="${SCENARIO_NAME:-juice_shop_drift}"
DEFAULT_PORTS="3000 8080 3306"
DRIFT_PORTS="${DRIFT_PORTS:-$DEFAULT_PORTS}"
MIN_SLEEP="${MIN_SLEEP:-60}"
MAX_SLEEP="${MAX_SLEEP:-180}"
STATE_DIR="/tmp/${SCENARIO_NAME}"
LOG_PREFIX="[$SCENARIO_NAME]"
LISTENER_BACKEND="none"
NC_MODE="plain"

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

validate_sleep_bounds() {
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
}

has_valid_ports() {
  for port in $DRIFT_PORTS; do
    case "$port" in
      ''|*[!0-9]*)
        ;;
      *)
        if [ "$port" -ge 1 ] && [ "$port" -le 65535 ]; then
          return 0
        fi
        ;;
    esac
  done
  return 1
}

detect_listener_backend() {
  if command -v python3 >/dev/null 2>&1; then
    LISTENER_BACKEND="python3"
    return
  fi

  if command -v python >/dev/null 2>&1; then
    LISTENER_BACKEND="python"
    return
  fi

  if command -v nc >/dev/null 2>&1; then
    LISTENER_BACKEND="nc"
    if nc -h 2>&1 | grep -q -- "-p "; then
      NC_MODE="with-port-flag"
    else
      NC_MODE="plain"
    fi
    return
  fi

  if command -v node >/dev/null 2>&1; then
    LISTENER_BACKEND="node"
    return
  fi

  LISTENER_BACKEND="none"
}

write_listener_helpers() {
  if [ "$LISTENER_BACKEND" = "python3" ] || [ "$LISTENER_BACKEND" = "python" ]; then
    cat > "$STATE_DIR/tcp_listener.py" <<'PY'
import socket
import sys

port = int(sys.argv[1])
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
sock.bind(("0.0.0.0", port))
sock.listen(64)

while True:
    conn, _addr = sock.accept()
    try:
        conn.sendall(b"OK\\n")
    except Exception:
        pass
    finally:
        conn.close()
PY
    chmod +x "$STATE_DIR/tcp_listener.py"
    return
  fi

  if [ "$LISTENER_BACKEND" = "node" ]; then
    cat > "$STATE_DIR/tcp_listener.js" <<'JS'
const net = require("net");
const port = parseInt(process.argv[2], 10);
const server = net.createServer((socket) => {
  socket.end("OK\\n");
});
server.listen(port, "0.0.0.0");
setInterval(() => {}, 1 << 30);
JS
    chmod +x "$STATE_DIR/tcp_listener.js"
  fi
}

start_tcp_listener() {
  port="$1"
  pid_file="$STATE_DIR/listener_${port}.pid"

  if pid_alive "$pid_file"; then
    return 1
  fi

  case "$LISTENER_BACKEND" in
    python3|python)
      nohup "$LISTENER_BACKEND" "$STATE_DIR/tcp_listener.py" "$port" >/dev/null 2>&1 &
      ;;
    nc)
      if [ "$NC_MODE" = "with-port-flag" ]; then
        nohup nc -lk -p "$port" >/dev/null 2>&1 &
      else
        nohup nc -lk "$port" >/dev/null 2>&1 &
      fi
      ;;
    node)
      nohup node "$STATE_DIR/tcp_listener.js" "$port" >/dev/null 2>&1 &
      ;;
    *)
      return 1
      ;;
  esac

  echo "$!" > "$pid_file"
  sleep 1
  if pid_alive "$pid_file"; then
    return 0
  fi

  rm -f "$pid_file"
  return 1
}

stop_tcp_listener() {
  port="$1"
  pid_file="$STATE_DIR/listener_${port}.pid"

  if pid_alive "$pid_file"; then
    kill_pid_file "$pid_file"
    return 0
  fi

  rm -f "$pid_file"
  return 1
}

cleanup() {
  for port in $DRIFT_PORTS; do
    case "$port" in
      ''|*[!0-9]*)
        ;;
      *)
        stop_tcp_listener "$port" >/dev/null 2>&1 || true
        ;;
    esac
  done
}
trap cleanup INT TERM

preflight() {
  validate_sleep_bounds

  detect_listener_backend
  if [ "$LISTENER_BACKEND" = "none" ]; then
    log "ERROR: no listener backend found (requires python/nc/node)"
    exit 1
  fi

  if ! has_valid_ports; then
    log "ERROR: DRIFT_PORTS has no valid ports"
    exit 1
  fi

  write_listener_helpers
  log "preflight: backend=$LISTENER_BACKEND ports=\"$DRIFT_PORTS\" sleep=${MIN_SLEEP}-${MAX_SLEEP}s"
}

preflight
log "scenario loop started"

while true; do
  sleep_time="$(rand_between "$MIN_SLEEP" "$MAX_SLEEP")"
  log "drift tick started"

  for port in $DRIFT_PORTS; do
    case "$port" in
      ''|*[!0-9]*)
        log "skip invalid port token: $port"
        continue
        ;;
      *)
        if [ "$port" -lt 1 ] || [ "$port" -gt 65535 ]; then
          log "skip out-of-range port: $port"
          continue
        fi
        ;;
    esac

    if coin_flip; then
      if start_tcp_listener "$port"; then
        log "open simulation: tcp/$port"
      else
        log "open simulation skipped/failed: tcp/$port"
      fi
    else
      if stop_tcp_listener "$port"; then
        log "close simulation: tcp/$port"
      else
        log "close simulation skipped: tcp/$port"
      fi
    fi
  done

  log "sleep ${sleep_time}s before next drift tick"
  sleep "$sleep_time"
done
