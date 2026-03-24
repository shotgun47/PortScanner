#!/bin/sh
# Generic scenario injector/runner from local terminal.
# Usage:
#   ./scenarios/scenario_setup.sh <scenario_name> [container_name]
# Example:
#   ./scenarios/scenario_setup.sh redis_drift

set -eu

if [ "$#" -lt 1 ] || [ "$#" -gt 2 ]; then
  echo "usage: $0 <scenario_name> [container_name]" >&2
  exit 1
fi

SCENARIO_NAME="$1"
CONTAINER_OVERRIDE="${2:-}"
SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
SCENARIO_DIR="$SCRIPT_DIR/$SCENARIO_NAME"
SCENARIO_SCRIPT="$SCENARIO_DIR/scenario.sh"
METADATA_FILE="$SCENARIO_DIR/metadata.json"
SCRIPT_DEST="/tmp/${SCENARIO_NAME}_scenario.sh"
BUSYBOX_IMAGE="${SCENARIO_BUSYBOX_IMAGE:-alpine:3.20}"
BUSYBOX_DEST="${BUSYBOX_DEST:-/tmp/busybox}"
BUSYBOX_CACHE="${SCENARIO_BUSYBOX_CACHE:-$SCRIPT_DIR/.busybox.static}"
BUSYBOX_CACHE_LOCK="${BUSYBOX_CACHE}.lock"
BUSYBOX_SHIM_DIR="${BUSYBOX_SHIM_DIR:-/tmp/.scenario-bin}"
EXEC_SHELL_MODE=""

if [ ! -f "$SCENARIO_SCRIPT" ]; then
  echo "scenario script not found: $SCENARIO_SCRIPT" >&2
  exit 1
fi

DOCKER_BIN="${DOCKER_BIN:-$(command -v docker 2>/dev/null || true)}"

if [ -z "$DOCKER_BIN" ] && [ -x /usr/bin/docker ]; then
  DOCKER_BIN="/usr/bin/docker"
fi
if [ -z "$DOCKER_BIN" ] && [ -x /usr/local/bin/docker ]; then
  DOCKER_BIN="/usr/local/bin/docker"
fi

if [ -z "$DOCKER_BIN" ]; then
  echo "docker command is required" >&2
  exit 1
fi

docker_exec() {
  MSYS_NO_PATHCONV=1 "$DOCKER_BIN" exec "$@"
}

get_container_from_metadata() {
  metadata_path="$1"
  if [ ! -f "$metadata_path" ]; then
    echo ""
    return 0
  fi

  parsed="$(tr -d '\n' < "$metadata_path" | sed -n 's/.*"container_name"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' | head -n 1)"
  if [ -n "$parsed" ]; then
    echo "$parsed"
    return 0
  fi

  echo ""
}

ensure_busybox_cache() {
  if [ -f "$BUSYBOX_CACHE" ]; then
    return 0
  fi

  if mkdir "$BUSYBOX_CACHE_LOCK" 2>/dev/null; then
    mkdir -p "$(dirname "$BUSYBOX_CACHE")"
    helper_tmp="$(mktemp "${TMPDIR:-/tmp}/scenario_busybox.XXXXXX")"
    if ! "$DOCKER_BIN" run --rm "$BUSYBOX_IMAGE" sh -lc "apk add --no-cache busybox-static >/dev/null 2>&1 && cat /bin/busybox.static" > "$helper_tmp"; then
      rm -f "$helper_tmp"
      rmdir "$BUSYBOX_CACHE_LOCK" >/dev/null 2>&1 || true
      return 1
    fi
    mv "$helper_tmp" "$BUSYBOX_CACHE"
    rmdir "$BUSYBOX_CACHE_LOCK" >/dev/null 2>&1 || true
    return 0
  fi

  wait_count=0
  while [ "$wait_count" -lt 60 ]; do
    if [ -f "$BUSYBOX_CACHE" ]; then
      return 0
    fi
    sleep 1
    wait_count=$((wait_count + 1))
  done

  return 1
}

prepare_busybox_helper() {
  if docker_exec "$CONTAINER_NAME" "$BUSYBOX_DEST" sh -lc "true" >/dev/null 2>&1; then
    return 0
  fi

  if ! ensure_busybox_cache; then
    return 1
  fi

  if ! "$DOCKER_BIN" cp "$BUSYBOX_CACHE" "$CONTAINER_NAME:$BUSYBOX_DEST" >/dev/null 2>&1; then
    return 1
  fi

  docker_exec "$CONTAINER_NAME" chmod +x "$BUSYBOX_DEST" >/dev/null 2>&1 || true
  docker_exec "$CONTAINER_NAME" "$BUSYBOX_DEST" chmod +x "$BUSYBOX_DEST" >/dev/null 2>&1 || true

  docker_exec "$CONTAINER_NAME" "$BUSYBOX_DEST" sh -lc "true" >/dev/null 2>&1
}

resolve_exec_shell() {
  if docker_exec "$CONTAINER_NAME" sh -lc "true" >/dev/null 2>&1; then
    EXEC_SHELL_MODE="native"
    return 0
  fi

  if docker_exec "$CONTAINER_NAME" "$BUSYBOX_DEST" sh -lc "true" >/dev/null 2>&1; then
    EXEC_SHELL_MODE="busybox"
    return 0
  fi

  return 1
}

run_shell() {
  cmd="$1"
  if [ "$EXEC_SHELL_MODE" = "native" ]; then
    docker_exec "$CONTAINER_NAME" sh -lc "$cmd"
    return $?
  fi
  docker_exec "$CONTAINER_NAME" "$BUSYBOX_DEST" sh -lc "$cmd"
}

prepare_busybox_shims() {
  run_shell "
    $BUSYBOX_DEST mkdir -p '$BUSYBOX_SHIM_DIR';
    for cmd in sh mkdir rm cat kill sleep date od chmod nohup grep tr ps awk sed head tail ln; do
      $BUSYBOX_DEST ln -sf '$BUSYBOX_DEST' '$BUSYBOX_SHIM_DIR'/\$cmd >/dev/null 2>&1 || true;
    done
  " >/dev/null 2>&1
}

CONTAINER_NAME="$CONTAINER_OVERRIDE"
if [ -z "$CONTAINER_NAME" ]; then
  CONTAINER_NAME="$(get_container_from_metadata "$METADATA_FILE")"
fi

if [ -z "$CONTAINER_NAME" ]; then
  echo "container name is required. set metadata.json.container_name or pass it as 2nd argument." >&2
  exit 1
fi

if ! "$DOCKER_BIN" ps --format '{{.Names}}' | grep -Fxq "$CONTAINER_NAME"; then
  echo "container not running: $CONTAINER_NAME" >&2
  exit 1
fi

if ! prepare_busybox_helper; then
  echo "failed to prepare busybox helper in container: $CONTAINER_NAME" >&2
  exit 1
fi

if ! resolve_exec_shell; then
  echo "failed to resolve executable shell in container: $CONTAINER_NAME" >&2
  exit 1
fi

prepare_busybox_shims || true

"$DOCKER_BIN" cp "$SCENARIO_SCRIPT" "$CONTAINER_NAME:$SCRIPT_DEST"
docker_exec "$CONTAINER_NAME" chmod +x "$SCRIPT_DEST" >/dev/null 2>&1 || \
  docker_exec "$CONTAINER_NAME" "$BUSYBOX_DEST" chmod +x "$SCRIPT_DEST" >/dev/null 2>&1 || true
run_shell "(command -v pkill >/dev/null 2>&1 && pkill -f '$SCRIPT_DEST') >/dev/null 2>&1 || true" >/dev/null 2>&1 || true

if [ "$EXEC_SHELL_MODE" = "native" ]; then
  docker_exec -d "$CONTAINER_NAME" sh -lc "PATH='$BUSYBOX_SHIM_DIR':\$PATH BUSYBOX_BIN='$BUSYBOX_DEST' sh '$SCRIPT_DEST'" >/dev/null
else
  docker_exec -d "$CONTAINER_NAME" "$BUSYBOX_DEST" sh -lc "PATH='$BUSYBOX_SHIM_DIR':\$PATH BUSYBOX_BIN='$BUSYBOX_DEST' '$BUSYBOX_DEST' sh '$SCRIPT_DEST'" >/dev/null
fi

echo "scenario started"
echo "- name: $SCENARIO_NAME"
echo "- container: $CONTAINER_NAME"
echo "- script_dest: $SCRIPT_DEST"
if [ "$EXEC_SHELL_MODE" = "native" ]; then
  echo "- monitor: docker exec -it $CONTAINER_NAME sh -lc \"ps -ef | grep -E 'scenario|redis|nc' && netstat -tpln\""
else
  echo "- monitor: docker exec -it $CONTAINER_NAME $BUSYBOX_DEST sh -lc \"ps -ef | grep -E 'scenario|redis|nc' && netstat -tpln\""
fi
