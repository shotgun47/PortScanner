# Scenario Authoring Guide

Use this folder to manage shared drift scenarios.

## Folder Layout

```text
scenarios/
  scenario_setup.sh
  <scenario_name>/
    scenario.sh
    metadata.json
```

Examples:

- `scenarios/redis_drift/scenario.sh`
- `scenarios/redis_drift/metadata.json`
- `scenarios/samba_drift/scenario.sh`
- `scenarios/samba_drift/metadata.json`
- `scenarios/tomcat_drift/scenario.sh`
- `scenarios/juice_shop_drift/scenario.sh`
- `scenarios/mysql_drift/scenario.sh`
- `scenarios/elasticsearch_drift/scenario.sh`
- `scenarios/vsftpd_drift/scenario.sh`

## Rules

1. Keep the scenario body in one file: `scenario.sh`.
2. Assume `scenario.sh` runs inside the target container.
3. Do not hardcode container or host in the script; use backend registry metadata instead.
4. Do not kill the container main process.
5. Make drift behavior explicit (ports and/or services must clearly change over time).

## Runtime Preconditions

1. `scenario.sh` should fail fast with a clear log when required binaries are missing.
2. Every scenario should be idempotent for parallel operations:
- If the same scenario is triggered multiple times, only one active loop should remain.
- Use lock + pid guard (do not accumulate duplicate loops in one container).
3. For `redis_drift`:
- `redis-server` and `redis-cli` are required.
- `nc` is preferred for tcp/22 and tcp/80 simulation.
- If `nc` is missing, runner-provided `busybox` fallback should be used.
- If Redis is PID 1 in the container, 6379 start/stop drift must be disabled to avoid killing the main process.
4. Always keep a preflight check at startup so unsupported environments do not silently pass.
5. `scenario_setup.sh` and backend runner inject `/tmp/busybox` and `/tmp/.scenario-bin` shims for low-feature containers (for example, missing `sh` or core utils).

## Backend Registry Fields (`metadata.json`)

Each scenario folder should include `metadata.json`.

Required fields:

- `name`: scenario name
- `target_hint`: target identifier hint
- `container_name`: target container name
- `script_path`: script path (example: `scenarios/redis_drift/scenario.sh`)
- `description`: scenario description

Example:

```json
{
  "name": "redis_drift",
  "target_hint": "redis-4-unacc.lab.local",
  "container_name": "vuln-redis-4-unacc",
  "script_path": "scenarios/redis_drift/scenario.sh",
  "description": "Randomly toggles Redis/SSH/HTTP ports to induce drift."
}
```

## Run

From local terminal:

```sh
./scenario_setup.sh redis_drift
```

```sh
./scenario_setup.sh tomcat_drift
```

```sh
./scenario_setup.sh samba_drift
```

Or:

```sh
./scenarios/scenario_setup.sh redis_drift
```

Container status check:

```sh
docker exec -it vuln-redis-4-unacc sh -lc "ps -ef | grep -E 'scenario|redis|nc' && netstat -tpln"
```

## Scenario List

- `redis_drift` -> `vuln-redis-4-unacc`
- `tomcat_drift` -> `vuln-tomcat-cve-2017-12615`
- `samba_drift` -> `vuln-sambacry`
- `juice_shop_drift` -> `vuln-juice-shop`
- `mysql_drift` -> `vuln-mysql-cve-2012-2122`
- `elasticsearch_drift` -> `vuln-elasticsearch-cve-2015-1427`
- `vsftpd_drift` -> `vuln-vsftpd-2-3-4`
