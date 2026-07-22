#!/bin/bash
# Full sluice-vs-nginx-vs-caddy benchmark matrix. One server under test at a
# time; each phase starts the server fresh, records idle RSS, runs the
# workloads via bench_one.sh, then SIGKILLs it (SIGKILL on purpose: a
# SIGTERM'd sluice/caddy drains gracefully and would keep the port via
# SO_REUSEPORT, splitting the next phase's traffic).
# Env overrides: BENCH_DIR (/srv/bench), SLUICE_BIN, CADDY_BIN, OHA is
# resolved by bench_one.sh.
set -u
ulimit -n 65535
R=${BENCH_DIR:-/srv/bench}/results
B=${BENCH_DIR:-/srv/bench}
SL=${SLUICE_BIN:-/root/bench/sluice-src/target/release/sluice}
CADDY=${CADDY_BIN:-/root/bench/caddy}

start_sluice() { SLUICE_ALLOW_ROOT=1 nohup "$SL" -c "$1" > "$B/log/sluice.log" 2>&1 & echo $!; }
start_caddy()  { nohup "$CADDY" run --config "$1" --adapter caddyfile > "$B/log/caddy.log" 2>&1 & echo $!; }
start_nginx()  { nginx -c "$1"; sleep 1; cat "$B/run/nginx.pid"; }

idle_rss() { python3 "$B/sampler.py" "$1" 2 | python3 -c 'import sys,json; print(json.load(sys.stdin)["peak_rss_mib"])'; }

run_workloads() {  # $1=name $2=pid $3=baseurl $4=mode
  local name=$1 pid=$2 base=$3 mode=$4
  sleep 3
  echo "idle_rss_mib $(idle_rss "$pid")" > "$R/${name}-${mode}.idle"
  if [ "$mode" = static ]; then
    for conc in 50 200; do
      "$B/bench_one.sh" "${name}-static1k"   "$base/1k.bin"   "$conc" "$pid" "$R"
      "$B/bench_one.sh" "${name}-static100k" "$base/100k.bin" "$conc" "$pid" "$R"
    done
  else
    for conc in 50 200; do
      "$B/bench_one.sh" "${name}-proxy1k" "$base/1k.bin" "$conc" "$pid" "$R"
    done
  fi
}

nginx -c "$B/origin.conf" 2>/dev/null || true   # shared plaintext origin :18000

echo "=== sluice static ==="
PID=$(start_sluice "$B/sluice-static.kdl")
run_workloads sluice "$PID" https://127.0.0.1:18081 static
kill -9 "$PID"; sleep 2

echo "=== sluice proxy ==="
PID=$(start_sluice "$B/sluice-proxy.kdl")
run_workloads sluice "$PID" https://127.0.0.1:18081 proxy
kill -9 "$PID"; sleep 2

echo "=== nginx static ==="
PID=$(start_nginx "$B/nginx-static.conf")
run_workloads nginx "$PID" https://127.0.0.1:18083 static
nginx -s stop -c "$B/nginx-static.conf"; sleep 2

echo "=== nginx proxy ==="
PID=$(start_nginx "$B/nginx-proxy.conf")
run_workloads nginx "$PID" https://127.0.0.1:18083 proxy
nginx -s stop -c "$B/nginx-proxy.conf"; sleep 2

echo "=== caddy static ==="
PID=$(start_caddy "$B/Caddyfile.static")
run_workloads caddy "$PID" https://127.0.0.1:18085 static
kill -9 "$PID"; sleep 2

echo "=== caddy proxy ==="
PID=$(start_caddy "$B/Caddyfile.proxy")
run_workloads caddy "$PID" https://127.0.0.1:18085 proxy
kill -9 "$PID"; sleep 2

echo ALL-DONE
