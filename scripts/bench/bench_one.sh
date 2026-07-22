#!/bin/bash
# bench_one.sh <label> <url> <conc> <server_pid> <outdir>
# 1 x 10s warmup (discarded) + 3 x 30s measured passes; RSS/CPU of the server
# process tree sampled during each measured pass.
set -u
label=$1; url=$2; conc=$3; spid=$4; outdir=$5
OHA=${OHA_BIN:-/root/bench/oha}
B=${BENCH_DIR:-/srv/bench}
mkdir -p "$outdir"

"$OHA" -z 10s -c "$conc" --insecure --no-tui --output-format json "$url" > /dev/null 2>&1

for pass in 1 2 3; do
    python3 "$B/sampler.py" "$spid" 28 > "$outdir/${label}-c${conc}-p${pass}.res" &
    sampler=$!
    "$OHA" -z 30s -c "$conc" --insecure --no-tui --output-format json "$url" \
        > "$outdir/${label}-c${conc}-p${pass}.json" 2> "$outdir/${label}-c${conc}-p${pass}.err"
    wait "$sampler"
done
echo "done ${label} c=${conc}"
