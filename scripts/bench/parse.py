#!/usr/bin/env python3
"""Aggregate /srv/bench/results into per-(server,workload,conc) rows.
Averages the 3 measured passes; reports mean req/s, latency percentiles (ms),
peak RSS (max over passes), mean CPU%, and total non-2xx/error count."""
import json, glob, os, re, statistics, sys

R = sys.argv[1] if len(sys.argv) > 1 else '/srv/bench/results'
rows = {}
for f in sorted(glob.glob(f'{R}/*-p[123].json')):
    m = re.match(r'(sluice|nginx|caddy)-(static1k|static100k|proxy1k)-c(\d+)-p(\d)\.json',
                 os.path.basename(f))
    if not m or os.path.getsize(f) == 0:
        continue
    server, wl, conc, p = m.group(1), m.group(2), int(m.group(3)), m.group(4)
    d = json.load(open(f))
    res = json.load(open(f.replace('.json', '.res')))
    s = d['summary']
    pct = d.get('latencyPercentiles', d.get('latency_percentiles', {}))
    codes = d.get('statusCodeDistribution', d.get('status_code_distribution', {}))
    errs = d.get('errorDistribution', d.get('error_distribution', {}))
    errs = {k: v for k, v in errs.items() if k != 'aborted due to deadline'}
    ok2xx = sum(v for k, v in codes.items() if k.startswith('2'))
    bad = sum(codes.values()) - ok2xx + sum(errs.values())
    key = (server, wl, conc)
    rows.setdefault(key, []).append({
        'rps': s['requestsPerSec'],
        'p50': pct.get('p50', 0) * 1000,
        'p90': pct.get('p90', 0) * 1000,
        'p99': pct.get('p99', 0) * 1000,
        'max': s['slowest'] * 1000,
        'rss': res['peak_rss_mib'],
        'cpu': res['avg_cpu_pct'],
        'bad': bad,
        'total': sum(codes.values()),
    })

out = {}
for (server, wl, conc), ps in sorted(rows.items()):
    out[f'{server}|{wl}|{conc}'] = {
        'passes': len(ps),
        'rps': round(statistics.mean(x['rps'] for x in ps)),
        'rps_sd': round(statistics.stdev(x['rps'] for x in ps)) if len(ps) > 1 else 0,
        'p50_ms': round(statistics.mean(x['p50'] for x in ps), 2),
        'p90_ms': round(statistics.mean(x['p90'] for x in ps), 2),
        'p99_ms': round(statistics.mean(x['p99'] for x in ps), 2),
        'max_ms': round(max(x['max'] for x in ps), 1),
        'peak_rss_mib': round(max(x['rss'] for x in ps), 1),
        'avg_cpu_pct': round(statistics.mean(x['cpu'] for x in ps), 1),
        'non2xx_or_err': sum(x['bad'] for x in ps),
        'total_reqs': sum(x['total'] for x in ps),
    }

for f in glob.glob(f'{R}/*.idle'):
    name = os.path.basename(f)[:-5]
    out[f'idle|{name}'] = open(f).read().strip()

print(json.dumps(out, indent=1))
