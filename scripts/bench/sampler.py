#!/usr/bin/env python3
"""Sample RSS (sum over a process and its direct children) and CPU% for dur
seconds. Usage: sampler.py <main_pid> <dur_secs> — prints one JSON line."""
import sys, time, os, json

main = int(sys.argv[1])
dur = float(sys.argv[2])
CLK = os.sysconf('SC_CLK_TCK')
PAGE = os.sysconf('SC_PAGE_SIZE')


def procs():
    ps = {main}
    for p in os.listdir('/proc'):
        if p.isdigit():
            try:
                with open(f'/proc/{p}/stat') as f:
                    st = f.read().rsplit(')', 1)[1].split()
                if int(st[1]) == main:
                    ps.add(int(p))
            except (OSError, IndexError):
                pass
    return ps


def sample():
    rss = 0
    cpu = 0
    for p in procs():
        try:
            with open(f'/proc/{p}/stat') as f:
                st = f.read().rsplit(')', 1)[1].split()
            cpu += int(st[11]) + int(st[12])  # utime + stime
            rss += int(st[21]) * PAGE          # rss pages
        except (OSError, IndexError):
            pass
    return rss, cpu


t0 = time.time()
r0, c0 = sample()
peak = r0
while time.time() - t0 < dur:
    time.sleep(1)
    r, _ = sample()
    peak = max(peak, r)
elapsed = time.time() - t0
_, c1 = sample()
print(json.dumps({
    "peak_rss_mib": round(peak / 1048576, 1),
    "avg_cpu_pct": round((c1 - c0) / CLK / elapsed * 100, 1),
}))
