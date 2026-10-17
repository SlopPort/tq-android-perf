"""Interleaved multi-variant A/B on fresh game processes, then `tqbench.py compare` against the first.

  python ab.py --rounds 3 --variant base= --variant slot="--opt slotcache:1.0" \
               --variant plt="--opt pltbypass" --common "--scenario-file scenarios/walk-road.json"

Each round runs every variant once, rotating the order between rounds, and every run restarts the
game (--fresh): each variant sees the same cold world and only one agent injection per process.
"""
import argparse, shlex, subprocess, sys

ap = argparse.ArgumentParser()
ap.add_argument('--rounds', type=int, default=3)
ap.add_argument('--variant', action='append', required=True, help='label=extra args')
ap.add_argument('--common', default='--scenario-file scenarios/walk-road.json')
ap.add_argument('--prefix', default='')
a = ap.parse_args()
variants = [(a.prefix + v.split('=', 1)[0], v.split('=', 1)[1] if '=' in v else '') for v in a.variant]


def valid_runs(label):
    import glob, json
    n = 0
    for f in glob.glob(f'results/{label}/run-*.json'):
        try:
            r = json.load(open(f, encoding='utf-8'))
            n += bool(r.get('stats') and 'error' not in r['stats'])
        except Exception:
            pass
    return n


def run(label, extra, retries=2):
    # Retry runs lost to device/infrastructure hiccups so every variant ends with the same count.
    for attempt in range(retries + 1):
        before = valid_runs(label)
        cmd = [sys.executable, 'tqbench.py', 'run', '--label', label, '--repeat', '1', '--fresh',
               *shlex.split(a.common), *shlex.split(extra)]
        print('>>', label, ' '.join(cmd[2:]), f'(attempt {attempt + 1})', flush=True)
        try:
            subprocess.run(cmd, check=False, timeout=900)
        except subprocess.TimeoutExpired:
            print('   run timed out', flush=True)
        if valid_runs(label) > before:
            return


for r in range(a.rounds):
    k = r % len(variants)
    for label, extra in variants[k:] + variants[:k]:
        run(label, extra)
for label, _ in variants[1:]:
    subprocess.run([sys.executable, 'tqbench.py', 'compare', variants[0][0], label])
