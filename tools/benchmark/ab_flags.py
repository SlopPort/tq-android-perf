"""Interleaved A/B of the *installed* module with its per-patch switch files: "before" = all engine patches
switched off, "after" = everything on. Every run restarts the game so
the module injects with the chosen flags.

  python ab_flags.py --rounds 3 --scenario scenarios/walk-road.json --prefix final-walk-
"""
import argparse, subprocess, sys

FLAGS = ['noplt', 'nosnd', 'noslot', 'nouneg', 'noabbox', 'nostrm', 'nogetend']
MOD = '/data/adb/modules/tq_autopatch'
ap = argparse.ArgumentParser()
ap.add_argument('--rounds', type=int, default=3)
ap.add_argument('--scenario', required=True)
ap.add_argument('--prefix', required=True)
a = ap.parse_args()


def adb_su(cmd):
    subprocess.run(['adb', 'shell', f"su -c '{cmd}'"], check=False, timeout=60)


def set_flags(before):
    if before:
        adb_su('; '.join(f'touch {MOD}/{f}' for f in FLAGS))
    else:
        adb_su('rm -f ' + ' '.join(f'{MOD}/{f}' for f in FLAGS))


variants = [('before', True), ('after', False)]
try:
    for r in range(a.rounds):
        order = variants if r % 2 == 0 else variants[::-1]
        for name, before in order:
            set_flags(before)
            label = a.prefix + name
            print('>>', label, 'round', r + 1, flush=True)
            for attempt in range(3):
                res = subprocess.run([sys.executable, 'tqbench.py', 'run', '--label', label, '--repeat', '1', '--fresh',
                                      '--scenario-file', a.scenario], timeout=900)
                if res.returncode == 0:
                    break
finally:
    set_flags(False)
subprocess.run([sys.executable, 'tqbench.py', 'compare', a.prefix + 'before', a.prefix + 'after'])
