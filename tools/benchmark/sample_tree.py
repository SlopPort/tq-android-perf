"""Aggregate `simpleperf report-sample --show-callchain` text: for samples whose stack contains FOCUS,
show the share of the whole profile per direct callee of FOCUS (and per leaf), plus the threads.

  python sample_tree.py results/prof-v14/samples.txt StartStream3D [--depth 2]
"""
import collections, sys


def samples(path):
    cur = None
    with open(path, encoding='utf-8', errors='replace') as f:
        for line in f:
            s = line.strip()
            if s == 'sample:':
                if cur: yield cur
                cur = {'thread': '', 'frames': []}
            elif cur is None:
                continue
            elif s.startswith('thread_name:'):
                cur['thread'] = s.split(':', 1)[1].strip()
            elif s.startswith('symbol:'):
                cur['frames'].append(s.split(':', 1)[1].strip())   # leaf first, then callers
    if cur: yield cur


def short(sym):
    sym = sym.replace('GAME::', '')
    return sym if len(sym) < 110 else sym[:107] + '...'


def main():
    path, focus = sys.argv[1], sys.argv[2]
    depth = int(sys.argv[sys.argv.index('--depth') + 1]) if '--depth' in sys.argv else 1
    total = hit = 0
    callee, leaf, threads = collections.Counter(), collections.Counter(), collections.Counter()
    for smp in samples(path):
        total += 1
        fr = smp['frames']
        idx = next((i for i in range(len(fr) - 1, -1, -1) if focus in fr[i]), None)   # outermost match
        if idx is None:
            continue
        hit += 1
        threads[smp['thread']] += 1
        path_below = tuple(short(f) for f in fr[max(0, idx - depth):idx][::-1])
        callee[path_below or ('<self>',)] += 1
        leaf[short(fr[0])] += 1
    pct = lambda n: f'{100 * n / total:6.2f}%'
    print(f'{total} samples, {hit} through "{focus}" ({pct(hit)})  threads: {dict(threads.most_common(4))}')
    print('\nby callee path:')
    for k, n in callee.most_common(20):
        print(pct(n), ' > '.join(k))
    print('\nby leaf:')
    for k, n in leaf.most_common(15):
        print(pct(n), k)


if __name__ == '__main__':
    main()
