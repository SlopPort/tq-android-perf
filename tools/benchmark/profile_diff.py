"""Compare two `simpleperf report-sample --show-callchain` dumps (e.g. cold vs warm process).

  python profile_diff.py cold-samples.txt warm-samples.txt [--focus SYMBOL_SUBSTRING]

Prints per-thread CPU, inclusive time per function on the busiest (render) thread, the biggest
inclusive differences, and - with --focus - the call paths leading to a function.
"""
import collections, re, sys


def load(path):
    samples = []      # (thread_name, [leaf, caller, caller, ...])
    cur = None
    in_chain = False
    with open(path, encoding='utf-8', errors='replace') as f:
        for line in f:
            if line.startswith('sample:'):
                if cur:
                    samples.append(cur)
                cur = ['', []]
                in_chain = False
            elif cur is None:
                continue
            elif line.startswith('  thread_name:'):
                cur[0] = line.split(':', 1)[1].strip()
            elif line.startswith('  callchain:'):
                in_chain = True
            elif 'symbol:' in line:
                sym = line.split('symbol:', 1)[1].strip()
                sym = re.sub(r'\(.*', '', sym) if not sym.startswith('[') else sym
                cur[1].append(sym)
    if cur:
        samples.append(cur)
    return samples


def main():
    a, b = sys.argv[1], sys.argv[2]
    focus = sys.argv[sys.argv.index('--focus') + 1] if '--focus' in sys.argv else None
    A, B = load(a), load(b)
    for name, S in (('A', A), ('B', B)):
        th = collections.Counter(s[0] for s in S)
        print(f'{name}: {len(S)} samples; threads:', ', '.join(f'{t}={c}' for t, c in th.most_common(8)))
    main_thread = collections.Counter(s[0] for s in A).most_common(1)[0][0]
    print('render/game thread:', main_thread)

    def inclusive(S):
        c = collections.Counter()
        n = 0
        for t, stack in S:
            if t != main_thread:
                continue
            n += 1
            for sym in set(stack):
                c[sym] += 1
        return c, n
    ca, na = inclusive(A)
    cb, nb = inclusive(B)
    print(f'\nrender-thread samples A={na} B={nb}  (1 sample = 1 ms)')
    rows = []
    for sym in set(ca) | set(cb):
        # ms per second of wall time is what matters for frame time; samples are 1 kHz over the same duration.
        rows.append((ca[sym] - cb[sym], ca[sym], cb[sym], sym))
    rows.sort(reverse=True)
    print('\nlargest inclusive increase A vs B (render thread, samples):')
    for d, x, y, s in rows[:25]:
        print(f'  {d:+6d}  A {x:6d}  B {y:6d}  {s[:120]}')
    print('\nlargest inclusive decrease:')
    for d, x, y, s in rows[-10:]:
        print(f'  {d:+6d}  A {x:6d}  B {y:6d}  {s[:120]}')
    if focus:
        for name, S in (('A', A), ('B', B)):
            paths = collections.Counter()
            total = 0
            for t, stack in S:
                for i, sym in enumerate(stack):
                    if focus in sym:
                        total += 1
                        callers = [c for c in stack[i + 1:i + 7] if not c.startswith('@plt')]
                        paths[' <- '.join(callers[:5])] += 1
                        break
            print(f'\n{name}: {total} samples in "{focus}"; top call paths:')
            for p, c in paths.most_common(8):
                print(f'  {c:6d}  {p[:300]}')


if __name__ == '__main__':
    main()
