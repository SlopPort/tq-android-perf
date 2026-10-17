"""Build the PLT-bypass patch list for libtq.so (3.0.5339).

libtq.so exports every symbol with default visibility, so even calls between its own functions go
through PLT stubs (adrp/ldr/add/br via the GOT): ~7% of game-thread CPU in the profile. For every
BL/B in .text whose target is a PLT stub of a function *defined in libtq itself*, emit a direct
branch to the definition. At runtime the agent re-checks each symbol's GOT entry still points to
libtq's own definition (i.e. not interposed) and each site still holds the original instruction.

  python plt_bypass_build.py ../libtq.so plt-bypass.bin [../ghidra-evidence/function-ranges.txt]
"""
import json, struct, sys, collections
sys.path.insert(0, '../python-libs')
from elftools.elf.elffile import ELFFile

lib, out = sys.argv[1], sys.argv[2]
f = ELFFile(open(lib, 'rb'))
data = open(lib, 'rb').read()
plt = f.get_section_by_name('.plt')
pa, ps, po = plt['sh_addr'], plt['sh_size'], plt['sh_offset']
text = f.get_section_by_name('.text')
ta, ts, to = text['sh_addr'], text['sh_size'], text['sh_offset']

# GOT slot -> symbol (JUMP_SLOT relocations)
got2sym = {}
for sec in f.iter_sections():
    if sec.name == '.rela.plt':
        st = f.get_section(sec['sh_link'])
        for r in sec.iter_relocations():
            got2sym[r['r_offset']] = st.get_symbol(r['r_info_sym'])

stubs = {}   # stub vaddr -> (symbol name, definition vaddr, got slot)
for off in range(32, ps, 16):     # first 32 bytes are PLT0
    stub = pa + off
    w0, w1, w2, w3 = struct.unpack_from('<IIII', data, po + off)
    if (w0 & 0x9f000000) != 0x90000000 or (w3 & 0xfffffc1f) != 0xd61f0000:
        continue
    imm = ((((w0 >> 5) & 0x7ffff) << 2) | ((w0 >> 29) & 3)) << 12
    if imm & (1 << 32):
        imm -= 1 << 33
    slot = (stub & ~0xfff) + imm + ((w1 >> 10) & 0xfff) * 8
    s = got2sym.get(slot)
    if s is None or s['st_shndx'] == 'SHN_UNDEF' or not s['st_value']:
        continue
    if s['st_info']['type'] not in ('STT_FUNC', 'STT_GNU_IFUNC') or s['st_info']['type'] == 'STT_GNU_IFUNC':
        continue
    stubs[stub] = (s.name, s['st_value'], slot)

# Only accept instructions inside known function bodies (every function is exported in this build),
# so no data word in .text can be misread as a branch.
import bisect
funcs = sorted((s['st_value'], s['st_value'] + s['st_size']) for s in f.get_section_by_name('.dynsym').iter_symbols()
               if s['st_info']['type'] == 'STT_FUNC' and s['st_value'] and s['st_size'])
# Optionally add function bodies found by Ghidra (local/outlined helpers have no dynamic symbol):
# ../ghidra-evidence/function-ranges.txt, lines "startRVA endRVA name" (ExportFunctionRanges.java).
if len(sys.argv) > 3:
    for line in open(sys.argv[3]):
        a0, a1, _ = line.split(maxsplit=2)
        funcs.append((int(a0, 16), int(a1, 16)))
    funcs.sort()
    merged = []
    for s0, s1 in funcs:
        if merged and s0 <= merged[-1][1]:
            merged[-1] = (merged[-1][0], max(merged[-1][1], s1))
        else:
            merged.append((s0, s1))
    funcs = merged
fstarts = [x[0] for x in funcs]


def in_function(a):
    i = bisect.bisect_right(fstarts, a) - 1
    return i >= 0 and funcs[i][0] <= a < funcs[i][1]


sites = []
per_sym = collections.Counter()
skipped_outside = 0
for off in range(0, ts, 4):
    w = struct.unpack_from('<I', data, to + off)[0]
    op = w >> 26
    if op not in (0x25, 0x05):      # BL / B
        continue
    imm = w & 0x3ffffff
    if imm & 0x2000000:
        imm -= 0x4000000
    site = ta + off
    tgt = site + imm * 4
    if tgt not in stubs:
        continue
    name, dest, slot = stubs[tgt]
    if not in_function(site):
        skipped_outside += 1
        continue
    delta = (dest - site) // 4
    if not -0x2000000 <= delta < 0x2000000:
        continue
    new = (w & 0xfc000000) | (delta & 0x3ffffff)
    sites.append([site, w, new, slot, dest])
    per_sym[name] += 1

# Binary for the agent: u32 count, then per site u32 [site, old, new, got slot, dest] (vaddrs).
sites.sort()
blob = struct.pack('<I', len(sites)) + b''.join(struct.pack('<IIIII', *s) for s in sites)
open(out, 'wb').write(blob)
print(f'internal PLT stubs: {len(stubs)}; call sites rewritten: {len(sites)} across {len(per_sym)} functions; '
      f'outside functions skipped: {skipped_outside}; blob {len(blob)} bytes')
print('pages touched:', len({s[0] >> 12 for s in sites}))
for n, c in per_sym.most_common(10):
    print(f'  {c:6d}  {n}')
