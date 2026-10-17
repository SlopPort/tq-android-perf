"""Which PLT stubs of libtq.so are hot, and do they resolve inside libtq (bypassable) or to other libs?

  python plt_profile.py ../libtq.so samples.txt
"""
import collections, re, struct, sys
sys.path.insert(0, '../python-libs')
from elftools.elf.elffile import ELFFile

lib, samples = sys.argv[1], sys.argv[2]
f = ELFFile(open(lib, 'rb'))
data = open(lib, 'rb').read()
plt = f.get_section_by_name('.plt')
pa, ps, po = plt['sh_addr'], plt['sh_size'], plt['sh_offset']
dynsym = f.get_section_by_name('.dynsym')
defined = {s.name for s in dynsym.iter_symbols() if s['st_value'] and s['st_shndx'] != 'SHN_UNDEF'}
got2sym = {}
for sec in f.iter_sections():
    if sec.name == '.rela.plt':
        st = f.get_section(sec['sh_link'])
        for r in sec.iter_relocations():
            got2sym[r['r_offset']] = st.get_symbol(r['r_info_sym']).name


def stub_symbol(vaddr):
    stub = pa + ((vaddr - pa) // 16) * 16
    o = po + (stub - pa)
    w0, w1 = struct.unpack_from('<II', data, o)
    if (w0 & 0x9f000000) != 0x90000000:
        return None
    imm = ((((w0 >> 5) & 0x7ffff) << 2) | ((w0 >> 29) & 3)) << 12
    if imm & (1 << 32):
        imm -= 1 << 33
    page = (stub & ~0xfff) + imm
    off = ((w1 >> 10) & 0xfff) * 8          # ldr x17, [x16, #imm12*8]
    return got2sym.get(page + off)


hot = collections.Counter()
total = 0
cur_leaf = None
with open(samples, encoding='utf-8', errors='replace') as fh:
    leaf_v = None
    for line in fh:
        if line.startswith('sample:'):
            leaf_v = None
            state = 'leaf'
        elif line.startswith('  vaddr_in_file:') and leaf_v is None:
            leaf_v = int(line.split(':')[1].strip(), 16)
        elif line.startswith('  symbol:') and leaf_v is not None and state == 'leaf':
            state = 'done'
            if line.strip().endswith('@plt') and pa <= leaf_v < pa + ps:
                total += 1
                hot[stub_symbol(leaf_v)] += 1
internal = sum(c for s, c in hot.items() if s in defined)
print(f'@plt samples: {total}; resolving inside libtq: {internal} ({internal / max(total, 1):.0%})')
for s, c in hot.most_common(30):
    print(f'{c:6d}  {"INT" if s in defined else "ext"}  {s}')
