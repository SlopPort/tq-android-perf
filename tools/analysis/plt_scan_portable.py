"""Reference (offline) version of the on-device PLT-bypass scan used by tq_autopatch v2.

Uses only what is mapped at runtime: program headers, the PLT stub pattern and .eh_frame_hdr (function
ranges, including local/outlined helpers). GOT values are taken from the file's relocation addends here;
on the device they are read from memory (already resolved). Compares with the Ghidra-based list.

  python plt_scan_portable.py ../libtq.so plt-bypass-full.bin
"""
import struct, sys


def u32(d, o): return struct.unpack_from('<I', d, o)[0]
def u64(d, o): return struct.unpack_from('<Q', d, o)[0]


def load_segments(d):
    phoff, phentsize, phnum = u64(d, 0x20), struct.unpack_from('<H', d, 0x36)[0], struct.unpack_from('<H', d, 0x38)[0]
    segs = []
    for i in range(phnum):
        p_type, p_flags, p_offset, p_vaddr, _, p_filesz, p_memsz, _ = struct.unpack_from('<IIQQQQQQ', d, phoff + i * phentsize)
        segs.append((p_type, p_flags, p_offset, p_vaddr, p_filesz, p_memsz))
    return segs


class Image:
    """Virtual-address view of the file (like the mapped module)."""
    def __init__(self, d):
        self.d, self.segs = d, load_segments(d)
    def off(self, va):
        for t, fl, o, v, fs, ms in self.segs:
            if t == 1 and v <= va < v + fs: return o + va - v
        raise KeyError(hex(va))
    def u32(self, va): return u32(self.d, self.off(va))
    def u64(self, va): return u64(self.d, self.off(va))
    def i32(self, va): return struct.unpack_from('<i', self.d, self.off(va))[0]


def read_encoded(img, va, enc, datarel):
    fmt = enc & 0x0f; app = enc & 0x70
    if fmt == 0x0b: v, n = img.i32(va), 4          # sdata4
    elif fmt == 0x03: v, n = img.u32(va), 4        # udata4
    elif fmt == 0x0c: v, n = struct.unpack('<q', img.d[img.off(va):img.off(va) + 8])[0], 8
    elif fmt == 0x04: v, n = img.u64(va), 8
    else: raise ValueError('enc %x' % enc)
    if app == 0x10: v += va                         # pcrel
    elif app == 0x30: v += datarel                  # datarel
    return v, n


def eh_ranges(img):
    hdr = [s for s in img.segs if s[0] == 0x6474e550][0][3]   # PT_GNU_EH_FRAME
    ver, ptr_enc, cnt_enc, tab_enc = img.d[img.off(hdr):img.off(hdr) + 4]
    p = hdr + 4
    _, n = read_encoded(img, p, ptr_enc, hdr); p += n
    count, n = read_encoded(img, p, cnt_enc, hdr); p += n
    out = []
    for i in range(count):
        loc, n1 = read_encoded(img, p, tab_enc, hdr)
        fde, n2 = read_encoded(img, p + n1, tab_enc, hdr)
        p += n1 + n2
        # FDE: length(4) CIE_ptr(4) pc_begin pc_range ... ; this build uses pcrel|sdata4 in the CIE ('zR')
        pc_begin, k = read_encoded(img, fde + 8, 0x1b, hdr)
        pc_range, _ = read_encoded(img, fde + 8 + k, 0x03, hdr)
        out.append((pc_begin, pc_begin + pc_range))
    return sorted(out)


def scan(img, got_value):
    ex = [s for s in img.segs if s[0] == 1 and s[1] & 1][0]
    t0, t1 = ex[3], ex[3] + ex[4]
    # PLT stubs: adrp x16 ; ldr x17,[x16,#lo] ; add x16,x16,#lo ; br x17
    stubs = {}
    va = (t0 + 15) & ~15
    while va + 16 <= t1:
        w0, w1, w2, w3 = (img.u32(va + 4 * k) for k in range(4))
        if (w0 & 0x9f00001f) == 0x90000010 and (w1 & 0xffc003ff) == 0xf9400211 and (w2 & 0xffc003ff) == 0x91000210 and w3 == 0xd61f0220:
            imm = ((((w0 >> 5) & 0x7ffff) << 2) | ((w0 >> 29) & 3)) << 12
            if imm & (1 << 32): imm -= 1 << 33
            slot = (va & ~0xfff) + imm + ((w1 >> 10) & 0xfff) * 8
            stubs[va] = slot
        va += 16
    sites = []
    for a, b in eh_ranges(img):
        for s in range(a, b, 4):
            if s in stubs: break
            w = img.u32(s)
            if (w & 0x7c000000) != 0x14000000: continue           # b / bl
            imm = w & 0x3ffffff
            if imm & 0x2000000: imm -= 0x4000000
            t = s + imm * 4
            if t not in stubs: continue
            dest = got_value(stubs[t])
            if dest is None or not (t0 <= dest < t1): continue
            delta = (dest - s) // 4
            if not (-0x2000000 <= delta < 0x2000000): continue
            neww = (w & 0xfc000000) | (delta & 0x3ffffff)
            sites.append((s, w, neww, stubs[t], dest))
    return stubs, sites


if __name__ == '__main__':
    d = open(sys.argv[1], 'rb').read()
    img = Image(d)
    # offline GOT values: JUMP_SLOT relocations resolved to the symbol value when it is defined here
    from elftools.elf.elffile import ELFFile
    f = ELFFile(open(sys.argv[1], 'rb'))
    got = {}
    for sec in f.iter_sections():
        if sec.name == '.rela.plt':
            st = f.get_section(sec['sh_link'])
            for r in sec.iter_relocations():
                sym = st.get_symbol(r['r_info_sym'])
                if sym['st_shndx'] != 'SHN_UNDEF' and sym['st_value'] and sym['st_info']['type'] == 'STT_FUNC':
                    got[r['r_offset']] = sym['st_value']
    stubs, sites = scan(img, got.get)
    print('stubs', len(stubs), 'sites', len(sites), 'eh ranges', len(eh_ranges(img)))
    if len(sys.argv) > 2:
        ref = open(sys.argv[2], 'rb').read()
        n = u32(ref, 0)
        refset = {struct.unpack_from('<5I', ref, 4 + i * 20) for i in range(n)}
        mine = set(sites)
        print('reference', n, 'common', len(refset & mine), 'only-portable', len(mine - refset), 'only-reference', len(refset - mine))
        for x in sorted(mine - refset)[:5]: print('  only-portable', [hex(v) for v in x])
        for x in sorted(refset - mine)[:5]: print('  only-reference', [hex(v) for v in x])
