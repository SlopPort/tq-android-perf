"""Relocation-insensitive function fingerprints for tq_autopatch v2.

A patch is applied only if every function whose layout it relies on (structure offsets, call order,
exact arithmetic) has a known fingerprint. The hash covers the function's instruction words with the
fields that change when the library is merely rebuilt/relinked masked out:
  - b/bl to targets outside the function (incl. PLT stubs), adrp/adr pages, literal loads,
  - the low-12 immediate of add/ldr/str whose base register was set by an adrp in the function.
Everything else (struct offsets, constants, intra-function branches) stays in the hash.
The JS twin is `fpHash` in the module (must stay byte-for-byte equivalent).

  python fingerprints.py ../libtq.so > fingerprints-3.0.5339.json
"""
import json, struct, sys

PATCHES = {
    'slot':   ['_ZN4GAME11SlotManager22CalculateSlotPositionsEf', '_ZNK4GAME9Character15GetPathPositionEv',
               '_ZNK4GAME24CharacterMovementManager15GetPathPositionEv'],
    'uneg':   ['_ZN4GAME15OpenGLESProgram18GetUniformLocationEjl', '_ZN4GAME15OpenGLESProgram21resetAttributeSamplerEv'],
    'abbox':  ['_ZNK4GAME5ABBox15GetIntersectionERKNS_3RayE'],
    'getend': ['_ZNK4GAME10PathRecast7Segment6GetEndEv'],
    'snd':    ['_ZN4GAME12SoundManager6Play3DERKNS_15SoundDescriptorEb', '_ZN4GAME12SoundManager6Play2DERKNS_15SoundDescriptorEb',
               '_ZN4GAME12SoundManager19ProcessFinishedListEv', '_ZN4GAME12SoundManager13StealInstanceEv'],
    'strm':   ['_ZN4GAME12SoundManager13StartStream3DERKNS_15SoundDescriptorE', '_ZN4GAME12SoundManager11StartStreamERKNS_15SoundDescriptorE',
               '_ZN4GAME12SoundManager19ProcessFinishedListEv', '_ZN4GAME12SoundManager13StealInstanceEv'],
}


def fp_hash(words):
    n = len(words)
    adrp = set()
    h = 0x811c9dc5
    for i, w in enumerate(words):
        m = w
        if (w & 0x7c000000) == 0x14000000:                                  # b / bl
            imm = w & 0x3ffffff
            if imm & 0x2000000: imm -= 0x4000000
            if not (0 <= i + imm < n): m = w & 0xfc000000
        elif (w & 0x9f000000) == 0x90000000:                                # adrp
            m = w & 0x9f00001f; adrp.add(w & 31)
        elif (w & 0x9f000000) == 0x10000000:                                # adr
            m = w & 0x9f00001f
        elif (w & 0x3b000000) == 0x18000000:                                # ldr (literal), incl. SIMD/FP
            m = w & 0xff00001f
        elif (w & 0x7f800000) == 0x11000000 and ((w >> 5) & 31) in adrp:    # add (imm) off an adrp base
            m = w & 0xffc003ff
        elif (w & 0x3b000000) == 0x39000000 and ((w >> 5) & 31) in adrp:    # ldr/str (unsigned imm) off an adrp base
            m = w & 0xffc003ff
        for k in range(4):
            h ^= (m >> (8 * k)) & 0xff
            h = (h * 0x01000193) & 0xffffffff
    return h


def symbols(path):
    e = open(path, 'rb').read()
    shoff = struct.unpack_from('<Q', e, 0x28)[0]
    shentsize, shnum = struct.unpack_from('<HH', e, 0x3a)
    secs = [struct.unpack_from('<IIQQQQIIQQ', e, shoff + i * shentsize) for i in range(shnum)]
    ds = [s for s in secs if s[1] == 11][0]; dst = secs[ds[6]]
    out = {}
    for i in range(ds[5] // 24):
        n, info, o, sh, val, size = struct.unpack_from('<IBBHQQ', e, ds[4] + i * 24)
        if val:
            out[e[dst[4] + n:e.index(b'\0', dst[4] + n)].decode()] = (val, size)
    return e, out


if __name__ == '__main__':
    e, syms = symbols(sys.argv[1])
    res = {}
    for patch, names in PATCHES.items():
        res[patch] = []
        for nm in names:
            va, size = syms[nm]
            words = list(struct.unpack_from('<%dI' % (size // 4), e, va))   # file offset == vaddr for .text here
            res[patch].append({'sym': nm, 'len': size, 'hash': '%08x' % fp_hash(words)})
    print(json.dumps(res, indent=1))
