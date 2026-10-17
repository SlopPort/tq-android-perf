"""Hand-written replacement for GAME::ABBox::GetIntersection(Ray const&) (libtq 3.0.5339, RVA 0x8a0934).

The original (Woo's ray/box test) computes all six slab divisions up front, builds min/max through two
out-of-line Vec3 operator calls and walks the axes through an index-dispatch loop on the stack. This
version does the same arithmetic in the same order (c-e, c+e, (plane-o)/d, o+t*d, same compares and
tie-breaks, same NaN/zero behaviour) but divides only for axes that need it and keeps everything in
registers. Box: center at +0, extent at +0xc. Ray: origin at +0, direction at +0xc. Returns 0 when
the origin is inside, Math::infinity on a miss, else the hit distance.

  python abbox_fast.py            # assemble + compare against the original in unicorn (random + edge cases)
  python abbox_fast.py --emit     # print the code bytes as a JS array literal (last 8 bytes = infinity ptr slot)
"""
import struct, sys, random

ASM = r'''
  ldp s0, s1, [x0]
  ldr s2, [x0, #8]
  ldp s3, s4, [x0, #12]
  ldr s5, [x0, #20]
  fsub s6, s0, s3
  fsub s7, s1, s4
  fsub s16, s2, s5
  fadd s0, s0, s3
  fadd s1, s1, s4
  fadd s2, s2, s5
  ldp s17, s18, [x1]
  ldr s19, [x1, #8]
  ldp s20, s21, [x1, #12]
  ldr s22, [x1, #20]
  fmov s23, #-1.0
  fmov s24, #-1.0
  fmov s25, #-1.0
  mov w9, #1
  fcmp s17, s6
  b.mi xl
  fcmp s17, s0
  b.le xd
  mov w9, wzr
  fcmp s20, #0.0
  b.eq xd
  fsub s26, s0, s17
  fdiv s23, s26, s20
  b xd
xl:
  mov w9, wzr
  fcmp s20, #0.0
  b.eq xd
  fsub s26, s6, s17
  fdiv s23, s26, s20
xd:
  fcmp s18, s7
  b.mi yl
  fcmp s18, s1
  b.le yd
  mov w9, wzr
  fcmp s21, #0.0
  b.eq yd
  fsub s26, s1, s18
  fdiv s24, s26, s21
  b yd
yl:
  mov w9, wzr
  fcmp s21, #0.0
  b.eq yd
  fsub s26, s7, s18
  fdiv s24, s26, s21
yd:
  fcmp s19, s16
  b.mi zl
  fcmp s19, s2
  b.le zd
  mov w9, wzr
  fcmp s22, #0.0
  b.eq zd
  fsub s26, s2, s19
  fdiv s25, s26, s22
  b zd
zl:
  mov w9, wzr
  fcmp s22, #0.0
  b.eq zd
  fsub s26, s16, s19
  fdiv s25, s26, s22
zd:
  cbnz w9, inside
  fcmp s24, s23
  fcsel s26, s24, s23, gt
  cset w10, gt
  mov w11, #2
  fcmp s25, s26
  csel w10, w11, w10, gt
  fcsel s26, s25, s26, gt
  fcmp s26, #0.0
  b.ls miss
  cbz w10, cy
  fmul s27, s26, s20
  fadd s27, s17, s27
  fcmp s27, s6
  b.mi miss
  fcmp s27, s0
  b.gt miss
cy:
  cmp w10, #1
  b.eq cz
  fmul s27, s26, s21
  fadd s27, s18, s27
  fcmp s27, s7
  b.mi miss
  fcmp s27, s1
  b.gt miss
cz:
  cmp w10, #2
  b.eq hit
  fmul s27, s26, s22
  fadd s27, s19, s27
  fcmp s27, s16
  b.mi miss
  fcmp s27, s2
  b.gt miss
hit:
  fmov s0, s26
  ret
inside:
  fmov s0, wzr
  ret
miss:
  ldr x8, infptr
  ldr s0, [x8]
  ret
  nop
infptr:
  .quad 0
'''


def assemble():
    from keystone import Ks, KS_ARCH_ARM64, KS_MODE_LITTLE_ENDIAN
    code = bytes(Ks(KS_ARCH_ARM64, KS_MODE_LITTLE_ENDIAN).asm(ASM, 0)[0])
    assert len(code) % 8 == 0 and code[-8:] == b'\0' * 8, 'infptr literal must be the last, 8-aligned quad'
    return code


def emulate_test(code, n=300000):
    import numpy as np
    from unicorn import Uc, UC_ARCH_ARM64, UC_MODE_ARM, UC_HOOK_CODE
    from unicorn.arm64_const import (UC_ARM64_REG_X0, UC_ARM64_REG_X1, UC_ARM64_REG_LR, UC_ARM64_REG_SP,
                                     UC_ARM64_REG_PC, UC_ARM64_REG_S0, UC_ARM64_REG_S1, UC_ARM64_REG_S2,
                                     UC_ARM64_REG_CPACR_EL1)
    lib = open(__file__.rsplit('benchmark', 1)[0] + 'libtq.so', 'rb').read()
    LIB, NEW, DATA, STACK, STOP = 0x10000000, 0x40000000, 0x50000000, 0x60000000, 0x70000000
    INF_VAR = DATA + 0x800
    uc = Uc(UC_ARCH_ARM64, UC_MODE_ARM)
    uc.reg_write(UC_ARM64_REG_CPACR_EL1, 0x300000)          # enable FP/SIMD
    size = (len(lib) + 0xfff) & ~0xfff
    uc.mem_map(LIB, size + 0x200000)
    uc.mem_write(LIB, lib)
    uc.mem_write(LIB + 0x11a0540, struct.pack('<Q', INF_VAR))   # GOT: &Math::infinity
    uc.mem_map(NEW, 0x1000); uc.mem_write(NEW, code[:-8] + struct.pack('<Q', INF_VAR))
    uc.mem_map(DATA, 0x1000); uc.mem_write(INF_VAR, struct.pack('<f', float('inf')))
    uc.mem_map(STACK, 0x10000); uc.mem_map(STOP, 0x1000)
    f32 = lambda b: np.frombuffer(b, dtype=np.float32)
    def vec_op(sub):
        a = f32(uc.mem_read(uc.reg_read(UC_ARM64_REG_X0), 12)); b = f32(uc.mem_read(uc.reg_read(UC_ARM64_REG_X1), 12))
        r = (a - b) if sub else (a + b)
        for reg, v in zip((UC_ARM64_REG_S0, UC_ARM64_REG_S1, UC_ARM64_REG_S2), r):
            uc.reg_write(reg, struct.unpack('<I', struct.pack('<f', float(v)))[0])
        uc.reg_write(UC_ARM64_REG_PC, uc.reg_read(UC_ARM64_REG_LR))
    def hook(uc_, addr, sz, ud):
        if addr == LIB + 0x7e1010: vec_op(True)
        elif addr == LIB + 0x7adf30: vec_op(False)
    uc.hook_add(UC_HOOK_CODE, hook, begin=LIB + 0x7ad000, end=LIB + 0x7e2000)
    BOX, RAY = DATA, DATA + 0x100

    def run(entry, box, ray):
        uc.mem_write(BOX, struct.pack('<6f', *box)); uc.mem_write(RAY, struct.pack('<6f', *ray))
        uc.reg_write(UC_ARM64_REG_X0, BOX); uc.reg_write(UC_ARM64_REG_X1, RAY)
        uc.reg_write(UC_ARM64_REG_SP, STACK + 0x8000); uc.reg_write(UC_ARM64_REG_LR, STOP)
        uc.reg_write(UC_ARM64_REG_S0, 0x7fc01234)
        uc.emu_start(entry, STOP)
        return uc.reg_read(UC_ARM64_REG_S0) & 0xffffffff

    rnd = random.Random(1234)
    specials = [0.0, -0.0, 1.0, -1.0, 1e-30, -1e-30, 1e30, float('inf'), float('-inf'), float('nan'), 0.5, 3.0]
    def val(scale):
        k = rnd.random()
        if k < 0.04: return rnd.choice(specials)
        if k < 0.10: return float(rnd.randint(-4, 4))            # exact ties on faces/edges
        return rnd.uniform(-scale, scale)
    bad = 0
    cats = {'inside': 0, 'miss': 0, 'hit': 0, 'nan': 0}
    for i in range(n):
        c = [val(50) for _ in range(3)]
        e = [abs(val(10)) if rnd.random() > 0.03 else val(10) for _ in range(3)]
        o = [val(80) for _ in range(3)]
        d = [val(1) if rnd.random() > 0.15 else 0.0 for _ in range(3)]
        if rnd.random() < 0.3:                                  # aim at the box
            d = [c[j] - o[j] + rnd.uniform(-1, 1) for j in range(3)]
        box, ray = c + e, o + d
        box = list(struct.unpack('<6f', struct.pack('<6f', *box))); ray = list(struct.unpack('<6f', struct.pack('<6f', *ray)))
        a, b = run(LIB + 0x8a0934, box, ray), run(NEW, box, ray)
        cats['inside' if a == 0 else 'miss' if a == 0x7f800000 else 'nan' if (a & 0x7f800000) == 0x7f800000 else 'hit'] += 1
        same = a == b or ((a & 0x7f800000) == 0x7f800000 and (a & 0x7fffff) and (b & 0x7f800000) == 0x7f800000 and (b & 0x7fffff))
        if not same:
            bad += 1
            if bad <= 10: print('MISMATCH', box, ray, hex(a), hex(b))
        if i and i % 50000 == 0: print(f'  {i} cases, {bad} mismatches', flush=True)
    print(f'{n} cases, {bad} mismatches', cats)
    return bad


if __name__ == '__main__':
    code = assemble()
    if '--emit' in sys.argv:
        print('[' + ','.join(str(x) for x in code) + ']')
    else:
        print(f'{len(code)} bytes ({len(code) // 4} words)')
        n = int(sys.argv[1]) if len(sys.argv) > 1 else 300000
        sys.exit(1 if emulate_test(code, n) else 0)
