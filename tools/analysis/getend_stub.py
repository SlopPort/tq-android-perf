"""Assembly wrapper for GAME::PathRecast::Segment::GetEnd() const (libtq 3.0.5339, RVA 0x98232c).

GetEnd returns a WorldVec3 (24 bytes) through x8 and does a floor raycast (PutOnFloor) on every call.
The wrapper asks C `ge_lookup(seg, out)` first; on a miss it runs the original (first instruction
relocated into the stub + branch back) and then `ge_store(seg, out)`.

Layout (offsets used by the agent / module):
  0x38  relocated first instruction of GetEnd (filled at install)
  0x3c  `b GetEnd+4` (filled at install)
  0x40  .quad ge_lookup
  0x48  .quad ge_store

  python getend_stub.py      # print the bytes as a JS array literal
"""
ASM = r'''
  stp x29, x30, [sp, #-32]!
  mov x29, sp
  stp x0, x8, [sp, #16]
  mov x1, x8
  ldr x16, lookup
  blr x16
  cbnz w0, done
  ldp x0, x8, [sp, #16]
  bl orig
  ldp x0, x1, [sp, #16]
  ldr x16, store
  blr x16
done:
  ldp x29, x30, [sp], #32
  ret
orig:
  nop
  nop
lookup:
  .quad 0
store:
  .quad 0
'''

if __name__ == '__main__':
    from keystone import Ks, KS_ARCH_ARM64, KS_MODE_LITTLE_ENDIAN
    code = bytes(Ks(KS_ARCH_ARM64, KS_MODE_LITTLE_ENDIAN).asm(ASM, 0)[0])
    assert len(code) == 0x50, hex(len(code))
    print('[' + ','.join(str(b) for b in code) + ']')
