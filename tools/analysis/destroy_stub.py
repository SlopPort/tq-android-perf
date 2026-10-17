"""Assembly wrapper for GAME::ObjectManager::DestroyObjectEx(Object*, char const*, int) (RVA 0x8f705c):
calls od_pre(om, obj), the original (first instruction relocated + branch back), then od_post(om, obj).

Layout: 0x48 relocated first instruction, 0x4c `b DestroyObjectEx+4`, 0x50 .quad od_pre, 0x58 .quad od_post.
Also emits the 8-byte `dmb ish; ret` barrier helper.

  python destroy_stub.py      # print {"destroy": [...], "barrier": [...]} as JSON
"""
import json

ASM = r'''
  stp x29, x30, [sp, #-48]!
  mov x29, sp
  stp x0, x1, [sp, #16]
  stp x2, x3, [sp, #32]
  ldr x16, pre
  blr x16
  ldp x0, x1, [sp, #16]
  ldp x2, x3, [sp, #32]
  bl orig
  str x0, [sp, #32]
  ldp x0, x1, [sp, #16]
  ldr x16, post
  blr x16
  ldr x0, [sp, #32]
  ldp x29, x30, [sp], #48
  ret
  nop
  nop
orig:
  nop
  nop
pre:
  .quad 0
post:
  .quad 0
'''

if __name__ == '__main__':
    from keystone import Ks, KS_ARCH_ARM64, KS_MODE_LITTLE_ENDIAN
    ks = Ks(KS_ARCH_ARM64, KS_MODE_LITTLE_ENDIAN)
    code = bytes(ks.asm(ASM, 0)[0])
    assert len(code) == 0x60, hex(len(code))
    barrier = bytes(ks.asm('dmb ish\nret', 0)[0])
    print(json.dumps({'destroy': list(code), 'barrier': list(barrier)}))
