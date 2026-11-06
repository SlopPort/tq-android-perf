/* bone patch, compiled offline (NDK clang -O2 -ffp-contract=off) into a flat position-independent blob.
 * Same float operations in the same order as the game's GetBoneCoords / GetAbsCoords (bit-identical results).
 * The context block (function pointers, identity coords, flags) sits at the end of the blob and is filled by JS. */
typedef unsigned int u32;
typedef int s32;
typedef unsigned long u64;
typedef unsigned char u8;
typedef void * (*FindFn) (void *, const void *);
typedef void (*EnsFn) (void *);
typedef void (*OBone) (void *, const void *, float *);
typedef void (*OAbs) (void *, void *, s32, float *);
typedef struct {
  FindFn find_fn; EnsFn ens_fn; OBone orig_bone; OAbs orig_abs;
  u64 * st;          /* RW counters: bone calls, abs calls, bone diffs, abs diffs (check mode only) */
  s32 * check;       /* RW flag */
  s32 neon;
  s32 pad;
  float ident[12];
} Ctx;
extern Ctx ctx;

static inline void m3q (float * m, const float * q)
{
  float x = q[0], y = q[1], z = q[2], w = q[3];
  float x2 = x + x, y2 = y + y, z2 = z + z;
  float wx = x2 * w, wy = y2 * w, wz = z2 * w;
  float xx = x * x2, xy = x * y2, xz = x * z2, yy = y * y2, yz = y * z2, zz = z * z2;
  m[0] = 1.0f - (yy + zz); m[1] = xy - wz; m[2] = xz + wy;
  m[3] = xy + wz; m[4] = 1.0f - (xx + zz); m[5] = yz - wx;
  m[6] = xz - wy; m[7] = yz + wx; m[8] = 1.0f - (xx + yy);
}
static inline void m3mul (float * r, const float * a, const float * b)
{
  for (int i = 0; i < 3; i++)
    for (int j = 0; j < 3; j++)
      r[i * 3 + j] = (a[i * 3] * b[j] + a[i * 3 + 1] * b[3 + j]) + a[i * 3 + 2] * b[6 + j];
}
static inline void cmul (float * out, const float * a, const float * b, int neon)
{
  float r[12];
  for (int i = 0; i < 4; i++)
    for (int j = 0; j < 3; j++) {
      float p0 = b[i * 3] * a[j], p1 = b[i * 3 + 1] * a[3 + j], p2 = b[i * 3 + 2] * a[6 + j], s;
      if (neon) { float acc = (i == 3) ? a[9 + j] : 0.0f; s = ((p0 + acc) + p1) + p2; }
      else { s = (p0 + p1) + p2; if (i == 3) s = s + a[9 + j]; }
      r[i * 3 + j] = s;
    }
  for (int i = 0; i < 12; i++) out[i] = r[i];
}
static void bone_fast (void * pose, const void * name, float * out)
{
  const float * e = (const float *) ctx.find_fn (pose, name);
  float m1[9], m2[9], r[9];
  if (e == 0) { for (int i = 0; i < 12; i++) out[i] = ctx.ident[i]; return; }
  m3q (m1, e + 10);
  for (int i = 0; i < 9; i++) m1[i] = e[7 + i / 3] * m1[i];
  m3q (m2, e + 3);
  m3mul (r, m2, m1);
  out[0] = r[0]; out[1] = r[3]; out[2] = r[6];
  out[3] = r[1]; out[4] = r[4]; out[5] = r[7];
  out[6] = r[2]; out[7] = r[5]; out[8] = r[8];
  out[9] = e[0]; out[10] = e[1]; out[11] = e[2];
}
static void abs_fast (void * mesh, void * pose, s32 idx, float * out)
{
  float bc[12], t1[12];
  int neon = ctx.neon;
  ctx.ens_fn (mesh);
  for (int i = 0; i < 12; i++) out[i] = ctx.ident[i];
  while (idx >= 0) {
    u8 * bone = *(u8 **) ((u8 *) mesh + 0x138) + (long) idx * 0x98;
    bone_fast (pose, bone, bc);
    cmul (t1, (const float *) (bone + 0x28), bc, neon);
    cmul (out, t1, out, neon);
    idx = *(s32 *) (bone + 0x88);
  }
}
static int same (const float * a, const float * b)
{
  const u32 * x = (const u32 *) a, * y = (const u32 *) b;
  for (int i = 0; i < 12; i++) if (x[i] != y[i]) return 0;
  return 1;
}
__attribute__((section(".text.a"))) void e_bone (void * pose, const void * name, float * out)
{
  if (*ctx.check) {
    float f[12];
    ctx.st[0]++;
    bone_fast (pose, name, f);
    ctx.orig_bone (pose, name, out);
    if (!same (f, out)) ctx.st[2]++;
    return;
  }
  bone_fast (pose, name, out);
}
__attribute__((section(".text.b"))) void e_abs (void * mesh, void * pose, s32 idx, float * out)
{
  if (*ctx.check) {
    float f[12];
    ctx.st[1]++;
    abs_fast (mesh, pose, idx, f);
    ctx.orig_abs (mesh, pose, idx, out);
    if (!same (f, out)) ctx.st[3]++;
    return;
  }
  abs_fast (mesh, pose, idx, out);
}
__attribute__((section(".ctx"), aligned(16))) Ctx ctx = { 0 };
