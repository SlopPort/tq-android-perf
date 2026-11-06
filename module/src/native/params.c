/* Shader parameter setters: GraphicsShader2::SetValue<T,V>(name, element, type, value) for all 8 instantiations and
 * GraphicsShader2::GetParameterIndex(name). The game's setter calls GetParameterIndex -> (PLT) unordered_map<Name,
 * unsigned>::find -> Name equality helper for every parameter (~41 per mesh draw, ~15k per frame in a fight). Here the
 * lookup is the same libc++ bucket walk on the live table (no cache), inlined into the setter. Same checks, same stores,
 * same return values (including 'true' when the shader has no such parameter). */
typedef unsigned int u32;
typedef unsigned long u64;
typedef unsigned char u8;
typedef int (*OGet) (const void *, const void *);
typedef int (*OSet) (const void *, const void *, u32, u32, const void *);
typedef struct { OGet o_get; OSet o_set[8]; u64 * st; } Ctx;   /* st: calls[2], diffs[2] */
extern Ctx ctx;

static inline u64 bucket (u64 h, u64 bc, int pow2)
{
  if (pow2) return h & (bc - 1);
  return h < bc ? h : h % bc;
}
/* libc++ __hash_table<pair<Name,unsigned>>::find; table at shader+0x120: {buckets, bucket_count, first, size, mlf};
 * node: {next, hash, Name[16], unsigned value}. std::hash<Name> = the Name's first 32-bit word. */
static inline const u64 * find (const u8 * shader, const u64 * name)
{
  const u64 * t = (const u64 *) (shader + 0x120);
  u64 bc = t[1];
  if (bc == 0) return 0;
  u64 h = *(const u32 *) name;
  int pow2 = __builtin_popcountl (bc) <= 1;
  u64 idx = bucket (h, bc, pow2);
  const u64 * nd = ((const u64 * const *) t[0])[idx];
  if (nd == 0) return 0;
  u64 k0 = name[0], k1 = name[1];
  for (nd = (const u64 *) nd[0]; nd; nd = (const u64 *) nd[0]) {
    if (nd[1] == h) { if (nd[2] == k0 && nd[3] == k1) return nd; }
    else if (bucket (nd[1], bc, pow2) != idx) return 0;
  }
  return 0;
}
static inline int get_index (const u8 * shader, const u64 * name)
{
  const u64 * nd = find (shader, name);
  return nd ? (int) *(const u32 *) (nd + 4) : -1;
}
/* param record (0x58 bytes) at *(shader+0xd8) + i*0x58: +0x2c count, +0x30 type, +0x38 data, +0x40 used,
 * +0x48 owner stamp, +0x4c frame stamp; shader+0xc8 owner stamp, shader+0x148 frame stamp */
static inline int set_value (const u8 * shader, const u64 * name, u32 el, u32 type, const u8 * v, u32 stride, u32 bytes)
{
  int i = get_index (shader, name);
  if (i == -1) return 1;
  u8 * p = *(u8 * const *) (shader + 0xd8) + (u64) (u32) i * 0x58;
  u32 own = *(u32 *) (p + 0x48);
  if (own != 0 && own != *(const u32 *) (shader + 0xc8)) return 0;
  if (*(u32 *) (p + 0x30) != type) return 0;
  if (*(u32 *) (p + 0x2c) <= el) return 0;
  u32 used = *(u32 *) (p + 0x40);
  *(u32 *) (p + 0x40) = el + 1 < used ? used : el + 1;
  u8 * d = *(u8 **) (p + 0x38) + (u64) el * stride;
  __builtin_memcpy (d, v, bytes);
  *(u32 *) (p + 0x48) = *(const u32 *) (shader + 0xc8);
  *(u32 *) (p + 0x4c) = *(const u32 *) (shader + 0x148);
  return 1;
}
#define SETTER(nm, stride, bytes) \
  int nm (const u8 * s, const u64 * n, u32 el, u32 ty, const u8 * v) { return set_value (s, n, el, ty, v, stride, bytes); }
__attribute__((section(".text.a"))) int get_param (const u8 * s, const u64 * n) { return get_index (s, n); }
SETTER (set_int, 4, 4)
SETTER (set_f4f, 16, 4)
SETTER (set_f4f2, 16, 8)
SETTER (set_f4f3, 16, 12)
SETTER (set_f4f4, 16, 16)
SETTER (set_f43, 48, 48)
SETTER (set_f44, 64, 64)
SETTER (set_tex, 8, 8)
__attribute__((noinline)) static int idx_slow (const u8 * s, const u64 * n) { return get_index (s, n); }
/* check mode: the lookup is compared against the game's GetParameterIndex; the setter's outcome (return value, and the
 * bytes at the target element) is predicted, then the game's setter runs and both are compared. */
__attribute__((noinline)) static int c_set (const u8 * s, const u64 * n, u32 el, u32 ty, const u8 * v, u32 stride, u32 bytes, int k)
{
  int i = idx_slow (s, n), oi = ctx.o_get (s, n), pred = 1;
  u8 * d = 0;
  if (i != -1) {
    u8 * p = *(u8 * const *) (s + 0xd8) + (u64) (u32) i * 0x58;
    u32 own = *(u32 *) (p + 0x48);
    if ((own != 0 && own != *(const u32 *) (s + 0xc8)) || *(u32 *) (p + 0x30) != ty || *(u32 *) (p + 0x2c) <= el) pred = 0;
    else d = *(u8 **) (p + 0x38) + (u64) el * stride;
  }
  int r = ctx.o_set[k] (s, n, el, ty, v) & 0xff;
  ctx.st[1]++;
  int bad = (i != oi) || (r != pred);
  if (d) for (u32 b = 0; b < bytes; b++) if (d[b] != v[b]) bad = 1;
  if (bad) ctx.st[3]++;
  return r;
}
int c_get (const u8 * s, const u64 * n) { int i = idx_slow (s, n), o = ctx.o_get (s, n); ctx.st[0]++; if (i != o) ctx.st[2]++; return o; }
#define CSETTER(nm, stride, bytes, k) \
  int nm (const u8 * s, const u64 * n, u32 el, u32 ty, const u8 * v) { return c_set (s, n, el, ty, v, stride, bytes, k); }
CSETTER (c_int, 4, 4, 0)
CSETTER (c_f4f, 16, 4, 1)
CSETTER (c_f4f2, 16, 8, 2)
CSETTER (c_f4f3, 16, 12, 3)
CSETTER (c_f4f4, 16, 16, 4)
CSETTER (c_f43, 48, 48, 5)
CSETTER (c_f44, 64, 64, 6)
CSETTER (c_tex, 8, 8, 7)
__attribute__((section(".ctx"), aligned(16))) Ctx ctx = { 0 };
