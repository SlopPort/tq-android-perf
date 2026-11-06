/* Small exact replacements:
 *  name_eq  : the game's 16-byte GAME::Name equality helper (4-word loop) -> two 64-bit compares.
 *  isa      : RTTI_ClassInfo::IsA(other)     = walk this, this->base (+0x10), ... until other or null.
 *  hasbase  : RTTI_ClassInfo::HasBase(other) = same walk starting at this->base.
 * The originals recurse IsA -> HasBase -> IsA through PLT stubs, one hop per class level. */
typedef unsigned long u64;
typedef unsigned char u8;
typedef int (*Orig) (const void *, const void *);
typedef struct { Orig orig[4]; u64 * st; } Ctx;   /* st: calls[4], diffs[4] */
extern Ctx ctx;

static inline int eq (const u64 * a, const u64 * b) { return a[0] == b[0] && a[1] == b[1]; }
static inline int walk (const u8 * a, const u8 * b)
{
  for (; a; a = *(const u8 * const *) (a + 0x10)) if (a == b) return 1;
  return 0;
}
__attribute__((section(".text.a"))) int name_eq (const void * a, const void * b) { return eq (a, b); }
__attribute__((section(".text.b"))) int isa (const void * a, const void * b) { return walk (a, b); }
int hasbase (const void * a, const void * b) { return walk (*(const u8 * const *) ((const u8 *) a + 0x10), b); }
/* std::string == (libc++ short-string layout: byte 0 bit 0 = long; short: size = byte0 >> 1, data at +1;
 * long: size at +8, data at +16). Same answer as the game's byte loop / char_traits::compare, 8 bytes per step,
 * never reading outside either string's bytes. */
static inline u64 ld8 (const u8 * p) { u64 v; __builtin_memcpy (&v, p, 8); return v; }
int str_eq (const u8 * a, const u8 * b)
{
  u64 na = (a[0] & 1) ? *(const u64 *) (a + 8) : (u64) (a[0] >> 1);
  u64 nb = (b[0] & 1) ? *(const u64 *) (b + 8) : (u64) (b[0] >> 1);
  if (na != nb) return 0;
  const u8 * p = (a[0] & 1) ? *(const u8 * const *) (a + 16) : a + 1;
  const u8 * q = (b[0] & 1) ? *(const u8 * const *) (b + 16) : b + 1;
  for (; na >= 8; na -= 8, p += 8, q += 8) if (ld8 (p) != ld8 (q)) return 0;
  for (; na; na--, p++, q++) if (*p != *q) return 0;
  return 1;
}
/* check mode: run both, count differences, return the game's result */
static int run (const void * a, const void * b, int r, int k)
{
  int o = ctx.orig[k] (a, b) & 0xff;
  ctx.st[k]++;
  if (o != r) ctx.st[4 + k]++;
  return o;
}
int c_name_eq (const void * a, const void * b) { return run (a, b, name_eq (a, b), 0); }
int c_isa (const void * a, const void * b) { return run (a, b, isa (a, b), 1); }
int c_hasbase (const void * a, const void * b) { return run (a, b, hasbase (a, b), 2); }
int c_str_eq (const u8 * a, const u8 * b) { return run (a, b, str_eq (a, b), 3); }
__attribute__((section(".ctx"), aligned(16))) Ctx ctx = { 0 };
