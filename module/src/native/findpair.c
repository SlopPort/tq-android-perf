/* SmallNameMap<T>::FindPair(Name const&) for T = SkeletalPose::AffineParts (stride 0x48), int (0x14),
 * AttachPoint (0xa8). Same probe sequence as the game (251 slots, double hashing on the Name's first word,
 * stop at an empty slot = GAME::Name::noName); the 16-byte key compare is done with two 64-bit loads instead of a
 * called word loop. Returns the slot index or -1. */
typedef unsigned int u32;
typedef unsigned long u64;
typedef unsigned char u8;
typedef int (*Orig) (const u8 * const *, const u32 *);
typedef struct { const u64 * noname; Orig orig[3]; u64 * st; int * check; } Ctx;   /* st: calls[3], diffs[3] */
extern Ctx ctx;

static inline int eq16 (const u64 * a, const u64 * b) { return a[0] == b[0] && a[1] == b[1]; }
static inline int fp (const u8 * const * self, const u32 * name, u32 stride)
{
  const u8 * base = self[0];
  if (base == self[1]) return -1;
  const u64 * empty = ctx.noname, * key = (const u64 *) name;
  u32 h = name[0], a = h % 251u, b = h % 250u + 1u;
  for (u32 i = 0; i < 251u; i++) {
    u32 idx = ((b * i + a) & 0xffffu) % 251u;
    const u64 * k = (const u64 *) (base + (u64) idx * stride);
    if (eq16 (k, empty)) return -1;
    if (eq16 (k, key)) return (int) idx;
  }
  return -1;
}
static inline int run (const u8 * const * self, const u32 * name, u32 stride, int k)
{
  int r = fp (self, name, stride);
  if (*ctx.check) {
    int o = ctx.orig[k] (self, name);
    ctx.st[k]++;
    if (o != r) ctx.st[3 + k]++;
    return o;
  }
  return r;
}
__attribute__((section(".text.a"))) int fp_aff (const u8 * const * self, const u32 * name) { return run (self, name, 0x48, 0); }
__attribute__((section(".text.b"))) int fp_int (const u8 * const * self, const u32 * name) { return run (self, name, 0x14, 1); }
int fp_att (const u8 * const * self, const u32 * name) { return run (self, name, 0xa8, 2); }
__attribute__((section(".ctx"), aligned(16))) Ctx ctx = { 0 };
