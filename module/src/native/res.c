/* GAME::Resource::EnsureAvailable() const, fused: the game's version calls MarkAsUsed (which calls an outlined
 * frame-count helper and BaseResourceManager::IncrementAccessCounter) before checking the load state. Same loads,
 * stores and calls in the same order; only the call/return overhead is gone. */
typedef unsigned int u32;
typedef unsigned long u64;
typedef unsigned char u8;
typedef void (*Fn) (void *);
typedef void (*UnloadFn) (void *, u32);
typedef void (*LoadFn) (void *, void *);
typedef struct { u8 ** engine; u64 * counter; UnloadFn unload; LoadFn load; Fn orig; u64 * st; } Ctx;  /* st: calls, diffs */
extern Ctx ctx;

static inline u32 frame (void) { return *(volatile u32 *) (*ctx.engine + 0x538); }
__attribute__((section(".text.a"))) void ensure (u8 * r)
{
  u32 f = frame ();
  ((volatile u32 *) (r + 0xc))[0] = f; ((volatile u32 *) (r + 0xc))[1] = f;
  u64 c = *(volatile u64 *) ctx.counter + 1; *(volatile u64 *) ctx.counter = c;
  *(volatile u64 *) (r + 0x18) = c;
  u64 s = __atomic_load_n ((u64 *) (r + 0x20), __ATOMIC_ACQUIRE);
  if (s != 2) { ctx.load (*(void **) (r + 0x48), r); return; }
  if (*(u32 *) (r + 0x28) - 1u > 2u) return;
  u32 now = frame ();
  if (now - *(u32 *) (r + 0xa8) < 0x3du) return;
  ctx.unload (r, 0);
  ctx.load (*(void **) (r + 0x48), r);
  *(u32 *) (r + 0xa8) = now;
}
__attribute__((section(".ctx"), aligned(16))) Ctx ctx = { 0 };
