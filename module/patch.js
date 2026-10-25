// tq-android-perf module 2.0 (public build). Runtime engine patches for Titan Quest on Android (arm64).
// Contains no game code: functions are resolved by exported name, fingerprints are hashes.
const held=[];
function hex(p,n){return Array.from(new Uint8Array(p.readByteArray(n))).map(x=>x.toString(16).padStart(2,'0')).join('');}
function put(p,a){Memory.patchCode(p,a.length,q=>q.writeByteArray(a));}
function clean(p){return p.and(ptr('0x00ffffffffffffff'));}
function branch(from,to,link){
 const delta=Number(to.toString())-Number(from.toString());
 if(delta%4!==0||delta< -0x8000000||delta>=0x8000000)throw Error('Branch out of range');
 const word=((link?0x94000000:0x14000000)|((delta/4)&0x03ffffff))>>>0;
 return [word&255,(word>>>8)&255,(word>>>16)&255,word>>>24];
}
const SOUND_C = `
#include <glib.h>
typedef int (*CreateFn) (void *, const void *, guint32, void *, void **);
typedef int (*ReleaseFn) (void *);
extern CreateFn orig_create;
extern ReleaseFn orig_release;
extern int (*clock_fn) (int, void *);
extern int (*lock_fn) (void *);
extern int (*unlock_fn) (void *);
extern guint8 mtx[64];
extern int enabled;
extern gint64 idle_ns;
typedef struct { const void * data; guint32 len, mode; guint64 h; void * sound; gint64 last; } E;
#define N 512
/* All mutable state lives in JS-allocated RW memory: this Frida build maps the compiled CModule
   (including its globals) read-only + executable, so writing a C global faults (SEGV_ACCERR). */
extern E tab[N];
extern guint64 st[8];   /* hits, misses, bypass, swallowed, evicted, full, miss_ns, entries */
#define hits st[0]
#define misses st[1]
#define bypass st[2]
#define swallowed st[3]
#define evicted st[4]
#define full st[5]
#define miss_ns st[6]
#define entries st[7]
static gint64 now (void) { gint64 t[2]; clock_fn (1, t); return t[0] * 1000000000LL + t[1]; }
static guint64 hsh (const guint8 * p, guint32 len)
{
  guint64 h = 1469598103934665603ULL;
  guint32 n = len < 32 ? len : 32, i;
  for (i = 0; i < n; i++) { h ^= p[i]; h *= 1099511628211ULL; }
  for (i = len - n; i < len; i++) { h ^= p[i]; h *= 1099511628211ULL; }
  return h;
}
int cs_create (void * sys, const void * data, guint32 mode, void * exinfo, void ** out)
{
  guint32 len;
  guint64 h;
  int i, r;
  gint64 t;
  if (!enabled || (mode & 0x800) == 0 || (mode & 0x80) != 0 || exinfo == NULL || data == NULL) { bypass++; return orig_create (sys, data, mode, exinfo, out); }
  len = *(guint32 *) ((guint8 *) exinfo + 4);
  if (len < 64) { bypass++; return orig_create (sys, data, mode, exinfo, out); }
  h = hsh ((const guint8 *) data, len);
  lock_fn (mtx);
  for (i = 0; i < N; i++) {
    E * e = &tab[i];
    if (e->sound != NULL && e->data == data && e->len == len && e->mode == mode && e->h == h) {
      e->last = now (); *out = e->sound; hits++;
      unlock_fn (mtx);
      return 0;
    }
  }
  unlock_fn (mtx);
  t = now ();
  r = orig_create (sys, data, mode, exinfo, out);
  misses++; miss_ns += now () - t;
  if (r == 0 && *out != NULL) {
    int slot = -1, oi = -1;
    gint64 oldest = 0x7fffffffffffffffLL, tn = now ();
    void * victim = NULL;
    lock_fn (mtx);
    for (i = 0; i < N; i++) {
      if (tab[i].sound == NULL) { slot = i; break; }
      if (tab[i].last < oldest) { oldest = tab[i].last; oi = i; }
    }
    if (slot < 0 && oi >= 0 && tn - oldest > idle_ns) { victim = tab[oi].sound; slot = oi; evicted++; entries--; }
    if (slot >= 0) {
      E * e = &tab[slot];
      e->data = data; e->len = len; e->mode = mode; e->h = h; e->sound = *out; e->last = tn; entries++;
    } else full++;
    unlock_fn (mtx);
    if (victim != NULL) orig_release (victim);
  }
  return r;
}
int cs_release (void * sound)
{
  int i;
  lock_fn (mtx);
  for (i = 0; i < N; i++) {
    if (tab[i].sound == sound) { swallowed++; unlock_fn (mtx); return 0; }
  }
  unlock_fn (mtx);
  return orig_release (sound);
}
`;
// --- v1.3: FMOD sample cache via libtq GOT slots (RVAs for libtq.so 3.0.5339)
function soundCache(b){
 const CACHE='/data/user/0/com.hg.titanquestultimate/cache/';
 const report=v=>{try{const f=new File(CACHE+'tq-sound-cache-status.json','w');f.write(JSON.stringify(v));f.close();}catch(e){}};
 try{
  const fmod=Process.getModuleByName('libfmod.so'),libc=Process.getModuleByName('libc.so');
  const createP=fmod.getExportByName('FMOD_System_CreateSound'),releaseP=fmod.getExportByName('FMOD_Sound_Release');
  const slots={create:V2.imp['FMOD_System_CreateSound'],release:V2.imp['FMOD_Sound_Release']};if(!slots.create||!slots.release)throw Error('FMOD imports not found');
  if(!slots.create.readPointer().equals(createP)||!slots.release.readPointer().equals(releaseP))throw Error('FMOD GOT slot mismatch');
  const v={orig_create:Memory.alloc(8),orig_release:Memory.alloc(8),clock_fn:Memory.alloc(8),lock_fn:Memory.alloc(8),unlock_fn:Memory.alloc(8),
   mtx:Memory.alloc(64),enabled:Memory.alloc(8),idle_ns:Memory.alloc(8),tab:Memory.alloc(512*40),st:Memory.alloc(64)};
  v.tab.writeByteArray(new Uint8Array(512*40));v.st.writeByteArray(new Uint8Array(64));v.mtx.writeByteArray(new Uint8Array(64));
  v.clock_fn.writePointer(libc.getExportByName('clock_gettime'));
  v.lock_fn.writePointer(libc.getExportByName('pthread_mutex_lock'));
  v.unlock_fn.writePointer(libc.getExportByName('pthread_mutex_unlock'));
  v.enabled.writeS32(1);v.idle_ns.writeS64(60000*1e6);
  v.orig_create.writePointer(createP);v.orig_release.writePointer(releaseP);
  const cm=new CModule(SOUND_C,v);V2.en.snd=v.enabled;
  held.push(cm,v);
  const setSlot=(slot,value)=>{const page=slot.and(ptr(Process.pageSize-1).not());Memory.protect(page,Process.pageSize,'rw-');slot.writePointer(value);Memory.protect(page,Process.pageSize,'r--');};
  setSlot(slots.release,cm.cs_release);
  setSlot(slots.create,cm.cs_create);
  const stats=()=>{const g=i=>v.st.add(i*8).readU64().toNumber();return{state:'active',pid:Process.id,entries:g(7),hits:g(0),misses:g(1),bypass:g(2),swallowed:g(3),evicted:g(4),full:g(5)};};
  report(stats());
  setInterval(()=>report(stats()),60000);
  console.log('TQ_SND active');
 }catch(e){report({state:'error',error:String(e)});console.log('TQ_SND_ERROR '+e);throw e;}
}
const SLOT_C = `
#include <glib.h>
typedef void (*CalcFn) (void *, float);
extern CalcFn orig_calc;
extern int enabled;
extern float t2;
typedef struct { void * mgr; void * region; float x, y, z; float pad; } A;
#define NA 64
extern A anchors[NA];
extern guint64 st[4];   /* calls, skipped, recomputes, nopos */
static A * find (void * mgr, int create)
{
  int i, free_i = -1;
  for (i = 0; i < NA; i++) {
    if (anchors[i].mgr == mgr) return &anchors[i];
    if (free_i < 0 && anchors[i].mgr == NULL) free_i = i;
  }
  if (!create) return NULL;
  if (free_i < 0) free_i = (int) (((gsize) mgr >> 4) % NA);   /* full: overwrite a slot */
  anchors[free_i].mgr = mgr; anchors[free_i].region = NULL;
  return &anchors[free_i];
}
void calc (void * self, float radius)
{
  guint8 * m = (guint8 *) self;
  guint8 * owner, * mm;
  void * reg;
  float x, y, z;
  A * a;
  st[0]++;
  if (!enabled) { orig_calc (self, radius); return; }
  owner = *(guint8 **) m;
  mm = owner != NULL ? *(guint8 **) (owner + 0xad0) : NULL;
  if (mm == NULL) { st[3]++; orig_calc (self, radius); return; }
  reg = *(void **) (mm + 0x10);
  x = *(float *) (mm + 0x18); y = *(float *) (mm + 0x1c); z = *(float *) (mm + 0x20);
  a = find (self, 0);
  if (reg != NULL && a != NULL && a->region == reg) {
    float dx = x - a->x, dy = y - a->y, dz = z - a->z;
    if (dx * dx + dy * dy + dz * dz < t2) {
      *(void **) (m + 0x38) = reg;
      *(float *) (m + 0x40) = x; *(float *) (m + 0x44) = y; *(float *) (m + 0x48) = z;
      st[1]++;
      orig_calc (self, radius);
      return;
    }
  }
  orig_calc (self, radius);
  st[2]++;
  a = find (self, 1);
  a->region = *(void **) (m + 0x38);
  a->x = *(float *) (m + 0x40); a->y = *(float *) (m + 0x44); a->z = *(float *) (m + 0x48);
}
`;
const UNIFORM_C = `
#include <glib.h>
extern int (*gl_get) (guint32, const char *);
extern void (*gl_link) (guint32);
extern void (*gl_binary) (guint32, guint32, const void *, gint32);
extern void (*gl_delete) (guint32);
extern const char * (*i2n) (glong);
extern int enabled;
extern guint64 st[4];   /* calls, queries, misses served, row clears */
#define NP 8192
extern guint8 neg[NP * 16];   /* 128 bits per GL program name */
static void clear_row (guint32 prog) { if (prog < NP) { int i; for (i = 0; i < 16; i++) neg[prog * 16 + i] = 0; st[3]++; } }
void link_hook (guint32 prog) { clear_row (prog); gl_link (prog); clear_row (prog); }
void binary_hook (guint32 prog, guint32 fmt, const void * bin, gint32 len) { clear_row (prog); gl_binary (prog, fmt, bin, len); clear_row (prog); }
void delete_hook (guint32 prog) { clear_row (prog); gl_delete (prog); }
int gul (guint8 * self, guint32 prog, glong idx)
{
  int * slot;
  int v;
  st[0]++;
  if ((gulong) idx > 0x6c) return -1;
  slot = (int *) (self + 0xe4 + idx * 4);
  v = *slot;
  if (v >= 0) return v;
  if (enabled && prog < NP && (neg[prog * 16 + (idx >> 3)] & (1 << (idx & 7)))) { st[2]++; return -1; }
  st[1]++;
  v = gl_get (prog, i2n (idx));
  *slot = v;
  if (v == -1 && prog < NP) neg[prog * 16 + (idx >> 3)] |= (guint8) (1 << (idx & 7));
  return v;
}
`;
// --- v1.4 (RVAs for libtq.so 3.0.5339)
function v14Report(k,v){
 try{const P='/data/user/0/com.hg.titanquestultimate/cache/tq-v14-status.json';let o={};
  try{o=JSON.parse(File.readAllText(P));}catch(e){}
  o[k]=v;o.pid=Process.id;const f=new File(P,'w');f.write(JSON.stringify(o));f.close();}catch(e){}
}
// Redirect a function entry to fn with a single atomic `b stub`. Returns a pointer that runs the
// original (relocated first instruction + branch back) when keepFirst is the expected entry word.
function entryRedirect(b,rva,fn,keepFirst){
 const t=b.add(rva);
 const stub=v2NearPage(t);held.push(stub);
 stub.writeU32(0x58000050);stub.add(4).writeU32(0xd61f0200);stub.add(8).writePointer(fn);   // ldr x16,#8; br x16
 if(keepFirst){
  if(hex(t,4)!==keepFirst)throw Error('entry mismatch '+rva.toString(16)+' '+hex(t,4));
  stub.add(16).writeByteArray(t.readByteArray(4));
  stub.add(20).writeByteArray(branch(stub.add(20),t.add(4),false));
 }
 if(!Memory.protect(stub,Process.pageSize,'r-x'))throw Error('RX protection failed');
 put(t,branch(t,stub,false));
 return stub.add(16);
}
function slotNativeV14(b){
 try{
  const v={orig_calc:Memory.alloc(8),enabled:Memory.alloc(8),t2:Memory.alloc(8),anchors:Memory.alloc(64*32),st:Memory.alloc(32)};
  v.anchors.writeByteArray(new Uint8Array(64*32));v.st.writeByteArray(new Uint8Array(32));
  v.enabled.writeS32(1);v.t2.writeFloat(1.0);
  const cm=new CModule(SLOT_C,v);V2.en.slot=v.enabled;held.push(cm,v);
  // orig_calc must be valid before the entry switches.
  const t=V2.exp('_ZN4GAME11SlotManager22CalculateSlotPositionsEf');
  if(hex(t,4)!=='ff4301d1')throw Error('CalculateSlotPositions entry mismatch '+hex(t,4));
  const stub=v2NearPage(t);held.push(stub);
  stub.writeU32(0x58000050);stub.add(4).writeU32(0xd61f0200);stub.add(8).writePointer(cm.calc);
  stub.add(16).writeByteArray(t.readByteArray(4));
  stub.add(20).writeByteArray(branch(stub.add(20),t.add(4),false));
  if(!Memory.protect(stub,Process.pageSize,'r-x'))throw Error('RX protection failed');
  v.orig_calc.writePointer(stub.add(16));
  put(t,branch(t,stub,false));
  const g=i=>v.st.add(i*8).readU64().toNumber();
  const rep=()=>v14Report('slot',{state:'active',calls:g(0),skipped:g(1),recomputes:g(2)});
  rep();setInterval(rep,60000);
  console.log('TQ_SLOT active');
 }catch(e){v14Report('slot',{state:'error',error:String(e)});console.log('TQ_SLOT_ERROR '+e);throw e;}
}
function uniformNegV14(b){
 try{
  const slots={get:V2.imp['glGetUniformLocation'],link:V2.imp['glLinkProgram'],binary:V2.imp['glProgramBinary'],del:V2.imp['glDeleteProgram']};for(const k in slots)if(!slots[k])throw Error('GL import not found: '+k);
  const v={gl_get:Memory.alloc(8),gl_link:Memory.alloc(8),gl_binary:Memory.alloc(8),gl_delete:Memory.alloc(8),i2n:Memory.alloc(8),
   enabled:Memory.alloc(8),st:Memory.alloc(32),neg:Memory.alloc(8192*16)};
  v.gl_get.writePointer(slots.get.readPointer());v.gl_link.writePointer(slots.link.readPointer());
  v.gl_binary.writePointer(slots.binary.readPointer());v.gl_delete.writePointer(slots.del.readPointer());
  for(const k of ['gl_get','gl_link','gl_binary','gl_delete'])if(v[k].readPointer().isNull())throw Error('empty GOT '+k);
  v.i2n.writePointer(V2.exp('_Z19uniforms_index2namel'));   // _Z19uniforms_index2namel (0x7bdf50 is its PLT stub)
  v.enabled.writeS32(1);v.st.writeByteArray(new Uint8Array(32));v.neg.writeByteArray(new Uint8Array(8192*16));
  const e=V2.exp('_ZN4GAME15OpenGLESProgram18GetUniformLocationEjl'),w=hex(e,4);
  // original stp, or v1.1's `b` to its wrapper
  if(w!=='f44fbea9'&&(parseInt(w.slice(6,8),16)&0xfc)!==0x14)throw Error('GetUniformLocation entry mismatch '+w);
  const cm=new CModule(UNIFORM_C,v);V2.en.uneg=v.enabled;held.push(cm,v);
  const setSlot=(slot,value)=>{const page=slot.and(ptr(Process.pageSize-1).not());Memory.protect(page,Process.pageSize,'rw-');slot.writePointer(value);Memory.protect(page,Process.pageSize,'r--');};
  // Invalidation hooks first, then the lookup.
  setSlot(slots.link,cm.link_hook);setSlot(slots.binary,cm.binary_hook);setSlot(slots.del,cm.delete_hook);
  entryRedirect(b,e.sub(b).toUInt32(),cm.gul,null);
  const g=i=>v.st.add(i*8).readU64().toNumber();
  const rep=()=>v14Report('uneg',{state:'active',calls:g(0),queries:g(1),missesServed:g(2),rowClears:g(3)});
  rep();setInterval(rep,60000);
  console.log('TQ_UNEG active');
 }catch(e){v14Report('uneg',{state:'error',error:String(e)});console.log('TQ_UNEG_ERROR '+e);throw e;}
}
const ABBOX_CODE = [0,4,64,45,2,8,64,189,3,144,65,45,5,20,64,189,6,56,35,30,39,56,36,30,80,56,37,30,0,40,35,30,33,40,36,30,66,40,37,30,49,72,64,45,51,8,64,189,52,212,65,45,54,20,64,189,23,16,62,30,24,16,62,30,25,16,62,30,41,0,128,82,32,34,38,30,36,1,0,84,32,34,32,30,141,1,0,84,233,3,31,42,136,34,32,30,32,1,0,84,26,56,49,30,87,27,52,30,6,0,0,20,233,3,31,42,136,34,32,30,96,0,0,84,218,56,49,30,87,27,52,30,64,34,39,30,36,1,0,84,64,34,33,30,141,1,0,84,233,3,31,42,168,34,32,30,32,1,0,84,58,56,50,30,88,27,53,30,6,0,0,20,233,3,31,42,168,34,32,30,96,0,0,84,250,56,50,30,88,27,53,30,96,34,48,30,36,1,0,84,96,34,34,30,141,1,0,84,233,3,31,42,200,34,32,30,32,1,0,84,90,56,51,30,89,27,54,30,6,0,0,20,233,3,31,42,200,34,32,30,96,0,0,84,26,58,51,30,89,27,54,30,105,4,0,53,0,35,55,30,26,207,55,30,234,215,159,26,75,0,128,82,32,35,58,30,106,193,138,26,58,207,58,30,72,35,32,30,137,3,0,84,234,0,0,52,91,11,52,30,59,42,59,30,96,35,38,30,228,2,0,84,96,35,32,30,172,2,0,84,95,5,0,113,224,0,0,84,91,11,53,30,91,42,59,30,96,35,39,30,228,1,0,84,96,35,33,30,172,1,0,84,95,9,0,113,224,0,0,84,91,11,54,30,123,42,59,30,96,35,48,30,228,0,0,84,96,35,34,30,172,0,0,84,64,67,32,30,192,3,95,214,224,3,39,30,192,3,95,214,136,0,0,88,0,1,64,189,192,3,95,214,31,32,3,213,0,0,0,0,0,0,0,0];
const STREAM_C = `
#include <glib.h>
typedef int (*CreateFn) (void *, const char *, guint32, void *, void **);
typedef int (*ReleaseFn) (void *);
typedef int (*LenFn) (void *, guint32 *, guint32);
extern CreateFn orig_stream;
extern CreateFn orig_create;
extern ReleaseFn next_release;
extern LenFn get_len;
extern int (*lock_fn) (void *);
extern int (*unlock_fn) (void *);
extern guint8 mtx[64];
extern int enabled;
extern guint32 max_ms;
extern guint32 budget_ms;
typedef struct { guint64 h; void * sound; gint32 state; guint32 ms; char name[112]; } E;   /* state 1 cached, 2 stream-only */
#define N 384
extern E tab[N];
extern guint64 st[8];   /* hits, loaded, long, bypass, swallowed, failed, entries, cached_ms */
static guint64 hs (const char * s) { guint64 h = 1469598103934665603ULL; while (*s) { h ^= (guint8) *s++; h *= 1099511628211ULL; } return h; }
static int eq (const char * a, const char * b) { while (*a && *a == *b) { a++; b++; } return *a == *b; }
static int slen (const char * s) { int n = 0; while (s[n] && n < 200) n++; return n; }
static void put (int slot, guint64 h, const char * name, void * snd, int state, guint32 ms)
{
  E * e = &tab[slot]; int i;
  for (i = 0; name[i] && i < 111; i++) e->name[i] = name[i];
  e->name[i] = 0; e->h = h; e->sound = snd; e->ms = ms; e->state = state; st[6]++;
}
int cs_stream (void * sys, const char * name, guint32 mode, void * ex, void ** out)
{
  guint64 h; int i, slot = -1, r, r2; void * snd = NULL; guint32 ms = 0;
  if (!enabled || ex != NULL || name == NULL || slen (name) > 110) { st[3]++; return orig_stream (sys, name, mode, ex, out); }
  h = hs (name);
  lock_fn (mtx);
  for (i = 0; i < N; i++) {
    E * e = &tab[(h + i) % N];
    if (e->state == 0) { slot = (int) ((h + i) % N); break; }
    if (e->h == h && eq (e->name, name)) {
      if (e->state == 1) { *out = e->sound; st[0]++; unlock_fn (mtx); return 0; }
      unlock_fn (mtx); st[2]++; return orig_stream (sys, name, mode, ex, out);
    }
  }
  unlock_fn (mtx);
  r = orig_stream (sys, name, mode, ex, out);
  if (r != 0 || *out == NULL || slot < 0) { st[3]++; return r; }
  if (get_len (*out, &ms, 1) != 0 || ms == 0 || ms > max_ms || st[7] + ms > budget_ms) {
    lock_fn (mtx); if (tab[slot].state == 0) put (slot, h, name, NULL, 2, ms); unlock_fn (mtx);
    st[2]++; return r;
  }
  r2 = orig_create (sys, name, mode, NULL, &snd);
  if (r2 != 0 || snd == NULL) {
    lock_fn (mtx); if (tab[slot].state == 0) put (slot, h, name, NULL, 2, ms); unlock_fn (mtx);
    st[5]++; return r;
  }
  lock_fn (mtx);
  if (tab[slot].state != 0) { unlock_fn (mtx); next_release (snd); return r; }   /* lost a race: keep the stream */
  put (slot, h, name, snd, 1, ms); st[7] += ms; st[1]++;
  unlock_fn (mtx);
  next_release (*out);   /* drop the probe stream; this play uses the sample */
  *out = snd;
  return 0;
}
int cs_release2 (void * sound)
{
  int i;
  if (sound != NULL) {
    lock_fn (mtx);
    for (i = 0; i < N; i++) if (tab[i].state == 1 && tab[i].sound == sound) { st[4]++; unlock_fn (mtx); return 0; }
    unlock_fn (mtx);
  }
  return next_release (sound);
}
`;
// --- v1.5 (RVAs for libtq.so 3.0.5339)
function nearJump(t,fn){
 const stub=v2NearPage(t);held.push(stub);
 stub.writeU32(0x58000050);stub.add(4).writeU32(0xd61f0200);stub.add(8).writePointer(fn);   // ldr x16,#8; br x16
 if(!Memory.protect(stub,Process.pageSize,'r-x'))throw Error('RX protection failed');
 put(t,branch(t,stub,false));
}
function abboxFastV15(b){
 try{
  const t=V2.exp('_ZNK4GAME5ABBox15GetIntersectionERKNS_3RayE');
  if(hex(t,4)!=='ffc301d1')throw Error('ABBox entry mismatch '+hex(t,4));   // sub sp, sp, #0x70
  const stub=v2NearPage(t);held.push(stub);
  stub.writeByteArray(ABBOX_CODE);
  stub.add(ABBOX_CODE.length-8).writePointer(V2.exp('_ZN4GAME4Math8infinityE'));   // &GAME::Math::infinity
  if(!Memory.protect(stub,Process.pageSize,'r-x'))throw Error('RX protection failed');
  put(t,branch(t,stub,false));
  v14Report('abbox',{state:'active'});
  console.log('TQ_ABBOX active');
 }catch(e){v14Report('abbox',{state:'error',error:String(e)});console.log('TQ_ABBOX_ERROR '+e);throw e;}
}
function streamCacheV15(b){
 try{
  const fmod=Process.getModuleByName('libfmod.so'),libc=Process.getModuleByName('libc.so');
  const site=V2.streamSite,relSlot=V2.imp['FMOD_Sound_Release'],streamSlot=V2.imp['FMOD_System_CreateStream'];
  const w=site.readU32();
  if((w>>>26)!==0x05||!site.add((((w&0x3ffffff)<<6)>>6)*4).equals(V2.streamStub))throw Error('stream tail branch mismatch '+w.toString(16));
  if(!streamSlot.readPointer().equals(fmod.getExportByName('FMOD_System_CreateStream')))throw Error('CreateStream GOT mismatch');
  const E=136,N=384;
  const v={orig_stream:Memory.alloc(8),orig_create:Memory.alloc(8),next_release:Memory.alloc(8),get_len:Memory.alloc(8),
   lock_fn:Memory.alloc(8),unlock_fn:Memory.alloc(8),mtx:Memory.alloc(64),enabled:Memory.alloc(8),
   max_ms:Memory.alloc(8),budget_ms:Memory.alloc(8),tab:Memory.alloc(E*N),st:Memory.alloc(64)};
  v.orig_stream.writePointer(streamSlot.readPointer());
  v.orig_create.writePointer(fmod.getExportByName('FMOD_System_CreateSound'));
  v.next_release.writePointer(relSlot.readPointer());
  v.get_len.writePointer(fmod.getExportByName('FMOD_Sound_GetLength'));
  v.lock_fn.writePointer(libc.getExportByName('pthread_mutex_lock'));
  v.unlock_fn.writePointer(libc.getExportByName('pthread_mutex_unlock'));
  v.mtx.writeByteArray(new Uint8Array(64));v.tab.writeByteArray(new Uint8Array(E*N));v.st.writeByteArray(new Uint8Array(64));
  v.enabled.writeS32(1);v.max_ms.writeU32(6000);v.budget_ms.writeU32(300000);
  const cm=new CModule(STREAM_C,v);V2.en.strm=v.enabled;held.push(cm,v);
  const page=relSlot.and(ptr(Process.pageSize-1).not());
  Memory.protect(page,Process.pageSize,'rw-');relSlot.writePointer(cm.cs_release2);Memory.protect(page,Process.pageSize,'r--');
  nearJump(site,cm.cs_stream);
  const g=i=>v.st.add(i*8).readU64().toNumber();
  const rep=()=>v14Report('strm',{state:'active',hits:g(0),loaded:g(1),long:g(2),bypass:g(3),swallowed:g(4),failed:g(5),cachedSec:g(7)/1000});
  rep();setInterval(rep,60000);
  console.log('TQ_STRM active');
 }catch(e){v14Report('strm',{state:'error',error:String(e)});console.log('TQ_STRM_ERROR '+e);throw e;}
}
const GETEND_STUB = [253,123,190,169,253,3,0,145,224,35,1,169,225,3,8,170,144,1,0,88,0,2,63,214,192,0,0,53,224,35,65,169,6,0,0,148,224,7,65,169,16,1,0,88,0,2,63,214,253,123,194,168,192,3,95,214,31,32,3,213,31,32,3,213,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0];
const GETEND_C = `
#include <glib.h>
extern int (*clock_fn) (int, void *);
extern int (*lock_fn) (void *);
extern int (*unlock_fn) (void *);
extern guint8 mtx[64];
extern int enabled;
extern gint64 max_age_ns;
typedef struct { void * seg; void * mesh; void * pb; void * pe; guint32 lx, ly, lz, pad; gint64 t; guint8 out[24]; } E;   /* 80 bytes */
#define N 1024
extern E tab[N];
extern guint64 st[4];   /* hits, misses, stores, skipped */
static gint64 now (void) { gint64 t[2]; clock_fn (1, t); return t[0] * 1000000000LL + t[1]; }
static int key (guint8 * seg, void ** mesh, void ** pb, void ** pe, guint32 * l)
{
  guint32 * last;
  *mesh = *(void **) seg; *pb = *(void **) (seg + 0x10); *pe = *(void **) (seg + 0x18);
  if (*mesh == NULL || *pb == *pe) return 0;
  last = (guint32 *) ((guint8 *) *pe - 12);
  l[0] = last[0]; l[1] = last[1]; l[2] = last[2];
  return 1;
}
static E * slot (void * mesh, guint32 * l)
{
  guint64 h = ((guint64) (gsize) mesh) * 0x9E3779B97F4A7C15ULL;
  h ^= l[0]; h *= 1099511628211ULL; h ^= l[1]; h *= 1099511628211ULL; h ^= l[2]; h *= 1099511628211ULL;
  return &tab[(h >> 20) % N];
}
int ge_lookup (guint8 * seg, guint8 * out)
{
  void * mesh; void * pb; void * pe; guint32 l[3]; E * e; int i;
  if (!enabled || !key (seg, &mesh, &pb, &pe, l)) { st[3]++; return 0; }
  e = slot (mesh, l);
  lock_fn (mtx);
  if (e->mesh == mesh && e->lx == l[0] && e->ly == l[1] && e->lz == l[2] && now () - e->t < max_age_ns) {
    for (i = 0; i < 24; i++) out[i] = e->out[i];
    unlock_fn (mtx); st[0]++; return 1;
  }
  unlock_fn (mtx); st[1]++;
  return 0;
}
void ge_store (guint8 * seg, guint8 * out)
{
  void * mesh; void * pb; void * pe; guint32 l[3]; E * e; int i;
  if (!enabled || !key (seg, &mesh, &pb, &pe, l)) return;
  e = slot (mesh, l);
  lock_fn (mtx);
  e->seg = seg; e->mesh = mesh; e->pb = pb; e->pe = pe; e->lx = l[0]; e->ly = l[1]; e->lz = l[2]; e->t = now ();
  for (i = 0; i < 24; i++) e->out[i] = out[i];
  unlock_fn (mtx); st[2]++;
}
`;
// --- v1.6 (RVAs for libtq.so 3.0.5339)
function getEndCacheV16(b){
 try{
  const libc=Process.getModuleByName('libc.so');
  const t=V2.exp('_ZNK4GAME10PathRecast7Segment6GetEndEv');
  if(hex(t,4)!=='ff4301d1')throw Error('GetEnd entry mismatch '+hex(t,4));   // sub sp, sp, #0x50
  const v={clock_fn:Memory.alloc(8),lock_fn:Memory.alloc(8),unlock_fn:Memory.alloc(8),mtx:Memory.alloc(64),enabled:Memory.alloc(8),
   max_age_ns:Memory.alloc(8),tab:Memory.alloc(1024*80),st:Memory.alloc(32)};
  v.clock_fn.writePointer(libc.getExportByName('clock_gettime'));
  v.lock_fn.writePointer(libc.getExportByName('pthread_mutex_lock'));
  v.unlock_fn.writePointer(libc.getExportByName('pthread_mutex_unlock'));
  v.mtx.writeByteArray(new Uint8Array(64));v.tab.writeByteArray(new Uint8Array(1024*80));v.st.writeByteArray(new Uint8Array(32));
  v.enabled.writeS32(1);v.max_age_ns.writeS64(500*1e6);
  const cm=new CModule(GETEND_C,v);V2.en.getend=v.enabled;held.push(cm,v);
  const stub=v2NearPage(t);held.push(stub);
  stub.writeByteArray(GETEND_STUB);
  stub.add(0x38).writeByteArray(t.readByteArray(4));
  stub.add(0x3c).writeByteArray(branch(stub.add(0x3c),t.add(4),false));
  stub.add(0x40).writePointer(cm.ge_lookup);stub.add(0x48).writePointer(cm.ge_store);
  if(!Memory.protect(stub,Process.pageSize,'r-x'))throw Error('RX protection failed');
  put(t,branch(t,stub,false));
  const g=i=>v.st.add(i*8).readU64().toNumber();
  const rep=()=>v14Report('getend',{state:'active',hits:g(0),misses:g(1),skipped:g(3)});
  rep();setInterval(rep,60000);
  console.log('TQ_GETEND active');
 }catch(e){v14Report('getend',{state:'error',error:String(e)});console.log('TQ_GETEND_ERROR '+e);throw e;}
}
const FP_KNOWN = {"slot": [["_ZN4GAME11SlotManager22CalculateSlotPositionsEf", 204, ["c25dc5a2"]], ["_ZNK4GAME9Character15GetPathPositionEv", 8, ["c4076237"]], ["_ZNK4GAME24CharacterMovementManager15GetPathPositionEv", 104, ["4f4cfd6f"]]], "uneg": [["_ZN4GAME15OpenGLESProgram18GetUniformLocationEjl", 80, ["2b7e279a"]], ["_ZN4GAME15OpenGLESProgram21resetAttributeSamplerEv", 72, ["43e6f4f2"]]], "abbox": [["_ZNK4GAME5ABBox15GetIntersectionERKNS_3RayE", 996, ["7fea5668"]]], "getend": [["_ZNK4GAME10PathRecast7Segment6GetEndEv", 160, ["5adcfaad"]]], "snd": [["_ZN4GAME12SoundManager6Play3DERKNS_15SoundDescriptorEb", 668, ["9d51de57"]], ["_ZN4GAME12SoundManager6Play2DERKNS_15SoundDescriptorEb", 496, ["f9a47c6f"]], ["_ZN4GAME12SoundManager19ProcessFinishedListEv", 248, ["e4d2ab3e"]], ["_ZN4GAME12SoundManager13StealInstanceEv", 156, ["a9e3d69c"]]], "strm": [["_ZN4GAME12SoundManager13StartStream3DERKNS_15SoundDescriptorE", 480, ["897ad4c0"]], ["_ZN4GAME12SoundManager11StartStreamERKNS_15SoundDescriptorE", 444, ["b426902c"]], ["_ZN4GAME12SoundManager19ProcessFinishedListEv", 248, ["e4d2ab3e"]], ["_ZN4GAME12SoundManager13StealInstanceEv", 156, ["a9e3d69c"]]]};
// ===== tq_autopatch v2: version-aware layer =====
// Nothing below uses fixed addresses. Functions are resolved by exported symbol name, GOT slots by import
// name (JUMP_SLOT/GLOB_DAT relocations of the mapped dynamic section), the PLT-bypass site list is computed on the device from the mapped ELF
// (program headers, PLT stub pattern, .eh_frame_hdr function ranges) and cached per build-id, and every
// patch is gated by relocation-insensitive fingerprints of the functions whose layout it relies on
// (see tools/analysis/fingerprints.py). A patch whose fingerprints are unknown is skipped and the reason is
// written to tq-v2-status.json; the other patches still apply.
const V2_CACHE = '/data/user/0/com.hg.titanquestultimate/cache/';
const V2 = { status: { module: '2.0', pid: Process.id, started: new Date().toISOString(), patches: {}, fingerprints: {} } };
function v2Save() { try { const f = new File(V2_CACHE + 'tq-v2-status.json', 'w'); f.write(JSON.stringify(V2.status)); f.close(); } catch (e) {} }
function v2Set(name, obj) { V2.status.patches[name] = Object.assign(V2.status.patches[name] || {}, obj); v2Save(); }
function v2Sleep(ms) { return new Promise(r => setTimeout(r, ms)); }
V2.exp = function (name) { const a = V2.mod.findExportByName(name); if (a === null) throw Error('missing symbol ' + name); return a; };

// --- fingerprints (twin of benchmark/fingerprints.py)
function fpHash(addr, len) {
  const n = len >>> 2, u = new Uint32Array(addr.readByteArray(n * 4)), adrp = new Set();
  let h = 0x811c9dc5;
  for (let i = 0; i < n; i++) {
    const w = u[i]; let m = w;
    if (((w & 0x7c000000) >>> 0) === 0x14000000) {
      let imm = w & 0x3ffffff; if (imm & 0x2000000) imm -= 0x4000000;
      if (!(i + imm >= 0 && i + imm < n)) m = (w & 0xfc000000) >>> 0;
    } else if (((w & 0x9f000000) >>> 0) === 0x90000000) { m = (w & 0x9f00001f) >>> 0; adrp.add(w & 31); }
    else if (((w & 0x9f000000) >>> 0) === 0x10000000) m = (w & 0x9f00001f) >>> 0;
    else if (((w & 0x3b000000) >>> 0) === 0x18000000) m = (w & 0xff00001f) >>> 0;
    else if (((w & 0x7f800000) >>> 0) === 0x11000000 && adrp.has((w >>> 5) & 31)) m = (w & 0xffc003ff) >>> 0;
    else if (((w & 0x3b000000) >>> 0) === 0x39000000 && adrp.has((w >>> 5) & 31)) m = (w & 0xffc003ff) >>> 0;
    for (let k = 0; k < 4; k++) { h = (h ^ ((m >>> (8 * k)) & 0xff)) >>> 0; h = Math.imul(h, 0x01000193) >>> 0; }
  }
  return ('0000000' + h.toString(16)).slice(-8);
}
function v2Fingerprints() {
  const res = {};
  for (const patch of Object.keys(FP_KNOWN)) {
    const why = [];
    for (const [sym, len, hashes] of FP_KNOWN[patch]) {
      const a = V2.mod.findExportByName(sym);
      if (a === null) { why.push('missing ' + sym); continue; }
      const h = V2.status.fingerprints[sym] || (V2.status.fingerprints[sym] = fpHash(a, len));
      if (hashes.indexOf(h) < 0) why.push('changed ' + sym + ' (' + h + ')');
    }
    res[patch] = why.length ? why.join('; ') : null;
  }
  return res;
}

// --- mapped ELF helpers (RVA based)
function v2Elf(b) {
  const phoff = b.add(0x20).readU64().toNumber(), es = b.add(0x36).readU16(), n = b.add(0x38).readU16(), ph = [];
  for (let i = 0; i < n; i++) {
    const p = b.add(phoff + i * es);
    ph.push({ type: p.readU32(), flags: p.add(4).readU32(), vaddr: p.add(16).readU64().toNumber(), filesz: p.add(32).readU64().toNumber() });
  }
  return ph;
}
function v2BuildId(b, ph) {
  for (const s of ph.filter(x => x.type === 4)) {
    let o = s.vaddr; const end = s.vaddr + s.filesz;
    while (o + 12 <= end) {
      const nsz = b.add(o).readU32(), dsz = b.add(o + 4).readU32(), type = b.add(o + 8).readU32();
      const name = o + 12, desc = name + ((nsz + 3) & ~3);
      if (type === 3 && nsz === 4) return Array.from(new Uint8Array(b.add(desc).readByteArray(dsz))).map(x => ('0' + x.toString(16)).slice(-2)).join('');
      o = desc + ((dsz + 3) & ~3);
    }
  }
  return null;
}
// Reader over one mapped segment, copied once (single NativePointer reads were ~47 s for 66k FDEs).
function v2Reader(b, seg) {
  const dv = new DataView(b.add(seg.vaddr).readByteArray(seg.filesz)), o = seg.vaddr;
  const inside = rva => rva >= o && rva + 8 <= o + seg.filesz;
  return {
    u8: rva => inside(rva) ? dv.getUint8(rva - o) : b.add(rva).readU8(),
    u16: rva => inside(rva) ? dv.getUint16(rva - o, true) : b.add(rva).readU16(),
    s16: rva => inside(rva) ? dv.getInt16(rva - o, true) : b.add(rva).readS16(),
    u32: rva => inside(rva) ? dv.getUint32(rva - o, true) : b.add(rva).readU32(),
    s32: rva => inside(rva) ? dv.getInt32(rva - o, true) : b.add(rva).readS32(),
    u64: rva => b.add(rva).readU64().toNumber(),
    s64: rva => b.add(rva).readS64().toNumber()
  };
}
function v2ReadEnc(R, rva, enc, datarel) {
  const fmt = enc & 0x0f, app = enc & 0x70;
  let v, n;
  if (fmt === 0x0b) { v = R.s32(rva); n = 4; } else if (fmt === 0x03) { v = R.u32(rva); n = 4; }
  else if (fmt === 0x0c) { v = R.s64(rva); n = 8; } else if (fmt === 0x04) { v = R.u64(rva); n = 8; }
  else if (fmt === 0x0a) { v = R.s16(rva); n = 2; } else if (fmt === 0x02) { v = R.u16(rva); n = 2; }
  else throw Error('unsupported eh encoding 0x' + enc.toString(16));
  if (app === 0x10) v += rva; else if (app === 0x30) v += datarel; else if (app !== 0) throw Error('unsupported eh application 0x' + enc.toString(16));
  return [v, n];
}
function v2Uleb(R, rva) { let r = 0, s = 0, n = 0, x; do { x = R.u8(rva + n); r += (x & 0x7f) * Math.pow(2, s); s += 7; n++; } while (x & 0x80); return [r, n]; }
function v2CieFdeEnc(R, cie) {
  let p = cie + 9, aug = '';
  for (let c; (c = R.u8(p)) !== 0; p++) aug += String.fromCharCode(c);
  p++;
  p += v2Uleb(R, p)[1]; p += v2Uleb(R, p)[1];                         // code / data alignment
  p += R.u8(cie + 8) === 1 ? 1 : v2Uleb(R, p)[1];          // return register
  if (aug[0] !== 'z') return 0x00;
  p += v2Uleb(R, p)[1];
  for (const ch of aug.slice(1)) {
    if (ch === 'R') return R.u8(p);
    if (ch === 'P') { const e = R.u8(p); p += 1 + v2ReadEnc(R, p + 1, e & 0x0f, 0)[1]; }
    else if (ch === 'L') p += 1;
  }
  return 0x00;
}
function v2FunctionRanges(b, ph) {
  const hdr = ph.find(x => x.type === 0x6474e550);
  if (!hdr) throw Error('no PT_GNU_EH_FRAME');
  const seg = ph.find(x => x.type === 1 && x.vaddr <= hdr.vaddr && hdr.vaddr < x.vaddr + x.filesz) || hdr, R = v2Reader(b, seg);
  const h = hdr.vaddr, ptrEnc = R.u8(h + 1), cntEnc = R.u8(h + 2), tabEnc = R.u8(h + 3);
  let p = h + 4;
  p += v2ReadEnc(R, p, ptrEnc, h)[1];
  const [count, cn] = v2ReadEnc(R, p, cntEnc, h); p += cn;
  const cies = new Map(), out = [];
  for (let i = 0; i < count; i++) {
    const [, n1] = v2ReadEnc(R, p, tabEnc, h);
    const [fde, n2] = v2ReadEnc(R, p + n1, tabEnc, h);
    p += n1 + n2;
    const cie = fde + 4 - R.u32(fde + 4);
    let enc = cies.get(cie); if (enc === undefined) { enc = v2CieFdeEnc(R, cie); cies.set(cie, enc); }
    const [begin, k] = v2ReadEnc(R, fde + 8, enc, h);
    const [range] = v2ReadEnc(R, fde + 8 + k, enc & 0x0f, h);
    out.push([begin, begin + range]);
  }
  return out;
}
function v2StubSlot(b, rva, word) {        // PLT stub `adrp x16; ldr x17,[x16,#lo]; add x16,x16,#lo; br x17` -> GOT slot RVA
  const w0 = word(rva), w1 = word(rva + 4), w2 = word(rva + 8), w3 = word(rva + 12);
  if (((w0 & 0x9f00001f) >>> 0) !== 0x90000010 || ((w1 & 0xffc003ff) >>> 0) !== 0xf9400211 || ((w2 & 0xffc003ff) >>> 0) !== 0x91000210 || w3 !== 0xd61f0220) return -1;
  let pages = (((w0 >>> 5) & 0x7ffff) << 2) | ((w0 >>> 29) & 3); if (pages & 0x100000) pages -= 0x200000;
  return (rva - (rva % 4096)) + pages * 4096 + ((w1 >>> 10) & 0xfff) * 8;
}

// --- GOT slots by import name, from the mapped dynamic section (Module.enumerateImports crashed inside
// Frida's ELF parser for a library mapped straight from the APK). JUMP_SLOT and GLOB_DAT relocations.
function v2Imports(b) {
  const dynSeg = v2Elf(b).find(x => x.type === 2);
  if (!dynSeg) throw Error('no PT_DYNAMIC');
  const d = {}, rva = v => (v.compare(b) >= 0 ? v.sub(b) : v).toUInt32();   // bionic keeps d_ptr as vaddr; tolerate relocated ones
  for (let o = dynSeg.vaddr; ; o += 16) {
    const tag = b.add(o).readU64().toNumber(); if (tag === 0) break;
    d[tag] = b.add(o + 8).readPointer();
  }
  const sym = rva(d[6]), str = rva(d[5]), out = {};
  const add = (rel, size) => {
    for (let o = rel; o < rel + size; o += 24) {
      const off = b.add(o).readU64().toNumber(), info = b.add(o + 8).readU64();
      const type = info.and(0xffffffff).toNumber(), idx = info.shr(32).toNumber();
      if ((type !== 1026 && type !== 1025) || idx === 0) continue;               // R_AARCH64_JUMP_SLOT / GLOB_DAT
      const name = b.add(str + b.add(sym + idx * 24).readU32()).readCString();
      if (!(name in out) || type === 1026) out[name] = b.add(off);
    }
  };
  if (d[23]) add(rva(d[23]), d[2].toUInt32());   // DT_JMPREL, DT_PLTRELSZ
  if (d[7]) add(rva(d[7]), d[8].toUInt32());     // DT_RELA, DT_RELASZ
  return out;
}
const PLT_SCAN_C = `
#include <glib.h>
extern guint64 P[9];   /* base, t0, t1, plt_lo, plt_hi, stub_slot[], ranges[], nranges, out[] */
gint64 scan (void)
{
  guint8 * base = (guint8 *) P[0];
  guint32 t0 = (guint32) P[1], t1 = (guint32) P[2], lo = (guint32) P[3], hi = (guint32) P[4];
  guint32 * slot_of = (guint32 *) P[5], * ranges = (guint32 *) P[6], * out = (guint32 *) P[8];
  guint32 nr = (guint32) P[7], r;
  gint64 n = 0;
  guint64 b0 = (guint64) base + t0, b1 = (guint64) base + t1;
  for (r = 0; r < nr; r++) {
    guint32 a = ranges[2 * r], e = ranges[2 * r + 1], s;
    if (a < t0 || e > t1) continue;
    for (s = a; s < e; s += 4) {
      guint32 w, t, slot; gint32 imm; guint64 dest; gint64 delta;
      if (s >= lo && s < hi && ((s - lo) & 15) == 0 && slot_of[(s - lo) >> 4] != 0) break;
      w = *(guint32 *) (base + s);
      if ((w & 0x7c000000) != 0x14000000) continue;
      imm = (gint32) (w << 6) >> 6;
      t = (guint32) ((gint64) s + (gint64) imm * 4);
      if (t < lo || t >= hi || ((t - lo) & 15) != 0) continue;
      slot = slot_of[(t - lo) >> 4];
      if (slot == 0) continue;
      dest = *(guint64 *) (base + slot) & 0x00ffffffffffffffULL;
      if (dest < b0 || dest >= b1) continue;
      dest -= (guint64) base;
      delta = ((gint64) dest - (gint64) s) / 4;
      if (delta < -0x2000000 || delta >= 0x2000000) continue;
      if (n >= 400000) return -1;
      out[5 * n] = s; out[5 * n + 1] = w; out[5 * n + 2] = (w & 0xfc000000) | ((guint32) delta & 0x3ffffff);
      out[5 * n + 3] = slot; out[5 * n + 4] = (guint32) dest;
      n++;
    }
  }
  return n;
}
`;
// --- PLT bypass computed on the device (twin of benchmark/plt_scan_portable.py)
function v2PltSites(b) {
  const ph = v2Elf(b), id = v2BuildId(b, ph) || 'nobuildid', path = V2_CACHE + 'tq-plt-' + id + '.bin';
  try { const u = new Uint32Array(File.readAllBytes(path)); if (u.length === 1 + u[0] * 5) return { u, cached: true, buildId: id }; } catch (e) {}
  const ex = ph.find(x => x.type === 1 && (x.flags & 1));
  const t0 = ex.vaddr, t1 = ex.vaddr + ex.filesz, U = new Uint32Array(b.add(t0).readByteArray(t1 - t0));
  const word = rva => U[(rva - t0) >>> 2];
  const stubs = new Map();
  for (let va = (t0 + 15) & ~15; va + 16 <= t1; va += 16) { const s = v2StubSlot(b, va, word); if (s >= 0) stubs.set(va, s); }
  const tS = Date.now(), ranges = v2FunctionRanges(b, ph), tR = Date.now();
  // The per-instruction loop runs in C (QuickJS needed ~44 s for 2.4M words).
  let lo = Infinity, hi = 0;
  for (const k of stubs.keys()) { if (k < lo) lo = k; if (k + 16 > hi) hi = k + 16; }
  if (!stubs.size) throw Error('no PLT stubs found');
  const tab = Memory.alloc(((hi - lo) / 16) * 4); tab.writeByteArray(new Uint8Array(((hi - lo) / 16) * 4));
  for (const [k, slot] of stubs) tab.add(((k - lo) / 16) * 4).writeU32(slot);
  const flat = new Uint32Array(ranges.length * 2);
  ranges.forEach(([a, e], i) => { flat[2 * i] = a; flat[2 * i + 1] = e; });
  const rg = Memory.alloc(flat.byteLength); rg.writeByteArray(flat.buffer);
  const cap = 400000 * 5, out = Memory.alloc(cap * 4), P = Memory.alloc(9 * 8);
  [b, ptr(t0), ptr(t1), ptr(lo), ptr(hi), tab, rg, ptr(ranges.length), out].forEach((v, i) => P.add(i * 8).writePointer(v));
  const cm = new CModule(PLT_SCAN_C, { P });
  const count = new NativeFunction(cm.scan, 'int64', [])().toNumber();
  if (count < 0) throw Error('PLT site buffer overflow');
  const sites = new Uint32Array(out.readByteArray(count * 20));
  const u = new Uint32Array(1 + sites.length); u[0] = sites.length / 5; u.set(sites, 1);
  try { const f = new File(path, 'wb'); f.write(u.buffer); f.close(); } catch (e) {}
  return { u, cached: false, buildId: id, stubs: stubs.size, rangesMs: tR - tS, sitesMs: Date.now() - tR };
}
function v2PltApply(b, u, done) {
  const n = u[0], gotOk = new Map(), st = { sites: n, applied: 0, skippedGot: 0, skippedMismatch: 0 };
  let i = 0;
  const step = () => {
    const t = Date.now();
    try {
      while (i < n && Date.now() - t < 8) {
        const page = Math.floor(u[1 + i * 5] / 4096); let j = i;
        while (j < n && Math.floor(u[1 + j * 5] / 4096) - page < 4) j++;
        const first = u[1 + i * 5], last = u[1 + (j - 1) * 5], work = [];
        for (let k = i; k < j; k++) {
          const o = 1 + k * 5, site = u[o], oldW = u[o + 1], newW = u[o + 2], slot = u[o + 3], dest = u[o + 4];
          let ok = gotOk.get(slot);
          if (ok === undefined) { ok = clean(b.add(slot).readPointer()).equals(b.add(dest)); gotOk.set(slot, ok); }
          if (!ok) { st.skippedGot++; continue; }
          const cur = b.add(site).readU32();
          if (cur !== oldW) { if (cur !== newW) st.skippedMismatch++; continue; }
          work.push([site - first, newW]);
        }
        if (work.length) { Memory.patchCode(b.add(first), last - first + 4, c => { for (const [off, w] of work) c.add(off).writeU32(w); }); st.applied += work.length; }
        i = j;
      }
    } catch (e) { done(Object.assign(st, { state: 'error', error: String(e) })); return; }
    if (i < n) setTimeout(step, 2); else done(Object.assign(st, { state: 'active' }));
  };
  setTimeout(step, 20);
}

// --- call-site finder for the stream helper (StartStream3D -> helper -> `b` CreateStream PLT stub)
function v2StreamSite(b) {
  const f = V2.exp('_ZN4GAME12SoundManager13StartStream3DERKNS_15SoundDescriptorE');
  const slot = V2.imp['FMOD_System_CreateStream'];
  if (!slot) throw Error('FMOD_System_CreateStream is not imported');
  const word = rva => b.add(rva).readU32();
  for (let i = 0; i < 120; i++) {
    const a = f.add(i * 4), w = a.readU32();
    if ((w >>> 26) !== 0x25) continue;
    const t = a.add((((w & 0x3ffffff) << 6) >> 6) * 4);
    for (let k = 0; k < 6; k++) {
      const s = t.add(k * 4), x = s.readU32();
      if ((x >>> 26) === 0x05) {
        const stub = s.add((((x & 0x3ffffff) << 6) >> 6) * 4), sr = stub.sub(b).toUInt32();
        if (v2StubSlot(b, sr, word) >= 0 && b.add(v2StubSlot(b, sr, word)).equals(slot)) return { site: s, stub };
        break;
      }
      if (x === 0xd65f03c0) break;
    }
  }
  throw Error('CreateStream call site not found');
}

async function v2WaitEngine() {
  for (let i = 0; i < 240; i++) {
    const m = Process.findModuleByName('libtq.so');
    if (m && Process.findModuleByName('libfmod.so')) {
      const ge = m.findExportByName('_ZN4GAME7gEngineE'), fc = m.findExportByName('_ZNK4GAME6Engine13GetFrameCountEv');
      if (ge && fc) {
        const e = clean(ge.readPointer());
        if (!e.isNull() && new NativeFunction(fc, 'uint', ['pointer'])(e) > 30) return m;
      }
    }
    await v2Sleep(500);
  }
  throw Error('Engine initialization timeout');
}

// Stub pages for `b` redirects (+-128 MB). One pool, allocated once near the middle of libtq's executable
// segment, so every function in libtq is in range of every page.
function v2MmapNear(mid, reach, size) {
  const mmap = new NativeFunction(Process.getModuleByName('libc.so').getExportByName('mmap'), 'pointer', ['pointer', 'size_t', 'int', 'int', 'int', 'long']);
  const munmap = new NativeFunction(Process.getModuleByName('libc.so').getExportByName('munmap'), 'int', ['pointer', 'size_t']);
  const m = Number(mid.toString()), lo = m - reach, hi = m + reach, ranges = [];
  // procfs reports size 0, so read until EOF instead of File.readAllText
  const f = new File('/proc/self/maps', 'r');
  let text = '', chunk;
  while ((chunk = f.readText(65536)) !== '') text += chunk;
  f.close();
  for (const line of text.split(String.fromCharCode(10))) {
    const r = /^([0-9a-f]+)-([0-9a-f]+)/.exec(line);
    if (r) ranges.push([parseInt(r[1], 16), parseInt(r[2], 16)]);
  }
  ranges.sort((x, y) => x[0] - y[0]);
  const gaps = [];
  let prev = 0;
  for (const [a, b] of ranges) { if (a > prev) gaps.push([prev, a]); prev = Math.max(prev, b); }
  // closest gaps first; keep one guard page on each side
  const cands = [];
  for (const [a, b] of gaps) {
    const s0 = Math.max(a, lo), e0 = Math.min(b, hi);
    if (e0 - s0 < size) continue;
    const at = m < s0 ? s0 : (m + size > e0 ? e0 - size : m);
    cands.push(Math.floor(at / 0x1000) * 0x1000);
  }
  cands.sort((x, y) => Math.abs(x - m) - Math.abs(y - m));
  for (const at of cands) {
    const want = ptr('0x' + at.toString(16));
    const got = mmap(want, size, 3, 0x22, -1, 0);          // PROT_READ|WRITE, MAP_PRIVATE|MAP_ANONYMOUS; address as a hint
    if (got.equals(want)) return got;
    if (!got.equals(ptr('-1'))) munmap(got, size);
  }
  let big = 0; for (const [a, b] of gaps) { const s0 = Math.max(a, lo), e0 = Math.min(b, hi); if (e0 > s0) big = Math.max(big, e0 - s0); }
  throw Error('no free gap within branch range (' + cands.length + ' candidates, ' + ranges.length + ' maps, ' + text.length + ' chars, largest gap in window ' + big + ', window ' + lo.toString(16) + '-' + hi.toString(16) + ')');
}
function v2NearPage(t) {
  // Stub pages must be within +-128 MB of every libtq function they jump to or from. The address space near
  // libtq can be packed (one failing layout had 6025 mappings and a largest free gap of 13 pages), so pages
  // come in small chunks: 8 pages, else 1 page, via Frida's near allocator, else a free gap from /proc/self/maps.
  if (!V2.pool || V2.pool.next >= V2.pool.pages) {
    const ex = v2Elf(V2.mod.base).find(x => x.type === 1 && (x.flags & 1));
    const mid = V2.mod.base.add(ex.vaddr + Math.floor(ex.filesz / 2)), span = Math.ceil(ex.filesz / 2) + 0x100000;
    let mem = null, pages = 0, via = '', lastErr = null;
    for (const n of [8, 1]) {
      const size = n * Process.pageSize;
      try { mem = Memory.alloc(size, { near: mid, maxDistance: 0x7ff0000 - span }); via = 'frida'; }
      catch (e) { lastErr = e; try { mem = v2MmapNear(mid, 0x7f00000 - span, size); via = 'maps'; } catch (e2) { lastErr = e2; } }
      if (mem) { pages = n; break; }
    }
    if (!mem) throw Error('no stub pages near libtq: ' + lastErr);
    held.push(mem);
    V2.pool = { mem, next: 0, pages };
    V2.status.stubpages = (V2.status.stubpages || []).concat([via + ':' + pages + '@' + mem]);
    v2Save();
  }
  const page = V2.pool.mem.add(V2.pool.next++ * Process.pageSize);
  const delta = page.compare(t) >= 0 ? page.sub(t) : t.sub(page);
  if (delta.compare(ptr(0x8000000 - Process.pageSize)) >= 0) throw Error('stub page out of branch range');
  return page;
}
// Generated by make_font.py from Pillow's bundled Aileron font (public domain).
const OV_FONT = {"w":512,"h":256,"size":34,"ascent":33,"white":[1,1],"glyphs":{"32":[6,2,7,0,0,33,7.0],"33":[15,2,8,24,0,9,8.0],"34":[25,2,12,26,0,7,12.0],"35":[39,2,19,24,0,9,19.0],"36":[60,2,20,31,0,5,20.0],"37":[82,2,24,24,0,9,24.0],"38":[108,2,22,24,0,9,22.0],"39":[132,2,7,26,0,7,7.0],"40":[141,2,10,30,0,6,10.0],"41":[153,2,11,30,0,6,11.0],"42":[166,2,19,17,0,16,19.0],"43":[187,2,20,19,0,14,20.0],"44":[209,2,8,8,-1,29,7.0],"45":[219,2,9,12,0,21,9.0],"46":[230,2,7,4,0,29,7.0],"47":[239,2,12,26,-1,8,10.0],"48":[253,2,20,24,0,9,20.0],"49":[275,2,20,24,0,9,20.0],"50":[297,2,20,24,0,9,20.0],"51":[319,2,20,24,0,9,20.0],"52":[341,2,20,24,0,9,20.0],"53":[363,2,20,24,0,9,20.0],"54":[385,2,20,24,0,9,20.0],"55":[407,2,20,24,0,9,20.0],"56":[429,2,20,24,0,9,20.0],"57":[451,2,20,24,0,9,20.0],"58":[473,2,7,19,0,14,7.0],"59":[482,2,9,23,-2,14,7.0],"60":[2,35,19,18,0,15,19.0],"61":[23,35,20,16,0,17,20.0],"62":[45,35,19,18,0,15,19.0],"63":[66,35,17,24,0,9,17.0],"64":[85,35,29,27,0,10,29.0],"65":[116,35,22,24,0,9,22.0],"66":[140,35,21,24,0,9,21.0],"67":[163,35,24,24,0,9,24.0],"68":[189,35,24,24,0,9,24.0],"69":[215,35,19,24,0,9,19.0],"70":[236,35,19,24,0,9,19.0],"71":[257,35,25,24,0,9,25.0],"72":[284,35,25,24,0,9,25.0],"73":[311,35,9,24,0,9,9.0],"74":[322,35,19,24,0,9,19.0],"75":[343,35,22,24,0,9,21.0],"76":[367,35,19,24,0,9,19.0],"77":[388,35,29,24,0,9,29.0],"78":[419,35,24,24,0,9,24.0],"79":[445,35,26,24,0,9,26.0],"80":[473,35,20,24,0,9,20.0],"81":[2,64,25,26,0,9,25.0],"82":[29,64,21,24,0,9,21.0],"83":[52,64,20,24,0,9,20.0],"84":[74,64,21,24,0,9,21.0],"85":[97,64,23,24,0,9,23.0],"86":[122,64,22,24,0,9,21.0],"87":[146,64,33,24,0,9,32.0],"88":[181,64,22,24,0,9,21.0],"89":[205,64,21,24,0,9,20.0],"90":[228,64,21,24,0,9,21.0],"91":[251,64,10,31,0,5,10.0],"92":[263,64,12,26,-1,8,10.0],"93":[277,64,10,31,0,5,10.0],"94":[289,64,20,22,0,11,20.0],"95":[311,64,18,3,0,33,18.0],"96":[331,64,10,24,0,9,10.0],"97":[343,64,18,19,0,14,18.0],"98":[363,64,21,26,0,7,21.0],"99":[386,64,18,19,0,14,18.0],"100":[406,64,21,26,0,7,21.0],"101":[429,64,19,19,0,14,19.0],"102":[450,64,11,27,0,6,11.0],"103":[463,64,21,26,0,14,21.0],"104":[486,64,21,26,0,7,21.0],"105":[2,97,7,24,0,9,7.0],"106":[11,97,8,31,-1,9,7.0],"107":[21,97,19,26,0,7,19.0],"108":[42,97,8,26,0,7,8.0],"109":[52,97,30,19,0,14,30.0],"110":[84,97,21,19,0,14,21.0],"111":[107,97,20,19,0,14,20.0],"112":[129,97,21,26,0,14,21.0],"113":[152,97,21,26,0,14,21.0],"114":[175,97,12,19,0,14,12.0],"115":[189,97,16,19,0,14,16.0],"116":[207,97,11,23,0,10,11.0],"117":[220,97,20,19,0,14,20.0],"118":[242,97,18,19,0,14,17.0],"119":[262,97,27,19,0,14,27.0],"120":[291,97,17,19,-1,14,16.0],"121":[310,97,18,26,0,14,17.0],"122":[330,97,16,19,0,14,16.0],"123":[348,97,10,31,0,5,10.0],"124":[360,97,8,35,0,5,8.0],"125":[370,97,10,31,0,5,10.0],"126":[382,97,20,13,0,20,20.0]},"data":"/////wAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD/////AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAP////8AAAAAAAAAAAAAAAAANP///wAAAAAAAAD///80AP///zQAAAAAAAAAAAAAov9ZAACG/3UAAAAAAAAAAAAAAAAAAHyAAAAAAAAAAAAAAAAAAAJnyPP31H8LAAAAAAAAAE7//10AAAAAAAAAAAAAAAthq93z/PPlxkQAAAAAAAAAAAAA////NAAAAAAAAAAAACv90wEAAAC9/0AAAAAAAAAAAAAAAAAAAAAAAAD/2AAAAAAAAAAAAAAAAAAAAAAAAAD4/wAAAAAAAAAAAAAAAABX///qAAAAAABMTExMTExMAAAAAE7l5k4AAAAAAAAAAAAAAAAAz/9NAAAAAAAAABx7x+f558d7HAAAAAAAAAAAAAAAAAAAAAAAKJ7j/v80AAAAAAAAAAAAAAAAABN2vOf58tmePAAAAAAAAAAAAAAAAARTp9vy+um7bQ0AAAAAAAAAAAAAAAAAAAAAAAAAj////wAAAAAAAAAAACD/////////////////OAAAAAAAAAAAAAA4mdj09NmeOgAAAAAAAAAAAAD//////////////////////wAAAAAAAAAAOZbO7vvw1Z1BAAAAAAAAAAAAAAAAAABCntrz9d6rVgEAAAAAAAAAAE7l5k4AAAAAAAAATuXmTgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA/////wAAAAAAAAAAAAAAAAA0////AAAAAAAAAP///zQA////NAAAAAAAAAAAAADW/yYAALr/QgAAAAAAAAAAAAAAAAAA+P8AAAAAAAAAAAAAAAABq////////9EPAAAAAAAK4P/CAAAAAAAAAAAAAABZ6f//////////ZAAAAAAAAAAAAAD///80AAAAAAAAAAAAsv9WAAAAAD7/ygAAAAAAAAAAAAAAAAAAAAAAAP/YAAAAAAAAAAAAAAAAAAAAAAAAAPj/AAAAAAAAAAAAAAAAAKv//4oAAAAAAP////////8AAAAA5v//5QAAAAAAAAAAAAAAACL/8gcAAAAAAABn8//////////zZwAAAAAAAAAAAAAAAAAACof6/////zQAAAAAAAAAAAAAAABh8///////////owkAAAAAAAAAAAAt0v//////////4zoAAAAAAAAAAAAAAAAAAAAAAEb+////AAAAAAAAAAAAPv////////////////84AAAAAAAAAAAMnP//////////owgAAAAAAAAAAP/////////////////////gAAAAAAAAEa////////////+4FwAAAAAAAAAAAAAXu///////////yB4AAAAAAAAA5v//5QAAAAAAAADm///lAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAADT///8AAAAAAAAA////NAD///80AAAAAAAAAAAAC/3xAQAA7P4PAAAAAAAAAAAAAAAAAAD4/wAAAAAAAAAAAAAAAGX///h5Zur//5gAAAAAAIf/+ywAAAAAAAAAAAAAe////8t6Vk9aZ4c9AAAAAAAAAAAAAP///zQAAAAAAAAAADz/1gIAAAAAAMD/VQAAAAAAAAAAAAAAAAAAAAAA/9gAAAAAAAAAAAAAAAAAAAAAAAAA+P8AAAAAAAAAAAAAAAAK9f/+JQAAAAAA/////////wAAAADn///nAAAAAAAAAAAAAAAAd/+lAAAAAAAAa////8ZuVG7H////awAAAAAAAAAAAAAAAEvf////////NAAAAAAAAAAAAAAAb////q1mUWm7////qgAAAAAAAAAALO7//9h7U2OT9v//8ioAAAAAAAAAAAAAAAAAAAAU5v////8AAAAAAAAAAABd//9+TExMTExMTExMTBAAAAAAAAAACL///7dqU22z////tAAAAAAAAAAATExMTExMTExMTExMTOP//18AAAAAAAjP///8qmZQXpj0///WEAAAAAAAAAAAGeD///KTW1V+3///2xYAAAAAAADn///nAAAAAAAAAOf//+cAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAANP///wAAAAAAAAD///80AP///zQAAAAAAAAAAAA9/78AACH/2wAAAAAAAAAAAAAAABRtqf7/t4g1AAAAAAAAAAAAx///hAAAU///9QUAAAAo+f+MAAAAAAAAAAAAAED+//1nAAAAAAAAAAAAAAAAAAAAAAAA////NAAA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AAAAAAAAAAAAAAAAAAAABd3//0IAAAAAAAAA8P//QQAAAAAAAAAO////LAAAAAAAAOL//0wAAAAAAAAAABv//8EAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA0////AAAAAAAAAP///zQA////NAAAAAAAAAAADP3wAQAA7f4PAAAAAAAAAAAAov//oQAA+P8AAB72//9BAAAAAACJ///gLRvE//+9AACU//kmAAAAAAAAAAAAAAAA0///XwAAAAAAAAA0////AAAAAAAAAAD///80AAAAAAAAEf7+DQAAAAAAAAAAAe//JwAAAAAAAAAAAAAAABBSwf//qUcJAAAAAAAAAAAAAP//////////////////AAAAAACm//4kAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAb/vYLAAAAAACY//+ZAAAAAAAAAAAAmv//lwAAAAAAAAAAAQAAAAAAAP///zQAAAAAAAAAAABN2NiDAAAAAAAAAABP///qAAAAAAAAAAAAAAAAAAAAAABY///vAwAAAAAAAAAAAAAAif//lQA0////AAAAAAAAAAAB9/+hAAAMLkU1EwAAAAAAAAAAAABk//92AC2f4fnsyoEVAAAAAAAAAAAAAAAAAAAAAAAAAABs//+6AAAAAAAAAACy//+GAAAAAAAAAFX///sMAAAAAAAA+P//OAAAAAAAAAAABf//7QAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAADT///8AAAAAAAAA////NAD///80AAAAAAD//////////////////wAAAAAAAADg//9SAAD4/wAAAJn//58AAAAAABLf////////9S8AMv3/hAAAAAAAAAAAAAAAAABt///LBwAAAAAAADT///8AAAAAAAAAAP///zQAAAAAAABM/9kAAAAAAAAAAAAAv/9kAAAAAAAAAAAAAAAAAB/r1uzVDAAAAAAAAAAAAAAA//////////////////8AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAG//rQAAAAAAAML//3AAAAAAAAAAAABy///BAAAAAAAAAAAA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AAAAAAAAAAAAABzw//9yAAAAAAAAAHP//5MAAAAAAAAAAAWk///////////dHP///xEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAADT///8AAAAAAAAAAAAAAAAAAAAAAAAAAP//////////////////AAAAAAAAAAAAP/D///////GeMAAAAAAAAAAAAAAAAAAAAAAE0//aBwGv////////rAAAAAAAAEL//+gXAAAAAAAAADT///8AAAAAAAAAAAAAAAAAAAAAAAD8/yMAAAAAAAAAAAAACP//FwAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA+P8AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABn/7UAAAAAAAAAAOH//1AAAAAAAAAAAABS///gAAAAAAAAAAAAAAAAAAAA////NAAAAAAAAAAAAAAAAAAAAAA68///kQAAAAAAAAAAAAAAAAAAAAAAAAAAAAHF//9eAAAAAAAAg///ngAAAAAAADT///8AAAAAAAAAAAAAAAAAAAAAAAAAAB////8bAAAAAO///0QAAAAAAAAAABL///8kAAAAAAAAAAAAAAAAJ/z/8xUAAAAAAAAAAAAAkv//vwAAAAAAAAAAAL///08AAAAAAAAAAABVyf7////3nBQi///yAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAANP///wAAAAAAAAAAAAAAAAAAAAAAAAAA//////////////////8AAAAAAAAAAAAAH67+////////rx0AAAAAAAAAAAAAAAAAAHX//0cAXP//5y0u6P//WQAAAAAAr///dgAAAAAAAAAANP///wAAAAAAAAAAAAAAAAAAAAAAAPz/IwAAAAAAAAAAAAAI//8XAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD4/wAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAALv/YQAAAAAAAAAAwv//cAAAAAAAAAAAAHL//8EAAAAAAAAAAAAAAAAAAAD///80AAAAAAAA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AAAAAAAKrv//+CcAAAAAAAAByP//wwwAAAAAVvz/zwMAAAAAAAAAAAAAAAAAAAB///9dAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA5v//5QAAAAAAAAAAAAAAAAAAAAAAAAAAAA397wEAAO3+DwAAAAAAAAAAAAAA9v//bwAAAPj/AAAACf///y0AAAAAAAAAJfj/owAAAAAAUP///Hl6/P//TQAAAAAAALD////mmWpVTlhtpv///wAAAAAAAAAAAAAAAAAAAAAAAEz/2QAAAAAAAAAAAAC//2QAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACz/2kAAAAAAAAAAAAAAABs////xWxTbcX///9rAAAAAAAAAAAAAAAAAAAAAAD///80AAAAAAAAAAAAMO3//8ZMTExMTExMTExMTAAAAAAAAAvN////x4Blbp7y///wOwAAAAAAAAAAAAAAAAAAAAAANP///wAAAAAAAAAAAGr////himdtnvP//9wYAAAAAAAAAAS7///3llpWie3//9oUAAAAAAAAAAAAAAPY//9VAAAAAAAAAAAAAAAAAAAAWfz//+6VYFBdjej///xgAAAAAAAAAAAt8v//3ndRZbH+/98bAAAAAAAAAAAAAAAAAAAAANP/8wsAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAADn///nAAAAAAAAAAAAAAAAAAAAAAAAAAAAQP+7AAAk/9cAAAAAAAAAAAAAAADc//+rAAAA+P8AAAAX////FQAAAAAAAAC5//AYAAAAAAAAm////////5cAAAAAAAAABIX0////////////////AAAAAAAAAAAAAAAAAAAAAAAAEf7+DgAAAAAAAAAAAe//JwAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAADfj9GAAAAAAAAAAAAAAAAABn8//////////zZwAAAAAAAAAAAAAAAAAAAAAAAP///zQAAAAAAAAAAADs////////////////////AAAAAAAAABS2////////////vyYAAAAAAAAAAAAAAAAAAAAAAAA0////AAAAAAAAAAAAAGr3//////////+tEQAAAAAAAAAAAAqr//////////+6FAAAAAAAAAAAAAAAZP//zQEAAAAAAAAAAAAAAAAAAAAARN3////////////YRAAAAAAAAAAAAAA55f////////+9HQAAAAAAAAAAAAAAAAAAAAAl//+fAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAFHm5lEAAAAAAAAAAAAAAAAAAAAAAAAAAAB1/4YAAFn/ogAAAAAAAAAAAAAAAJ3///okAAD4/wAAAGf//9IAAAAAAAAAVv//bQAAAAAAAAABYsn19clhAAAAAAAAAAAAABFfocvp9v3y5Na1i2EAAAAAAAAAAAAAAAAAAAAAAAAAxf9XAAAAAAAAAAA9/90AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABb/8EAAAAAAAAAAAAAAAAAAAAcfMjo+ujIfBwAAAAAAAAAAAAAAAAAAAAAAAAA////NAAAAAAAAAAAAP////////////////////8AAAAAAAAAAABAnNXw++7OlDoAAAAAAAAAAAAAAAAAAAAAAAAAADT///8AAAAAAAAAAAAAABp9wer689eXNgAAAAAAAAAAAAAAAABBndry9t+kSAAAAAAAAAAAAAAAAAjj//9HAAAAAAAAAAAAAAAAAAAAAAAABVKi1/H88dSfTQQAAAAAAAAAAAAAAAANdcXv+OCtUAEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAM////8sWAPj/AABF8P//WgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABs/60AAAAAAAAAAJP/hAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAK//bQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAj////+iM+v9ztv///5oAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABb79gwAAAAAAAAC5/8qAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAL9v4bAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAADj/////////////h4AQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAALb/XgAAAAAAAEb/0AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAANJ3b9v//+tCDGwAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAPP/WAgAAAAAAwf9VAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA+P8EAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAsv9WAAAAAD7/ygAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD4/wAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAr/dIBAAAAvf9BAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAPj/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACSkAAAAAAAAA//////////////////8AAAAAAAAAMgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAQc7vn+fLYnz8AAAAAAAAAAAAAAAAAAAAAACl9u+P39t+/eScAAAAAAAAAAAAAAAAAAAAAAAAAwv///4YAAAAAAAAAAAAAAAAA//////////336MiTQAAAAAAAAAAAAAAAAAAAABxsttvy9+bFjDMAAAAAAAAAAAAAAP/////////99ubAiToAAAAAAAAAAAAAAAAA////////////////////gAAAAAAA////////////////////gAAAAAAAAAAAAAALVZ7S6Prw3bB2GgAAAAAAAAAAAAAA////NAAAAAAAAAAAAAAANP///wAAAAAAAAAA////NAAAAAAAAAAAAAAAAAAAAAAANP///wAAAAAAAAD///80AAAAAAAAAAAAAab//78HAAAAAAD///80AAAAAAAAAAAAAAAAAAAAAAD//////y4AAAAAAAAAAAAAABj+/////wAAAAAAAAAA/////+0MAAAAAAAAAAAA////NAAAAAAAAAAAAAAAACp4vd3y9uHIiD4AAAAAAAAAAAAAAAAA//////////346sqRNAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABWnlgAAAAAAAAAD//////////////////wAAAAAAAAD+qykAAAAAAAAAAAAAAAAAAAAAAAAAVu///////////6sMAAAAAAAAAAAAAAAAADi8/////////////aEaAAAAAAAAAAAAAAAAAAAAAB3+////3AAAAAAAAAAAAAAAAAD/////////////////wRwAAAAAAAAAAAAAAA6K+f///////////7seAAAAAAAAAAAA/////////////////9E/AAAAAAAAAAAAAAD///////////////////+AAAAAAAD///////////////////+AAAAAAAAAAAAEaej////////////8mQ8AAAAAAAAAAAD///80AAAAAAAAAAAAAAA0////AAAAAAAAAAD///80AAAAAAAAAAAAAAAAAAAAAAA0////AAAAAAAAAP///zQAAAAAAAAAAACQ///PDgAAAAAAAP///zQAAAAAAAAAAAAAAAAAAAAAAP//////fAAAAAAAAAAAAAAAZf//////AAAAAAAAAAD//////3YAAAAAAAAAAAD///80AAAAAAAAAAAAACGo/v///////////8U5AAAAAAAAAAAAAAD/////////////////pAoAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA1/e//9+AAAAAAAAAExMTExMTExMTExMTExMAAAAAAAAAP///aEiAAAAAAAAAAAAAAAAAAAAAGD////Nc1JeoPr//7oCAAAAAAAAAAAAAA+q////55xxWFhvp+3//+czAAAAAAAAAAAAAAAAAAAAdv//2///MwAAAAAAAAAAAAAAAP///3BMTExMU3Ky/f//3BAAAAAAAAAAAAAe1////Lt0V1ZxsPv//+0uAAAAAAAAAAD///9wTExMTVZvqvD///6FAAAAAAAAAAAAAP///3BMTExMTExMTExMTCYAAAAAAP///3BMTExMTExMTExMTCYAAAAAAAAADrn///7EelxSaJ3v////2xwAAAAAAAAAAP///zQAAAAAAAAAAAAAADT///8AAAAAAAAAAP///zQAAAAAAAAAAAAAAAAAAAAAADT///8AAAAAAAAA////NAAAAAAAAAAAef//3RgAAAAAAAAA////NAAAAAAAAAAAAAAAAAAAAAAA/////v/KAAAAAAAAAAAAAACy//3///8AAAAAAAAAAP//////6QkAAAAAAAAAAP///zQAAAAAAAAAAAA97v//+7t2W1VuqvP///xjAAAAAAAAAAAAAP///3BMTExMU2ar/P//vQIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAVXX///lbQcAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAPL3///qXGwAAAAAAAAAAAAAAAAAf+P//iQEAAAAAPvf//2AAAAAAAAAAAAAw3P//wEIBAAAAAAAACXX0//QwAAAAAAAAAAAAAAAAAADQ/+pS//+JAAAAAAAAAAAAAAAA////NAAAAAAAAAA89v//ggAAAAAAAAAAG+X//8stAAAAAAAAI8j//+YRAAAAAAAAAP///zQAAAAAAAAADoj+//+MAAAAAAAAAAAA////NAAAAAAAAAAAAAAAAAAAAAAA////NAAAAAAAAAAAAAAAAAAAAAAAAA3Q///TNwAAAAAAAAyU////1QgAAAAAAAAA////NAAAAAAAAAAAAAAANP///wAAAAAAAAAA////NAAAAAAAAAAAAAAAAAAAAAAANP///wAAAAAAAAD///80AAAAAAAAAGL//+kkAAAAAAAAAAD///80AAAAAAAAAAAAAAAAAAAAAAD////N//4ZAAAAAAAAAAAACfb/xf///wAAAAAAAAAA////uP//cAAAAAAAAAAA////NAAAAAAAAAAAOff//74nAAAAAAAAE53///9lAAAAAAAAAAAA////NAAAAAAAAAA/9f//agAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAEvP///mbwgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD6////3jRUAAAAAAAAAAAAAAI7//8YBAAAAAAAAjP//wAAAAAAAAAAAKO7/7lAAAAAAAAAAAAAAAC3f/9sOAAAAAAAAAAAAAAAAKf//lwj0/98AAAAAAAAAAAAAAAD///80AAAAAAAAAACD///TAAAAAAAAAAPB///DCgAAAAAAAAAADNH//5YAAAAAAAAA////NAAAAAAAAAAAAFz///9MAAAAAAAAAAD///80AAAAAAAAAAAAAAAAAAAAAAD///80AAAAAAAAAAAAAAAAAAAAAAAAqf//yg8AAAAAAAAAAACL////ggAAAAAAAAD///80AAAAAAAAAAAAAAA0////AAAAAAAAAAD///80AAAAAAAAAAAAAAAAAAAAAAA0////AAAAAAAAAP///zQAAAAAAABN/P/yMgAAAAAAAAAAAP///zQAAAAAAAAAAAAAAAAAAAAAAP///4X//2YAAAAAAAAAAABN//96////AAAAAAAAAAD///9H8//lBwAAAAAAAAD///80AAAAAAAAAA/f//+tBQAAAAAAAAAAAH7///YrAAAAAAAAAAD///80AAAAAAAAAACG///TAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAEHG///ncAgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABAwf//84MPAAAAAAAAAAAA1P//ZwAAAAAAAABG///vAAAAAAAAABXd/9YfAAAAAAAAAAAAAAAAACny/4gAAAAAAAAAAAAAAACE//8/AKv//zYAAAAAAAAAAAAAAP///zQAAAAAAAAAAEj///YAAAAAAAAAa///7BQAAAAAAAAAAAAANv//9Q4AAAAAAAD///80AAAAAAAAAAAAAJH//+MEAAAAAAAAAP///zQAAAAAAAAAAAAAAAAAAAAAAP///zQAAAAAAAAAAAAAAAAAAAAAAFj//+8YAAAAAAAAAAAAAAXa///rBgAAAAAAAP///zQAAAAAAAAAAAAAADT///8AAAAAAAAAAP///zQAAAAAAAAAAAAAAAAAAAAAADT///8AAAAAAAAA////NAAAAAAAO/b/+UIAAAAAAAAAAAAA////NAAAAAAAAAAAAAAAAAAAAAAA////Qfn/tAAAAAAAAAAAAJv/9Dv///8AAAAAAAAAAP///zSK//9pAAAAAAAAAP///zQAAAAAAAAAiv//3AoAAAAAAAAAAAAAALP//70AAAAAAAAAAP///zQAAAAAAAAAAC7///8RAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAADe8///ocgkAAAAAAAAAAAAAAAAATExMTExMTExMTExMTEwAAAAAAAAAAAAAAAAAQsL//+55CwAAAAAAAADz//8+AAAAAAAAAD7///MAAAAAAAAApv/nHwAAAAAAFDlEHgAAAAAAAGf/8RAAAAAAAAAAAAAAANz/5QIAWv//jAAAAAAAAAAAAAAA////NAAAAAAAAAAARv//7QAAAAAAAAPf//9mAAAAAAAAAAAAAAAAxf//UgAAAAAAAP///zQAAAAAAAAAAAAAEfH//1MAAAAAAAAA////NAAAAAAAAAAAAAAAAAAAAAAA////NAAAAAAAAAAAAAAAAAAAAAAB0///awAAAAAAAAAAAAAAAG////8+AAAAAAAA////NAAAAAAAAAAAAAAANP///wAAAAAAAAAA////NAAAAAAAAAAAAAAAAAAAAAAANP///wAAAAAAAAD///80AAAAACzu//1VAAAAAAAAAAAAAAD///80AAAAAAAAAAAAAAAAAAAAAAD///80vP/3CgAAAAAAAAAB5v+xNP///wAAAAAAAAAA////NBb2/+AFAAAAAAAA////NAAAAAAAAA3w//9PAAAAAAAAAAAAAAAAIP3//zEAAAAAAAAA////NAAAAAAAAAAADv///yoAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACy///pdAoAAAAAAAAAAAAAAAAAAAD//////////////////wAAAAAAAAAAAAAAAAAAAEPE///pSAAAAAAAABscHAUAAAAAAAAAYf//0AAAAAAAADP+/z0AAAAALLj9////rxusrG0ABuT/XgAAAAAAAAAAAAA4//+QAAAO+f/iAQAAAAAAAAAAAAD///80AAAAAAAAAAB2///GAAAAAAAASv//7wkAAAAAAAAAAAAAAAB4//+CAAAAAAAA////NAAAAAAAAAAAAAAAoP//qQAAAAAAAAD///80AAAAAAAAAAAAAAAAAAAAAAD///80AAAAAAAAAAAAAAAAAAAAAEH///ELAAAAAAAAAAAAAAAAIezs7GYAAAAAAAD///80AAAAAAAAAAAAAAA0////AAAAAAAAAAD///80AAAAAAAAAAAAAAAAAAAAAAA0////AAAAAAAAAP///zQAAAAe5P//agAAAAAAAAAAAAAAAP///zQAAAAAAAAAAAAAAAAAAAAAAP///zRv//9QAAAAAAAAADb//2Q0////AAAAAAAAAAD///80AI///2IAAAAAAAD///80AAAAAAAAW///5AMAAAAAAAAAAAAAAAAAtP//jwAAAAAAAAD///80AAAAAAAAAAAO////KQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAP//iAsAAAAAAAAAAAAAAAAAAAAAAP//////////////////AAAAAAAAAAAAAAAAAAAAAABF3v+AAAAAAAAAAAAAAAAAAAAAAAC4//+CAAAAAAAAuf+rAAAAAFP5////////k///cAAAlf+fAAAAAAAAAAAAAJL//zkAAAC3//85AAAAAAAAAAAAAP///zQAAAAAAAAAF+f//18AAAAAAACM//+lAAAAAAAAAAAAAAAAAA4sLBoAAAAAAAD///80AAAAAAAAAAAAAABX///hAAAAAAAAAP///zQAAAAAAAAAAAAAAAAAAAAAAP///zQAAAAAAAAAAAAAAAAAAAAAhv//pwAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAP///zQAAAAAAAAAAAAAADT///8AAAAAAAAAAP///zQAAAAAAAAAAAAAAAAAAAAAADT///8AAAAAAAAA////NAAAFNj//4AAAAAAAAAAAAAAAAAA////NAAAAAAAAAAAAAAAAAAAAAAA////NCL//54AAAAAAAAAhP/9FjT///8AAAAAAAAAAP///zQAGvj/2wMAAAAAAP///zQAAAAAAACZ//+cAAAAAAAAAAAAAAAAAABq///MAAAAAAAAAP///zQAAAAAAAAAAC7///4QAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA///yhBEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAANLT//38AAAAAAAAAAAAAAAAAAAAAP/7/9xsAAAAAACD+/iUAAAA7+v//kCIHS/H0//80AABW/9MAAAAAAAAAAAAD6P/gAQAAAGX//48AAAAAAAAAAAAA////NAAAAAAPKW/m//+uAwAAAAAAAMf//20AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAP///zQAAAAAAAAAAAAAACn///8OAAAAAAAA////NAAAAAAAAAAAAAAAAAAAAAAA////NAAAAAAAAAAAAAAAAAAAAADE//9vAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA////NAAAAAAAAAAAAAAANP///wAAAAAAAAAA////NAAAAAAAAAAAAAAAAAAAAAAANP///wAAAAAAAAD///80AAvJ//+YAAAAAAAAAAAAAAAAAAD///80AAAAAAAAAAAAAAAAAAAAAAD///80ANP/6QIAAAAAAADR/8QANP///wAAAAAAAAAA////NAAAlf//XAAAAAAA////NAAAAAAAAM7//2gAAAAAAAAAAAAAAAAAADX///wFAAAAAAAA////NAAAAAAAAAAAhf//zgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA0uP//8YIRAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAMrL//+x1CQAAAAAAAAAAAAAAAAAAABTi//9wAAAAAAAAbv/BAAAAB9v//34AAAAAf///8wQAADf/5wAAAAAAAAAAAEb//4oAAAAAFv3/5AEAAAAAAAAAAAD////////////////wgAMAAAAAAAAA4v//SwAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA////NAAAAAAAAAAAAAAAEf///x8AAAAAAAD///9wTExMTExMTExMTAAAAAAAAAD///9wTExMTExMTExMTAAAAAAAAOD//0wAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD///80AAAAAAAAAAAAAAA0////AAAAAAAAAAD///80AAAAAAAAAAAAAAAAAAAAAAA0////AAAAAAAAAP///zQFt///rAIAAAAAAAAAAAAAAAAAAP///zQAAAAAAAAAAAAAAAAAAAAAAP///zQAhP//OgAAAAAAH///dAA0////AAAAAAAAAAD///80AAAe+v/WAgAAAAD///80AAAAAAAA5f//SgAAAAAAAAAAAAAAAAAAGP///xgAAAAAAAD///80AAAAAAAAAD/1//9gAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAPcL///CAEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAMbH///F/DQAAAAAAAAAAAAAAAAAAAAAHwv//sgEAAAAAAACr/3oAAABi///ZBAAAAABX//+7AAAAJP/5AAAAAAAAAAAAoP//MgAAAAAAwv//PAAAAAAAAAAAAP///////////////65HAQAAAAAAAAD1//87AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD///80AAAAAAAAAAAAAAAE////LgAAAAAAAP//////////////////AAAAAAAAAP//////////////////AAAAAAAA9P//OwAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAP////////////////////////8AAAAAAAAAAP///zQAAAAAAAAAAAAAAAAAAAAAADT///8AAAAAAAAA////NaT//9AHAAAAAAAAAAAAAAAAAAAA////NAAAAAAAAAAAAAAAAAAAAAAA////NAAz//+IAAAAAABs//8kADT///8AAAAAAAAAAP///zQAAACb//9VAAAAAP///zQAAAAAAAD3//87AAAAAAAAAAAAAAAAAAAI////KgAAAAAAAP///3BMTExMUmWq/P//sQEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAEfL///vfw8AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAMK////WJEgAAAAAAAAAAAAAAAAAAAAAAAKf//74IAAAAAAAAANX/RwAAAML//3EAAAAAAGj//34AAAAk//MAAAAAAAAAAAjx/9sAAAAAAABx//+SAAAAAAAAAAAA////cExMTExQZZzn///FHwAAAAAAAPj//zwAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAP///zQAAAAAAAAAAAAAAAv///8mAAAAAAAA//////////////////8AAAAAAAAA//////////////////8AAAAAAAD4//88AAAAAAAAAADs//////////80AAAAAAAA/////////////////////////wAAAAAAAAAA////NAAAAAAAAAAAAAAAAAAAAAAANP///wAAAAAAAAD///+7////+jwAAAAAAAAAAAAAAAAAAAD///80AAAAAAAAAAAAAAAAAAAAAAD///80AADh/9YAAAAAALr/1AAANP///wAAAAAAAAAA////NAAAACL7/9EBAAAA////NAAAAAAAAPf//zsAAAAAAAAAAAAAAAAAAAf///8qAAAAAAAA/////////////////5wGAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABR0///730OAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAALq3+//mTGAAAAAAAAAAAAAAAAAAAAAAAAAB///+/DAAAAAAAAAAA8P8nAAAH+f//LgAAAAAAlf//QQAAADX/4gAAAAAAAAAAVP///////////////+YCAAAAAAAAAAD///80AAAAAAAAAAig///hEwAAAAAA5///SwAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA////NAAAAAAAAAAAAAAAGv///xUAAAAAAAD///80AAAAAAAAAAAAAAAAAAAAAAD///80AAAAAAAAAAAAAAAAAAAAAOf//0wAAAAAAAAAAOz//////////zQAAAAAAAD///9wTExMTExMTExMTExw////AAAAAAAAAAD///80AAAAAAAAAAAAAAAAAAAAAAA0////AAAAAAAAAP//////8P//6R4AAAAAAAAAAAAAAAAAAP///zQAAAAAAAAAAAAAAAAAAAAAAP///zQAAJH//yQAAAAN+f+EAAA0////AAAAAAAAAAD///80AAAAAKH//04AAAD///80AAAAAAAA5f//SgAAAAAAAAAAAAAAAAAAGP///xgAAAAAAAD///////////ru0Zc1AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACW9v//+5OAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAKz+//ydHgAAAAAAAAAAAAAAAAAAAAAAAAAAOP3/xgoAAAAAAAAAAAD8/xsAACL///8LAAAAAADQ//oKAAAAX/+3AAAAAAAAAACu/////////////////z8AAAAAAAAAAP///zQAAAAAAAAAAALU//+JAAAAAADR//9tAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD///80AAAAAAAAAAAAAAA////0AgAAAAAAAP///zQAAAAAAAAAAAAAAAAAAAAAAP///zQAAAAAAAAAAAAAAAAAAAAA0f//bgAAAAAAAAAARkxMTEyL////NAAAAAAAAP///zQAAAAAAAAAAAAAADT///8AAAAAAAAAAP///zQAAAAAAAAAAAAAAAAAAAAAADT///8AAAAAAAAA/////7ga4f//zgoAAAAAAAAAAAAAAAAA////NAAAAAAAAAAAAAAAAAAAAAAA////NAAAQP//cgAAAFX//zQAADT///8AAAAAAAAAAP///zQAAAAAJ/3/ygAAAP///zQAAAAAAADO//9oAAAAAAAAAAAAAAAAAAA1///8BQAAAAAAAP///zQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABGXi/4AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA//6nJgAAAAAAAAAAAAAAAAAAAAAAAAAAAADA//AYAAAAAAAAAAAAAPP/JgAAMP///wcAAAAAJf//yAAAAACn/3wAAAAAAAAAD/j/4XR0dHR0dHR0rf//lQAAAAAAAAAA////NAAAAAAAAAAAAGz//9cAAAAAAJ3//6MAAAAAAAAAAAAAAAAAFSgoDwAAAAAAAP///zQAAAAAAAAAAAAAAHH//8AAAAAAAAAA////NAAAAAAAAAAAAAAAAAAAAAAA////NAAAAAAAAAAAAAAAAAAAAACc//+lAAAAAAAAAAAAAAAAAGz///80AAAAAAAA////NAAAAAAAAAAAAAAANP///wAAAAAAAAAA////NAAAAAAAAHh4eBgAAAAAAAAANP///wAAAAAAAAD////KCwA1+P//qQAAAAAAAAAAAAAAAAD///80AAAAAAAAAAAAAAAAAAAAAAD///80AAAD6/+/AAAAo//jAAAANP///wAAAAAAAAAA////NAAAAAAAp///SAAA////NAAAAAAAAJj//50AAAAAAAAAAAAAAAAAAGr//8sAAAAAAAAA////NAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAdvaQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACxLgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAGP7/lQAAAAAAAAAAAAAA3/85AAAi////IAAAAACd//+SAAAAIfn8HQAAAAAAAABi//+IAAAAAAAAAAAo///pAwAAAAAAAAD///80AAAAAAAAAAAASP//9wAAAAAAYP//7QcAAAAAAAAAAAAAAACr//9PAAAAAAAA////NAAAAAAAAAAAAAAAwv//fgAAAAAAAAD///80AAAAAAAAAAAAAAAAAAAAAAD///80AAAAAAAAAAAAAAAAAAAAAF7//+8JAAAAAAAAAAAAAAAAnv///zQAAAAAAAD///80AAAAAAAAAAAAAAA0////AAAAAAAAAAD///80AAAAAAAA////NAAAAAAAAAA0////AAAAAAAAAP///zgAAABk////ewAAAAAAAAAAAAAAAP///zQAAAAAAAAAAAAAAAAAAAAAAP///zQAAACe//sRAAPs/5QAAAA0////AAAAAAAAAAD///80AAAAAAAr/v/EAAD///80AAAAAAAAWv//5QMAAAAAAAAAAAAAAAAAtf//jgAAAAAAAAD///80AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA1xMRSAAAAAAAAAAAAAADH/2UAAALx//9zAAAAV////3wAAAzI/5MAAAAAAAAAALz//zYAAAAAAAAAAADV//9CAAAAAAAAAP///zQAAAAAAAAAAAA7///0AAAAAAAP8///XQAAAAAAAAAAAAAACO///x4AAAAAAAD///80AAAAAAAAAAAAADD+//wdAAAAAAAAAP///zQAAAAAAAAAAAAAAAAAAAAAAP///zQAAAAAAAAAAAAAAAAAAAAADvL//2QAAAAAAAAAAAAAAAfn////NAAAAAAAAP///zQAAAAAAAAAAAAAADT///8AAAAAAAAAAP///zQAAAAAAAD1//88AAAAAAAAAD////sAAAAAAAAA////NAAAAACb///+TgAAAAAAAAAAAAAA////NAAAAAAAAAAAAAAAAAAAAAAA////NAAAAEz//1sAPv//RAAAADT///8AAAAAAAAAAP///zQAAAAAAACt//9BAP///zQAAAAAAAAM7///UAAAAAAAAAAAAAAAACD9//8wAAAAAAAAAP///zQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAIv/pwAAAJn///l/VZj8wP//2Fdu2v/ECAAAAAAAAAAY/P/iAQAAAAAAAAAAAIH//5gAAAAAAAAA////NAAAAAAAAAAAAGD//9cAAAAAAACT///lDQAAAAAAAAAAAABo///JAAAAAAAAAP///zQAAAAAAAAAAAACv///pAAAAAAAAAAA////NAAAAAAAAAAAAAAAAAAAAAAA////NAAAAAAAAAAAAAAAAAAAAAAAkP//6hMAAAAAAAAAAAAAcP////80AAAAAAAA////NAAAAAAAAAAAAAAANP///wAAAAAAAAAA////NAAAAAAAANv//1wAAAAAAAAAa///5gAAAAAAAAD///80AAAAAAfK///yKgAAAAAAAAAAAAD///80AAAAAAAAAAAAAAAAAAAAAAD///80AAAAB/P/qQCL/+8EAAAANP///wAAAAAAAAAA////NAAAAAAAADD//74A////NAAAAAAAAACJ///cCQAAAAAAAAAAAAAAs///vAAAAAAAAAAA////NAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAASP/0FQAAEtb//////+gYw///////oAoAAAAAAAAAAHD//5AAAAAAAAAAAAAALf//6wQAAAAAAAD///80AAAAAAAAAAAAwP//lQAAAAAAABTo//+1BQAAAAAAAAAAIu7//1MAAAAAAAAA////NAAAAAAAAAAAAZD//+sVAAAAAAAAAAD///80AAAAAAAAAAAAAAAAAAAAAAD///80AAAAAAAAAAAAAAAAAAAAAAAR5f//vwkAAAAAAAAAADf35v///zQAAAAAAAD///80AAAAAAAAAAAAAAA0////AAAAAAAAAAD///80AAAAAAAAnf//qwAAAAAAAADE//+uAAAAAAAAAP///zQAAAAAAB7r///cEgAAAAAAAAAAAP///zQAAAAAAAAAAAAAAAAAAAAAAP///zQAAAAAqv/xBdn/pAAAAAA0////AAAAAAAAAAD///80AAAAAAAAALP//zr///80AAAAAAAAAA7f//+sBAAAAAAAAAAAAH3///YqAAAAAAAAAAD///80AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABO5eZOAAAAAAAAAAAAAAAF3/+NAAAADYfd+uOSFwAMcaeshjAAAAAAAAAAAAAAyv//PQAAAAAAAAAAAAAA2f//RQAAAAAAAP///zQAAAAAAAAABZD///olAAAAAAAAAEn8//+9IAAAAAAAADzi//+rAAAAAAAAAAD///80AAAAAAAAAB6t///4QwAAAAAAAAAAAP///zQAAAAAAAAAAAAAAAAAAAAAAP///zQAAAAAAAAAAAAAAAAAAAAAAABD+v//xykAAAAAAABZ9P9z////NAAAAAAAAP///zQAAAAAAAAAAAAAADT///8AAAAAAAAAAP///zQAAAAAAAA1///+UgAAAAAAcP///0sAAAAAAAAA////NAAAAAAAAEP8//+7AwAAAAAAAAAA////NAAAAAAAAAAAAAAAAAAAAAAA////NAAAAABZ//9r//9UAAAAADT///8AAAAAAAAAAP///zQAAAAAAAAANv//t////zQAAAAAAAAAADn3//++JgAAAAAAABOc////ZQAAAAAAAAAAAP///zQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAOb//+UAAAAAAAAAAAAAAABk//5PAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACP//+gCAAAAAAAAAAAAAACG//+bAAAAAAAA////cExMTExOWofX///9YAAAAAAAAAAAAFP5///4rmxTWHrB////uggAAAAAAAAAAP///3BMTExPWXe1+f//8EkAAAAAAAAAAAAA////cExMTExMTExMTExMJgAAAAAA////NAAAAAAAAAAAAAAAAAAAAAAAAABK9v//+7dxVll+0P//3gz///80AAAAAAAA////NAAAAAAAAAAAAAAANP///wAAAAAAAAAA////NAAAAAAAAACT///9qmNQZ7f///+oAAAAAAAAAAD///80AAAAAAAAAHf///+QAAAAAAAAAAD///+NcHBwcHBwcHBwcHA4AAAAAAD///80AAAAAA75/+//9wwAAAAANP///wAAAAAAAAAA////NAAAAAAAAAAAuf//////NAAAAAAAAAAAAD7v///7uXRZVWyo8v///GQAAAAAAAAAAAAA////NAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA5///5wAAAAAAAAAAAAAAAAO6//VaAAAAAAAAAAAAAAAAB3ptAAAAAAAAAAAAfv//lwAAAAAAAAAAAAAAADL//+0EAAAAAAD/////////////////40oAAAAAAAAAAAAAADXH////////////9HwDAAAAAAAAAAAA/////////////////rMeAAAAAAAAAAAAAAD///////////////////+AAAAAAAD///80AAAAAAAAAAAAAAAAAAAAAAAAAAAtvf///////////8MZAP///zQAAAAAAAD///80AAAAAAAAAAAAAAA0////AAAAAAAAAAD///80AAAAAAAAAASP////////////mAcAAAAAAAAAAP///zQAAAAAAAAAAK3///9hAAAAAAAAAP///////////////////4AAAAAAAP///zQAAAAAALb///+0AAAAAAA0////AAAAAAAAAAD///80AAAAAAAAAAA8//////80AAAAAAAAAAAAACKq/v///////////8Y6AAAAAAAAAAAAAAD///80AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABR5uZRAAAAAAAAAAAAAAAAAA/V//+mJwAAAAAAAAAAG3nf/9wBAAAAAAAAAADX//9FAAAAAAAAAAAAAAAAAN3//0gAAAAAAP//////////+/Laq14JAAAAAAAAAAAAAAAAAAFDkc/n+vHerm0RAAAAAAAAAAAAAAD//////////fXiuIAnAAAAAAAAAAAAAAAAAP///////////////////4AAAAAAAP///zQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAOonK5Pny2qBKAAAA////NAAAAAAAAP///zQAAAAAAAAAAAAAADT///8AAAAAAAAAAP///zQAAAAAAAAAAAAwl9Xy++3Kjy0AAAAAAAAAAAAA////NAAAAAAAAAAADdf///k5AAAAAAAA////////////////////gAAAAAAA////NAAAAAAAZf///2QAAAAAADT///8AAAAAAAAAAP///zQAAAAAAAAAAAC//////zQAAAAAAAAAAAAAAAArer7e8/fjyYk+AAAAAAAAAAAAAAAAAP///zQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABCz///9yIVkUVtul9H9//+wGwAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAFi3/////////////63RAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAFT5fR6Prt2K5tJAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAKni93fL24ceGOgAAAAAAAAAAAAAAAP///////////ffnxIwzAAAAAAAAAAAAAAAAD2235vn03KVNAQAAAAAAAAD//////////////////////////wAAAAAA////NAAAAAAAAAAAAAA0////AAAAAAC9//9oAAAAAAAAAAAAAAAAAL///2IAAAb1//9VAAAAAAAAAAAAif///6cAAAAAAAAAAAAX///1BwAAADf9//clAAAAAAAAAAAAAAbV//9/AAAAFO///1wAAAAAAAAAAAAAABz2//43AAAAAAD//////////////////////wAAAAAAAExMTExMJgAAAAv2/hsAAAAAAAAAAAAAACZMTExMSgAAAAAAAAAAAAAAAACD//86AAAAAAAAAAAAAAAATExMTExMTExMTExMTEwAAAAAAEL9/10AAAAAAAAAAAAAAAZht+j69NidOAAAAAAAAAAAAAD///80AAAAAAAAAAAAAAAAAAAAAAAAAAAADnLA6Prrw3oTAAAAAAAAAAAAAAAAAAAAAAAAAAAA////NAAAAAAAAAAAAApruOT57MyFHAAAAAAAAAAAAAAAABZceXJdAAAAAAAAAAALbbrl+u/FfhYA////NAAAAAAAAAD///80AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAIaj+////////////vzIAAAAAAAAAAAAA//////////////////+oDQAAAAAAAAAAAFvu///////////EHAAAAAAAAP//////////////////////////AAAAAAD///80AAAAAAAAAAAAADT///8AAAAAAGf//7sAAAAAAAAAAAAAAAAW/P/4DwAAALr//5AAAAAAAAAAAADL////5gAAAAAAAAAAAFb//7cAAAAAAI7//74AAAAAAAAAAAAAhf//ygQAAAAAcf//5AsAAAAAAAAAAAAAof//pAAAAAAAAP//////////////////////AAAAAAAA//////+AAAAAAK//bQAAAAAAAAAAAAAAgP/////8AAAAAAAAAAAAAAAABun//6cAAAAAAAAAAAAAAAD//////////////////wAAAAAAAIf/3QUAAAAAAAAAAAAk0v//////////iAAAAAAAAAAAAP///zQAAAAAAAAAAAAAAAAAAAAAAAAAAFTp//////////BUAAAAAAAAAAAAAAAAAAAAAAAAAAD///80AAAAAAAAAABO5f/////////1ZwAAAAAAAAAAAAB5+f////8AAAAAAAAAUuj/////////6hn///80AAAAAAAAAP///zQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD3u///7u3ZbVW6q8///+lgAAAAAAAAAAAD///9wTExMTFBaf8z////DBQAAAAAAAAB1///+snFTXpjz///cFQAAAAAATExMTExMTEz///9wTExMTExMTEwAAAAAAP///zQAAAAAAAAAAAAANP///wAAAAAAFPv/+xEAAAAAAAAAAAAAAGj//64AAAAAeP//ywAAAAAAAAAAD/z/////JgAAAAAAAAAAlP//cQAAAAAACtz//2EAAAAAAAAAADH7//YnAAAAAAAF2f//ggAAAAAAAAAAADD9//UcAAAAAAAATExMTExMTExMTExMUOn//8wAAAAAAAD//////4AAAAAAW//BAAAAAAAAAAAAAACA//////wAAAAAAAAAAAAAAABe/67h+hoAAAAAAAAAAAAAAP//////////////////AAAAAAAABMn/ZwAAAAAAAAAAEuH//9h2VWm+////VwAAAAAAAAAA////NAAAAAAAAAAAAAAAAAAAAAAAAABt/v//tmdRbcT///1WAAAAAAAAAAAAAAAAAAAAAAAAAP///zQAAAAAAAAAZ/3//7RpUWWs/v//agAAAAAAAAAAZ/////rg8wAAAAAAAHD+///HcVNjqfz/rf///zQAAAAAAAAA////NAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA59///vicAAAAAAAATnf///lgAAAAAAAAAAP///zQAAAAAAAAAAGr///9nAAAAAAAAN/3/7zgAAAAAAB/X//+nAAAAAAAAAAAAAAAAAP///zQAAAAAAAAAAAAAAAAA////NAAAAAAAAAAAAAA0////AAAAAAAAuv//XwAAAAAAAAAAAAAAvf//VAAAAAA2///7CwAAAAAAAABO//++//9mAAAAAAAAAADT//8sAAAAAAAAQf7/7RUAAAAAAAAF0P//bAAAAAAAAABN///2HgAAAAAAAAAAvP//gAAAAAAAAAAAAAAAAAAAAAAAAACH///xIwAAAAAAAP/4AAAAAAAAAAAO+P0XAAAAAAAAAAAAAAAAAAD//AAAAAAAAAAAAAAAAMv/Rn//ggAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAIvLkCAAAAAAAAACP//+/BwAAAACj///KAAAAAAAAAAD///80AAAAAAAAAAAAAAAAAAAAAAAAQ/3/+VIAAAAAAID///AZAAAAAAAAAAAAAAAAAAAAAAAA////NAAAAAAAAD37/+9DAAAAAABG9//4KQAAAAAAAADg//+pCgAAAAAAAABH/f/+agAAAAAAM+P/////NAAAAAAAAAD///80AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD9///60FAAAAAAAAAAAAfv//8SAAAAAAAAAA////NAAAAAAAAAAAAK///8EAAAAAAACo//92AAAAAAAAACr7//8mAAAAAAAAAAAAAAAA////NAAAAAAAAAAAAAAAAAD///80AAAAAAAAAAAAADT///8AAAAAAABk//+xAAAAAAAAAAAAABX8//EIAAAAAAPw//9CAAAAAAAAAI///T3//6YAAAAAAAAAEv7/5gAAAAAAAAAAmf//pQAAAAAAAH7//7oBAAAAAAAAAAC6//+nAAAAAAAAAEr//+QKAAAAAAAAAAAAAAAAAAAAAAAARP3//1YAAAAAAAAA//gAAAAAAAAAAACz/2kAAAAAAAAAAAAAAAAAAP/8AAAAAAAAAAAAAAA5/94BHPzpBgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAuv//zEAAAAAADX///wJAAAAAAAAAP///zQAAAAAAAAAAAAAAAAAAAAAAALb//9pAAAAAAAAAL3//4cAAAAAAAAAAAAAAAAAAAAAAAD///80AAAAAAAB1v//SQAAAAAAAAB4//+kAAAAAAAAGf///yMAAAAAAAAAAtv//38AAAAAAAAALPb///80AAAAAAAAAP///zQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACK///cCgAAAAAAAAAAAAAAs///sAAAAAAAAAD///80AAAAAAAAAAAAWv//7gAAAAAAAOb//zwAAAAAAAAAALj//3sAAAAAAAAAAAAAAAD///80AAAAAAAAAAAAAAAAAP///zQAAAAAAAAAAAAANP///wAAAAAAABL7//cLAAAAAAAAAAAAZ///oAAAAAAAALL//30AAAAAAAAA0f/LAOn/5QAAAAAAAABQ//+hAAAAAAAAAAAO4///SAAAAAAs+f/uGwAAAAAAAAAAACz8//86AAAAAAAD1P//XAAAAAAAAAAAAAAAAAAAAAAAABbn//+YAAAAAAAAAAD/+AAAAAAAAAAAAF//vQAAAAAAAAAAAAAAAAAA//wAAAAAAAAAAAAAAKb/egAAs/9dAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAi///xAQAAAAAADP///yIAAAAAAAAA////NAAAAAAAAAAAAAAAAAAAAAAAUv//3gEAAAAAAAAASf//3AAAAAAAAAAAAAAAAAAAAAAAAP///zQAAAAAAE3//70AAAAAAAAAAA73//kLAAAAAAAt////BQAAAAAAAABQ///pBgAAAAAAAAAAlP///zQAAAAAAAAA////NAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAADfD//08AAAAAAAAAAAAAAAAg/f/9JAAAAAAAAP///zQAAAAAAAAAAAA8///6AAAAAAAA+v//RAAAAAAAAAAAcNzckgAAAAAAAAAAAAAAAP///zQAAAAAAAAAAAAAAAAA////NAAAAAAAAAAAAAA0////AAAAAAAAALf//1UAAAAAAAAAAAC8//9GAAAAAAAAcP//uAAAAAAAABT+/4gAqf//JQAAAAAAAI7//1sAAAAAAAAAAABL///fCgAAA8v//1kAAAAAAAAAAAAAAJf//8oBAAAAAGb//8kBAAAAAAAAAAAAAAAAAAAAAAABuf//0QgAAAAAAAAAAP/4AAAAAAAAAAAAEPr8FAAAAAAAAAAAAAAAAAD//AAAAAAAAAAAAAAZ+vsYAABN/8oAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAQUFBAAAAAAAAAD////LwAAAAAAAAD///80AAAAAAAAAAAAAAAAAAAAAACc//+JAAAAAAAAAAAHi4yLBQAAAAAAAAAAAAAAAAAAAAAA////NAAAAAAAmf//ZwAAAAAAAAAAAL///0EAAAAAADP///8AAAAAAAAAAJj//5MAAAAAAAAAAABC////NAAAAAAAAAD///80AAAAAAAAAAAAAAAAAAAAAAAAAAAAAABb///kAwAAAAAAAAAAAAAAAAC0//+EAAAAAAAA////NAAAAAAAAAAAAEj//+IAAAAAAADm//+KAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA////NAAAAAAAAAAAAAAAAAD///80AAAAAAAAAAAAADT///8AAAAAAAAAYf//pwAAAAAAAAAAFPv/6AMAAAAAAAAu///xAgAAAAAAVP//RQBp//9kAAAAAAAAzf/+FwAAAAAAAAAAAACl//+MAAB3//+oAAAAAAAAAAAAAAAAFPD//14AAAAL5///OQAAAAAAAAAAAAAAAAAAAAAAAHj///QnAAAAAAAAAAAA//gAAAAAAAAAAAAAt/9lAAAAAAAAAAAAAAAAAP/8AAAAAAAAAAAAAIH/rgAAAAPj/zgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAFjdFT1T///8zAAAAAAAAAP///zQAMZrY9PfgrFYBAAAAAAAAANX//1YAAAAAAAAAAAAAAAAAAAAAAAAAAAttuuX678V+FgD///80AAAAAADT//83AAAAAAAAAAAAlf//ZgAAAAAANP///wAAAAAAAAAA0f//XAAAAAAAAAAAABX///80AAAAAAAAAP///zQAPKPf+PTVkCEAAAAAAAAAAAAAAAAAAJn//5wAAAAAAAAAAAAAAAAAAGr//8EAAAAAAAD///80AAAAAAAAAAAAjP//nQAAAAAAAKb///dHAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD///80AAAAAAAAAAAAAAAAAP///zQAAAAAAAAAAAAANP///wAAAAAAAAAQ+f/yBwAAAAAAAABl//+SAAAAAAAAAAHq//8uAAAAAACW//kJACj//6QAAAAAAA78/9AAAAAAAAAAAAAAABTq//wyJ/f/5RIAAAAAAAAAAAAAAAAAc///5QsAAIH//6YAAAAAAAAAAAAAAAAAAAAAAAA4+///XQAAAAAAAAAAAAD/+AAAAAAAAAAAAABj/7kAAAAAAAAAAAAAAAAA//wAAAAAAAAAAAAG6P9IAAAAAIH/pQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAFSqu7//////////zQAAAAAAAAA////NHL9/////////8cbAAAAAAAA7f//PwAAAAAAAAAAAAAAAAAAAAAAAABS6P/////////qGf///zQAAAAAAOz///////////////////94AAAAAP///////////wAAAADq//9BAAAAAAAAAAAABP///zQAAAAAAAAA////NJT/////////9FAAAAAAAAAAAAAAAAAAzv//aAAAAAAAAAAAAAAAAAAANf//9wMAAAAAAP///zQAAAAAAAAAADX1//MjAAAAAAAALfr///6rRgUAAAAAAAAAAAAAAAAAAAAAAAAAAP///zQAAAAAAAAAAAAAAAAA////NAAAAAAAAAAAAAA0////AAAAAAAAAAC0//9LAAAAAAAAALr//zgAAAAAAAAAAKr//2oAAAAAANf/vwAAAOb/4wAAAAAASv//iwAAAAAAAAAAAAAAAFf//83F//9HAAAAAAAAAAAAAAAAAAAG2///gwAZ9P/2HQAAAAAAAAAAAAAAAAAAAAAAD9///54AAAAAAAAAAAAAAP/4AAAAAAAAAAAAABP7+xIAAAAAAAAAAAAAAAD//AAAAAAAAAAAAFz/4AIAAAAAHf36GQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAfzf////3ezcjT////NAAAAAAAAAD///9n+//EclNipPv//94YAAAAAAD7//83AAAAAAAAAAAAAAAAAAAAAAAAcP7//8dxU2Op/P+t////NAAAAAAA+////////////////////3gAAAAA////////////AAAAAPr//zcAAAAAAAAAAAAA////NAAAAAAAAAD///9w//yiXVSE7P//+CwAAAAAAAAAAAAAAADl//9KAAAAAAAAAAAAAAAAAAAY////FAAAAAAA////NAAAAAACCzSD+f/qOAAAAAAAAAAAUfT/////9bl0JQAAAAAAAAAAAAAAAAAAAAAA////NAAAAAAAAAAAAAAAAAD///80AAAAAAAAAAAAADT///8AAAAAAAAAAF7//50AAAAAAAAT+//dAAAAAAAAAAAAaP//pQAAAAAZ//98AAAApv//IwAAAACI//9FAAAAAAAAAAAAAAAAALD/////lQAAAAAAAAAAAAAAAAAAAABP///3Hpz//4IAAAAAAAAAAAAAAAAAAAAAAACr///VCgAAAAAAAAAAAAAA//gAAAAAAAAAAAAAALv/YQAAAAAAAAAAAAAAAP/8AAAAAAAAAAAAyf98AAAAAAAAtf+AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD+H//9pZDAAAAAD///80AAAAAAAAAP////H4XAAAAAAANu///7EAAAAAAPH//0IAAAAAAAAAAAAAAAAAAAAAAEf9//5qAAAAAAAz4/////80AAAAAADx//9zTExMTExMTExMTExMIQAAAABMcP///0xMTEwAAAAA9P//QgAAAAAAAAAAAAz///80AAAAAAAAAP///+r4QwAAAAAg8P//rAAAAAAAAAAAAAAAAPf//zsAAAAAAAAAAAAAAAAAAAj///8mAAAAAAD////////////////3jRoAAAAAAAAAAAAAI6f8////////w0cAAAAAAAAAAAAAAAAAAAD///80AAAAAAAAAAAAAAAAAP///zQAAAAAAAAAAAAANP///wAAAAAAAAAADvj/6wMAAAAAAGT//4QAAAAAAAAAAAAm///gAAAAAFv//zkAAABm//9jAAAAAMf/9wgAAAAAAAAAAAAAAAAAGfH//+EKAAAAAAAAAAAAAAAAAAAAAAC9///E/P/lCwAAAAAAAAAAAAAAAAAAAAAAaf//9isAAAAAAAAAAAAAAAD/+AAAAAAAAAAAAAAAZ/+1AAAAAAAAAAAAAAAA//wAAAAAAAAAADb//BoAAAAAAABP/+cGAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACF///WDgAAAAAAAP///zQAAAAAAAAA/////2YAAAAAAAAATv///zwAAAAA3///XQAAAAAAAAAAAAAAAAAAAAAC2///fwAAAAAAAAAs9v///zQAAAAAAN7//0QAAAAAAAAAAAAAAAAAAAAAAAA0////AAAAAAAAAADg//9jAAAAAAAAAAAAIv///zQAAAAAAAAA/////3EAAAAAAAB3///2AwAAAAAAAAAAAAAA9///OwAAAAAAAAAAAAAAAAAAB////y8AAAAAAP////////////////6PAgAAAAAAAAAAAAAAABlwt/T//////6cLAAAAAAAAAAAAAAAAAP///zQAAAAAAAAAAAAAAAAA////NAAAAAAAAAAAAAA0////AAAAAAAAAAAAsf//QQAAAAAAuf//KgAAAAAAAAAAAADj//8bAAAAnP/yBAAAACX//6MAAAAK+v+6AAAAAAAAAAAAAAAAAAA3/P//+jIAAAAAAAAAAAAAAAAAAAAAAC78/////14AAAAAAAAAAAAAAAAAAAAAAC33//9jAAAAAAAAAAAAAAAAAP/4AAAAAAAAAAAAAAAV/PkPAAAAAAAAAAAAAAD//AAAAAAAAAAApP+wAAAAAAAAAAPl/1sAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAANb//2IAAAAAAAAO////NAAAAAAAAAD////bAQAAAAAAAAAAxf//ogAAAAC0//+PAAAAAAAAAAANREQ8AAAAAFD//+kGAAAAAAAAAACU////NAAAAAAAr///aQAAAAAAAAAAAFpgYBMAAAAAADT///8AAAAAAAAAALL//5wAAAAAAAAAAABU////NAAAAAAAAAD////tBwAAAAAAADX///8iAAAAAAAAAAAAAADl//9KAAAAAAAAAAAAAAAAAAAY////IwAAAAAA////cExMTExMXKf///+BAAAAAAAAAAAAAAAAAAAABUCZ9v///7cBAAAAAAAAAAAAAAAA////NAAAAAAAAAAAAAAAAAD///80AAAAAAAAAAAAADT///8AAAAAAAAAAABb//+UAAAAABL7/9AAAAAAAAAAAAAAAKL//1YAAADe/7MAAAAAAOT/4gAAAET//3UAAAAAAAAAAAAAAAAACtr/+///1ggAAAAAAAAAAAAAAAAAAAAAAJn////LAQAAAAAAAAAAAAAAAAAAAAAK1v//pQAAAAAAAAAAAAAAAAAA//gAAAAAAAAAAAAAAAC//10AAAAAAAAAAAAAAP/8AAAAAAAAABf5/0oAAAAAAAAAAIP/yQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA9v//PAAAAAAAADv///80AAAAAAAAAP///4cAAAAAAAAAAABp///kAAAAAHr//+ABAAAAAAAAAG3//7MAAAAAmP//kwAAAAAAAAAAAEL///80AAAAAABw//+sAAAAAAAAAAAs///8DQAAAAAANP///wAAAAAAAAAAcP//7AkAAAAAAAAAAKr///80AAAAAAAAAP///6cAAAAAAAAAD////y4AAAAAAAAAAAAAAM7//2gAAAAAAAAAAAAAAAAAADX///4IAAAAAAD///80AAAAAAAAAGT///oWAAAAAAAAAAAAAAAAAAAAAAAYuP///10AAAAAAAAAAAAAAAD///80AAAAAAAAAAAAAAAAAP///zQAAAAAAAAAAAAANP///wAAAAAAAAAAAA33/+QBAAAAYv//dgAAAAAAAAAAAAAAYP//kgAAH///cAAAAAAAo///IgAAgv//LwAAAAAAAAAAAAAAAACW//9xrv//kQAAAAAAAAAAAAAAAAAAAAAAFv///0kAAAAAAAAAAAAAAAAAAAAAAJ3//9kMAAAAAAAAAAAAAAAAAAD/+AAAAAAAAAAAAAAAAGv/sQAAAAAAAAAAAAAA//wAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAADz//9YAAAAAAAAm////zYAAAAAAAAA////VQAAAAAAAAAAADD///8TAAAAHvz//2UAAAAAAAAI1f//WQAAAADR//9cAAAAAAAAAAAAFf///zQAAAAAABP2//ooAAAAAAAAAJ3//7YAAAAAAAA0////AAAAAAAAAAAT9///fgAAAAAAAAA3/P///zQAAAAAAAAA////dAAAAAAAAAAE////MgAAAAAAAAAAAAAAmP//nQAAAAAAAAAAAAAAAAAAav//1wAAAAAAAP///zQAAAAAAAAAAMX//3AAAAAAAAAAAAAAAAAAAAAAAAAH0v//vAAAAAAAAAAAAAAAAP///zQAAAAAAAAAAAAAAAAA/v//NgAAAAAAAAAAAAA4///9AAAAAAAAAAAAAK7//zgAAAC3//4eAAAAAAAAAAAAAAAd///NAABh//8tAAAAAABj//9hAADB/+kBAAAAAAAAAAAAAAAAR///xwIW6//+RQAAAAAAAAAAAAAAAAAAAAAA////NAAAAAAAAAAAAAAAAAAAAABZ///4MAAAAAAAAAAAAAAAAAAAAP/4AAAAAAAAAAAAAAAAGP34DQAAAAAAAAAAAAD//AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAML//8YDAAAAAFT9////PwAAAAAAAAD///8/AAAAAAAAAAAAD////yYAAAAAnP//9kUAAAAABab//9QDAAAAAOr//0EAAAAAAAAAAAAE////NAAAAAAAAIP//9kjAAAAAAB0///9OQAAAAAAADT///8AAAAAAAAAAACB///8WAAAAAAAN+jx////NAAAAAAAAAD///9RAAAAAAAAAAH///8zAAAAAAAAAAAAAABa///lAwAAAAAAAAAAAAAAAAC1//+QAAAAAAAA////NAAAAAAAAAAAb///pQAAAAAAAAgICAAAAAAAAAAAAABm///sAAAAAAAAAAAAAAAA////NAAAAAAAAAAAAAAAAAD2//9DAAAAAAAAAAAAAEb///MAAAAAAAAAAAAAWP//igAAEfr/wgAAAAAAAAAAAAAAAADc//wMAKP/6QEAAAAAACL//6EAB/f/pAAAAAAAAAAAAAAAABLl//gpAABU///kEQAAAAAAAAAAAAAAAAAAAAD///80AAAAAAAAAAAAAAAAAAAAI/H//2oAAAAAAAAAAAAAAAAAAAAA//gAAAAAAAAAAAAAAAAAw/9ZAAAAAAAAAAAAAP/8AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAVf///9RzVGGs/rzn//9LAAAAAAAAAP///zQAAAAAAAAAAAAE////LgAAAAAM0////qhfUnfX///uLQAAAAAA+v//NwAAAAAAAAAAAAD///80AAAAAAAAA7n///ecX1Fwxv///3YAAAAAAAAANP///wAAAAAAAAAAAAXA////t2hSZ639/2L///80AAAAAAAAAP///0AAAAAAAAAAAP///zQAAAAAAAAAAAAAAAzv//9QAAAAAAAAAAAAAAAAIP3//zAAAAAAAAD///80AAAAAAAAAAA6///QAAAAAAAF+P//QAAAAAAAAAAAADz///gAAAAAAAAAAAAAAAD///80AAAAAAAAAAAAAAAAANj//2gAAAAAAAAAAAAAbf//0wAAAAAAAAAAAAAL9v/cAABh//9oAAAAAAAAAAAAAAAAAJr//0MA5P+nAAAAAAAAAOH/4QA+//9fAAAAAAAAAAAAAAAAqf//egAAAACn//+oAAAAAAAAAAAAAAAAAAAAAP///zQAAAAAAAAAAAAAAAAAAAbL//+rAAAAAAAAAAAAAAAAAAAAAAD/+AAAAAAAAAAAAAAAAABv/60AAAAAAAAAAAAA//wAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAhv/////////+QMv//2MAAAAAAAAA////NwAAAAAAAAAAAA////8dAAAAAAAQtP//////////0iwAAAAAAAD0//9CAAAAAAAAAAAADP///zQAAAAAAAAABZb9/////////+1eAAAAAAAAAAA0////AAAAAAAAAAAAAAqp//////////+fAP///zIAAAAAAAAA////NgAAAAAAAAAA////NAAAAAAAAAAAAAAAAIn//9wJAAAAAAAAAAAAAACz//+sAAAAAAAAAP///zQAAAAAAAAAABX//+8AAAAAAADG//+iAAAAAAAAAAAASP//4AAAAAAAAAAAAAAAAP///zQAAAAAAAAAAAAAAAAApP//tQAAAAAAAAAAAAC5//+fAAAAAAAAAAAAAACr//8uALb/+hMAAAAAAAAAAAAAAAAAWP//fib//2QAAAAAAAAAoP//IHz//xoAAAAAAAAAAAAAAFr//84EAAAAABLm//9bAAAAAAAAAAAAAAAAAAAA////NAAAAAAAAAAAAAAAAAAAjv//3g8AAAAAAAAAAAAAAAAAAAAAAP/4AAAAAAAAAAAAAAAAABz+9gsAAAAAAAAAAAD//AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAP6vm+/TXmjIArv//fgAAAAAAAAD///9IAAAAAAAAAAAAKv///AgAAAAAAAAAQp/c9fjirlkFAAAAAAAAAOD//2MAAAAAAAAAAAAi////NAAAAAAAAAAAACuO0e/76rxwEQAAAAAAAAAAADT///8AAAAAAAAAAAAAAAA+ndv0+OKqSAAK////IwAAAAAAAAD///80AAAAAAAAAAD///80AAAAAAAAAAAAAAAADt///6wEAAAAAAAAAAAAff//6RgAAAAAAAAA////NAAAAAAAAAAAAPT//wwAAAAAAGb///0+AAAAAAAAAACd//+bAAAAAAAAAAAAAAAA////NAAAAAAAAAAAAAAAAABH///+PwAAAAAAAAAAQ////0MAAAAAAAAAAAAAAFX//4AQ+v+0AAAAAAAAAAAAAAAAAAAW//+6Z///IQAAAAAAAABg//9gu//UAAAAAAAAAAAAAAAc7//7LwAAAAAAAEz//+8dAAAAAAAAAAAAAAAAAAD///80AAAAAAAAAAAAAAAAAEr+//o1AAAAAAAAAAAAAAAAAAAAAAAA//gAAAAAAAAAAAAAAAAAAMf/VQAAAAAAAAAAAP/8AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAP///3UAAAAAAAAAAABg///MAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAsv//nAAAAAAAAAAAAFT///80AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAANP///wAAAAAAAAAAQJiYUgAAAAAAAAAAACf///4NAAAAAAAAAP///zQAAAAAAAAAAP///zQAAAAAAAAAAAAAAAAAOff//74mAAAAAAAAE5z//+4yAAAAAAAAAAD///80AAAAAAAAAAAAzf//OAAAAAAABtL///BIAAAAAAABcP7/+SkAAAAAAAAAAAAAAAD///80AAAAAAAAAAAAAAAAAAC7///sQAAAAAAAAELu//+2AAAAAAAAAAAAAAAACvT/0l///1oAAAAAAAAAAAAAAAAAAADU//Ks/94AAAAAAAAAAB///6T0/44AAAAAAAAAAAAAAbv//4MAAAAAAAAAAJ///70BAAAAAAAAAAAAAAAAAP///zQAAAAAAAAAAAAAAAAa6///cAAAAAAAAAAAAAAAAAAAAAAAAAD/+AAAAAAAAAAAAAAAAAAAc/+pAAAAAAAAAAAA//wAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA////xQAAAAAAAAAAALz//4UAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABw///sCQAAAAAAAAAAqv///zQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA0////AAAAAAAAAABM//+yAAAAAAAAAAAAbP//0gAAAAAAAAAA////NAAAAAAAAAAA////NAAAAAAAAAAAAAAAAAAAPe////u5dFlVbKjy////cQgAAAAAAAAAAP///zQAAAAAAAAAAACd//9sAAAAAAAAJuT////AdFNUetD///1gAAAAAAAAAAAAAAAAAP///zQAAAAAAAAAAAAAAAAAABfa////u3JUVHK8////1xUAAAAAAAAAAAAAAAAAqP//0//1CwAAAAAAAAAAAAAAAAAAAJL///v/mwAAAAAAAAAAAN7/+f//SQAAAAAAAAAAAABt///UBgAAAAAAAAAAD+L//3IAAAAAAAAAAAAAAAAA////NAAAAAAAAAAAAAAAAL///9xMTExMTExMTExMTExMTAAAAAAAAP/4AAAAAAAAAAAAAAAAAAAf//QJAAAAAAAAAAD//AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD/////UQAAAAAAAABM///5GgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABP3//9+AAAAAAAAADf8////NAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAADT///8AAAAAAAAAABT7//gfAAAAAAAAAAze//+AAAAAAAAAAAD///80AAAAAAAAAAD///80AAAAAAAAAAAAAAAAAAAAIqr+////////////////7HQFAAAAAAAA////NAAAAAAAAAAAAGD//7cAAAAAAAAAHLP////////////jSQAAAAAAAAAAAAAAAAAA////NAAAAAAAAAAAAAAAAAAAABWt/////////////6oTAAAAAAAAAAAAAAAAAABS/////6YAAAAAAAAAAAAAAAAAAAAAUP////9YAAAAAAAAAAAAnf////kKAAAAAAAAAAAAJ/b//DYAAAAAAAAAAAAARf//+CsAAAAAAAAAAAAAAAD///80AAAAAAAAAAAAAAAA////////////////////////AAAAAAAA//gAAAAAAAAAAAAAAAAAAADL/1EAAAAAAAAAAP/8AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAP/////zTwAAAAAAQvL//3sAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAIH///xYAAAAAAA36PH///80AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAANP///wAAAAAAAAAAAKj//84bAAAAAAARuv//7BEAAAAAAAAAAP///zQAAAAAAAAAAP///zQAAAAAAAAAAAAAAAAAAAAAACp5vt7z/////////////8YPAAAAAAD///80AAAAAAAAAAAAFfv//CkAAAAAAAAAADGNxur69uCtXggAAAAAAAAAAAAAAAAAAAD///80AAAAAAAAAAAAAAAAAAAAAAAui8Xo+Pjow4ksAAAAAAAAAAAAAAAAAAAAAAjy////TAAAAAAAAAAAAAAAAAAAAAAQ/P///hYAAAAAAAAAAABc////vgAAAAAAAAAAAATK//+LAAAAAAAAAAAAAAAAl///zwYAAAAAAAAAAAAAAP///zQAAAAAAAAAAAAAAAD///////////////////////8AAAAAAAD/+AAAAAAAAAAAAAAAAAAAAHf/pQAAAAAAAAAA//wAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA////rv//vWxSZq/+//+lAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABcD///+3aFJnrf3/Yv///zQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA0////AAAAAAAAAAAAG+f///KaYFBflO////lBAAAAAAAAAAAA////NAAAAAAAAAAA////NAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAoxd9T/gwAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAP/4AAAAAAAAAAAAAAAAAAAAIv/xBwAAAAAAAAD//AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD///84y//////////3fAEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACqn//////////58A////NAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAADT///8AAAAAAAAAAAAAJcv////////////bNgAAAAAAAAAAAAD///80AAAAAAAAAAD///80AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAC0AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA//gAAAAAAAAAAAAAAAAAAAAAzv9NAAAAAAAAAP/8AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAP///zQIarnp++vJgRwAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD6d2/T44qpIAAD///80AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAANP///wAAAAAAAAAAAAAAAkyf0vD88tulVwMAAAAAAAAAAAAAAP///zQAAAAAAAAAAP///zQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD/+AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA//wAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA0////AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAP/4AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD//AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA//pMTEwmAAAAAAAAAAAAAAAAAAAAAAAAJkxMTP/8AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD//////4AAAAAAAAAAAAAAAAAAAAAAAACA//////wAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAP//////gAAAAAAAAAAAAAAAAAAAAAAAAID//////AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAY/CSAAAAAAAAAGPwkgAAAAAAAACAgIAaAAAAAAAAAAAAAAAAAAAAAP///zQAAAAAAAAA////NBaM1PX115UiAAAALqDe+PfWiRQAAAAAAAAAAAD///80ADqi3vj01ZAhAAAAAAAAAAAAAAAADWu03/T137RrDQAAAAAAAAAAAAD///80ADGa2PT34KxWAQAAAAAAAAAAAAAAC2265frvxX4WAP///zQAAAAAAAAA////NA+K4P6AAAAAAAAAIIvQ8vrotl0EAAAAAAAAAAD///80AAAAAAAAAAD///80AAAAAAAAAAD///80AAAAAMr//20AAAAAAAAAAAAJ9P/8GAAA0v//iAAAAAAAAACY////RwAAAAAAAADG//9UAAAApP//ywIAAAAAAAAAwv//kAAAyv//fQAAAAAAAAAAAB7///kSAAAAAP////////////////8AAAAAAAAAAAAPOEkAAAAAAAD/+AAAAAAAAEk4DwAAAAAAAAAAAAAAAFPU+eKKFgAAAAAA8/kAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAADq//8eAAAAAAAA6v//HgAAAAAAAP///zQAAAAAAAAAAAAAAAAAAAAA////NAAAAAAAAAD///852f////////RFADD5////////5ysAAAAAAAAAAP///zSR//////////RQAAAAAAAAAAAAAFrp///////////pWQAAAAAAAAAAAP///zRy/f/////////HGwAAAAAAAAAAAFLo/////////+oZ////NAAAAAAAAAD///80qv///4AAAAAAAFr1/////////8YUAAAAAAAAAP///zQAAAAAAAAAAP///zQAAAAAAAAAAP///zQAAAAAbv//wgAAAAAAAAAAAFD//7kAAACE///LAAAAAAAAANf///+IAAAAAAAADfv/+Q0AAAAS5///bAAAAAAAAGD//9oJAABs///QAAAAAAAAAAAAcP//rwAAAAAA/////////////////wAAAAAAAAAMpvv//wAAAAAAAP/4AAAAAAAA///6owsAAAAAAAAAAAA8/f/////yegoAAB//4gAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAOn//x0AAAAAAADp//8dAAAAAAAA////NAAAAAAAAAAAAAAAAAAAAAD///80AAAAAAAAAP///6f/v2FaivP///Ie1P+iWWKf/P//2wcAAAAAAAAA////bf/9pl5cifL///gsAAAAAAAAAABw////2oBZWYHa///+cAAAAAAAAAAA////Z/v/xHJTYqT7///eGAAAAAAAAABw/v//x3FTY6n8/63///80AAAAAAAAAP///4n/+6VlKAAAAAA5/P//sWJdlfr//8cDAAAAAAAA////NAAAAAAAAAAA////NAAAAAAAAAAA////NAAAAAAW+//9GAAAAAAAAAAAo///XQAAADf///0QAAAAAAAW/////8gAAAAAAABM//+6AAAAAABQ///xGQAAAAAS6v/9OQAAABT6//8jAAAAAAAAAADD//9RAAAAAABMTExMTExMTEzR///WAAAAAAAAAJn/////AAAAAAAA//gAAAAAAAD/////lAAAAAAAAAAAAKz/vliH6v//6YZXv/+qAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAY/CSAAAAAAAAAGPwkgAAAAAAAAD///80AAAAAAAAAAAAAAAAAAAAAP///zQAAAAAAAAA/////6YBAAAAK/X//+f/cgAAAABV////WgAAAAAAAAD////o+ksAAAAAHe3//6wAAAAAAAAAP/3//4sFAAAAAAWM///9PgAAAAAAAAD////x+FwAAAAAADbv//+xAAAAAAAAR/3//moAAAAAADPj/////zQAAAAAAAAA/////d8rAAAAAAAAALP//6IAAAAAP/z//2EAAAAAAAD///80AAAAAAAAAAD///80AAAAAAAAAAD///80AAAAAAC2//9qAAAAAAAAAAXv//UMAAAAAef//1AAAAAAAFX//8H/+w0AAAAAAI///2wAAAAAAACn//+oAAAAAJv//4kAAAAAALL//3cAAAAAAAAAGP3/7QYAAAAAAAAAAAAAAAAAW///+C8AAAAAAAAA6P+RHQMAAAAAAAD/+AAAAAAAAAQel//jAAAAAAAAAAAA4/8cAAAKe/P//////TwAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAP///zQAAAAAAAAAAAAAAAAAAAAA////NAAAAAAAAAD////4FAAAAAAAmf///9YBAAAAAADN//+aAAAAAAAAAP////96AAAAAAAAcv//9gMAAAAAAAHX//+fAAAAAAAAAACg///XAQAAAAAAAP////9mAAAAAAAAAE7///88AAAAAALb//9/AAAAAAAAACz2////NAAAAAAAAAD////7LQAAAAAAAAAA7f//RwAAAAAAov//vgAAAAD///////////8AAAAAAP///zQAAAAAAAAAAP///zQAAAAAAFn//74AAAAAAAAASP//pQAAAAAAnP//kgAAAAAAlP/kXf//SQAAAAAA0v//HwAAAAAAABPp//9GAAA6/v/UBwAAAAAAVf//ygAAAAAAAABp//+VAAAAAAAAAAAAAAAAACPy//9vAAAAAAAAAAD8/QcAAAAAAAAAAP/4AAAAAAAAAAAN//cAAAAAAAAAAAD67gAAAAAAF4/k+tRTAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAP///zQAAAAAAAD///80AAAAAAAA////NAAAAAAAAAAAAAAAAAAAAAD///80AAAAAAAAAP///7AAAAAAAABa////fAAAAAAAAI7//7cAAAAAAAAA////8AoAAAAAAAAz////IgAAAAAAS///9BEAAAAAAAAAABL1//9LAAAAAAAA////2wEAAAAAAAAAAMX//6IAAAAAUP//6QYAAAAAAAAAAJT///80AAAAAAAAAP///6oAAAAAAAAAAAD4//9QAAAAAAA8pKSWAAAAAP///////////wAAAAAA////NAAAAAAAAAAA////NAAAAAAACvL//BUAAAAAAACb//9JAAAAAABO///VAAAAAADT/6Qd//+KAAAAABb+/9EAAAAAAAAAAFT//9sIBNH/+zMAAAAAAAAI8P//HgAAAAAAALz//zgAAAAAAAAAAAAAAAAFyv//tgEAAAAAAAAAAOj/CQAAAAAAAAAA//gAAAAAAAAAABD/5QAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA////NAAAAAAAAP///zQAAAAAAAD///80AAAAAAAAAAAAAAAAAAAAAP///zQAAAAAAAAA////dgAAAAAAAEP///9CAAAAAAAAd///xAAAAAAAAAD///+rAAAAAAAAAA////8uAAAAAACa//+iAAAAAAAAAAAAAKL//5kAAAAAAAD///+HAAAAAAAAAAAAaf//5AAAAACY//+TAAAAAAAAAAAAQv///zQAAAAAAAAA////ZAAAAAAAAAAAANX//8IHAAAAAAAAAAAAAAAATEz///9wTExMAAAAAAD///80AAAAAAAAAAD///80AAAAAAAAof//ZgAAAAAAA+r/6QQAAAAAAAr2//8YAAAAE/7/YwDd/8oAAAAAWf//hAAAAAAAAAAAAKr//4Jz//+BAAAAAAAAAACb//9xAAAAAAAS+//ZAAAAAAAAAAAAAAAAAIr//+gWAAAAAAAAAAAAxf8sAAAAAAAAAAD/+AAAAAAAAAAAMP/CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD///80AAAAAAAA////NAAAAAAAAP///zQAAAAAAAAKyv//0BAAAAAA////NAAAAAAAAAD///9TAAAAAAAAOf///x8AAAAAAABt///KAAAAAAAAAP///3YAAAAAAAAABP///zIAAAAAANP//2QAAAAAAAAAAAAAZf//0gAAAAAAAP///1UAAAAAAAAAAAAw////EwAAANH//1wAAAAAAAAAAAAV////NAAAAAAAAAD///9CAAAAAAAAAAAAcf///9hkEAAAAAAAAAAAAAAAAP///zQAAAAAAAAAAP///zQAAAAAAAAAAP///zQAAAAAAABF//+6AAAAAABA//+RAAAAAAAAALP//1oAAABR//8jAJ3//A4AAACc//82AAAAAAAAAAAAFev/+fT/zwUAAAAAAAAAAD7//8QAAAAAAGH//3wAAAAAAAAAAAAAAABF/v/+SAAAAAAAAAAAAACd/1UAAAAAAAAAAP/4AAAAAAAAAABX/5sAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAP///zQAAAAAAAD///80AAAAAAAA////NAAAAAAAA7H//9oWAAAAAAD///80AAAAAAAAAP///z4AAAAAAAA2////CgAAAAAAAGr//8wAAAAAAAAA////UgAAAAAAAAAB////MwAAAAAA7f//QwAAAAAAAAAAAABF///sAAAAAAAA////PwAAAAAAAAAAAA////8mAAAA6v//QQAAAAAAAAAAAAT///80AAAAAAAAAP///zUAAAAAAAAAAAADof/////7vWsQAAAAAAAAAAAA////NAAAAAAAAAAA////NAAAAAAAAAAD////NAAA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AAAAAAAAAAAAAAAA////NAAAAAAAAP///zQAAAAAAAD///80AAA/+P/2PAAAAAAAAAAAAP///zQAAAAAAAAA////NAAAAAAAADT///8AAAAAAAAAaP//zAAAAAAAAAD///80AAAAAAAAAAD///80AAAAAACb//+kAAAAAAAAAAAAAKX//5oAAAAAAAD///91AAAAAAAAAAAAYP//zAAAAACy//+cAAAAAAAAAAAAVP///zQAAAAAAAAA////NAAAAAAAAAAAAAAAAAAAAAAAAJX///cJAAAAAAD///80AAAAAAAAAAD4//9LAAAAAAAAAHL///80AAAAAAAAAAB4//9fAADd/8UAAAAAAAAAAAAAMP//pgCM/+EAAAAAXf//TQHq/7MAAAAAAAAAAAAABdD/+y1w//+vAAAAAAAAAAAAAG3//2UACvX/pwAAAAAAAAAAAAAM2v//rgAAAAAAAAAAAAAAAAAAD//2AAAAAAAAAAD/+AAAAAAAAAAA9/8SAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD///80AAAAAAAA////NAAAAAAAAP///zQAKe7/+kkAAAAAAAAAAAAA////NAAAAAAAAAD///80AAAAAAAANP///wAAAAAAAABo///MAAAAAAAAAP///zQAAAAAAAAAAP///zQAAAAAAE3///UTAAAAAAAAAAAT9v//TQAAAAAAAP///8UAAAAAAAAAAAC8//+FAAAAAHD//+wJAAAAAAAAAACq////NAAAAAAAAAD///80AAAAAAAAAACG1NSIAAAAAAAAIP///yoAAAAAAP///zQAAAAAAAAAAOn//2wAAAAAAAAAv////zQAAAAAAAAAAB3+/7MAMf//aQAAAAAAAAAAAAAA4f/oAMv/oQAAAAAc//+NL///ZQAAAAAAAAAAAACD//+KAAPO//9ZAAAAAAAAAAAAFfv/uABS//9JAAAAAAAAAAAAAKH//+MSAAAAAAAAAAAAAAAAAABf/8oAAAAAAAAAAP/4AAAAAAAAAADO/2IAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAP///zQAAAAAAAD///80AAAAAAAA////NBjg//1WAAAAAAAAAAAAAAD///80AAAAAAAAAP///zQAAAAAAAA0////AAAAAAAAAGj//8wAAAAAAAAA////NAAAAAAAAAAA////NAAAAAAAAtn//6IAAAAAAAAAAKL//9kCAAAAAAAA/////1EAAAAAAAAATP//+RoAAAAAE/f//34AAAAAAAAAN/z///80AAAAAAAAAP///zQAAAAAAAAAAGv//+sIAAAAAAAW////JAAAAAAA////NAAAAAAAAAAAyf//vAAAAAAAADj/////NAAAAAAAAAAAAL//+A6D//oTAAAAAAAAAAAAAACV//85/P9hAAAAAADd/85y//4ZAAAAAAAAAAAAM/v/4QsAADb9/+wWAAAAAAAAAAAAs//6EaX/6AMAAAAAAAAAAABa///9PwAAAAAAAAAAAAAAAAA2gvb7RgAAAAAAAAAA//gAAAAAAAAAAFL+9oM2AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA////NAAAAAAAAP///zQAAAAAAAD///9Azf//ZQAAAAAAAAAAAAAAAP///zQAAAAAAAAA////NAAAAAAAADT///8AAAAAAAAAaP//zAAAAAAAAAD///80AAAAAAAAAAD///80AAAAAAAAQf7//40FAAAAAAWN///+QQAAAAAAAAD/////808AAAAAAELy//97AAAAAAAAgf///FgAAAAAADfo8f///zQAAAAAAAAA////NAAAAAAAAAAAE/X//5wCAAAAAIL//+oEAAAAAAD///80AAAAAAAAAAB8////aAAAAAAd3uv///80AAAAAAAAAAAAY///XNb/sQAAAAAAAAAAAAAAAEf//7f//yAAAAAAAJ3//cb/ygAAAAAAAAAAAAbT//9PAAAAAJb//6sAAAAAAAAAAABW//9l8f+OAAAAAAAAAAAAIvH//4UAAAAAAAAAAAAAAAAAAP/9qTUAAAAAAAAAAAD/+AAAAAAAAAAAAEi5/v8AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD///80AAAAAAAA////NAAAAAAAAP///9r///9mAAAAAAAAAAAAAAAA////NAAAAAAAAAD///80AAAAAAAANP///wAAAAAAAABo///MAAAAAAAAAP///zQAAAAAAAAAAP///zQAAAAAAAAAdP///9qAV1iB2v///3QAAAAAAAAAAP///67//71sUmav/v//pQEAAAAAAAAFwP///7doUmet/f9i////NAAAAAAAAAD///80AAAAAAAAAAAAbv///89zVGi2////cwAAAAAAAP///zQAAAAAAAAAAA/i////smpVhu3/df///zQAAAAAAAAAAAAP9//S//9VAAAAAAAAAAAAAAAABvL////gAAAAAAAAXf////99AAAAAAAAAAAAh///sgAAAAAAD+f//1QAAAAAAAAAAAjw/+r//zAAAAAAAAAAAADJ///rUExMTExMTExMTAAAAAAA6v/3jgUAAAAAAAAAAP/4AAAAAAAAAAADgOz/6wAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAP///zQAAAAAAAD///80AAAAAAAA//////////tEAAAAAAAAAAAAAAD///80AAAAAAAAAP///zQAAAAAAAA0////AAAAAAAAAGj//8wAAAAAAAAA////NAAAAAAAAAAA////NAAAAAAAAAAAXev//////////+tcAAAAAAAAAAAA////OMv/////////93wBAAAAAAAAAAAKqf//////////nwD///80AAAAAAAAAP///zQAAAAAAAAAAAAAdfn//////////IQBAAAAAAAA////NAAAAAAAAAAAACng/////////84K////NAAAAAAAAAAAAACr////8QgAAAAAAAAAAAAAAAAArP///6AAAAAAAAAc/////y8AAAAAAAAAADb8//UfAAAAAAAAWv//6RQAAAAAAAAAAJz////TAAAAAAAAAAAAAP//////////////////AAAAAAAAN9j/fAAAAAAAAAAA//gAAAAAAAAAAHv/2TgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA////NAAAAAAAAP///zQAAAAAAAD/////cqj//+8oAAAAAAAAAAAAAP///zQAAAAAAAAA////NAAAAAAAADT///8AAAAAAAAAaP//zAAAAAAAAAD///80AAAAAAAAAAD///80AAAAAAAAAAAADmy14fb24bVsDgAAAAAAAAAAAAD///80CGq56fvryYEcAAAAAAAAAAAAAAAAPp3b9PjiqkgAAP///zQAAAAAAAAA////NAAAAAAAAAAAAAAAI4rN8PzwzY0pAAAAAAAAAAD///8+AAAAAAAAAAAAAA55yvL76LZcBAD///80AAAAAAAAAAAAAE7///+dAAAAAAAAAAAAAAAAAABf////YAAAAAAAAADc///iAAAAAAAAAAAH1v//dgAAAAAAAAAAuv//pwAAAAAAAAAAP////3UAAAAAAAAAAAAA//////////////////8AAAAAAAAAO//dAAAAAAAAAAD/+AAAAAAAAAAA3f8+AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD///80AAAAAAAA////NAAAAAAAAP///5UACs7//90UAAAAAAAAAAAA////NAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAP///zQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA////NAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAPf//3sAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAB5v/9GgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAH//oAAAAAAAAAAP/4AAAAAAAAAAD6/wsAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAP///zQAAAAAAAD///80AAAAAAAA////NAAAHen//8MGAAAAAAAAAAD///80AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA////NAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD///80AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAxP//+IJdYgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABf7/7QAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA//6QAAAAAAAAAA//gAAAAAAAAAAOn/EgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA////NAAAAAAAAP///zQAAAAAAAD///80AAAAO/n//6IAAAAAAAAAAP///zQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD///80AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAP///zQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABZ////////AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAhf//RgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAALv/HAAAAAAAAAAD/+AAAAAAAAAAAyP8vAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD///80AAAAAAAA////NAAAAAAAAP///zQAAAAAZP///3wAAAAAAAAA////PwAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAP///zQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA////NAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABayO399eEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAADf4/8MAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABV/54AAAAAAAAAAP/4AAAAAAAAAACf/1UAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAP///zQAAAAAAAD///80AAAAAAAA////NAAAAAAAk////lYAAAAAAADx//+2UAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA////NAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD///80AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAUFuW+f/2KQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAID/cwAAAAAAAAAA//gAAAAAAAAAAHT/fwAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAP///zQAAAAAAAD///80AAAAAAAEvf//9zcAAAAAALv/////AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD///80AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAP///zQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD/////9UsAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAqv9HAAAAAAAAAAD/+AAAAAAAAAAAS/+oAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA////MgAAAAAAAP///zQAAAAAAAAT3f//6B4AAAAAI7jx/OsAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAP///zQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA////NAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAPj95qAnAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAADR/yAAAAAAAAAAAP/4AAAAAAAAAAAm/84AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAj///8rAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAPH9AwAAAAAAAAAA//gAAAAAAAAAAAn/7QAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAQf///xUAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA+v8VAAAAAAAAAAD/+AAAAAAAAAAAHf/1AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAARJPr///YAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAADa/8tnTwAAAAAAAP/4AAAAAAAAT2nP/9QAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACA/////1gAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAG3/////AAAAAAAA//gAAAAAAAD/////aAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAHr97MNPAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAFu/7v0AAAAAAAD/+AAAAAAAAP3uvlgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAP/4AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA//gAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD/+AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAP/4AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="};
const OVERLAY_C = `
/* In-game options overlay for tq-android-perf.
 *
 * Drawn from a hook on libtq's SwappyGL_swap import (game thread, GL context current): one shader, one
 * texture (glyph atlas with a white block for boxes), one draw call, full GL state saved and restored.
 * Input comes from hooks on libtq's SDL_GetNumTouchFingers / SDL_GetTouchFinger / SDL_GetMouseState imports
 * (SDLInputDevice::Update polls finger state on the game thread): a finger that starts on the menu button, or
 * any finger while the panel is open, is handled here and hidden from the game.
 *
 * All mutable state is in 'st' (JS-allocated: CModule globals are read-only in this Frida build).
 * Layout of the head of St is fixed and mirrored in JS.
 */
#include <glib.h>

typedef struct { gint64 id; float x, y, pressure; } Finger;

enum { G_GETINTEGERV, G_GETBOOLEANV, G_ISENABLED, G_ENABLE, G_DISABLE, G_BLENDFUNCSEP, G_BLENDEQSEP, G_USEPROGRAM,
       G_CREATESHADER, G_SHADERSOURCE, G_COMPILESHADER, G_CREATEPROGRAM, G_ATTACHSHADER, G_BINDATTRIBLOC, G_LINKPROGRAM,
       G_GETUNIFORMLOC, G_UNIFORM2F, G_UNIFORM1I, G_GENBUFFERS, G_BINDBUFFER, G_BUFFERDATA, G_VERTEXATTRIBPTR,
       G_ENABLEVAA, G_GENVAOS, G_BINDVAO, G_GENTEXTURES, G_BINDTEXTURE, G_TEXIMAGE2D, G_TEXPARAMETERI, G_ACTIVETEXTURE,
       G_DRAWARRAYS, G_VIEWPORT, G_COLORMASK, G_DEPTHMASK, G_PIXELSTOREI, G_BINDFRAMEBUFFER, G_ISPROGRAM, G_BINDSAMPLER,
       G_BLENDFUNC, G_GETSHADERIV, G_GETPROGRAMIV, G_COUNT };

typedef void (*f_v_ip) (guint32, void *);
typedef guint8 (*f_b_i) (guint32);
typedef void (*f_v_i) (guint32);
typedef void (*f_v_iiii) (guint32, guint32, guint32, guint32);
typedef void (*f_v_ii) (guint32, guint32);
typedef guint32 (*f_i_i) (guint32);
typedef guint32 (*f_i_v) (void);
typedef void (*f_v_iipp) (guint32, gint32, const char **, const gint32 *);
typedef void (*f_v_iip) (guint32, guint32, const char *);
typedef gint32 (*f_i_ip) (guint32, const char *);
typedef void (*f_v_iff) (gint32, float, float);
typedef void (*f_v_iI) (gint32, gint32);
typedef void (*f_v_ipi) (guint32, gintptr, const void *, guint32);
typedef void (*f_v_vap) (guint32, gint32, guint32, guint8, gint32, gintptr);
typedef void (*f_v_ip2) (gint32, guint32 *);
typedef void (*f_v_teximg) (guint32, gint32, gint32, gint32, gint32, gint32, guint32, guint32, const void *);
typedef void (*f_v_iii) (guint32, guint32, gint32);
typedef void (*f_v_draw) (guint32, gint32, gint32);
typedef void (*f_v_vp) (gint32, gint32, gint32, gint32);
typedef void (*f_v_cm) (guint8, guint8, guint8, guint8);
typedef void (*f_v_b) (guint8);
typedef void (*f_v_ii2) (guint32, gint32);
typedef void (*f_v_iipi) (guint32, guint32, gint32 *);

extern void * glf[G_COUNT];
extern gint32 (*egl_query) (void *, void *, gint32, gint32 *);
extern gint32 (*o_swap) (void *, void *);
extern gint32 (*o_num) (gint64);
extern Finger * (*o_get) (gint64, gint32);
extern guint32 (*o_mouse) (gint32 *, gint32 *);
extern void (*set_texred) (void *, gint32);
extern void (*get_stats) (void *, void *);
extern void * (*get_options) (void *);
extern guint8 (*opt_getbool) (void *, gint32);
extern void (*opt_setbool) (void *, gint32, guint8);
extern void ** gengine;            /* &GAME::gEngine */
extern guint8 * atlas;             /* alpha, aw x ah */
extern float * glyphs;             /* 95 x 7: x, y, w, h, xoff, yoff, adv */
extern gint32 * fontinfo;          /* aw, ah, size, ascent, whitex, whitey */
/* add-ons (overlay-glue.js): up to 4, each { frame, draw, touch } (see the add-on section below) */
extern void * addon_tab[12];
extern gint32 addon_n;
extern gint32 core_cfg[4];         /* [0] show the perf rows (0 in a build without engine patches) */
extern char core_label[16];        /* text of the menu button */

#define NITEMS 17
#define NPATCH 7
#define MAXV 12000
typedef struct { float x, y, u, v; guint32 c; } Vtx;
typedef struct {
  /* fixed head, mirrored in JS */
  gint32 open, dirty, frames, ready;     /* 0 */
  gint32 ov[32];                          /* 16: override / desired, -1 = none */
  gint32 inst[8];                         /* 144: patches: 1 running, 0 not running, -1 unavailable */
  gint32 * pen[8];                        /* 176: patch 'enabled' flags (live toggles) or NULL */
  gint32 init[32];                        /* 240: graphics values captured at the first frame */
  gint32 dbg[16];                         /* 368: num calls, fingers, last x*1000, last y*1000, W, H, presses, mouse calls,
                                             draw calls, faces, emitters, lights */
  guint8 gstats[64];                      /* 432 */
  /* private */
  gint32 W, H, glok, prog, vbo, vao, tex, u_sc, u_tx, nv, capt, texchk;
  gint64 own[16]; gint64 own_dev[16]; gint32 nown;
  gint64 game[16]; gint64 game_dev[16]; gint32 ngame;
  Finger * kept[16]; gint32 nkept;
  gint32 seen_own[16], seen_game[16];
  float press_x, press_y;
  gint32 hide;                            /* an add-on hides the menu button this frame */
  Vtx v[MAXV];
} St;
extern St st;
gint32 st_size (void) { return (gint32) sizeof (St); }

typedef struct { const char * label; gint32 kind; gint32 off; gint32 invert; gint32 restart; } Item;
/* kind 3 = engine patch (off = patch index), 1 = GraphicsEngine byte, 2 = texture resolution,
   4 = shadows: GraphicsEngine byte AND Options bool #9 (hidden in the mobile settings) */
static const Item items[NITEMS] = {
  { "Direct calls (PLT bypass)", 3, 0, 0, 1 },
  { "Sound sample cache", 3, 1, 0, 0 },
  { "Short effects as samples", 3, 2, 0, 0 },
  { "Attack slot cache", 3, 3, 0, 0 },
  { "Shader uniform cache", 3, 4, 0, 0 },
  { "Fast ray-box test", 3, 5, 0, 1 },
  { "Path end-point cache", 3, 6, 0, 0 },
  { "Shadows (experimental)", 4, 0x11f, 0, 0 },
  { "Grass", 1, 0x125, 0, 0 },
  { "Water", 1, 0x12a, 0, 0 },
  { "Fog", 1, 0x123, 0, 0 },
  { "Decals (blood, scorch marks)", 1, 0x129, 0, 0 },
  { "Particle effects", 1, 0x128, 0, 0 },
  { "See-through objects", 1, 0x12b, 0, 0 },
  { "Detailed terrain", 1, 0x12e, 1, 0 },
  { "Detailed lighting", 1, 0x12f, 1, 0 },
  { "Full-res textures", 2, 0, 0, 0 },
};

static void * opts (void) { void * e = *gengine; return e == NULL ? NULL : get_options (e); }
static guint8 * ge (void) { void * e = *gengine; if (e == NULL) return NULL; return *(guint8 **) ((guint8 *) e + 0x1b8); }

/* ---------- item state ---------- */
static gint32 patch_running (gint32 i) { gint32 k = items[i].off; if (st.pen[k] != NULL) return *st.pen[k] != 0; return st.inst[k] == 1; }
static gint32 item_value (gint32 i)
{
  guint8 * g;
  if (items[i].kind == 3) return st.ov[i] < 0 ? 1 : st.ov[i];
  g = ge (); if (g == NULL) return 0;
  if (items[i].kind == 1) { gint32 b = g[items[i].off] != 0; return items[i].invert ? !b : b; }
  if (items[i].kind == 4) { void * o = opts (); return g[items[i].off] != 0 && o != NULL && opt_getbool (o, 9) != 0; }
  return *(gint32 *) (g + 0xf8) == 0;
}
static gint32 item_restart (gint32 i)   /* desired state differs from what runs now and cannot change live */
{
  gint32 k = items[i].off;
  if (items[i].kind != 3 || st.inst[k] < 0) return 0;
  if (st.pen[k] != NULL) return 0;
  return item_value (i) != (st.inst[k] == 1);
}
static void apply_gfx (void)
{
  guint8 * g = ge (); gint32 i;
  if (g == NULL) return;
  if (!st.capt) { void * o = opts (); if (o == NULL) return; for (i = 0; i < NITEMS; i++) if (items[i].kind == 1) st.init[i] = g[items[i].off]; else if (items[i].kind == 2) st.init[i] = *(gint32 *) (g + 0xf8); else if (items[i].kind == 4) st.init[i] = opt_getbool (o, 9); st.capt = 1; }
  for (i = 0; i < NITEMS; i++) {
    if (items[i].kind == 1 && st.ov[i] >= 0) { guint8 want = (guint8) (items[i].invert ? !st.ov[i] : st.ov[i]); if (g[items[i].off] != want) g[items[i].off] = want; }
    if (items[i].kind == 4 && st.ov[i] >= 0) {
      void * o = opts ();
      if (st.ov[i] && g[items[i].off] == 0) g[items[i].off] = 1;
      if (o != NULL && (opt_getbool (o, 9) != 0) != (st.ov[i] != 0)) opt_setbool (o, 9, (guint8) st.ov[i]);
    }
  }
  if (++st.texchk >= 30) {
    st.texchk = 0;
    for (i = 0; i < NITEMS; i++) if (items[i].kind == 2 && st.ov[i] >= 0) { gint32 want = st.ov[i] ? 0 : 1; if (*(gint32 *) (g + 0xf8) != want) set_texred (g, want); }
  }
}
static void toggle (gint32 i)
{
  gint32 nv;
  if (items[i].kind == 3) {
    gint32 k = items[i].off;
    if (st.inst[k] < 0) return;
    nv = !item_value (i); st.ov[i] = nv;
    if (st.pen[k] != NULL) *st.pen[k] = nv;
  } else {
    guint8 * g = ge (); if (g == NULL) return;
    nv = !item_value (i); st.ov[i] = nv;
    if (items[i].kind == 2) { set_texred (g, nv ? 0 : 1); }
    else if (items[i].kind == 4) { void * o = opts (); if (nv) g[items[i].off] = 1; if (o != NULL) opt_setbool (o, 9, (guint8) nv); }
    else g[items[i].off] = (guint8) (items[i].invert ? !nv : nv);
  }
  st.dirty++;
}
static void reset_gfx (void)
{
  guint8 * g = ge (); gint32 i;
  for (i = 0; i < NITEMS; i++) {
    if (items[i].kind == 3 || st.ov[i] < 0) continue;
    st.ov[i] = -1;
    if (g != NULL && st.capt) { if (items[i].kind == 1) g[items[i].off] = (guint8) st.init[i]; else if (items[i].kind == 4) { void * o = opts (); if (o != NULL) opt_setbool (o, 9, (guint8) st.init[i]); } else set_texred (g, st.init[i]); }
  }
  st.dirty++;
}

/* ---------- layout (pixels of the EGL surface) ---------- */
typedef struct { float x, y, w, h; } R;
static float S (void) { return (float) st.H / 1080.0f; }
static R btn_rect (void) { R r; float s = S (); r.x = st.W * 0.245f; r.y = 12 * s; r.w = 120 * s; r.h = 58 * s; return r; }
static R panel_rect (void) { R r; r.x = st.W * 0.05f; r.y = st.H * 0.06f; r.w = st.W * 0.90f; r.h = st.H * 0.88f; return r; }
static R close_rect (void) { R p = panel_rect (), r; float s = S (); r.w = 150 * s; r.h = 54 * s; r.x = p.x + p.w - r.w - 20 * s; r.y = p.y + 14 * s; return r; }
static R reset_rect (void) { R p = panel_rect (), r; float s = S (); r.w = 300 * s; r.h = 54 * s; r.x = p.x + p.w - r.w - 20 * s; r.y = p.y + p.h - r.h - 14 * s; return r; }
static R row_rect (gint32 i)
{
  R p = panel_rect (), r; float s = S (), top = p.y + 140 * s, rowh = 50 * s, colw = (p.w - 60 * s) / 2;
  gint32 col = items[i].kind == 3 ? 0 : 1, idx = col == 0 ? i : i - NPATCH;
  r.x = p.x + 20 * s + col * (colw + 20 * s); r.y = top + idx * rowh; r.w = colw; r.h = rowh - 6 * s; return r;
}
static gint32 inside (R r, float x, float y) { return x >= r.x && x < r.x + r.w && y >= r.y && y < r.y + r.h; }

/* ---------- add-ons ----------
   addon_tab[3k..3k+2] = frame, draw, touch of add-on k (C functions of the add-on's own CModule):
     gint32 frame (void)                                   game thread, every frame; nonzero hides the menu button
     void draw (gint32 panel, float x, float y, float w)   panel = 1: its section of the open panel at (x, y), width w;
                                                           panel = 0: anything it shows over the game
     gint32 touch (float x, float y, gint32 panel, gint32 press)
                                                           press = 0: claim this finger?  press = 1: handle the press;
                                                           returns 2 to close the panel
   They draw with ui_box / ui_text / ui_text_w and read sizes with ui_metrics. */
typedef gint32 (*A_frame) (void);
typedef void (*A_draw) (gint32, float, float, float);
typedef gint32 (*A_touch) (float, float, gint32, gint32);
static R addon_area (void)
{
  R p = panel_rect (), r; float s = S ();
  if (core_cfg[0]) { R last = row_rect (NPATCH - 1); r.x = last.x; r.y = last.y + last.h + 80 * s; r.w = last.w; }
  else { r.x = p.x + 20 * s; r.y = p.y + 140 * s; r.w = (p.w - 60 * s) / 2; }
  r.h = 0; return r;
}
static gint32 addons_touch (float px, float py, gint32 press)
{
  gint32 k, r;
  for (k = 0; k < addon_n && k < 4; k++) if ((r = ((A_touch) addon_tab[3 * k + 2]) (px, py, st.open, press)) != 0) return r;
  return 0;
}

/* ---------- touch ---------- */
static gint32 claims (float px, float py)
{
  if (st.open) return 1;
  if (addons_touch (px, py, 0)) return 1;
  return !st.hide && inside (btn_rect (), px, py);
}
static void on_press (float px, float py)
{
  gint32 i;
  st.dbg[6]++;
  if (!st.open) {
    if (addons_touch (px, py, 1)) return;
    if (!st.hide && inside (btn_rect (), px, py)) st.open = 1;
    return;
  }
  if (!inside (panel_rect (), px, py) || inside (close_rect (), px, py)) { st.open = 0; return; }
  if (core_cfg[0] && inside (reset_rect (), px, py)) { reset_gfx (); return; }
  if (core_cfg[0]) for (i = 0; i < NITEMS; i++) if (inside (row_rect (i), px, py)) { toggle (i); return; }
  if (addons_touch (px, py, 1) == 2) st.open = 0;
}
gint32 h_num (gint64 touch)
{
  /* the game polls every touch device each frame; ownership is tracked per device so a finger is not
     "released" just because another device's list does not contain it */
  gint32 n = o_num (touch), i, j, k;
  st.dbg[0]++;
  for (j = 0; j < st.nown; j++) st.seen_own[j] = st.own_dev[j] != touch;
  for (j = 0; j < st.ngame; j++) st.seen_game[j] = st.game_dev[j] != touch;
  st.nkept = 0;
  for (i = 0; i < n && i < 16; i++) {
    Finger * f = o_get (touch, i);
    gint32 known = 0;
    if (f == NULL) continue;
    st.dbg[1]++; st.dbg[2] = (gint32) (f->x * 1000); st.dbg[3] = (gint32) (f->y * 1000);
    for (j = 0; j < st.nown; j++) if (st.own_dev[j] == touch && st.own[j] == f->id) { st.seen_own[j] = 1; known = 1; }
    if (known) continue;
    for (j = 0; j < st.ngame; j++) if (st.game_dev[j] == touch && st.game[j] == f->id) { st.seen_game[j] = 1; known = 2; }
    if (!known && st.W > 0) {
      float px = f->x * st.W, py = f->y * st.H;
      if (claims (px, py) && st.nown < 16) { st.own[st.nown] = f->id; st.own_dev[st.nown] = touch; st.seen_own[st.nown] = 1; st.nown++; on_press (px, py); continue; }
      if (st.ngame < 16) { st.game[st.ngame] = f->id; st.game_dev[st.ngame] = touch; st.seen_game[st.ngame] = 1; st.ngame++; }
    }
    st.kept[st.nkept++] = f;
  }
  for (j = 0, k = 0; j < st.nown; j++) if (st.seen_own[j]) { st.own[k] = st.own[j]; st.own_dev[k] = st.own_dev[j]; k++; }
  st.nown = k;
  for (j = 0, k = 0; j < st.ngame; j++) if (st.seen_game[j]) { st.game[k] = st.game[j]; st.game_dev[k] = st.game_dev[j]; k++; }
  st.ngame = k;
  return st.nkept;
}
Finger * h_get (gint64 touch, gint32 index) { if (index < 0 || index >= st.nkept) return NULL; return st.kept[index]; }
guint32 h_mouse (gint32 * x, gint32 * y)
{
  guint32 b = o_mouse (x, y);
  st.dbg[7]++;
  if (st.open || st.nown > 0) return 0;
  return b;
}

/* ---------- drawing ---------- */
static guint32 rgba (gint32 r, gint32 g, gint32 b, gint32 a) { return (guint32) r | ((guint32) g << 8) | ((guint32) b << 16) | ((guint32) a << 24); }
static void quad (float x, float y, float w, float h, float u0, float v0, float u1, float v1, guint32 c)
{
  Vtx * q;
  if (st.nv + 6 > MAXV) return;
  q = &st.v[st.nv];
  q[0].x = x; q[0].y = y; q[0].u = u0; q[0].v = v0;
  q[1].x = x + w; q[1].y = y; q[1].u = u1; q[1].v = v0;
  q[2].x = x; q[2].y = y + h; q[2].u = u0; q[2].v = v1;
  q[3] = q[1]; q[4].x = x + w; q[4].y = y + h; q[4].u = u1; q[4].v = v1; q[5] = q[2];
  q[0].c = q[1].c = q[2].c = q[3].c = q[4].c = q[5].c = c;
  st.nv += 6;
}
static void box (R r, guint32 c)
{
  float u = (fontinfo[4] + 1.0f) / fontinfo[0], v = (fontinfo[5] + 1.0f) / fontinfo[1];
  quad (r.x, r.y, r.w, r.h, u, v, u, v, c);
}
static float text_w (const char * s, float scale) { float w = 0; for (; *s; s++) { gint32 c = (guint8) *s; if (c < 32 || c > 126) c = '?'; w += glyphs[(c - 32) * 7 + 6] * scale; } return w; }
static void text (float x, float y, const char * s, float scale, guint32 col)
{
  float aw = (float) fontinfo[0], ah = (float) fontinfo[1];
  for (; *s; s++) {
    gint32 c = (guint8) *s; float * g;
    if (c < 32 || c > 126) c = '?';
    g = &glyphs[(c - 32) * 7];
    if (g[2] > 0 && g[3] > 0)
      quad (x + g[4] * scale, y + g[5] * scale, g[2] * scale, g[3] * scale, g[0] / aw, g[1] / ah, (g[0] + g[2]) / aw, (g[1] + g[3]) / ah, col);
    x += g[6] * scale;
  }
}
void ui_box (float x, float y, float w, float h, guint32 c) { R r; r.x = x; r.y = y; r.w = w; r.h = h; box (r, c); }
void ui_text (float x, float y, const char * str, float scale, guint32 c) { text (x, y, str, scale, c); }
float ui_text_w (const char * str, float scale) { return text_w (str, scale); }
void ui_metrics (float * m) { m[0] = (float) st.W; m[1] = (float) st.H; m[2] = S (); m[3] = (float) fontinfo[2]; m[4] = (float) st.frames; }
static void addons_draw (void)
{
  gint32 k; R a = addon_area ();
  for (k = 0; k < addon_n && k < 4; k++) ((A_draw) addon_tab[3 * k + 1]) (st.open, a.x, a.y, a.w);
}
static void build (void)
{
  float s = S (), fs = s * 0.78f, ts;
  gint32 i;
  guint32 white = rgba (240, 236, 226, 255), dim = rgba (160, 158, 150, 255), gold = rgba (214, 170, 92, 255);
  R b = btn_rect ();
  st.nv = 0;
  if (!st.open) {
    if (!st.hide) {
      box (b, rgba (16, 18, 18, 150));
      ts = fs * 0.95f;
      text (b.x + (b.w - text_w (core_label, ts)) / 2, b.y + (b.h - fontinfo[2] * ts) / 2 + 2 * s, core_label, ts, white);
    }
    addons_draw ();
    return;
  }
  {
    R p = panel_rect (), c = close_rect (), rs = reset_rect (), h;
    box (p, rgba (12, 14, 14, 228));
    const char * title = core_cfg[0] ? "TQ Android Perf" : "TQ Android mods";
    text (p.x + 24 * s, p.y + 22 * s, title, s * 1.05f, gold);
    {
      char buf[16]; gint32 f = st.dbg[12], n = 0, d = 100;
      if (f < 0) f = 0; if (f > 999) f = 999;
      for (; d > 0; d /= 10) if (f >= d || n > 0 || d == 1) buf[n++] = (char) ('0' + (f / d) % 10);
      buf[n++] = ' '; buf[n++] = 'F'; buf[n++] = 'P'; buf[n++] = 'S'; buf[n] = 0;
      text (p.x + 24 * s + text_w (title, s * 1.05f) + 30 * s, p.y + 30 * s, buf, fs, dim);
    }
    box (c, rgba (60, 60, 56, 255));
    text (c.x + (c.w - text_w ("Close", fs)) / 2, c.y + 10 * s, "Close", fs, white);
    if (core_cfg[0]) {
      h = row_rect (0); text (h.x, h.y - 52 * s, "Engine patches", fs, gold);
      h = row_rect (NPATCH); text (h.x, h.y - 52 * s, "Graphics (applies live)", fs, gold);
      for (i = 0; i < NITEMS; i++) {
        R r = row_rect (i), pill; gint32 on = item_value (i), na = items[i].kind == 3 && st.inst[items[i].off] < 0;
        box (r, rgba (255, 255, 255, 14));
        text (r.x + 14 * s, r.y + 8 * s, items[i].label, fs * 0.92f, na ? dim : white);
        pill.w = 104 * s; pill.h = r.h - 10 * s; pill.x = r.x + r.w - pill.w - 8 * s; pill.y = r.y + 5 * s;
        if (na) { box (pill, rgba (50, 50, 50, 255)); text (pill.x + (pill.w - text_w ("N/A", fs * 0.8f)) / 2, pill.y + 6 * s, "N/A", fs * 0.8f, dim); continue; }
        box (pill, on ? rgba (47, 120, 104, 255) : rgba (70, 70, 66, 255));
        text (pill.x + (pill.w - text_w (on ? "ON" : "OFF", fs * 0.8f)) / 2, pill.y + 6 * s, on ? "ON" : "OFF", fs * 0.8f, white);
        if (item_restart (i)) text (pill.x - text_w ("restart", fs * 0.7f) - 12 * s, pill.y + 8 * s, "restart", fs * 0.7f, gold);
      }
      box (rs, rgba (60, 60, 56, 255));
      text (rs.x + (rs.w - text_w ("Reset graphics", fs)) / 2, rs.y + 10 * s, "Reset graphics", fs, white);
      text (p.x + 24 * s, p.y + p.h - 50 * s, "'restart' = applies on the next game launch. Tap outside to close.", fs * 0.72f, dim);
    }
    addons_draw ();
  }
}

#define GLF(t, i) ((t) glf[i])
static const char * VS = "attribute vec2 p; attribute vec2 t; attribute vec4 c; uniform vec2 sc; varying vec2 vt; varying vec4 vc;"
  "void main(){ gl_Position = vec4(p.x / sc.x * 2.0 - 1.0, 1.0 - p.y / sc.y * 2.0, 0.0, 1.0); vt = t; vc = c; }";
static const char * FS = "precision mediump float; varying vec2 vt; varying vec4 vc; uniform sampler2D tx;"
  "void main(){ gl_FragColor = vec4(vc.rgb, vc.a * texture2D(tx, vt).a); }";

static gint32 gl_setup (void)
{
  guint32 vs, fs, p; gint32 ok = 0; guint32 ids[1];
  vs = GLF (f_i_i, G_CREATESHADER) (0x8B31); fs = GLF (f_i_i, G_CREATESHADER) (0x8B30);
  GLF (f_v_iipp, G_SHADERSOURCE) (vs, 1, &VS, NULL); GLF (f_v_i, G_COMPILESHADER) (vs);
  GLF (f_v_iipp, G_SHADERSOURCE) (fs, 1, &FS, NULL); GLF (f_v_i, G_COMPILESHADER) (fs);
  p = GLF (f_i_v, G_CREATEPROGRAM) ();
  GLF (f_v_ii, G_ATTACHSHADER) (p, vs); GLF (f_v_ii, G_ATTACHSHADER) (p, fs);
  GLF (f_v_iip, G_BINDATTRIBLOC) (p, 0, "p"); GLF (f_v_iip, G_BINDATTRIBLOC) (p, 1, "t"); GLF (f_v_iip, G_BINDATTRIBLOC) (p, 2, "c");
  GLF (f_v_i, G_LINKPROGRAM) (p);
  GLF (f_v_iipi, G_GETPROGRAMIV) (p, 0x8B82, &ok);
  if (!ok) return 0;
  st.prog = (gint32) p;
  st.u_sc = GLF (f_i_ip, G_GETUNIFORMLOC) (p, "sc"); st.u_tx = GLF (f_i_ip, G_GETUNIFORMLOC) (p, "tx");
  GLF (f_v_ip2, G_GENBUFFERS) (1, ids); st.vbo = (gint32) ids[0];
  GLF (f_v_ip2, G_GENVAOS) (1, ids); st.vao = (gint32) ids[0];
  GLF (f_v_ip2, G_GENTEXTURES) (1, ids); st.tex = (gint32) ids[0];
  GLF (f_v_ii, G_BINDTEXTURE) (0x0DE1, st.tex);
  GLF (f_v_ii2, G_PIXELSTOREI) (0x0CF5, 1);
  GLF (f_v_teximg, G_TEXIMAGE2D) (0x0DE1, 0, 0x1906, fontinfo[0], fontinfo[1], 0, 0x1906, 0x1401, atlas);
  GLF (f_v_iii, G_TEXPARAMETERI) (0x0DE1, 0x2801, 0x2601); GLF (f_v_iii, G_TEXPARAMETERI) (0x0DE1, 0x2800, 0x2601);
  GLF (f_v_iii, G_TEXPARAMETERI) (0x0DE1, 0x2802, 0x812F); GLF (f_v_iii, G_TEXPARAMETERI) (0x0DE1, 0x2803, 0x812F);
  GLF (f_v_i, G_BINDVAO) (st.vao);
  GLF (f_v_ii, G_BINDBUFFER) (0x8892, st.vbo);
  GLF (f_v_i, G_ENABLEVAA) (0); GLF (f_v_i, G_ENABLEVAA) (1); GLF (f_v_i, G_ENABLEVAA) (2);
  GLF (f_v_vap, G_VERTEXATTRIBPTR) (0, 2, 0x1406, 0, sizeof (Vtx), 0);
  GLF (f_v_vap, G_VERTEXATTRIBPTR) (1, 2, 0x1406, 0, sizeof (Vtx), 8);
  GLF (f_v_vap, G_VERTEXATTRIBPTR) (2, 4, 0x1401, 1, sizeof (Vtx), 16);
  return 1;
}

static void draw (void * dpy, void * surf)
{
  gint32 prog, abuf, vao, atex, tex0, fbo, vp[4], samp, unpack, bsr, bdr, bsa, bda, ber, bea;
  guint8 cm[4], dm, en_blend, en_depth, en_cull, en_sten, en_sci, en_poly, en_a2c;
  gint32 w = 0, h = 0;
  egl_query (dpy, surf, 0x3057, &w); egl_query (dpy, surf, 0x3056, &h);
  if (w <= 0 || h <= 0) return;
  st.W = w; st.H = h; st.dbg[4] = w; st.dbg[5] = h;
  build ();
  if (st.nv == 0) return;
  /* save */
  GLF (f_v_ip, G_GETINTEGERV) (0x8B8D, &prog); GLF (f_v_ip, G_GETINTEGERV) (0x8894, &abuf); GLF (f_v_ip, G_GETINTEGERV) (0x85B5, &vao);
  GLF (f_v_ip, G_GETINTEGERV) (0x84E0, &atex); GLF (f_v_ip, G_GETINTEGERV) (0x8CA6, &fbo); GLF (f_v_ip, G_GETINTEGERV) (0x0BA2, vp);
  GLF (f_v_ip, G_GETINTEGERV) (0x0CF5, &unpack);
  GLF (f_v_ip, G_GETINTEGERV) (0x80C9, &bsr); GLF (f_v_ip, G_GETINTEGERV) (0x80C8, &bdr); GLF (f_v_ip, G_GETINTEGERV) (0x80CB, &bsa);
  GLF (f_v_ip, G_GETINTEGERV) (0x80CA, &bda); GLF (f_v_ip, G_GETINTEGERV) (0x8009, &ber); GLF (f_v_ip, G_GETINTEGERV) (0x883D, &bea);
  GLF (f_v_ip, G_GETBOOLEANV) (0x0C23, cm); GLF (f_v_ip, G_GETBOOLEANV) (0x0B72, &dm);
  en_blend = GLF (f_b_i, G_ISENABLED) (0x0BE2); en_depth = GLF (f_b_i, G_ISENABLED) (0x0B71); en_cull = GLF (f_b_i, G_ISENABLED) (0x0B44);
  en_sten = GLF (f_b_i, G_ISENABLED) (0x0B90); en_sci = GLF (f_b_i, G_ISENABLED) (0x0C11); en_poly = GLF (f_b_i, G_ISENABLED) (0x8037);
  en_a2c = GLF (f_b_i, G_ISENABLED) (0x809E);
  GLF (f_v_i, G_ACTIVETEXTURE) (0x84C0);
  GLF (f_v_ip, G_GETINTEGERV) (0x8069, &tex0); GLF (f_v_ip, G_GETINTEGERV) (0x8919, &samp);
  /* draw */
  if (!st.glok || !GLF (f_b_i, G_ISPROGRAM) ((guint32) st.prog)) st.glok = gl_setup ();
  if (st.glok) {
    GLF (f_v_ii, G_BINDFRAMEBUFFER) (0x8D40, 0);
    GLF (f_v_vp, G_VIEWPORT) (0, 0, w, h);
    GLF (f_v_i, G_DISABLE) (0x0B71); GLF (f_v_i, G_DISABLE) (0x0B44); GLF (f_v_i, G_DISABLE) (0x0B90); GLF (f_v_i, G_DISABLE) (0x0C11);
    GLF (f_v_i, G_DISABLE) (0x8037); GLF (f_v_i, G_DISABLE) (0x809E);
    GLF (f_v_i, G_ENABLE) (0x0BE2); GLF (f_v_ii, G_BLENDFUNC) (0x0302, 0x0303); GLF (f_v_ii, G_BLENDEQSEP) (0x8006, 0x8006);
    GLF (f_v_cm, G_COLORMASK) (1, 1, 1, 1); GLF (f_v_b, G_DEPTHMASK) (0);
    GLF (f_v_i, G_USEPROGRAM) (st.prog);
    GLF (f_v_iff, G_UNIFORM2F) (st.u_sc, (float) w, (float) h); GLF (f_v_iI, G_UNIFORM1I) (st.u_tx, 0);
    GLF (f_v_ii, G_BINDTEXTURE) (0x0DE1, st.tex); GLF (f_v_ii, G_BINDSAMPLER) (0, 0);
    GLF (f_v_i, G_BINDVAO) (st.vao);
    GLF (f_v_ii, G_BINDBUFFER) (0x8892, st.vbo);
    GLF (f_v_ipi, G_BUFFERDATA) (0x8892, (gintptr) (st.nv * sizeof (Vtx)), st.v, 0x88E0);
    GLF (f_v_draw, G_DRAWARRAYS) (4, 0, st.nv);
  }
  /* restore */
  GLF (f_v_i, G_BINDVAO) (vao); GLF (f_v_ii, G_BINDBUFFER) (0x8892, abuf);
  GLF (f_v_ii, G_BINDSAMPLER) (0, samp); GLF (f_v_ii, G_BINDTEXTURE) (0x0DE1, tex0); GLF (f_v_i, G_ACTIVETEXTURE) (atex);
  GLF (f_v_i, G_USEPROGRAM) (prog); GLF (f_v_ii, G_BINDFRAMEBUFFER) (0x8D40, fbo);
  GLF (f_v_vp, G_VIEWPORT) (vp[0], vp[1], vp[2], vp[3]); GLF (f_v_ii2, G_PIXELSTOREI) (0x0CF5, unpack);
  GLF (f_v_iiii, G_BLENDFUNCSEP) (bsr, bdr, bsa, bda); GLF (f_v_ii, G_BLENDEQSEP) (ber, bea);
  GLF (f_v_cm, G_COLORMASK) (cm[0], cm[1], cm[2], cm[3]); GLF (f_v_b, G_DEPTHMASK) (dm);
  if (en_blend) GLF (f_v_i, G_ENABLE) (0x0BE2); else GLF (f_v_i, G_DISABLE) (0x0BE2);
  if (en_depth) GLF (f_v_i, G_ENABLE) (0x0B71);
  if (en_cull) GLF (f_v_i, G_ENABLE) (0x0B44);
  if (en_sten) GLF (f_v_i, G_ENABLE) (0x0B90);
  if (en_sci) GLF (f_v_i, G_ENABLE) (0x0C11);
  if (en_poly) GLF (f_v_i, G_ENABLE) (0x8037);
  if (en_a2c) GLF (f_v_i, G_ENABLE) (0x809E);
}

gint32 h_swap (void * dpy, void * surf)
{
  st.frames++;
  if (core_cfg[0]) apply_gfx ();
  {
    gint32 k, hide = 0;
    for (k = 0; k < addon_n && k < 4; k++) if (((A_frame) addon_tab[3 * k]) ()) hide = 1;
    st.hide = hide;
  }
  if (st.frames % 15 == 0) {
    guint8 * g = ge ();
    if (g != NULL) {
      get_stats (g, st.gstats);
      st.dbg[8] = (gint32) *(guint32 *) (st.gstats + 20); st.dbg[9] = (gint32) *(guint32 *) (st.gstats + 12);
      st.dbg[10] = (gint32) *(guint32 *) (g + 0x168); st.dbg[11] = (gint32) *(guint32 *) (st.gstats + 28);
      st.dbg[12] = (gint32) (*(float *) (st.gstats + 8) + 0.5f);
    }
  }
  draw (dpy, surf);
  return o_swap (dpy, surf);
}
`;
// ---- in-game options overlay (overlay.c); settings in cache/tq-perf-menu.json
const OV_IDS = ['plt', 'snd', 'strm', 'slot', 'uneg', 'abbox', 'getend', 'shadows', 'grass', 'water', 'fog', 'decals', 'effects',
  'seethrough', 'terrainhq', 'lightinghq', 'texfull'];
const OV_PATCH = ['plt', 'snd', 'strm', 'slot', 'uneg', 'abbox', 'getend'];
const OV_GL = ['glGetIntegerv', 'glGetBooleanv', 'glIsEnabled', 'glEnable', 'glDisable', 'glBlendFuncSeparate', 'glBlendEquationSeparate',
  'glUseProgram', 'glCreateShader', 'glShaderSource', 'glCompileShader', 'glCreateProgram', 'glAttachShader', 'glBindAttribLocation',
  'glLinkProgram', 'glGetUniformLocation', 'glUniform2f', 'glUniform1i', 'glGenBuffers', 'glBindBuffer', 'glBufferData',
  'glVertexAttribPointer', 'glEnableVertexAttribArray', 'glGenVertexArrays', 'glBindVertexArray', 'glGenTextures', 'glBindTexture',
  'glTexImage2D', 'glTexParameteri', 'glActiveTexture', 'glDrawArrays', 'glViewport', 'glColorMask', 'glDepthMask', 'glPixelStorei',
  'glBindFramebuffer', 'glIsProgram', 'glBindSampler', 'glBlendFunc', 'glGetShaderiv', 'glGetProgramiv'];
const OV_CFG = V2_CACHE + 'tq-perf-menu.json';
V2.en = {};
// Add-ons (e.g. tq-blue-trader's tq-addon.js, appended to this script) push { name, install(ctx) } here; install returns
// { frame, draw, touch } (C functions, see overlay.c) and optionally a status object.
var OVERLAY_ADDONS = [];

function ovConfig() { try { return JSON.parse(File.readAllText(OV_CFG)); } catch (e) { return {}; } }
function ovWanted(name) { const c = ovConfig(); return c[name] === undefined ? true : !!c[name]; }   // patches default on
function ovB64(s) {
  const T = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/', L = new Uint8Array(256);
  for (let i = 0; i < 64; i++) L[T.charCodeAt(i)] = i;
  const n = s.length, pad = s.endsWith('==') ? 2 : s.endsWith('=') ? 1 : 0, out = new Uint8Array(n / 4 * 3 - pad);
  for (let i = 0, o = 0; i < n; i += 4) {
    const v = (L[s.charCodeAt(i)] << 18) | (L[s.charCodeAt(i + 1)] << 12) | (L[s.charCodeAt(i + 2)] << 6) | L[s.charCodeAt(i + 3)];
    if (o < out.length) out[o++] = v >> 16; if (o < out.length) out[o++] = (v >> 8) & 255; if (o < out.length) out[o++] = v & 255;
  }
  return out;
}
// opts: { perfRows: show the engine-patch and graphics rows, label: menu button text }
function overlayInstall(b, states, opts) {
  opts = Object.assign({ perfRows: true, label: 'Perf' }, opts || {});
  const gles = Process.findModuleByName('libGLESv3.so') || Process.getModuleByName('libGLESv2.so');
  const egl = Process.getModuleByName('libEGL.so');
  const slots = { swap: V2.imp['SwappyGL_swap'], num: V2.imp['SDL_GetNumTouchFingers'], get: V2.imp['SDL_GetTouchFinger'], mouse: V2.imp['SDL_GetMouseState'] };
  for (const k in slots) if (!slots[k]) throw Error('overlay: import not found: ' + k);
  const P = n => { const m = Memory.alloc(8); held.push(m); return m; };
  const glf = Memory.alloc(OV_GL.length * 8); held.push(glf);
  OV_GL.forEach((n, i) => glf.add(i * 8).writePointer(gles.getExportByName(n)));
  const atlasBytes = ovB64(OV_FONT.data), atlas = Memory.alloc(atlasBytes.length); atlas.writeByteArray(atlasBytes);
  const gl = new Float32Array(95 * 7);
  for (let c = 32; c < 127; c++) OV_FONT.glyphs[c].forEach((v, k) => { gl[(c - 32) * 7 + k] = v; });
  const glyphs = Memory.alloc(gl.byteLength); glyphs.writeByteArray(gl.buffer);
  const fi = Memory.alloc(6 * 4);
  [OV_FONT.w, OV_FONT.h, OV_FONT.size, OV_FONT.ascent, OV_FONT.white[0], OV_FONT.white[1]].forEach((v, i) => fi.add(i * 4).writeS32(v));
  const st = Memory.alloc(512 * 1024); st.writeByteArray(new Uint8Array(512 * 1024));
  held.push(atlas, glyphs, fi, st);
  const v = { glf, st, atlas: P(), glyphs: P(), fontinfo: P(), egl_query: P(), o_swap: P(), o_num: P(), o_get: P(), o_mouse: P(), set_texred: P(), get_stats: P(), get_options: P(), opt_getbool: P(), opt_setbool: P(), gengine: P() };
  v.atlas.writePointer(atlas); v.glyphs.writePointer(glyphs); v.fontinfo.writePointer(fi);
  v.egl_query.writePointer(egl.getExportByName('eglQuerySurface'));
  v.o_swap.writePointer(slots.swap.readPointer()); v.o_num.writePointer(slots.num.readPointer());
  v.o_get.writePointer(slots.get.readPointer()); v.o_mouse.writePointer(slots.mouse.readPointer());
  v.set_texred.writePointer(V2.exp('_ZN4GAME14GraphicsEngine19SetTextureReductionEi'));
  v.get_stats.writePointer(V2.exp('_ZN4GAME14GraphicsEngine8GetStatsERNS_13GraphicsStatsE'));
  v.get_options.writePointer(V2.exp('_ZN4GAME6Engine10GetOptionsEv'));
  v.opt_getbool.writePointer(V2.exp('_ZNK4GAME7Options7GetBoolENS0_8BoolNameE'));
  v.opt_setbool.writePointer(V2.exp('_ZN4GAME7Options7SetBoolENS0_8BoolNameEb'));
  v.gengine.writePointer(V2.exp('_ZN4GAME7gEngineE'));
  v.addon_tab = Memory.alloc(12 * 8); v.addon_n = Memory.alloc(4); v.core_cfg = Memory.alloc(16); v.core_label = Memory.alloc(16);
  held.push(v.addon_tab, v.addon_n, v.core_cfg, v.core_label);
  v.addon_n.writeS32(0); v.core_cfg.writeS32(opts.perfRows ? 1 : 0); v.core_label.writeUtf8String(opts.label.slice(0, 15));
  const cm = new CModule(OVERLAY_C, v); held.push(cm);
  const size = new NativeFunction(cm.st_size, 'int', [])();
  if (size > 512 * 1024) throw Error('overlay state too large: ' + size);
  V2.status.addons = {};
  const ctx = { ui: { box: cm.ui_box, text: cm.ui_text, text_w: cm.ui_text_w, metrics: cm.ui_metrics }, buildId: V2.status.buildId };
  for (const a of OVERLAY_ADDONS) {
    const n = v.addon_n.readS32();
    if (n >= 4) break;
    try {
      const r = a.install(ctx);
      [r.frame, r.draw, r.touch].forEach((f, i) => v.addon_tab.add((3 * n + i) * 8).writePointer(f));
      v.addon_n.writeS32(n + 1);
      V2.status.addons[a.name] = Object.assign({ state: 'active' }, r.status || {});
    } catch (e) { V2.status.addons[a.name] = { state: 'error', error: String(e), at: String(e.stack || '').split('\n').slice(0, 3).join(' | ') }; }
  }
  // settings: -1 = untouched (patches default on); patch rows hold the desired state
  const cfg = ovConfig();
  for (let i = 0; i < 32; i++) st.add(16 + i * 4).writeS32(-1);
  OV_IDS.forEach((id, i) => { if (cfg[id] !== undefined) st.add(16 + i * 4).writeS32(cfg[id] ? 1 : 0); });
  OV_PATCH.forEach((id, k) => {
    const s = states[id] || {};
    st.add(144 + k * 4).writeS32(s.available === false ? -1 : s.running ? 1 : 0);
    st.add(176 + k * 8).writePointer(s.running && V2.en[id] ? V2.en[id] : ptr(0));
  });
  // input first, then drawing (atomic GOT pointer swaps)
  const setSlot = (slot, value) => { const page = slot.and(ptr(Process.pageSize - 1).not()); Memory.protect(page, Process.pageSize, 'rw-'); slot.writePointer(value); Memory.protect(page, Process.pageSize, 'r--'); };
  setSlot(slots.get, cm.h_get); setSlot(slots.num, cm.h_num); setSlot(slots.mouse, cm.h_mouse); setSlot(slots.swap, cm.h_swap);
  let lastDirty = 0;
  setInterval(() => {
    const d8 = []; for (let i = 0; i < 13; i++) d8.push(st.add(368 + i * 4).readS32());
    V2.status.menuDebug = { numCalls: d8[0], fingers: d8[1], lastX: d8[2] / 1000, lastY: d8[3] / 1000, W: d8[4], H: d8[5], presses: d8[6], mouseCalls: d8[7], drawCalls: d8[8], faces: d8[9], emitters: d8[10], lights: d8[11], fps: d8[12], frames: st.add(8).readS32(), open: st.readS32() };
    v2Save();
    const d = st.add(4).readS32();
    if (d === lastDirty) return;
    lastDirty = d;
    const out = {};
    OV_IDS.forEach((id, i) => { const x = st.add(16 + i * 4).readS32(); if (x >= 0) out[id] = x; });
    try { const f = new File(OV_CFG, 'w'); f.write(JSON.stringify(out)); f.close(); } catch (e) {}
  }, 1000);
  return { stateBytes: size };
}

rpc.exports.init = async function (stage, p) {
  try {
    const m = await v2WaitEngine();
    const b = m.base;
    V2.mod = m;
    V2.status.buildId = v2BuildId(b, v2Elf(b));
    if (p.mode !== 'apply') throw Error('unknown mode');
    // Fingerprints first: nothing in this process has touched the fingerprinted functions yet.
    const fp = v2Fingerprints();
    V2.imp = v2Imports(b);
    const states = {};
    const gated = (name, flag, fn) => {
      if (!flag) { v2Set(name, { state: 'off' }); states[name] = { running: false }; return; }
      if (fp[name]) { v2Set(name, { state: 'skipped', reason: fp[name] }); states[name] = { available: false }; return; }
      if (name === 'abbox' && !ovWanted(name)) { v2Set(name, { state: 'off (menu)' }); states[name] = { running: false }; return; }
      try {
        fn(); v2Set(name, { state: 'active' }); states[name] = { running: true };
        if (!ovWanted(name) && V2.en[name]) { V2.en[name].writeS32(0); v2Set(name, { state: 'installed, off (menu)' }); }
      } catch (e) { v2Set(name, { state: 'error', error: String(e) }); states[name] = { available: false }; }
    };
    gated('snd', p.snd, () => soundCache(b));
    gated('slot', p.slot, () => slotNativeV14(b));
    gated('uneg', p.uneg, () => uniformNegV14(b));
    gated('abbox', p.abbox, () => abboxFastV15(b));
    gated('strm', p.strm, () => { const s = v2StreamSite(b); V2.streamSite = s.site; V2.streamStub = s.stub; streamCacheV15(b); });
    gated('getend', p.getend, () => getEndCacheV16(b));
    if (p.plt && ovWanted('plt')) {
      try {
        const t = Date.now(), r = v2PltSites(b);
        states.plt = { running: true };
        v2Set('plt', { state: 'running', sites: r.u[0], cached: r.cached, buildId: r.buildId, scanMs: Date.now() - t });
        v2PltApply(b, r.u, st => { v2Set('plt', st); console.log('TQ_PLT ' + JSON.stringify(st)); });
      } catch (e) { v2Set('plt', { state: 'error', error: String(e) }); states.plt = { available: false }; }
    } else { v2Set('plt', { state: p.plt ? 'off (menu)' : 'off' }); states.plt = { running: false }; }
    if (p.menu) {
      try { v2Set('menu', Object.assign({ state: 'active' }, overlayInstall(b, states))); }
      catch (e) { v2Set('menu', { state: 'error', error: String(e) }); }
    } else v2Set('menu', { state: 'off' });
    console.log('TQ_V2 ' + JSON.stringify(V2.status.patches));
  } catch (e) { console.log('TQ_ERROR ' + String(e)); }
};
