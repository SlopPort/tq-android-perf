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
  const cm=new CModule(SOUND_C,v);
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
 const stub=Memory.alloc(Process.pageSize,{near:t,maxDistance:0x7000000});held.push(stub);
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
  const cm=new CModule(SLOT_C,v);held.push(cm,v);
  // orig_calc must be valid before the entry switches.
  const t=V2.exp('_ZN4GAME11SlotManager22CalculateSlotPositionsEf');
  if(hex(t,4)!=='ff4301d1')throw Error('CalculateSlotPositions entry mismatch '+hex(t,4));
  const stub=Memory.alloc(Process.pageSize,{near:t,maxDistance:0x7000000});held.push(stub);
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
  const cm=new CModule(UNIFORM_C,v);held.push(cm,v);
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
 const stub=Memory.alloc(Process.pageSize,{near:t,maxDistance:0x7000000});held.push(stub);
 stub.writeU32(0x58000050);stub.add(4).writeU32(0xd61f0200);stub.add(8).writePointer(fn);   // ldr x16,#8; br x16
 if(!Memory.protect(stub,Process.pageSize,'r-x'))throw Error('RX protection failed');
 put(t,branch(t,stub,false));
}
function abboxFastV15(b){
 try{
  const t=V2.exp('_ZNK4GAME5ABBox15GetIntersectionERKNS_3RayE');
  if(hex(t,4)!=='ffc301d1')throw Error('ABBox entry mismatch '+hex(t,4));   // sub sp, sp, #0x70
  const stub=Memory.alloc(Process.pageSize,{near:t,maxDistance:0x7000000});held.push(stub);
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
  const cm=new CModule(STREAM_C,v);held.push(cm,v);
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
  const cm=new CModule(GETEND_C,v);held.push(cm,v);
  const stub=Memory.alloc(Process.pageSize,{near:t,maxDistance:0x7000000});held.push(stub);
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
    const gated = (name, flag, fn) => {
      if (!flag) { v2Set(name, { state: 'off' }); return; }
      if (fp[name]) { v2Set(name, { state: 'skipped', reason: fp[name] }); return; }
      try { fn(); v2Set(name, { state: 'active' }); } catch (e) { v2Set(name, { state: 'error', error: String(e) }); }
    };
    gated('snd', p.snd, () => soundCache(b));
    gated('slot', p.slot, () => slotNativeV14(b));
    gated('uneg', p.uneg, () => uniformNegV14(b));
    gated('abbox', p.abbox, () => abboxFastV15(b));
    gated('strm', p.strm, () => { const s = v2StreamSite(b); V2.streamSite = s.site; V2.streamStub = s.stub; streamCacheV15(b); });
    gated('getend', p.getend, () => getEndCacheV16(b));
    if (p.plt) {
      try {
        const t = Date.now(), r = v2PltSites(b);
        v2Set('plt', { state: 'running', sites: r.u[0], cached: r.cached, buildId: r.buildId, scanMs: Date.now() - t });
        v2PltApply(b, r.u, st => { v2Set('plt', st); console.log('TQ_PLT ' + JSON.stringify(st)); });
      } catch (e) { v2Set('plt', { state: 'error', error: String(e) }); }
    } else v2Set('plt', { state: 'off' });
    console.log('TQ_V2 ' + JSON.stringify(V2.status.patches));
  } catch (e) { console.log('TQ_ERROR ' + String(e)); }
};
