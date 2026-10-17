// Titan Quest (com.hg.titanquestultimate 3.0.5339) benchmark + dev-console server agent.
// Injected ONCE per game process (frida-inject -e). The host (tqbench.py) prepends
// `const PARAMS = {port};` and then talks to it over TCP 127.0.0.1:<port> via `adb forward`.
// Protocol: one JSON request per line -> zero or more {"progress":...} lines, then {"result":...}.
//
// All engine calls happen on the game thread (hook Game::UpdateCamera), one job at a time.
// Engine facilities used:
//   - WidgetConsole (Game+0x60): developer console, HandleCommand runs any registered command.
//   - DebugControllerPlayerScriptLoopPath: built-in scripted player walk loop.
//   - Game::SetGodMode / TeleportPlayer / Spawn, Engine::SetRenderOnlyPlayer,
//     AmbianceManager (Engine+0x48) time of day.
// Crash diagnostics: the game installs BackTraceUtil::NativeCrashSignalHandler which ends the
// process with _exit (no tombstone). We hook it, FatalError, exit, _exit and abort and write
// cache/tq-bench-crash.json with PC/LR/frame-pointer chain plus the last action breadcrumb.
//
// Layouts verified against libtq.so SHA256 2bb70a14...:
//   WorldVec3        {Region* +0x0, float x,y,z +0x8} size 0x18
//   Region           IntVec3 offsetFromWorld +0x64
//   Game             WidgetConsole* +0x60, Player* +0xb0
//   WidgetConsole    std::vector<pair<std::string, ConsoleMethod*>> commands +0xf0/+0xf8
//   ControllerPlayer active script +0x540, LoopPath instance +0x548
//   LoopPath         index u32 +0x10, std::vector<WorldVec3> +0x18/+0x20/+0x28, running u8 +0x30

'use strict';
const P = (typeof PARAMS === 'object') ? PARAMS : { port: 27099 };
const CACHE = '/data/user/0/com.hg.titanquestultimate/cache/';
const CRASH_FILE = CACHE + 'tq-bench-crash.json';
const BREADCRUMB_FILE = CACHE + 'tq-bench-breadcrumb.json';

const tq = Process.getModuleByName('libtq.so');
const sym = name => tq.getExportByName(name);
const clean = p => p.and(ptr('0x00ffffffffffffff'));   // strip Android heap pointer tag for Frida reads
const STR = 'ERKNSt6__ndk112basic_stringIcNS1_11char_traitsIcEENS1_9allocatorIcEEEE';

const fn = {
  setGod:        new NativeFunction(sym('_ZN4GAME4Game10SetGodModeEb'), 'void', ['pointer', 'bool']),
  isGod:         new NativeFunction(sym('_ZNK4GAME4Game16IsGodModeEnabledEv'), 'bool', ['pointer']),
  teleport:      new NativeFunction(sym('_ZN4GAME4Game14TeleportPlayerERKNS_9WorldVec3E'), 'void', ['pointer', 'pointer']),
  gameAddPoint:  new NativeFunction(sym('_ZN4GAME4Game45AddPointToDebugControllerPlayerScriptLoopPathEv'), 'void', ['pointer']),
  startScript:   new NativeFunction(sym('_ZN4GAME4Game38StartActiveDebugControllerPlayerScriptEv'), 'void', ['pointer']),
  stopScript:    new NativeFunction(sym('_ZN4GAME4Game37StopActiveDebugControllerPlayerScriptEv'), 'void', ['pointer']),
  setActive:     new NativeFunction(sym('_ZN4GAME16ControllerPlayer20SetActiveDebugScriptENS_32EDebugControllerPlayerScriptTypeE'), 'void', ['pointer', 'int']),
  loopAddPoint:  new NativeFunction(sym('_ZN4GAME35DebugControllerPlayerScriptLoopPath8AddPointERKNS_9WorldVec3E'), 'void', ['pointer', 'pointer']),
  renderOnlyPlayer: new NativeFunction(sym('_ZN4GAME6Engine19SetRenderOnlyPlayerEb'), 'void', ['pointer', 'bool']),
  regionWorld:   new NativeFunction(sym('_ZN4GAME6Region8GetWorldEv'), 'pointer', ['pointer']),
  regionAt:      new NativeFunction(sym('_ZNK4GAME5World24GetRegionContainingPointERKNS_7IntVec3E'), 'pointer', ['pointer', 'pointer']),
  spawn:         new NativeFunction(sym('_ZN4GAME4Game5SpawnEPKc'), 'void', ['pointer', 'pointer']),
  // SetEnabled is a no-op in this build and HandleCommand has no enable check.
  consoleCommand: new NativeFunction(sym('_ZN4GAME13WidgetConsole13HandleCommand' + STR), 'void', ['pointer', 'pointer']),
  consoleShow:   new NativeFunction(sym('_ZN4GAME13WidgetConsole4ShowEv'), 'void', ['pointer']),
  setTime:       new NativeFunction(sym('_ZN4GAME15AmbianceManager7SetTimeEf'), 'void', ['pointer', 'float']),
  getTime:       new NativeFunction(sym('_ZNK4GAME15AmbianceManager7GetTimeEv'), 'float', ['pointer']),
  setTimeEnabled: new NativeFunction(sym('_ZN4GAME15AmbianceManager14SetTimeEnabledEb'), 'void', ['pointer', 'bool']),
  envEffects:    new NativeFunction(sym('_ZN4GAME15AmbianceManager24EnableEnvironmentEffectsEb'), 'void', ['pointer', 'bool']),
  // Engine-side render statistics (same numbers as the gr.Stats overlay).
  graphicsEngine: new NativeFunction(sym('_ZNK4GAME6Engine17GetGraphicsEngineEv'), 'pointer', ['pointer']),
  getStats:      new NativeFunction(sym('_ZN4GAME14GraphicsEngine8GetStatsERNS_13GraphicsStatsE'), 'void', ['pointer', 'pointer']),
  objectManager: new NativeFunction(sym('_ZN4GAME9SingletonINS_13ObjectManagerEE3GetEv'), 'pointer', []),
  numObjects:    new NativeFunction(sym('_ZNK4GAME13ObjectManager13GetNumObjectsEv'), 'uint', ['pointer']),
  regionByIndex: new NativeFunction(sym('_ZN4GAME5World9GetRegionEi'), 'pointer', ['pointer', 'int']),
  regionIndex:   new NativeFunction(sym('_ZNK4GAME5World14GetRegionIndexEPNS_6RegionE'), 'int', ['pointer', 'pointer']),
  // FPS_LIMIT: 0 = none (8.33 ms Swappy interval, i.e. display refresh), 1 = refresh/2, 2 = /3, 3 = /4.
  setFpsLimited: new NativeFunction(sym('_ZN4GAME11MobileUtils13SetFPSLimitedENS_9FPS_LIMITE'), 'void', ['int']),
};
// OpenGLESDevice::SetFPSLimit caches the active limit in this byte (libtq.so+0x11bde2c).
const fpsLimitVar = tq.base.add(0x11bde2c);
function setFpsLimit(v) { fn.setFpsLimited(v); return fpsLimitVar.readU8(); }

// Full uncap for measurement: Swappy paces every frame to a vsync multiple, so a 25 ms frame
// still shows as 33 ms. Replacing SwappyGL_swap with eglSwapInterval(0) + eglSwapBuffers removes
// the pacing and exposes the real frame time. uncap(false) hands pacing back to Swappy.
const eglMod = Process.getModuleByName('libEGL.so');
const eglSwapBuffersFn = new NativeFunction(eglMod.getExportByName('eglSwapBuffers'), 'uint', ['pointer', 'pointer']);
const eglSwapIntervalFn = new NativeFunction(eglMod.getExportByName('eglSwapInterval'), 'uint', ['pointer', 'int']);
// libswappy.so is mapped straight from split_config.arm64_v8a.apk, so look it up by module name.
const swappyMod = Process.findModuleByName('libswappy.so');
const swappySwap = swappyMod ? swappyMod.findExportByName('SwappyGL_swap') : null;
let uncapped = false, uncapIntervalSet = false;
// Installed once at agent start (JS thread); toggled by a flag only. Changing Interceptor state from a
// game-thread hook or reverting live replacements can deadlock Frida.
const origSwappySwap = swappySwap ? new NativeFunction(swappySwap, 'uint', ['pointer', 'pointer']) : null;
const uncappedSwap = new NativeCallback((dpy, surf) => {
  if (!uncapped) {
    if (uncapIntervalSet) { eglSwapIntervalFn(dpy, 1); uncapIntervalSet = false; }   // hand pacing back to Swappy
    return origSwappySwap(dpy, surf);
  }
  if (!uncapIntervalSet) { eglSwapIntervalFn(dpy, 0); uncapIntervalSet = true; }
  return eglSwapBuffersFn(dpy, surf);
}, 'uint', ['pointer', 'pointer']);
let uncapReady = false;
try { if (swappySwap) { Interceptor.replace(swappySwap, uncappedSwap); uncapReady = true; } }
catch (e) { /* already replaced by an earlier agent in this process (hot swap): uncap unavailable */ }
function uncap(on) {
  if (!uncapReady) throw Error('uncap unavailable (SwappyGL_swap missing or replaced by an earlier agent; restart the game)');
  uncapped = !!on;
  return uncapped;
}
const libc = Process.getModuleByName('libc.so');
const clock_gettime = new NativeFunction(libc.getExportByName('clock_gettime'), 'int', ['int', 'pointer']);
const rename = new NativeFunction(libc.getExportByName('rename'), 'int', ['pointer', 'pointer']);
const gettid = new NativeFunction(libc.getExportByName('gettid'), 'int', []);
const gGameVar = sym('_ZN4GAME5gGameE');
const gEngineVar = sym('_ZN4GAME7gEngineE');

const tsBuf = Memory.alloc(16);
function nowMs() {
  clock_gettime(1 /* CLOCK_MONOTONIC */, tsBuf);
  return tsBuf.readS64().toNumber() * 1e3 + tsBuf.add(8).readS64().toNumber() / 1e6;
}
function writeJson(path, value) {
  const tmp = path + '.tmp';
  const f = new File(tmp, 'w');
  try { f.write(JSON.stringify(value)); f.flush(); } finally { f.close(); }
  if (rename(Memory.allocUtf8String(tmp), Memory.allocUtf8String(path)) !== 0) throw Error('rename failed: ' + path);
}
const t0 = nowMs();
const rel = t => +((t - t0) / 1000).toFixed(3);

// ---------------------------------------------------------------- engine state
let ctrl = null;           // ControllerPlayer* (raw, tagged) of the live player, see liveController()
const ctrlSeen = new Map(); // clean address -> { raw, lastTick }; menus/loads leave stale controllers behind
function game() { return gGameVar.readPointer(); }
function player() { const g = game(); return clean(g).isNull() ? ptr(0) : clean(g).add(0xb0).readPointer(); }
function console_() { return clean(game()).add(0x60).readPointer(); }
function ambiance() { return clean(gEngineVar.readPointer()).add(0x48).readPointer(); }
function loopPath() { return ctrl ? clean(ctrl).add(0x548).readPointer() : ptr(0); }
function loopVec(loop) {
  const l = clean(loop);
  const begin = l.add(0x18).readPointer(), end = l.add(0x20).readPointer();
  return { begin, end, count: (clean(end).sub(clean(begin))).toInt32() / 0x18 };
}
function loopIndex(loop) { return clean(loop).add(0x10).readU32(); }
function loopRunning(loop) { return clean(loop).add(0x30).readU8() !== 0; }
function loopClear(loop) {
  const l = clean(loop);
  l.add(0x30).writeU8(0);
  l.add(0x20).writePointer(l.add(0x18).readPointer());
  l.add(0x10).writeU32(0);
}
function readWorldVec3(p) {
  const c = clean(p);
  const region = c.readPointer();
  const off = clean(region).add(0x64);
  return {
    region,
    world: [c.add(8).readFloat() + off.readS32(), c.add(12).readFloat() + off.add(4).readS32(), c.add(16).readFloat() + off.add(8).readS32()],
  };
}
// Current player position via the engine's own AddPoint (no struct-return ABI guessing):
// push the position into the loop path, read it, then pop it again.
function playerPosition(loop) {
  if (loopRunning(loop)) throw Error('debug loop is running');
  fn.gameAddPoint(game());
  const v = loopVec(loop);
  if (v.count < 1) throw Error('AddPoint did not add a point');
  const last = v.end.sub(0x18);
  const pos = readWorldVec3(last);
  clean(loop).add(0x20).writePointer(last);
  return pos;
}
const wv = Memory.alloc(0x18), iv = Memory.alloc(12);
function makeWorldVec3(world, w, regionIndex) {
  iv.writeS32(Math.floor(w[0])); iv.add(4).writeS32(Math.floor(w[1])); iv.add(8).writeS32(Math.floor(w[2]));
  const region = (regionIndex !== undefined && regionIndex !== null) ? fn.regionByIndex(world, regionIndex) : fn.regionAt(world, iv);
  if (clean(region).isNull()) throw Error('No region contains point ' + JSON.stringify(w));
  const off = clean(region).add(0x64);
  wv.writePointer(region);
  wv.add(8).writeFloat(w[0] - off.readS32());
  wv.add(12).writeFloat(w[1] - off.add(4).readS32());
  wv.add(16).writeFloat(w[2] - off.add(8).readS32());
  return wv;
}
// GraphicsStats (0x24): usedMB f32, vramFreeMB f32, avgFps f32, faces u32, facesPerSec f32,
// drawCalls u32, reflections u32, lights u32, shadowCasting u32. Emitters/trails live at
// GraphicsEngine+0x168/+0x16c/+0x170/+0x174 (see ghidra-evidence/graphics-stats-decompile.txt).
const gstats = Memory.alloc(0x40);
function engineStats() {
  const ge = fn.graphicsEngine(gEngineVar.readPointer());
  fn.getStats(ge, gstats);
  const g = clean(ge);
  return {
    usedMB: +gstats.readFloat().toFixed(1), vramFreeMB: +gstats.add(4).readFloat().toFixed(1),
    engineFps: +gstats.add(8).readFloat().toFixed(2), faces: gstats.add(12).readU32(),
    drawCalls: gstats.add(20).readU32(), reflections: gstats.add(24).readU32(),
    lights: gstats.add(28).readU32(), shadowCasting: gstats.add(32).readU32(),
    emitters: g.add(0x168).readU32(), emittersMax: g.add(0x16c).readU32(),
    trails: g.add(0x170).readU32(), trailsMax: g.add(0x174).readU32(),
    objects: fn.numObjects(fn.objectManager()),
  };
}
function currentWorld(loop) { return fn.regionWorld(playerPosition(loop).region); }

// Order the player to walk to a world point (same call LoopPath::Update makes). A MoveTo whose
// target is the player's current spot never finishes on this build, which stalls the loop, so a
// run kicks the loop with an explicit move to route point 1.
const aiDataCtor = new NativeFunction(sym('_ZN4GAME21ControllerAIStateDataC1EjjjRKNS_9WorldVec3ES3_'), 'void', ['pointer', 'uint', 'uint', 'uint', 'pointer', 'pointer']);
const forceState = new NativeFunction(sym('_ZN4GAME16ControllerPlayer10ForceState' + STR + 'RKNS_21ControllerAIStateDataE'), 'void', ['pointer', 'pointer', 'pointer']);
const zeroVec = Memory.alloc(0x18), aiData = Memory.alloc(0x100), moveToName = stdStringShort('MoveTo');
function forceMoveToPtr(worldVec3) {
  aiDataCtor(aiData, 0, 0, 0, worldVec3, zeroVec);   // trivial destructor, buffer reused
  forceState(ctrl, moveToName.s, aiData);
}
function forceMoveTo(world, w) { forceMoveToPtr(makeWorldVec3(world, w)); }
// Hand control back to the player after a scripted walk (MoveTo would otherwise stay active).
const idleName = stdStringShort('Idle');
function forceIdle(loop) {
  // Use the player's own current WorldVec3 (pushed by AddPoint) rather than an empty one.
  fn.gameAddPoint(game());
  const v = loopVec(loop);
  if (v.count < 1) return;
  const here = v.end.sub(0x18);
  aiDataCtor(aiData, 0, 0, 0, here, here);
  forceState(ctrl, idleName.s, aiData);
  clean(loop).add(0x20).writePointer(here);
}

// Strings handed to the engine by const&. libc++ keeps strings of <= 22 chars in short mode, and
// lookups such as ControllerAI::GetState only match that canonical form, so use it when possible.
function stdString(text) {
  if (text.length <= 22) return stdStringShort(text);
  return stdStringLong(text);
}
// libc++ long mode: {cap|1, size, data}.
function stdStringLong(text) {
  const bytes = Memory.allocUtf8String(text), len = text.length;
  const s = Memory.alloc(24);
  s.writeU64(((len + 16) & ~15) | 1); s.add(8).writeU64(len); s.add(16).writePointer(bytes);
  return { s, keep: bytes };
}
// libc++ short mode (len <= 22): {len<<1, chars..., 0}.
function stdStringShort(text) {
  if (text.length > 22) return stdStringLong(text);
  const s = Memory.alloc(24);
  s.writeU8(text.length << 1);
  s.add(1).writeUtf8String(text);
  return { s };
}
function readStdString(p) {
  const c = clean(p), long = (c.readU8() & 1) !== 0;
  const n = long ? c.add(8).readU64().toNumber() : c.readU8() >>> 1;
  if (n > 4096) return '<too long>';
  return (long ? clean(c.add(16).readPointer()) : c.add(1)).readUtf8String(n);
}
let cmdNames = null;
function commandNames() {
  if (cmdNames) return cmdNames;
  const c = clean(console_());
  const b = clean(c.add(0xf0).readPointer()), n = clean(c.add(0xf8).readPointer()).sub(b).toInt32() / 32;
  cmdNames = [];
  for (let i = 0; i < n; i++) cmdNames.push(readStdString(b.add(i * 32)));
  return cmdNames;
}
// Commands are registered with a category prefix (g.God, gr.Stats); accept the bare name too.
function resolveCommand(text) {
  const names = commandNames();
  let [head, ...rest] = text.trim().split(/\s+/);
  if (!names.includes(head)) {
    const m = names.filter(n => n.toLowerCase() === head.toLowerCase() || n.toLowerCase().endsWith('.' + head.toLowerCase()));
    if (m.length !== 1) throw Error(m.length ? 'ambiguous command: ' + m.join(', ') : 'unknown command: ' + head);
    head = m[0];
  }
  return [head, ...rest].join(' ');
}

// ---------------------------------------------------------------- breadcrumbs + crash capture
let breadcrumb = { t: 0, action: 'server start' };
function crumb(action) {
  breadcrumb = { t: rel(nowMs()), action, tick: ticks };
  try { writeJson(BREADCRUMB_FILE, breadcrumb); } catch (e) { }
}
// Lock-free address info for crash paths: module ranges are snapshotted once at agent start.
// (Process.findModuleByAddress / DebugSymbol take Frida locks and can deadlock on a crashing thread.)
const MODULE_RANGES = Process.enumerateModules().map(m => ({ name: m.name, base: m.base, end: m.base.add(m.size) }));
// Monotonic ms with sub-ms resolution (clock_gettime(CLOCK_MONOTONIC)).
const _hrBuf = Memory.alloc(16);
const _clockGettime = new NativeFunction(Process.getModuleByName('libc.so').getExportByName('clock_gettime'), 'int', ['int', 'pointer']);
function hrNow() { _clockGettime(1, _hrBuf); return _hrBuf.readS64().toNumber() * 1000 + _hrBuf.add(8).readS64().toNumber() / 1e6; }
function addrInfo(a) {
  try {
    const c = clean(a);
    for (const m of MODULE_RANGES)
      if (c.compare(m.base) >= 0 && c.compare(m.end) < 0) return { addr: a.toString(), module: m.name, offset: '0x' + c.sub(m.base).toString(16) };
    return { addr: a.toString(), module: null };
  } catch (e) { return { addr: a.toString() }; }
}
function fpChain(fp, max) {
  const out = [];
  for (let i = 0; i < max && !fp.isNull(); i++) {
    try { const lr = fp.add(8).readPointer(); out.push(addrInfo(lr)); fp = fp.readPointer(); } catch (e) { break; }
  }
  return out;
}
let crashWritten = false;
function writeCrash(kind, extra, context) {
  if (crashWritten) return;
  crashWritten = true;
  const rec = { kind, time: rel(nowMs()), pid: Process.id, tid: gettid(), breadcrumb, currentJob: job ? job.req : null, ...extra };
  try { if (context) { rec.pc = addrInfo(context.pc); rec.lr = addrInfo(context.lr); rec.fpChain = fpChain(context.fp, 16); } } catch (e) { rec.contextError = String(e); }   // no Thread.backtrace: takes Frida locks
  try { writeJson(CRASH_FILE, rec); } catch (e) { }
}
Interceptor.attach(sym('_ZN4GAME13BackTraceUtil24NativeCrashSignalHandlerEiP7siginfoPv'), {
  onEnter(args) {
    // ucontext_t (arm64): uc_mcontext at +0xb0 -> fault_address, regs[31], sp, pc, pstate.
    const uc = args[2], mc = uc.add(0xb0);
    const extra = { signal: args[0].toInt32(), siCode: args[1].add(8).readS32(), siAddr: String(args[1].add(16).readPointer()), ucontext: String(uc), faultAddress: mc.readPointer().toString() };
    try {
      const reg = i => mc.add(8 + i * 8).readPointer();
      extra.pc = addrInfo(mc.add(8 + 31 * 8 + 8).readPointer());
      extra.lr = addrInfo(reg(30));
      extra.sp = mc.add(8 + 31 * 8).readPointer().toString();
      extra.x0 = reg(0).toString(); extra.x1 = reg(1).toString(); extra.x8 = reg(8).toString();
      extra.fpChain = fpChain(reg(29), 24);
    } catch (e) { extra.contextError = String(e); }
    writeCrash('signal', extra, null);
  }
});
Interceptor.attach(sym('_ZN4GAME10FatalErrorEPKw'), {
  onEnter(args) {
    let msg = '';
    try { for (let i = 0; i < 512; i++) { const c = args[0].add(i * 4).readU32(); if (!c) break; msg += String.fromCodePoint(c); } } catch (e) { }
    writeCrash('FatalError', { message: msg }, this.context);
  }
});
// No Process.setExceptionHandler: a JS handler on a crashing game/FMOD thread deadlocks on Frida's
// symbol/backtrace locks and turns a crash into a silent hang. Crashes go to the game's handler and
// debuggerd (tombstone) instead.
for (const name of ['exit', '_exit', 'abort']) {
  Interceptor.attach(libc.getExportByName(name), {
    onEnter(args) { writeCrash(name, { code: name === 'abort' ? null : args[0].toInt32() }, this.context); }
  });
}

// ---------------------------------------------------------------- frame timing
const MAX_FRAMES = 200000;
const swapAt = new Float64Array(MAX_FRAMES), swapDur = new Float32Array(MAX_FRAMES);
let frames = 0, measuring = false, swapEnter = 0, measureStart = 0, totalSwaps = 0;
const swapThreads = new Set();
Interceptor.attach(Process.getModuleByName('libEGL.so').getExportByName('eglSwapBuffers'), {
  onEnter() { swapEnter = nowMs(); if (swapThreads.size < 4) swapThreads.add(this.threadId); },
  onLeave() {
    totalSwaps++;
    if (!measuring || frames >= MAX_FRAMES) return;
    swapAt[frames] = swapEnter - measureStart;
    swapDur[frames] = nowMs() - swapEnter;
    frames++;
  }
});

// ---------------------------------------------------------------- jobs
// A job: { req, reply(obj), begin(), tick(t) -> true when finished, result }
const queue = [];
let job = null, ticks = 0, tickThread = null;
let stopRequested = false;

function finishJob(result, error) {
  const j = job;
  job = null;
  measuring = false;
  if (!j) return;
  const msg = { id: j.req.id, result: result || null, error: error ? String(error.stack || error) : null };
  // Kept so the host can fetch it again if the adb-forwarded connection dropped meanwhile.
  finished.set(j.req.id, msg);
  if (finished.size > 8) finished.delete(finished.keys().next().value);
  j.reply(msg);
}
const finished = new Map();

function needLoop() {
  // Only controllers updated during the last ~60 ticks count; single-player has exactly one.
  const live = Array.from(ctrlSeen.values()).filter(c => ticks - c.lastTick <= 60);
  if (live.length > 1) throw Error('More than one live ControllerPlayer; refusing to guess which is local');
  ctrl = live.length ? live[0].raw : null;
  if (clean(game()).isNull() || clean(player()).isNull() || ctrl === null) throw Error('No player/controller - is a character loaded in the world?');
  const loop = loopPath();
  if (clean(loop).isNull()) throw Error('ControllerPlayer has no LoopPath debug script');
  return loop;
}

// --- steps (console / arena). One step per tick so engine work spreads over frames.
function stepsJob(req) {
  const steps = req.steps || [];
  let i = 0, waitUntil = 0;
  const out = [];
  return {
    tick(t) {
      if (ticks < waitUntil) return false;
      if (i >= steps.length) { finishJob({ steps: out }); return true; }
      const st = steps[i++];
      const r = { step: st };
      crumb('step ' + JSON.stringify(st));
      try {
        if (st.cmd !== undefined) {
          r.resolved = resolveCommand(st.cmd);
          const str = stdString(r.resolved);
          fn.consoleCommand(console_(), str.s);
        } else if (st.op === 'pos') {
          r.world = playerPosition(needLoop()).world.map(x => +x.toFixed(2));
        } else if (st.op === 'teleport') {
          fn.teleport(game(), makeWorldVec3(currentWorld(needLoop()), st.world));
          waitUntil = ticks + 30;
        } else if (st.op === 'time') {
          if (st.hour !== undefined) fn.setTime(ambiance(), st.hour);
          if (st.frozen !== undefined) fn.setTimeEnabled(ambiance(), st.frozen ? 0 : 1);
          r.time = fn.getTime(ambiance());
        } else if (st.op === 'envfx') {
          fn.envEffects(ambiance(), st.on ? 1 : 0);
        } else if (st.op === 'show') {
          fn.consoleShow(console_());
        } else if (st.op === 'god') {
          fn.setGod(game(), st.on ? 1 : 0);
          r.god = !!fn.isGod(game());
        } else if (st.op === 'renderOnlyPlayer') {
          fn.renderOnlyPlayer(gEngineVar.readPointer(), st.on ? 1 : 0);
        } else if (st.op === 'spawn') {
          const rec = Memory.allocUtf8String(st.record);
          for (let k = 0; k < (st.count || 1); k++) fn.spawn(game(), rec);
        } else if (st.op === 'state') {
          r.time = fn.getTime(ambiance());
          r.god = !!fn.isGod(game());
        } else if (st.op === 'fps') {
          r.before = fpsLimitVar.readU8();
          r.fpsLimit = st.limit === undefined ? r.before : setFpsLimit(st.limit);
        } else if (st.op === 'loop') {
          // Debug helper: build (st.route) and/or start/stop the built-in loop, then report its state.
          const loop = needLoop();
          if (st.route) {
            if (loopRunning(loop)) fn.stopScript(game());
            loopClear(loop);
            const world = debugWorld = currentWorld(loop);
            for (const w of st.route) fn.loopAddPoint(loop, makeWorldVec3(world, w));
            if (!clean(clean(ctrl).add(0x540).readPointer()).equals(clean(loop))) fn.setActive(ctrl, 0);
          }
          if (st.start) {
            fn.startScript(game());
            if (st.route && st.route.length > 1) { clean(loop).add(0x10).writeU32(2 % st.route.length); forceMoveTo(debugWorld, st.route[1]); }
          }
          if (st.stop) { fn.stopScript(game()); loopClear(loop); }
          r.loop = { ctrl: ctrl.toString(), loop: loop.toString(), owner: clean(loop).add(8).readPointer().toString(), points: loopVec(loop).count, index: loopIndex(loop), running: loopRunning(loop),
                     activeIsLoop: clean(clean(ctrl).add(0x540).readPointer()).equals(clean(loop)) };
        } else if (st.op === 'ai') {
          // Debug helper: player controller AI state (LoopPath only advances when the executing
          // state differs from the "MoveTo" state).
          needLoop();
          const exec = new NativeFunction(sym('_ZNK4GAME12ControllerAI17GetExecutingStateEv'), 'pointer', ['pointer'])(ctrl);
          // Only pointer-returning calls here: GetExecutingStateName's return ABI is unverified and
          // guessing it crashed the game once (2026-10-17).
          const moveTo = new NativeFunction(sym('_ZN4GAME12ControllerAI8GetState' + STR), 'pointer', ['pointer', 'pointer'])(ctrl, stdString(st.state || 'MoveTo').s);
          const moveToShort = new NativeFunction(sym('_ZN4GAME12ControllerAI8GetState' + STR), 'pointer', ['pointer', 'pointer'])(ctrl, stdStringShort(st.state || 'MoveTo').s);
          r.ai = { executing: exec.toString(), lookup: moveTo.toString(), lookupShort: moveToShort.toString(), same: clean(exec).equals(clean(moveToShort)) };
        } else if (st.op === 'count') {
          // Debug/profiling helper: count calls of an exported libtq function. {name, on:true|false}
          if (st.on) {
            if (counters[st.name]) counters[st.name].listener.detach();
            const c = { calls: 0, firstArg0: null, threads: {} };
            c.listener = Interceptor.attach(sym(st.name), {
              onEnter(args) { c.calls++; if (c.firstArg0 === null) c.firstArg0 = args[0].toString(); c.threads[this.threadId] = 1; }
            });
            counters[st.name] = c;
          } else {
            const c = counters[st.name];
            if (!c) throw Error('no counter for ' + st.name);
            r.count = { calls: c.calls, firstArg0: c.firstArg0, threads: Object.keys(c.threads) };
            if (st.on === false) { c.listener.detach(); delete counters[st.name]; }
          }
        } else if (st.op === 'region') {
          // Debug helper: player's region vs. the region World::GetRegionContainingPoint picks for st.world.
          const loop = needLoop();
          const here = playerPosition(loop), world = fn.regionWorld(here.region);
          const idx = new NativeFunction(sym('_ZNK4GAME5World14GetRegionIndexEPNS_6RegionE'), 'int', ['pointer', 'pointer']);
          const w = st.world || here.world;
          iv.writeS32(Math.floor(w[0])); iv.add(4).writeS32(Math.floor(w[1])); iv.add(8).writeS32(Math.floor(w[2]));
          const picked = fn.regionAt(world, iv);
          r.region = { player: here.region.toString(), playerIndex: idx(world, here.region), playerWorld: here.world.map(x => +x.toFixed(2)),
                       picked: picked.toString(), pickedIndex: clean(picked).isNull() ? null : idx(world, picked) };
        } else if (st.op === 'pathpos') {
          // ABI check: GetPathPosition (struct return) vs. the AddPoint-based player position.
          const loop = needLoop();
          const viaAddPoint = playerPosition(loop);
          const p = getPathPosition(player());
          r.pathpos = { addPoint: { region: clean(viaAddPoint.region).toString(), world: viaAddPoint.world.map(x => +x.toFixed(3)) },
                        getPathPosition: { region: clean(p[0]).toString(), local: [p[1], p[2], p[3]].map(x => +x.toFixed(3)) } };
        } else if (st.op === 'opt') {
          throw Error("use the immediate 'opt' request (Interceptor changes must not run on the game thread)");
        } else if (st.op === 'slotprobe') {
          // Diagnostic for SlotManager::CalculateSlotPositions(float radius): how often it is called,
          // how often it actually recomputes (cache miss -> one floor raycast per slot) and with which
          // radii. Cache key in the engine: radius at +0x50 and the owner's position at +0x38.
          if (st.on) {
            const sp = { calls: 0, recomputes: 0, slotCalcs: 0, radii: {}, managers: {} };
            const calc = Interceptor.attach(sym('_ZN4GAME11SlotManager22CalculateSlotPositionsEf'), {
              onEnter(args) { this.m = clean(args[0]); this.r0 = this.m.add(0x50).readFloat(); this.n0 = sp.slotCalcs; },
              onLeave() {
                sp.calls++;
                if (sp.slotCalcs !== this.n0) sp.recomputes++;
                const r = this.m.add(0x50).readFloat().toFixed(2);
                sp.radii[r] = (sp.radii[r] || 0) + 1;
                sp.managers[this.m.toString()] = 1;
              }
            });
            const one = Interceptor.attach(sym('_ZN4GAME11SlotManager21CalculateSlotPositionEjf'), { onEnter() { sp.slotCalcs++; } });
            counters.slotprobe = { sp, listeners: [calc, one], t0: nowMs() };
          } else {
            const c = counters.slotprobe;
            if (!c) throw Error('slotprobe not running');
            const secs = (nowMs() - c.t0) / 1000;
            r.slotprobe = { seconds: +secs.toFixed(1), calls: c.sp.calls, recomputes: c.sp.recomputes, slotCalcs: c.sp.slotCalcs,
                            perSecond: { calls: +(c.sp.calls / secs).toFixed(1), recomputes: +(c.sp.recomputes / secs).toFixed(1), raycasts: +(c.sp.slotCalcs / secs).toFixed(1) },
                            radii: c.sp.radii, managers: Object.keys(c.sp.managers).length };
            if (st.on === false) { for (const l of c.listeners) l.detach(); delete counters.slotprobe; }
          }
        } else if (st.op === 'resprobe') {
          // Resource::EnsureAvailable reload branch (0x9b66f4): a loaded resource whose +0x28 state is 1..3
          // is unloaded and loaded again when > 60 frames passed since the last such reload. Counts hits per file.
          if (st.on) {
            const rp = { hits: 0, files: {} };
            const fileName = res => { const f = res.add(0x30); return (f.readU8() & 1) ? f.add(0x10).readPointer().readUtf8String() : f.add(1).readUtf8String(); };
            const l = Interceptor.attach(tq.base.add(0x9b66f4), function () {
              const res = clean(this.context.x19);
              rp.hits++;
              let k;
              try { k = fileName(res) + ' [state ' + res.add(0x28).readS32() + ', type ' + res.add(0x50).readS32() + ']'; } catch (e) { k = '?'; }
              rp.files[k] = (rp.files[k] || 0) + 1;
            });
            counters.resprobe = { rp, listeners: [l], t0: nowMs() };
          } else {
            const c = counters.resprobe;
            if (!c) throw Error('resprobe not running');
            const secs = (nowMs() - c.t0) / 1000;
            const top = Object.entries(c.rp.files).sort((a, b) => b[1] - a[1]).slice(0, 25);
            r.resprobe = { seconds: +secs.toFixed(1), reloads: c.rp.hits, perSecond: +(c.rp.hits / secs).toFixed(2), distinct: Object.keys(c.rp.files).length, top };
            if (st.on === false) { for (const l of c.listeners) l.detach(); delete counters.resprobe; }
          }
        } else if (st.op === 'streamprobe') {
          // SoundManager::StartStream3D: FMOD_System_CreateStream(system, file, mode, NULL, &sound) is called
          // through 0x949f54 from 0x947d14 (game thread only). Per file: count and time spent in the call.
          if (st.on) {
            const sp = { calls: 0, ms: 0, files: {} };
            // libtq's PLT stub for FMOD_System_CreateStream (only libtq code calls it; game thread).
            const a = Interceptor.attach(tq.base.add(0x7a8f00), {
              onEnter(args) { let f = '?'; try { f = args[1].readUtf8String(); } catch (e) {} this.k = f + ' [mode 0x' + (args[2].toInt32() >>> 0).toString(16) + ']'; this.t0 = Date.now(); this.h = hrNow(); },
              onLeave() {
                const dt = hrNow() - this.h;
                const e = sp.files[this.k] || (sp.files[this.k] = { n: 0, ms: 0, max: 0 });
                e.n++; e.ms += dt; e.max = Math.max(e.max, dt); sp.calls++; sp.ms += dt;
              }
            });
            const b = a;
            counters.streamprobe = { sp, listeners: [a], t0: nowMs() };
          } else {
            const c = counters.streamprobe;
            if (!c) throw Error('streamprobe not running');
            const secs = (nowMs() - c.t0) / 1000;
            const top = Object.entries(c.sp.files).sort((x, y) => y[1].ms - x[1].ms).slice(0, 40)
              .map(([k, v]) => [k, v.n, +v.ms.toFixed(1), +(v.ms / v.n).toFixed(2), +v.max.toFixed(1)]);
            r.streamprobe = { seconds: +secs.toFixed(1), calls: c.sp.calls, totalMs: +c.sp.ms.toFixed(1), distinct: Object.keys(c.sp.files).length,
                              columns: ['file', 'calls', 'ms', 'msAvg', 'msMax'], top };
            if (st.on === false) { for (const l of c.listeners) l.detach(); delete counters.streamprobe; }
          }
        } else if (st.op === 'countprobe') {
          // Generic hit counter: st.targets = ['tq:0xRVA' | 'module!export', ...]; st.on=false/null reads (false detaches).
          if (st.on) {
            const cp = { hits: {}, threads: {} };
            const ls = st.targets.map(t => {
              const a = t.startsWith('tq:') ? tq.base.add(ptr(t.slice(3))) : Process.getModuleByName(t.split('!')[0]).getExportByName(t.split('!')[1]);
              cp.hits[t] = 0;
              return Interceptor.attach(a, function () { cp.hits[t]++; const k = t + '@' + Process.getCurrentThreadId(); cp.threads[k] = (cp.threads[k] || 0) + 1; });
            });
            counters.countprobe = { cp, listeners: ls, t0: nowMs() };
          } else {
            const c = counters.countprobe;
            if (!c) throw Error('countprobe not running');
            r.countprobe = { seconds: +((nowMs() - c.t0) / 1000).toFixed(1), hits: c.cp.hits, threads: c.cp.threads };
            if (st.on === false) { for (const l of c.listeners) l.detach(); delete counters.countprobe; }
          }
        } else if (st.op === 'uncap') {
          r.uncapped = uncap(!!st.on);
        } else if (st.op === 'stats') {
          r.stats = engineStats();
        } else if (st.op === 'commands') {
          r.commands = commandNames();
        } else if (st.op === 'wait') {
          waitUntil = ticks + (st.frames || 30);
        } else throw Error('unknown step');
      } catch (e) { r.error = String(e); }
      if (st.op !== 'wait') out.push(r);
      if (r.error && req.stopOnError !== false) { finishJob({ steps: out }, 'step failed: ' + r.error); return true; }
      return false;
    }
  };
}

// --- probe
function probeJob(req) {
  const start = nowMs(), swaps0 = totalSwaps, ticks0 = ticks;
  return {
    tick(t) {
      if (t - start < (req.durationSec || 3) * 1000) return false;
      const loop = needLoop(), v = loopVec(loop);
      finishJob({
        game: game().toString(), player: player().toString(), ctrl: ctrl.toString(), loop: loop.toString(),
        activeScriptIsLoop: clean(clean(ctrl).add(0x540).readPointer()).equals(clean(loop)),
        loopPoints: v.count, loopRunning: loopRunning(loop), godMode: !!fn.isGod(game()),
        timeOfDay: fn.getTime(ambiance()), consoleCommands: commandNames().length,
        ticksPerSec: (ticks - ticks0) / ((t - start) / 1000), framesPerSec: (totalSwaps - swaps0) / ((t - start) / 1000),
        tickThread, swapThreads: Array.from(swapThreads), ctrlCount: ctrlSeen.size,
      });
      return true;
    }
  };
}

// --- record a route while the user walks
// Points carry the player's own region index next to world coordinates, so replay does not have
// to guess between overlapping regions.
function recordJob(req) {
  const start = nowMs(), pts = [], regions = [];
  let started = false;
  stopRequested = false;
  return {
    tick(t) {
      const loop = needLoop();
      if (!started) { loopClear(loop); started = true; crumb('record start'); }
      if (ticks % 5 !== 0) return false;
      const here = playerPosition(loop), pos = here.world;
      const prev = pts[pts.length - 1];
      if (!prev || Math.hypot(pos[0] - prev[0], pos[2] - prev[2]) >= (req.spacing || 8)) {
        pts.push(pos.map(x => +x.toFixed(2)));
        regions.push(fn.regionIndex(fn.regionWorld(here.region), here.region));
        job.progress({ points: pts.length, elapsed: +((t - start) / 1000).toFixed(1) });
      }
      if (stopRequested || t - start > (req.durationSec || 120) * 1000) {
        if (pts.length < 2) finishJob(null, 'Fewer than 2 points recorded');
        else finishJob({ points: pts, regions });
        return true;
      }
      return false;
    }
  };
}

// --- benchmark run
// Walking: the engine's DebugControllerPlayerScriptLoopPath cannot be used on this build, because
// the player's MoveTo state never finishes after arrival and LoopPath waits for it forever.
// We drive the route ourselves: MoveTo the next point once the player is within arriveRadius.
function runJob(req) {
  let phase = 'setup', phaseStart = nowMs(), godBefore = null, fpsBefore = null, fpsActive = null, uncapBefore = false, runWorld = null;
  let laps = 0, target = 0, lastTargetChange = 0, lastProgress = 0, lastSample = 0, lastIssue = 0, lastPos = null, moved = 0;
  let lastStallCheck = 0, stallPos = null, reissues = 0;
  const engineSamples = [], optResults = [];
  const progress = [], events = [];
  const scenario = req.scenario || 'walk';
  const route = req.route || [];
  const arrive = req.arriveRadius || 2.5;
  function point(i) { return makeWorldVec3(runWorld, route[i], req.regions ? req.regions[i] : undefined); }
  function setPhase(p) { phase = p; phaseStart = nowMs(); events.push({ t: rel(phaseStart), phase: p }); crumb('run ' + p); job.progress({ phase: p }); }
  function goTo(i) { target = i; forceMoveToPtr(point(i)); lastIssue = nowMs(); }
  function restore(loop) {
    try {
      loopClear(loop);
      if (scenario === 'walk') forceIdle(loop);
      if (req.renderOnlyPlayer) fn.renderOnlyPlayer(gEngineVar.readPointer(), 0);
      if (fpsBefore !== null && fpsLimitVar.readU8() !== fpsBefore) fn.setFpsLimited(fpsBefore);
      if (req.uncap && !uncapBefore) uncap(false);
      if (godBefore !== null && req.restoreGod !== false) fn.setGod(game(), godBefore ? 1 : 0);
      // Never change Interceptor state from inside a game-thread hook (deadlocks Frida); defer to the JS thread.
      for (const o of req.opts || []) { try { lastOptResults.push(setOptimization(o.name, false, o)); } catch (e) { } }   // flag-only switches
    } catch (e) { events.push({ cleanupError: String(e) }); }
  }
  function fail(loop, e) { measuring = false; restore(loop); finishJob({ events }, e); return true; }
  return {
    tick(t) {
      const loop = needLoop();
      try {
        if (phase === 'setup') {
          if (loopRunning(loop)) fn.stopScript(game());
          loopClear(loop);
          godBefore = !!fn.isGod(game());
          fpsBefore = fpsLimitVar.readU8();
          uncapBefore = uncapped;
          if (req.uncap) uncap(true);
          fpsActive = (req.fpsLimit === undefined || req.fpsLimit === null) ? fpsBefore : setFpsLimit(req.fpsLimit);
          if (req.god !== false) fn.setGod(game(), 1);
          // Interceptor changes happen here, on the game thread inside its tick hook, never from the JS
          // thread (that deadlocked against the game thread waiting for Frida locks) and never flushed.
          for (const o of req.opts || []) {
            try { optResults.push(setOptimization(o.name, true, o)); } catch (e) { optResults.push({ name: o.name, error: String(e) }); }
          }
          if (route.length < 1) return fail(loop, 'Route has no points');
          if (scenario === 'walk' && route.length < 2) return fail(loop, 'Walk route needs at least 2 points');
          runWorld = currentWorld(loop);
          // Teleport reloads resources, which also normalizes cache state between runs.
          fn.teleport(game(), point(0));
          if (req.timeOfDay !== undefined && req.timeOfDay !== null) { fn.setTime(ambiance(), req.timeOfDay); fn.setTimeEnabled(ambiance(), 0); }
          if (req.renderOnlyPlayer) fn.renderOnlyPlayer(gEngineVar.readPointer(), 1);
          setPhase('warmup');
          return false;
        }
        if (phase === 'warmup') {
          if (req.spawn && !this.spawned && t - phaseStart > 2000) {
            this.spawned = 0;
            for (const s of req.spawn) { const rec = Memory.allocUtf8String(s.record); for (let k = 0; k < (s.count || 1); k++) { fn.spawn(game(), rec); this.spawned++; } }
          }
          if (this.optsPending) { phaseStart = t; return false; }   // warmup starts once optimizations are applied
          if (t - phaseStart < (req.warmupSec ?? 10) * 1000) return false;
          if (scenario === 'walk') goTo(1);
          frames = 0; measuring = true; measureStart = t; lastTargetChange = t;
          setPhase('measuring');
          return false;
        }
        // measuring
        if (scenario === 'walk' && ticks % 4 === 0) {
          const pos = playerPosition(loop).world, tgt = route[target];
          if (lastPos) moved += Math.hypot(pos[0] - lastPos[0], pos[2] - lastPos[2]);
          lastPos = pos;
          if (Math.hypot(pos[0] - tgt[0], pos[2] - tgt[2]) <= arrive) {
            const next = (target + 1) % route.length;
            if (next === 0) laps++;
            goTo(next);
            lastTargetChange = t;
            progress.push([+((t - measureStart) / 1000).toFixed(2), next, laps]);
          } else if (t - lastStallCheck >= 500) {
            // Re-issue quickly when the move was interrupted (auto-attack response, stun, knock-back)
            // instead of idling: < 0.4 units in the last 0.5 s counts as stalled.
            if (stallPos && Math.hypot(pos[0] - stallPos[0], pos[2] - stallPos[2]) < 0.4) { goTo(target); reissues++; }
            stallPos = pos; lastStallCheck = t;
          }
        }
        if (t - lastSample >= 500) {
          lastSample = t;
          try { engineSamples.push({ t: +((t - measureStart) / 1000).toFixed(2), ...engineStats() }); } catch (e) { }
        }
        if (t - lastProgress > 1000) { lastProgress = t; job.progress({ phase, elapsed: +((t - measureStart) / 1000).toFixed(1), frames, laps, target }); }
        if (scenario === 'walk' && t - lastTargetChange > (req.stuckSec || 20) * 1000) return fail(loop, `Player stuck before route point ${target}`);
        if (t - measureStart >= (req.durationSec || 60) * 1000) {
          measuring = false;
          const measuredMs = t - measureStart;
          restore(loop);
          finishJob({
            events, laps, progress, measuredMs, distance: +moved.toFixed(1), reissues, engineSamples, optResults, fpsLimit: fpsActive, uncapped, spawned: this.spawned || 0,
            tickThread, swapThreads: Array.from(swapThreads),
            frameTimestampsMs: Array.from(swapAt.subarray(0, frames)), swapDurationsMs: Array.from(swapDur.subarray(0, frames)),
          });
          return true;
        }
        return false;
      } catch (e) { return fail(loop, e); }
    }
  };
}

// ---------------------------------------------------------------- optimizations (session-only, toggleable)
// slotcache: SlotManager::CalculateSlotPositions(radius) recomputes every attack slot around a
// character (one World::GetNearestFloorHeight raycast per slot, ~0.33 ms each on SM6125) whenever
// the owner's path position differs *exactly* from the cached one at +0x38. A walking player moves a
// little every frame, so with monsters chasing it recomputes ~23x/s (188 raycasts/s, ~60 ms/s CPU).
// Patch: if the owner moved less than `threshold` world units (same region) since the last real
// recompute, write the current position into the cache key so the engine's own check skips the
// recompute; the radius is still compared by the engine. Slots then lag the owner by < threshold.
// Character::GetPathPosition returns WorldVec3 (24 bytes) by value: AArch64 indirect result (x8),
// declared here as a 24-byte struct so Frida passes the result buffer correctly.
const getPathPosition = new NativeFunction(sym('_ZNK4GAME9Character15GetPathPositionEv'), ['pointer', 'float', 'float', 'float', 'uint32'], ['pointer']);
const optState = {};
const lastOptResults = [];

// pltbypass: libtq.so calls its own exported functions through PLT stubs (~7% of game-thread CPU).
// Rewrites BL/B <stub> into BL/B <definition> for the sites listed in plt-bypass.bin (built offline by
// plt_bypass_build.py), only where the GOT slot still resolves to libtq's own definition and the
// site still holds the original instruction. Single aligned 32-bit stores; both targets stay valid,
// so a thread racing the patch executes either the old or the new call. Fully revertible.
const PLT_BLOB = CACHE + 'tq-bench-plt-bypass.bin';
function pltBypass(on) {
  const base = tq.base;
  const u = new Uint32Array(File.readAllBytes(PLT_BLOB));
  const n = u[0];
  const gotOk = new Map();
  const res = { sites: n, applied: 0, reverted: 0, skippedGot: 0, skippedMismatch: 0, pages: 0, ms: 0 };
  const t = nowMs();
  let i = 0;
  // Patch in blocks of up to 16 consecutive pages: far fewer patchCode calls (each costs a protection
  // change and a cache flush) than one per page.
  while (i < n) {
    const page = Math.floor(u[1 + i * 5] / 4096);
    let j = i;
    while (j < n && Math.floor(u[1 + j * 5] / 4096) - page < 16) j++;
    const first = u[1 + i * 5], last = u[1 + (j - 1) * 5];
    const work = [];
    for (let k = i; k < j; k++) {
      const o = 1 + k * 5, site = u[o], oldW = u[o + 1], newW = u[o + 2], slot = u[o + 3], dest = u[o + 4];
      let ok = gotOk.get(slot);
      if (ok === undefined) { ok = clean(base.add(slot).readPointer()).equals(base.add(dest)); gotOk.set(slot, ok); }
      if (!ok) { res.skippedGot++; continue; }
      const cur = base.add(site).readU32();
      const from = on ? oldW : newW, to = on ? newW : oldW;
      if (cur !== from) { if (cur !== to) res.skippedMismatch++; continue; }
      work.push([site - first, to]);
    }
    if (work.length) {
      Memory.patchCode(base.add(first), last - first + 4, code => { for (const [off, w] of work) code.add(off).writeU32(w); });
      res.pages++;
      if (on) res.applied += work.length; else res.reverted += work.length;
    }
    i = j;
  }
  res.ms = +(nowMs() - t).toFixed(1);
  return res;
}

// floorcache: memo for WorldVec3::PutOnFloor (two World::GetIntersection raycasts each, ~0.3 ms on
// SM6125). Profile: 8% of game-thread CPU, partly the same points again and again (path segment ends
// re-snapped to the floor on every ShouldPickNewPath). Key = region + exact x/y/z bits of the input;
// entries live ttlMs so moving geometry cannot leave a stale floor for long. Main thread only.
// verify=1 also runs the original on every hit and counts differences.
const FLOOR_C = `
#include <glib.h>
typedef struct { void *region; float x, y, z; guint32 pad; } WV;
typedef gboolean (*PutFn) (WV *);
extern PutFn orig_put;
extern int (*clock_fn) (int, void *);
extern int (*tid_fn) (void);
extern int main_tid;
extern int verify;
extern int passthrough;
extern gint64 ttl_ns;
typedef struct { void *region; guint32 x, y, z; float out; int ok; gint64 t; } Entry;
#define N 4096
static Entry table[N];
guint64 hits, misses, mismatches, foreign;
static gint64 now_ns (void) { gint64 ts[2]; clock_fn (1, ts); return ts[0] * 1000000000LL + ts[1]; }
gboolean put_on_floor (WV * v)
{
  if (orig_put == NULL) return FALSE;
  if (passthrough) return orig_put (v);
  if (tid_fn () != main_tid) { foreign++; return orig_put (v); }
  guint32 xb = *(guint32 *) &v->x, yb = *(guint32 *) &v->y, zb = *(guint32 *) &v->z;
  guint64 h = ((guint64) (gsize) v->region >> 4) ^ (xb * 0x9E3779B1u) ^ (yb * 0x85EBCA77u) ^ (zb * 0xC2B2AE3Du);
  Entry * e = &table[(h ^ (h >> 13)) & (N - 1)];
  gint64 t = now_ns ();
  if (e->region == v->region && e->x == xb && e->y == yb && e->z == zb && t - e->t < ttl_ns) {
    hits++;
    if (verify) {
      WV c = *v;
      gboolean ok = orig_put (&c);
      if (ok != e->ok || (ok && *(guint32 *) &c.y != *(guint32 *) &e->out)) mismatches++;
    }
    if (e->ok) v->y = e->out;
    return e->ok;
  }
  misses++;
  gboolean ok = orig_put (v);
  e->region = v->region; e->x = xb; e->y = yb; e->z = zb; e->out = v->y; e->ok = ok; e->t = t;
  return ok;
}
`;
function floorCache(on, opts) {
  throw Error('floorcache disabled: its C globals are written but CModule memory is read-only here (crashed); needs the RW-extern rewrite like soundcache');
  const target = sym('_ZN4GAME9WorldVec310PutOnFloorEv');
  let st = optState.floorcache;
  if (on && !st) {
    const vars = { orig_put: Memory.alloc(8), clock_fn: Memory.alloc(8), tid_fn: Memory.alloc(8), main_tid: Memory.alloc(8), verify: Memory.alloc(8), passthrough: Memory.alloc(8), ttl_ns: Memory.alloc(8) };
    vars.passthrough.writeS32(opts.passthrough ? 1 : 0);
    vars.clock_fn.writePointer(libc.getExportByName('clock_gettime'));
    vars.tid_fn.writePointer(libc.getExportByName('gettid'));
    if (tickThread === null) throw Error('game thread not seen yet');
    vars.main_tid.writeS32(tickThread);
    vars.verify.writeS32(opts.verify ? 1 : 0);
    vars.ttl_ns.writeS64(Math.round((opts.ttlMs || opts.threshold || 500) * 1e6));   // --opt floorcache:<ttlMs>
    const cm = new CModule(FLOOR_C, vars);
    const orig = Interceptor.replaceFast(target, cm.put_on_floor);
    vars.orig_put.writePointer(orig);
    st = optState.floorcache = { cm, vars, target };
  } else if (!on && st) {
    st.vars.passthrough.writeS32(1);   // no live revert (see uncap); the C hook just forwards
  } else if (on && st) {
    st.vars.passthrough.writeS32(0);
  }
  if (!st) return { name: 'floorcache', on: false };
  const r = { name: 'floorcache', on, hits: st.cm.hits.readU64().toNumber(), misses: st.cm.misses.readU64().toNumber(),
              mismatches: st.cm.mismatches.readU64().toNumber(), foreign: st.cm.foreign.readU64().toNumber(),
              verify: st.vars.verify.readS32(), ttlMs: st.vars.ttl_ns.readS64().toNumber() / 1e6 };
  return r;
}

// throttle: run selected per-frame bookkeeping only every `every` frames (default 2).
//  - UIDetailMapWidget::WidgetUpdate(int dt): gathers minimap data (GetDetailMapData, connected
//    regions); no input handling. Skipped frames' dt is accumulated and passed on the next run.
//  - GraphicsTransparencyManager::SetTargetPosition(WorldVec3 const&): loops over every world region
//    (GetRegion/IsLevelLoaded/IsNeighbor) to fade occluders. On skipped frames only the target
//    position is stored (first 0x14 bytes, as the original does); its Timer measures real elapsed
//    time, so fade speed is unchanged.
// Interceptor.replace + NativeFunction(target) calls the original (re-entrancy is handled by Frida).
const THROTTLE_TARGETS = {
  minimap: { sym: '_ZN4GAME17UIDetailMapWidget12WidgetUpdateEi', ret: 'void', args: ['pointer', 'int'] },
  transparency: { sym: '_ZN4GAME27GraphicsTransparencyManager17SetTargetPositionERKNS_9WorldVec3E', ret: 'void', args: ['pointer', 'pointer'] },
};
function throttle(on, opts) {
  let st = optState.throttle;
  if (on && st) { st.enabled = true; }
  else if (on && !st) {
    const every = opts.every || opts.threshold || 2;
    st = optState.throttle = { every, targets: [], counts: {}, enabled: true };
    for (const which of (opts.which || ['minimap', 'transparency'])) {
      const t = THROTTLE_TARGETS[which], target = sym(t.sym);
      const orig = new NativeFunction(target, t.ret, t.args);
      const c = st.counts[which] = { calls: 0, run: 0 };
      let acc = 0;
      const cb = which === 'minimap'
        ? new NativeCallback((self, dt) => {
            if (!st.enabled) return orig(self, dt);
            c.calls++; acc += dt;
            if (c.calls % every !== 1 % every) return;
            c.run++; const d = acc; acc = 0; orig(self, d);
          }, t.ret, t.args)
        : new NativeCallback((self, pos) => {
            if (!st.enabled) return orig(self, pos);
            c.calls++;
            if (c.calls % every !== 1 % every) { clean(self).writeByteArray(clean(pos).readByteArray(0x14)); return; }
            c.run++; orig(self, pos);
          }, t.ret, t.args);
      Interceptor.replace(target, cb);
      st.targets.push({ target, cb });
    }
  } else if (!on && st) {
    // Never revert replaced code in a live process (Interceptor revert/flush can deadlock against a
    // thread waiting for the JS lock inside the replacement); just switch to pass-through.
    st.enabled = false;
  }
  return st ? { name: 'throttle', on: st.enabled, every: st.every, counts: st.counts } : { name: 'throttle', on: false };
}

// soundcache: SoundManager::Play3D calls FMOD_System_CreateSound(image, FMOD_OPENMEMORY|FMOD_3D[|LOOP],
// exinfo{length}) for every played effect, i.e. the whole in-memory file is decoded to a PCM sample
// again each time (8% of game-thread CPU with casters), and released when the channel ends.
// Cache decoded samples: key = image pointer + length + mode + bytes from both ends of the image
// (guards against the pointer being reused for another file). Hits return the existing FMOD::Sound
// (a sample may play on many channels at once). FMOD_Sound_Release on a cached sound is swallowed.
// Streams (FMOD_CREATESTREAM / System_CreateStream) are never cached. Entries unused for > idleMs
// are really released when the cache holds more than maxEntries.
// The hooks run on FMOD and game threads; they are written in C (no JS lock involved), because a JS
// hook here deadlocked: the game thread held the JS lock inside CreateSound while FMOD waited for
// one of its own threads that was entering the JS Release hook.
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
function soundCache(on, opts) {
  let st = optState.soundcache;
  if (on && !st) {
    const fmod = Process.getModuleByName('libfmod.so');
    const createP = fmod.getExportByName('FMOD_System_CreateSound'), releaseP = fmod.getExportByName('FMOD_Sound_Release');
    const v = { orig_create: Memory.alloc(8), orig_release: Memory.alloc(8), clock_fn: Memory.alloc(8), lock_fn: Memory.alloc(8),
                unlock_fn: Memory.alloc(8), mtx: Memory.alloc(64), enabled: Memory.alloc(8), idle_ns: Memory.alloc(8),
                tab: Memory.alloc(512 * 40), st: Memory.alloc(8 * 8) };
    v.tab.writeByteArray(new Uint8Array(512 * 40));
    v.st.writeByteArray(new Uint8Array(64));
    v.clock_fn.writePointer(libc.getExportByName('clock_gettime'));
    v.lock_fn.writePointer(libc.getExportByName('pthread_mutex_lock'));
    v.unlock_fn.writePointer(libc.getExportByName('pthread_mutex_unlock'));
    v.mtx.writeByteArray(new Uint8Array(64));            // bionic PTHREAD_MUTEX_INITIALIZER is all zero
    v.enabled.writeS32(opts.passthrough ? 0 : 1);
    v.idle_ns.writeS64(Math.round((opts.idleMs || 60000) * 1e6));
    const cm = new CModule(SOUND_C, v);
    // Redirect libtq's GOT slots (JUMP_SLOT relocations, RVAs from libtq.so 3.0.5339) instead of using
    // Interceptor: one atomic pointer store each, no code patching, no thread suspension, no Frida
    // locks while the game runs (Interceptor-based variants of this hook deadlocked). Only libtq's
    // own calls are redirected; FMOD-internal calls are untouched.
    const slots = { create: tq.base.add(0x117b1b8), release: tq.base.add(0x1198500) };
    if (!slots.create.readPointer().equals(createP) || !slots.release.readPointer().equals(releaseP))
      throw Error('FMOD GOT slots do not point to libfmod (layout mismatch or already hooked)');
    v.orig_create.writePointer(createP);
    v.orig_release.writePointer(releaseP);
    const setSlot = (slot, value) => {
      const page = slot.and(ptr(Process.pageSize - 1).not());
      Memory.protect(page, Process.pageSize, 'rw-');
      slot.writePointer(value);
      Memory.protect(page, Process.pageSize, 'r--');
    };
    setSlot(slots.release, cm.cs_release);
    setSlot(slots.create, cm.cs_create);
    st = optState.soundcache = { cm, v, slots };
  } else if (st) {
    st.v.enabled.writeS32(on ? 1 : 0);   // never revert live replacements; releases of cached sounds stay swallowed
  }
  if (!st) return { name: 'soundcache', on: false };
  const g = i => st.v.st.add(i * 8).readU64().toNumber();
  const misses = g(1);
  return { name: 'soundcache', on: st.v.enabled.readS32() === 1, entries: g(7), hits: g(0), misses, bypass: g(2),
           swallowed: g(3), evicted: g(4), full: g(5), missMsAvg: misses ? +(g(6) / misses / 1e6).toFixed(2) : 0 };
}

// slotnative: native version of `slotcache` (the JS hook cost as much as it saved). Replaces
// SlotManager::CalculateSlotPositions(float radius). The owner's current path position is read
// straight from CharacterMovementManager (Character+0xad0 -> +0x10 WorldVec3, the value
// Character::GetPathPosition returns). If the owner moved < threshold (same region) since the last
// real recompute, the current position is written into the engine's cache key (SlotManager+0x38) so
// the original skips the 8 floor raycasts; the radius is still compared by the engine.
// State lives in JS-allocated RW memory (CModule memory is read-only here). Installed on the game
// thread; switched off by a flag only.
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
function slotNative(on, opts) {
  let s = optState.slotnative;
  if (on && !s) {
    const target = sym('_ZN4GAME11SlotManager22CalculateSlotPositionsEf');
    const thr = opts.threshold || 1.0;
    const v = { orig_calc: Memory.alloc(8), enabled: Memory.alloc(8), t2: Memory.alloc(8), anchors: Memory.alloc(64 * 32), st: Memory.alloc(32) };
    v.anchors.writeByteArray(new Uint8Array(64 * 32)); v.st.writeByteArray(new Uint8Array(32));
    v.enabled.writeS32(1); v.t2.writeFloat(thr * thr);
    const cm = new CModule(SLOT_C, v);
    v.orig_calc.writePointer(Interceptor.replaceFast(target, cm.calc));   // game thread; takes effect after this tick
    s = optState.slotnative = { cm, v, thr };
  } else if (s) {
    s.v.enabled.writeS32(on ? 1 : 0);
  }
  if (!s) return { name: 'slotnative', on: false };
  const g = i => s.v.st.add(i * 8).readU64().toNumber();
  return { name: 'slotnative', on: s.v.enabled.readS32() === 1, threshold: s.thr, calls: g(0), skipped: g(1), recomputes: g(2), nopos: g(3) };
}

// uniformneg: OpenGLESProgram::GetUniformLocation caches locations in this+0xe4+idx*4, but -1 means
// both "not queried yet" and "uniform absent", so every lookup of an absent uniform goes to the driver
// again (measured 2026-10-07: 31 program/name pairs, >100k repeated glGetUniformLocation in 20 s).
// The slot is shared by up to three GL program variants of one object, so the miss is NOT stored in
// the slot: it goes to a bitmap keyed by (GL program name, uniform index). A program's row is cleared
// whenever libtq links, loads a binary into, or deletes that GL name (GOT redirection), so a reused
// name never inherits stale misses. The engine slot keeps its original semantics.
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
function uniformNeg(on) {
  let s = optState.uniformneg;
  if (on && !s) {
    const target = sym('_ZN4GAME15OpenGLESProgram18GetUniformLocationEjl');
    const slots = { get: tq.base.add(0x1178538), link: tq.base.add(0x1195b60), binary: tq.base.add(0x1180e18), del: tq.base.add(0x118af38) };
    const v = { gl_get: Memory.alloc(8), gl_link: Memory.alloc(8), gl_binary: Memory.alloc(8), gl_delete: Memory.alloc(8), i2n: Memory.alloc(8),
                enabled: Memory.alloc(8), st: Memory.alloc(32), neg: Memory.alloc(8192 * 16) };
    v.gl_get.writePointer(slots.get.readPointer());
    v.gl_link.writePointer(slots.link.readPointer());
    v.gl_binary.writePointer(slots.binary.readPointer());
    v.gl_delete.writePointer(slots.del.readPointer());
    for (const k of ['gl_get', 'gl_link', 'gl_binary', 'gl_delete']) if (v[k].readPointer().isNull()) throw Error('uniformneg: empty GOT ' + k);
    v.i2n.writePointer(sym('_Z19uniforms_index2namel'));
    v.enabled.writeS32(1); v.st.writeByteArray(new Uint8Array(32)); v.neg.writeByteArray(new Uint8Array(8192 * 16));
    const cm = new CModule(UNIFORM_C, v);
    const setSlot = (slot, value) => { const page = slot.and(ptr(Process.pageSize - 1).not()); Memory.protect(page, Process.pageSize, 'rw-'); slot.writePointer(value); Memory.protect(page, Process.pageSize, 'r--'); };
    setSlot(slots.link, cm.link_hook); setSlot(slots.binary, cm.binary_hook); setSlot(slots.del, cm.delete_hook);
    Interceptor.replaceFast(target, cm.gul);   // full reimplementation; the original is not called
    s = optState.uniformneg = { cm, v, targets: Object.fromEntries(['gl_get', 'gl_link', 'gl_delete'].map(k => [k, addrInfo(v[k].readPointer())])) };
  } else if (s) {
    s.v.enabled.writeS32(on ? 1 : 0);
  }
  if (!s) return { name: 'uniformneg', on: false };
  const g = i => s.v.st.add(i * 8).readU64().toNumber();
  return { name: 'uniformneg', on: s.v.enabled.readS32() === 1, calls: g(0), queries: g(1), missesServed: g(2), rowClears: g(3), targets: s.targets };
}

// abboxfast: hand-written ARM64 replacement for ABBox::GetIntersection(Ray const&) (6% self in caster
// combat; called by every floor/pick raycast). Same arithmetic and compares, at most 3 divisions instead
// of 6, no Vec3 operator calls, no stack. Bit-identical to the original on 300k emulated cases
// (abbox_fast.py). Installed by one atomic `b` at the entry to a stub allocated within +-128 MB.
const ABBOX_CODE = [0,4,64,45,2,8,64,189,3,144,65,45,5,20,64,189,6,56,35,30,39,56,36,30,80,56,37,30,0,40,35,30,33,40,36,30,66,40,37,30,49,72,64,45,51,8,64,189,52,212,65,45,54,20,64,189,23,16,62,30,24,16,62,30,25,16,62,30,41,0,128,82,32,34,38,30,36,1,0,84,32,34,32,30,141,1,0,84,233,3,31,42,136,34,32,30,32,1,0,84,26,56,49,30,87,27,52,30,6,0,0,20,233,3,31,42,136,34,32,30,96,0,0,84,218,56,49,30,87,27,52,30,64,34,39,30,36,1,0,84,64,34,33,30,141,1,0,84,233,3,31,42,168,34,32,30,32,1,0,84,58,56,50,30,88,27,53,30,6,0,0,20,233,3,31,42,168,34,32,30,96,0,0,84,250,56,50,30,88,27,53,30,96,34,48,30,36,1,0,84,96,34,34,30,141,1,0,84,233,3,31,42,200,34,32,30,32,1,0,84,90,56,51,30,89,27,54,30,6,0,0,20,233,3,31,42,200,34,32,30,96,0,0,84,26,58,51,30,89,27,54,30,105,4,0,53,0,35,55,30,26,207,55,30,234,215,159,26,75,0,128,82,32,35,58,30,106,193,138,26,58,207,58,30,72,35,32,30,137,3,0,84,234,0,0,52,91,11,52,30,59,42,59,30,96,35,38,30,228,2,0,84,96,35,32,30,172,2,0,84,95,5,0,113,224,0,0,84,91,11,53,30,91,42,59,30,96,35,39,30,228,1,0,84,96,35,33,30,172,1,0,84,95,9,0,113,224,0,0,84,91,11,54,30,123,42,59,30,96,35,48,30,228,0,0,84,96,35,34,30,172,0,0,84,64,67,32,30,192,3,95,214,224,3,39,30,192,3,95,214,136,0,0,88,0,1,64,189,192,3,95,214,31,32,3,213,0,0,0,0,0,0,0,0];
function abboxFast(on) {
  if (!on) return { name: 'abboxfast', on: !!optState.abboxfast, note: 'cannot be switched off in-process' };
  if (!optState.abboxfast) {
    const t = sym('_ZNK4GAME5ABBox15GetIntersectionERKNS_3RayE');
    const first = t.readU32();
    if (first !== 0xd101c3ff) throw Error('abboxfast: unexpected entry 0x' + first.toString(16));   // sub sp, sp, #0x70
    const inf = tq.base.add(0x11a0540).readPointer();   // GOT -> GAME::Math::infinity
    const stub = Memory.alloc(Process.pageSize, { near: t, maxDistance: 0x7000000 });
    stub.writeByteArray(ABBOX_CODE);
    stub.add(ABBOX_CODE.length - 8).writePointer(inf);
    Memory.protect(stub, Process.pageSize, 'r-x');
    const delta = stub.sub(t).toInt32();
    Memory.patchCode(t, 4, c => c.writeU32((0x14000000 | ((delta >> 2) & 0x03ffffff)) >>> 0));
    optState.abboxfast = { stub, inf: inf.readFloat() };
  }
  return { name: 'abboxfast', on: true, stub: optState.abboxfast.stub.toString(), infinity: optState.abboxfast.inf };
}

// streamcache: SoundManager::StartStream3D/StartStream play short effects (swipes, hits, spells, monster
// voices) as OGG *streams*: every play opens the file and sets up a Vorbis decoder on the game thread
// (measured: ~9 calls/s in caster combat, 3.7 ms each). The shared helper's tail branch to
// FMOD_System_CreateStream (0x949f60) is redirected here. On a file's first play its length is read from
// the stream; files <= max_ms are then loaded once as a decoded sample (playable on many channels) and
// served from the table; longer files (music, long ambience) stay streams. The game releases the sound
// before stopping the channel (ProcessFinishedList/StealInstance), so swallowing Release of a cached
// sample is safe. Release is chained on libtq's GOT slot (on top of soundcache, if present).
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
function streamCache(on, opts) {
  let s = optState.streamcache;
  if (on && !s) {
    const fmod = Process.getModuleByName('libfmod.so');
    const site = tq.base.add(0x949f60), relSlot = tq.base.add(0x1198500), streamSlot = tq.base.add(0x117dd20);
    const w = site.readU32();
    if ((w >>> 26) !== 0x05 || !site.add((((w & 0x3ffffff) << 6) >> 6) * 4).equals(tq.base.add(0x7a8f00))) throw Error('streamcache: unexpected tail branch 0x' + w.toString(16));
    const E = 136, N = 384;
    const v = { orig_stream: Memory.alloc(8), orig_create: Memory.alloc(8), next_release: Memory.alloc(8), get_len: Memory.alloc(8),
                lock_fn: Memory.alloc(8), unlock_fn: Memory.alloc(8), mtx: Memory.alloc(64), enabled: Memory.alloc(8),
                max_ms: Memory.alloc(8), budget_ms: Memory.alloc(8), tab: Memory.alloc(E * N), st: Memory.alloc(64) };
    v.orig_stream.writePointer(streamSlot.readPointer());
    v.orig_create.writePointer(fmod.getExportByName('FMOD_System_CreateSound'));
    v.next_release.writePointer(relSlot.readPointer());
    v.get_len.writePointer(fmod.getExportByName('FMOD_Sound_GetLength'));
    v.lock_fn.writePointer(libc.getExportByName('pthread_mutex_lock'));
    v.unlock_fn.writePointer(libc.getExportByName('pthread_mutex_unlock'));
    v.mtx.writeByteArray(new Uint8Array(64)); v.tab.writeByteArray(new Uint8Array(E * N)); v.st.writeByteArray(new Uint8Array(64));
    v.enabled.writeS32(1); v.max_ms.writeU32(opts.maxMs || 6000); v.budget_ms.writeU32(opts.budgetMs || 300000);
    const cm = new CModule(STREAM_C, v);
    // release chain first, then the create redirect (one atomic `b` to a near stub)
    const page = relSlot.and(ptr(Process.pageSize - 1).not());
    Memory.protect(page, Process.pageSize, 'rw-'); relSlot.writePointer(cm.cs_release2); Memory.protect(page, Process.pageSize, 'r--');
    const stub = Memory.alloc(Process.pageSize, { near: site, maxDistance: 0x7000000 });
    stub.writeU32(0x58000050); stub.add(4).writeU32(0xd61f0200); stub.add(8).writePointer(cm.cs_stream);
    Memory.protect(stub, Process.pageSize, 'r-x');
    const delta = stub.sub(site).toInt32();
    Memory.patchCode(site, 4, c => c.writeU32((0x14000000 | ((delta >> 2) & 0x03ffffff)) >>> 0));
    s = optState.streamcache = { cm, v, stub };
  } else if (s) {
    s.v.enabled.writeS32(on ? 1 : 0);
  }
  if (!s) return { name: 'streamcache', on: false };
  const g = i => s.v.st.add(i * 8).readU64().toNumber();
  return { name: 'streamcache', on: s.v.enabled.readS32() === 1, hits: g(0), loaded: g(1), long: g(2), bypass: g(3), swallowed: g(4),
           failed: g(5), entries: g(6), cachedSec: +(g(7) / 1000).toFixed(1) };
}

// getendcache: PathRecast::Segment::GetEnd() const converts the segment's last point to world space and
// puts it on the floor with a full raycast on every call (~180 calls/s in caster combat, mostly the same
// end points from ShouldPickNewPath, but on freshly built path objects). An asm wrapper (getend_stub.py)
// asks ge_lookup first. The result depends only on the nav mesh and the last path point (plus static floor
// geometry), so entries are keyed by mesh + last point bits and expire after max_age_ns (0.5 s). User-approved 2026-10-17
// (distinct from the rejected global floorcache).
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
function getEndCache(on, opts) {
  let s = optState.getendcache;
  if (on && !s) {
    const t = sym('_ZNK4GAME10PathRecast7Segment6GetEndEv');
    const first = t.readU32();
    if (first !== 0xd10143ff) throw Error('getendcache: unexpected entry 0x' + first.toString(16));   // sub sp, sp, #0x50
    const v = { clock_fn: Memory.alloc(8), lock_fn: Memory.alloc(8), unlock_fn: Memory.alloc(8), mtx: Memory.alloc(64), enabled: Memory.alloc(8),
                max_age_ns: Memory.alloc(8), tab: Memory.alloc(1024 * 80), st: Memory.alloc(32) };
    v.clock_fn.writePointer(libc.getExportByName('clock_gettime'));
    v.lock_fn.writePointer(libc.getExportByName('pthread_mutex_lock'));
    v.unlock_fn.writePointer(libc.getExportByName('pthread_mutex_unlock'));
    v.mtx.writeByteArray(new Uint8Array(64)); v.tab.writeByteArray(new Uint8Array(1024 * 80)); v.st.writeByteArray(new Uint8Array(32));
    v.enabled.writeS32(1); v.max_age_ns.writeS64(Math.round((opts.maxAgeMs || 500) * 1e6));
    const cm = new CModule(GETEND_C, v);
    const stub = Memory.alloc(Process.pageSize, { near: t, maxDistance: 0x7000000 });
    stub.writeByteArray(GETEND_STUB);
    stub.add(0x38).writeU32(first);
    const back = t.add(4).sub(stub.add(0x3c)).toInt32();
    stub.add(0x3c).writeU32((0x14000000 | ((back >> 2) & 0x03ffffff)) >>> 0);
    stub.add(0x40).writePointer(cm.ge_lookup); stub.add(0x48).writePointer(cm.ge_store);
    Memory.protect(stub, Process.pageSize, 'r-x');
    const delta = stub.sub(t).toInt32();
    Memory.patchCode(t, 4, c => c.writeU32((0x14000000 | ((delta >> 2) & 0x03ffffff)) >>> 0));
    s = optState.getendcache = { cm, v, stub };
  } else if (s) {
    s.v.enabled.writeS32(on ? 1 : 0);
  }
  if (!s) return { name: 'getendcache', on: false };
  const g = i => s.v.st.add(i * 8).readU64().toNumber();
  return { name: 'getendcache', on: s.v.enabled.readS32() === 1, hits: g(0), misses: g(1), stores: g(2), skipped: g(3) };
}

// getobjcache: ObjectManager::GetObject<Object>(id) takes a recursive CriticalSection and does an
// unordered_map lookup on every call (~61k calls/s in caster combat, ~2% of the game thread). A direct-
// mapped id -> Object* cache used ONLY on the game thread (single reader/writer, no torn entries); only
// non-null results are cached. Objects leave the map only in DestroyObjectEx (emplace_unique never
// overwrites), which is wrapped (destroy_stub.py): on the game thread the id's entry is cleared before and
// after the original; from other threads a global generation (part of each entry key) is bumped before and
// after, and the game thread reads it behind a `dmb ish` before the map lookup.
const DESTROY_STUB = [253, 123, 189, 169, 253, 3, 0, 145, 224, 7, 1, 169, 226, 15, 2, 169, 16, 2, 0, 88, 0, 2, 63, 214, 224, 7, 65, 169, 226, 15, 66, 169, 10, 0, 0, 148, 224, 19, 0, 249, 224, 7, 65, 169, 112, 1, 0, 88, 0, 2, 63, 214, 224, 19, 64, 249, 253, 123, 195, 168, 192, 3, 95, 214, 31, 32, 3, 213, 31, 32, 3, 213, 31, 32, 3, 213, 31, 32, 3, 213, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
const DMB_STUB = [191, 59, 3, 213, 192, 3, 95, 214];
const GETOBJ_C = `
#include <glib.h>
extern void * (*orig_get) (void *, guint32);
extern int (*gettid_fn) (void);
extern void (*dmb_fn) (void);
extern int (*lock_fn) (void *);
extern int (*unlock_fn) (void *);
extern guint8 mtx[64];
extern int main_tid;
extern int enabled;
extern volatile guint32 gen;
typedef struct { guint64 key; void * obj; } E;
#define N 4096
extern E tab[N];
extern guint64 st[6];   /* hits, misses, other-thread, destroys-main, destroys-other, null */
void * og (void * om, guint32 id)
{
  E * e; guint64 key; void * o;
  if (!enabled || gettid_fn () != main_tid) { st[2]++; return orig_get (om, id); }
  key = ((guint64) gen << 32) | id;
  e = &tab[id & (N - 1)];
  if (e->key == key && e->obj != NULL) { st[0]++; return e->obj; }
  dmb_fn ();
  o = orig_get (om, id);
  st[1]++;
  if (o != NULL) { e->obj = o; e->key = key; } else st[5]++;
  return o;
}
static void inval (guint8 * obj)
{
  guint32 id;
  if (gettid_fn () == main_tid) {
    if (obj != NULL) { id = *(guint32 *) (obj + 0x24); if ((guint32) tab[id & (N - 1)].key == id) tab[id & (N - 1)].key = 0; }
    st[3]++;
  } else {
    lock_fn (mtx); gen = gen + 1; unlock_fn (mtx);
    st[4]++;
  }
}
void od_pre (void * om, guint8 * obj) { inval (obj); }
void od_post (void * om, guint8 * obj) { inval (obj); }
`;
function getObjCache(on, opts) {
  let s = optState.getobjcache;
  if (on && !s) {
    const tGet = sym('_ZN4GAME13ObjectManager9GetObjectINS_6ObjectEEEPT_j');
    const tDes = sym('_ZN4GAME13ObjectManager15DestroyObjectExEPNS_6ObjectEPKci');
    if (tGet.readU32() !== 0xd100c3ff) throw Error('getobjcache: GetObject entry 0x' + tGet.readU32().toString(16));
    if (tDes.readU32() !== 0xd10283ff) throw Error('getobjcache: DestroyObjectEx entry 0x' + tDes.readU32().toString(16));
    const bjmp = (from, to) => (0x14000000 | ((to.sub(from).toInt32() >> 2) & 0x03ffffff)) >>> 0;
    // relocated original GetObject: first instruction + branch back, plus the dmb helper
    const sGet = Memory.alloc(Process.pageSize, { near: tGet, maxDistance: 0x7000000 });
    sGet.writeU32(tGet.readU32()); sGet.add(4).writeU32(bjmp(sGet.add(4), tGet.add(4)));
    sGet.add(16).writeByteArray(DMB_STUB);
    sGet.add(32).writeU32(0x58000050); sGet.add(36).writeU32(0xd61f0200);   // entry jump to og (filled below)
    const v = { orig_get: Memory.alloc(8), gettid_fn: Memory.alloc(8), dmb_fn: Memory.alloc(8), lock_fn: Memory.alloc(8), unlock_fn: Memory.alloc(8),
                mtx: Memory.alloc(64), main_tid: Memory.alloc(8), enabled: Memory.alloc(8), gen: Memory.alloc(8), tab: Memory.alloc(4096 * 16), st: Memory.alloc(48) };
    v.orig_get.writePointer(sGet); v.dmb_fn.writePointer(sGet.add(16));
    v.gettid_fn.writePointer(libc.getExportByName('gettid'));
    v.lock_fn.writePointer(libc.getExportByName('pthread_mutex_lock')); v.unlock_fn.writePointer(libc.getExportByName('pthread_mutex_unlock'));
    v.mtx.writeByteArray(new Uint8Array(64)); v.tab.writeByteArray(new Uint8Array(4096 * 16)); v.st.writeByteArray(new Uint8Array(48));
    v.main_tid.writeS32(Process.getCurrentThreadId()); v.enabled.writeS32(1); v.gen.writeU32(1);
    const cm = new CModule(GETOBJ_C, v);
    sGet.add(40).writePointer(cm.og);
    Memory.protect(sGet, Process.pageSize, 'r-x');
    const sDes = Memory.alloc(Process.pageSize, { near: tDes, maxDistance: 0x7000000 });
    sDes.writeByteArray(DESTROY_STUB);
    sDes.add(0x48).writeU32(tDes.readU32()); sDes.add(0x4c).writeU32(bjmp(sDes.add(0x4c), tDes.add(4)));
    sDes.add(0x50).writePointer(cm.od_pre); sDes.add(0x58).writePointer(cm.od_post);
    Memory.protect(sDes, Process.pageSize, 'r-x');
    // destroy wrapper first, then the lookup
    Memory.patchCode(tDes, 4, c => c.writeU32(bjmp(tDes, sDes)));
    Memory.patchCode(tGet, 4, c => c.writeU32(bjmp(tGet, sGet.add(32))));
    s = optState.getobjcache = { cm, v, sGet, sDes };
  } else if (s) {
    s.v.enabled.writeS32(on ? 1 : 0);
  }
  if (!s) return { name: 'getobjcache', on: false };
  const g = i => s.v.st.add(i * 8).readU64().toNumber();
  return { name: 'getobjcache', on: s.v.enabled.readS32() === 1, mainTid: s.v.main_tid.readS32(), gen: s.v.gen.readU32(), hits: g(0), misses: g(1),
           otherThread: g(2), destroysMain: g(3), destroysOther: g(4), nulls: g(5) };
}

// regionfast: GraphicsTransparencyManager::SetTargetPosition walks every region of the world once per frame
// and calls IsLevelLoaded(R) (a cache miss on each Region object) before IsNeighbor(cur, R). The result is
// only used through IsNeighbor(cur, loaded ? R : NULL), so the `bl IsLevelLoaded` at 0x95cfa0 is redirected
// to a stub that returns IsNeighbor(cur, R) && IsLevelLoaded(R) (cur is in x20, R in x0/x22). Both are pure
// reads and IsNeighbor(cur, NULL) is false, so the per-region fade values are identical.
function regionFast(on) {
  if (!on) return { name: 'regionfast', on: !!optState.regionfast, note: 'cannot be switched off in-process' };
  if (!optState.regionfast) {
    const site = tq.base.add(0x95cfa0), isLoaded = tq.base.add(0x8d8c2c), isNeighbor = tq.base.add(0x8d9744);
    const w = site.readU32();
    const tgt = site.add((((w & 0x3ffffff) << 6) >> 6) * 4);
    if ((w >>> 26) !== 0x25 || !tgt.equals(tq.base.add(0x7d48b0))) throw Error('regionfast: unexpected call 0x' + w.toString(16));
    if (!sym('_ZNK4GAME6Region13IsLevelLoadedEv').equals(isLoaded) || !sym('_ZNK4GAME6Region10IsNeighborEPKS0_').equals(isNeighbor)) throw Error('regionfast: symbol mismatch');
    const stub = Memory.alloc(Process.pageSize, { near: site, maxDistance: 0x7000000 });
    const enc = (op, from, to) => (op | ((to.sub(from).toInt32() >> 2) & 0x03ffffff)) >>> 0;
    const words = [
      0xa9bf7bfd,                    // stp x29, x30, [sp, #-16]!
      0x910003fd,                    // mov x29, sp
      0xaa0003e1,                    // mov x1, x0
      0xaa1403e0,                    // mov x0, x20
      null,                          // bl IsNeighbor
      0x36000060,                    // tbz w0, #0, +12  (-> no)
      0xaa1603e0,                    // mov x0, x22
      null,                          // bl IsLevelLoaded
      0xa8c17bfd,                    // ldp x29, x30, [sp], #16   (also reached from `no` with w0 = 0)
      0xd65f03c0                     // ret
    ];
    words.forEach((x, i) => { if (x !== null) stub.add(i * 4).writeU32(x); });
    stub.add(16).writeU32(enc(0x94000000, stub.add(16), isNeighbor));
    stub.add(28).writeU32(enc(0x94000000, stub.add(28), isLoaded));
    Memory.protect(stub, Process.pageSize, 'r-x');
    Memory.patchCode(site, 4, c => c.writeU32(enc(0x94000000, site, stub)));
    optState.regionfast = { stub };
  }
  return { name: 'regionfast', on: true, stub: optState.regionfast.stub.toString() };
}

function setOptimization(name, on, opts) {
  if (name === 'regionfast') return regionFast(on);
  if (name === 'getobjcache') return getObjCache(on, opts);
  if (name === 'getendcache') return getEndCache(on, opts);
  if (name === 'streamcache') return streamCache(on, opts);
  if (name === 'abboxfast') return abboxFast(on);
  if (name === 'uniformneg') return uniformNeg(on);
  if (name === 'slotnative') return slotNative(on, opts);
  if (name === 'soundcache') return soundCache(on, opts);
  if (name === 'throttle') return throttle(on, opts);
  if (name === 'floorcache') return floorCache(on, opts);
  if (name === 'pltbypassfull') name = 'pltbypass';   // same patcher; the host uploads the larger site list
  if (name === 'pltbypass') {
    const was = !!optState.pltbypass;
    if (on === was) return { name, on, unchanged: true };
    const r = pltBypass(on);
    if (on) optState.pltbypass = r; else delete optState.pltbypass;
    return { name, on, ...r };
  }
  if (name !== 'slotcache') throw Error('unknown optimization ' + name);
  const cur = optState.slotcache;
  if (on && !cur) {
    const st = { threshold: opts.threshold || 1.0, calls: 0, skipped: 0, anchors: new Map() };
    const t2 = st.threshold * st.threshold;
    st.listener = Interceptor.attach(sym('_ZN4GAME11SlotManager22CalculateSlotPositionsEf'), {
      onEnter(args) {
        st.calls++;
        const m = clean(args[0]), key = m.toString();
        this.m = m; this.key = key;
        const anchor = st.anchors.get(key);
        if (!anchor) return;
        const owner = m.readPointer();
        if (clean(owner).isNull()) return;
        const p = getPathPosition(owner);
        if (!clean(p[0]).equals(anchor.region)) return;
        const dx = p[1] - anchor.x, dz = p[3] - anchor.z, dy = p[2] - anchor.y;
        if (dx * dx + dz * dz + dy * dy >= t2) return;
        // Same region and close enough: make the engine's exact-equality cache hit.
        m.add(0x38).writePointer(p[0]);
        m.add(0x40).writeFloat(p[1]); m.add(0x44).writeFloat(p[2]); m.add(0x48).writeFloat(p[3]);
        this.skipped = true;
        st.skipped++;
      },
      onLeave() {
        if (this.skipped) return;
        // Not forced: the engine either recomputed (new position) or hit its own cache; either way
        // +0x38 is the position the current slots were computed for.
        const m = this.m;
        st.anchors.set(this.key, { region: clean(m.add(0x38).readPointer()), x: m.add(0x40).readFloat(), y: m.add(0x44).readFloat(), z: m.add(0x48).readFloat() });
        if (st.anchors.size > 4096) st.anchors.clear();
      }
    });
    optState.slotcache = st;
  } else if (!on && cur) {
    cur.listener.detach();
    delete optState.slotcache;
    return { name, on: false, calls: cur.calls, skipped: cur.skipped };
  }
  const s = optState.slotcache;
  return s ? { name, on: true, threshold: s.threshold, calls: s.calls, skipped: s.skipped } : { name, on: false };
}

const counters = {};
let debugWorld = null;
function optJob(req) {
  return { tick() { let r; try { r = setOptimization(req.name, !!req.on, req); } catch (e) { finishJob(null, e); return true; } finishJob(r); return true; } };
}
const JOBS = { opt: optJob, steps: stepsJob, probe: probeJob, record: recordJob, run: runJob };

// ---------------------------------------------------------------- game-thread pump
Interceptor.attach(sym('_ZN4GAME16ControllerPlayer6UpdateEi'), {
  onEnter(args) {
    const key = clean(args[0]).toString(), c = ctrlSeen.get(key);
    if (c) c.lastTick = ticks; else ctrlSeen.set(key, { raw: args[0], lastTick: ticks });
  }
});
Interceptor.attach(sym('_ZN4GAME4Game12UpdateCameraEi'), {
  // Game-level per-frame update: outside entity iteration, same thread as console commands.
  onEnter() {
    ticks++;
    if (tickThread === null) tickThread = gettid();
    if (!job && queue.length) {
      const next = queue.shift();
      try { job = Object.assign(JOBS[next.req.op](next.req), next); }
      catch (e) { next.reply({ id: next.req.id, error: String(e) }); return; }
    }
    if (!job) return;
    try { job.tick(nowMs()); } catch (e) { finishJob(null, e); }
  }
});

// ---------------------------------------------------------------- TCP server
// Minimal UTF-8 encoder (no TextEncoder dependency in the agent runtime).
function utf8Encode(str) {
  const out = [];
  for (const ch of str) {
    const c = ch.codePointAt(0);
    if (c < 0x80) out.push(c);
    else if (c < 0x800) out.push(0xc0 | c >> 6, 0x80 | c & 63);
    else if (c < 0x10000) out.push(0xe0 | c >> 12, 0x80 | c >> 6 & 63, 0x80 | c & 63);
    else out.push(0xf0 | c >> 18, 0x80 | c >> 12 & 63, 0x80 | c >> 6 & 63, 0x80 | c & 63);
  }
  return out;
}
let serverListener = null;
function sendLine(conn, obj) {
  const bytes = utf8Encode(JSON.stringify(obj) + '\n');
  return conn.output.writeAll(bytes).catch(() => { });
}
function immediate(req) {
  // Answered on the I/O thread without touching the engine.
  if (req.op === 'ping') return { pid: Process.id, version: P.version || null, ticks, ctrl: ctrl ? ctrl.toString() : null, busy: job ? job.req.op : null, queued: queue.length, uptimeSec: rel(nowMs()) };
  if (req.op === 'stop') { stopRequested = true; return { ok: true }; }
  if (req.op === 'optstatus') return { opts: Object.keys(optState), last: lastOptResults.slice(-8) };
  if (req.op === 'result') {
    const m = finished.get(req.of);
    return m ? { ready: true, message: m } : { ready: false, busy: job ? job.req.id : null };
  }
  if (req.op === 'shutdown') {
    // Lets the host replace this agent with a newer build in the same game process.
    if (job || queue.length) return { ok: false, busy: true };
    try { uncap(false); } catch (e) { }
    Interceptor.detachAll();
    setTimeout(() => { if (serverListener) serverListener.close().catch(() => { }); }, 100);
    return { ok: true };
  }
  return null;
}
async function serve(conn) {
  let buf = '';
  try {
    for (;;) {
      const chunk = await conn.input.read(4096);
      if (chunk.byteLength === 0) break;
      // Requests are ASCII JSON from the host; non-ASCII bytes are escaped by json.dumps.
      for (const b of new Uint8Array(chunk)) buf += String.fromCharCode(b);
      let nl;
      while ((nl = buf.indexOf('\n')) >= 0) {
        const line = buf.slice(0, nl).trim(); buf = buf.slice(nl + 1);
        if (!line) continue;
        let req;
        try { req = JSON.parse(line); } catch (e) { await sendLine(conn, { error: 'bad json' }); continue; }
        const now = immediate(req);
        if (now) { await sendLine(conn, { id: req.id, result: now }); continue; }
        if (!JOBS[req.op]) { await sendLine(conn, { id: req.id, error: 'unknown op ' + req.op }); continue; }
        queue.push({ req, reply: obj => sendLine(conn, obj), progress: obj => sendLine(conn, { id: req.id, progress: obj }) });
      }
    }
  } catch (e) { }
  try { await conn.close(); } catch (e) { }
}
(async () => {
  try {
    const listener = await Socket.listen({ family: 'ipv4', host: '127.0.0.1', port: P.port });
    serverListener = listener;
    writeJson(CACHE + 'tq-bench-server.json', { pid: Process.id, port: P.port, started: Date.now() });
    for (;;) { const conn = await listener.accept(); serve(conn); }
  } catch (e) {
    try { writeJson(CACHE + 'tq-bench-server.json', { pid: Process.id, error: String(e) }); } catch (e2) { }
  }
})();
crumb('server start');
