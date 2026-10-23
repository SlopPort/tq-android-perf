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
function overlayInstall(b, states) {
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
  const cm = new CModule(OVERLAY_C, v); held.push(cm);
  const size = new NativeFunction(cm.st_size, 'int', [])();
  if (size > 512 * 1024) throw Error('overlay state too large: ' + size);
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
