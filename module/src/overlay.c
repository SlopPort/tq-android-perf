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
