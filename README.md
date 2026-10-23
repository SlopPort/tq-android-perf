# Making Titan Quest run better on a budget Android phone, without lowering the graphics any further

**TL;DR:** On a Redmi Note 8 (Snapdragon 665, Adreno 610), Titan Quest for Android was CPU-bound and stuttered in big fights. The graphics were already turned down and I didn't want to go lower, so I patched the game engine at runtime instead. Measured on the same phone and settings, walking without monsters went from **42.5 to 53.3 FPS** and a heavy fight from **25.4 to 35.2 FPS** (frame rate cap removed for measurement). Every change was A/B tested on fresh game processes, and anything that didn't measurably help was thrown away. The patches ship as a Magisk module that injects once when the game starts. Since version 2.0 it finds everything at runtime instead of using fixed addresses, and it checks each patch before applying it, so it can work on other game versions. Version 2.1 adds an in-game menu to switch every patch and several hidden graphics options (including real shadows) on and off.

> Most of the work (reverse engineering, writing patches, running the phone over adb, A/B testing) was done by Claude (Anthropic's AI, via Claude Code) at my direction. I made the decisions and checked the game myself (sound, visuals, no crashes).

---

## Results

Two things to know before reading the numbers:

- **The graphics on this phone were already reduced** (details under "Test setup" below). With stock graphics the absolute FPS will be lower.
- **The FPS cap was removed for measurement.** In normal play the game is capped at 30 FPS, so on this phone the gains show up as fewer stutters and a steadier 30 FPS in fights, not as 50 FPS.

"Before" is the game with only the graphics settings. "After" is the same game with all engine patches. Both were measured in the same session, 3 interleaved runs each, every run on a freshly started game:

| Scenario | Before | After | Change |
|---|---|---|---|
| Walking a fixed road loop, no monsters: average FPS | 42.5 | 53.3 | +25% |
| Same, p95 frame time | 28.3 ms | 21.4 ms | −24% |
| Same loop with 10 high-level casters chasing you and Plague cast every 3 s: average FPS | 25.4 | 35.2 | +39% |
| Same, p95 frame time | 52.7 ms | 34.6 ms | −34% |
| Same, frames slower than 50 ms (per 40 s run) | 93 | 6 | −94% |

"p95" is the frame time that 95% of frames beat. For a steady 30 FPS it has to stay under 33.3 ms. The scene workload was the same in both variants (draw calls −2.5%, particle emitters +3% on the "after" side), so the difference comes from the patches, not from a lighter random scene.

### Test setup: graphics were already reduced

The phone already ran an earlier set of graphics tweaks:

- grass rendering off;
- small local lights filtered out (the main light stays);
- low terrain and lighting quality, reflections off;
- textures one step lower;
- Plague's looping effects emitting at 50%;
- particles and decorations on.

These graphics tweaks are not part of the published module. The engine patches below save CPU time, so their relative gains should carry over to other settings, but the absolute numbers will differ.

The phone's owner had disabled thermal throttling and set the CPU and GPU governors to performance. The SoC temperature was logged before and after every run (typically 44–52 °C). The A/B runs alternate between variants, so slow temperature drift affects both sides equally. On a stock phone that throttles, long sessions will run slower than these numbers.

### What's in the patch set

Each patch was A/B tested on its own, on top of the patches before it, with 3–4 runs per variant. The gains were measured separately, in different scenes and against different baselines, so **they don't add up** to the total above.

Patch 1 was measured on the walking route, the others in the heavy fight. The table shows both the average FPS and a stutter measure for each patch. Some patches mostly raise the average. The sound patches mostly remove long frames (a sound loading on the game thread is a single long stall), so their average barely moves but their p95/p99 drops.

| # | Patch | What was slow | Fix | Avg FPS | Stutters |
|---|---|---|---|---|---|
| 1 | **Direct calls instead of PLT** | Calls between the game library's own functions went through a trampoline (explained below). That was 7.3% of CPU time. | Rewrite the call instructions to jump straight to the target. | **+15.9%** | p99 −15% |
| 2 | **Sound sample cache** | Every played sound effect decoded its whole file from memory to PCM again, then freed it. | Keep decoded sounds and reuse them. | +1.8% | p99 −9%, frames > 50 ms −48% |
| 3 | **Short effects as samples, not streams** | Weapon swings, hits, spell and monster voice sounds were played as OGG *streams*: open the file and set up a Vorbis decoder on every play, 3.7 ms on the game thread, ~9 times a second in combat. | On a file's first play, read its length. Files ≤ 6 s are loaded once as a decoded sample and reused. Music and long ambience stay streams. | +6.4% (n.s.) | p95 −9.2%, p99 −7.2% |
| 4 | **Attack slot cache** | Each monster's "slots around the target" were recomputed with 8 floor raycasts even when the target hadn't moved. | Skip the recompute while the target moved less than 1 unit. | **+4.7%** | p95 −4.4% |
| 5 | **Missing shader uniform cache** | The engine caches uniform locations, but "-1" means both "not looked up yet" and "doesn't exist", so absent uniforms were asked from the GL driver again every frame (>100k driver calls in 20 s). | Remember misses per (GL program, uniform). Clear on `glLinkProgram` / `glProgramBinary` / `glDeleteProgram`. | +7.9%¹ | p95 −9.8%¹ |
| 6 | **Faster ray-box test** | `ABBox::GetIntersection` was the single hottest function (6% self): 6 divisions per call, two out-of-line vector operator calls, a loop over axes on the stack. | Hand-written ARM64 with the same arithmetic in the same order: at most 3 divisions, no stack. Checked **bit-identical on 300,000 cases** against the original code in an emulator. | **+1.7%** | p95 −3.2% |
| 7 | **Path end-point floor cache** | `PathRecast::Segment::GetEnd()` (a const getter) did a floor raycast on every call, ~180 times a second, mostly for the same points. | Remember results for 0.5 s, keyed by nav mesh and end point. | +3.2% (n.s.) | p95 −5.4%, p99 −6.7% |

"n.s." means not significant: the 95% confidence interval includes zero.

¹ The runs with patch 5 happened to have a lighter scene (14% fewer particle emitters and 6% fewer draw calls, because monsters and Plague are random). The real gain is smaller than shown. It wasn't re-measured.

None of the patches 1–7 changes anything visible. Sound was checked by ear after patches 2 and 3.

#### Patch 1 in plain words, and why a 7% profile entry gave +16%

When a program calls a function that lives in another shared library, the call goes through a small trampoline called a PLT stub. The stub loads the real address from a table (the GOT) and jumps there. That's needed for calls into other libraries. Titan Quest's engine library exports every symbol, so even calls between its own functions take that detour: an extra memory load plus an indirect jump, on every call.

The patch rewrites the call instructions themselves (`bl <stub>` → `bl <function>`). It only does this where the GOT entry points back into the same library, so calls into other libraries are left alone.

The profiler showed 7.3% of CPU time inside the stubs, but the FPS gain was 15.9%. My explanation is that the profiler only counts the four instructions inside each stub, not their side effects in the calling code:

- every indirect jump has to be predicted by the CPU from a limited table shared by about 24,000 stubs;
- the stubs take extra instruction-cache space;
- the jump can't start until the load from the GOT finishes.

Direct calls remove all three. I didn't measure how the gain splits between them.

The +15.9% was measured with the first list of 97,575 rewritten calls (functions that have a symbol). Adding the remaining helper functions found later (116,717 in total) gave another +1.4%, within noise. The version-aware module finds 118,851 on the phone, as explained below.

#### Memory

The sound patches keep decoded audio in memory instead of decoding it again on every play. Their sizes are bounded:

- **Sample cache (patch 2):** at most 512 sounds. When it's full, sounds unused for 60 seconds are released. In the combat test it held about 90 sounds.
- **Stream-to-sample cache (patch 3):** files of at most 6 seconds, and at most 300 seconds of audio in total. In the combat test it held about 70 files, roughly 95 seconds of audio.

The game process stayed at about 780–815 MB with the caches, the same range as without them. Cached sounds stay loaded until the game exits. "Swallowing the game's `Release` call" means the game's free is ignored for a sound the cache still owns. It isn't a leak, because the cache is the owner and its size is capped.

#### Battery and long sessions

These weren't measured. At a 30 FPS cap, less CPU work per frame should leave the CPU idle longer each frame, but I have no numbers to back that.

### Things that were tried and rejected

Being strict about measurement meant throwing away several ideas that looked good in theory:

- **Global floor-height cache.** It caused a hang because of Frida pitfall #2 below (CModule globals are read-only). Dropped by choice.
- **Throttling some per-frame work, and a JavaScript version of the slot cache.** The hook overhead ate the gain. No measurable change.
- **Lock-free object lookup cache** (`ObjectManager::GetObject`, ~61,000 calls/s, each taking a mutex). It hit 94% of the time and was stable, but there was no FPS gain in either A/B, so it wasn't worth the risk.
- **Reordering a per-frame loop over every region in the world.** The CPU profile showed the same cost before and after.
- **A "reload resources every 60 frames" code path** that looked suspicious. A probe showed it never ran in 55 s of combat.

---

## How it was done

### 1. Build a benchmark you can trust first

Playing a route by hand and reading the FPS counter gave about ±9% noise between runs, which is more than most single optimizations are worth. So the first job was a controlled test environment inside the real game:

- **A Frida agent running inside the game as a small TCP server.** The PC sends JSON commands over `adb forward`. Commands run on the game thread (queued from a hook on `Game::UpdateCamera`), so they never race the engine.
- **The game's own developer console is reachable from the PC.** The engine still contains a developer console (`WidgetConsole`, 60 commands). The agent calls its `HandleCommand` directly. That gives god mode, fixed time of day, spawning any monster record, and engine statistics (draw calls, faces, emitters, lights).
- **A scripted walker.** The engine's own debug "loop path" script is broken on mobile, so the agent drives the character with `MoveTo` states along a fixed loop of 22 points. It re-issues a move if the character stalls.
- **Reproducible combat.** The same 10 caster monsters (fire, ghost, water and bone casters, levels 36–40) are spawned at the same spot. The character casts Plague every 3 seconds through simulated screen taps.
- **Uncapped frame rate during runs.** The game's FPS limit is switched off and the Swappy frame pacer is bypassed (`eglSwapInterval(0)`). Otherwise every frame time gets rounded to 33 or 50 ms and small improvements become invisible.
- **Interleaved A/B on fresh processes.** For each variant, the game is restarted, the save loaded, the agent injected, the patch applied, and the scenario run. Variants alternate (A, B, B, A…), 3 or more runs each. The comparison reports avg FPS, p50/p95/p99, 1% low and frames over 50 ms, with bootstrap confidence intervals. It also compares the engine workload (faces, draw calls, emitters), so a "win" caused by a randomly lighter scene can be spotted.

With this setup, a plain walk usually repeated within ±0.4–2%, and combat within about ±4.5%. For effects around 1%, FPS A/B can't tell the difference, so those were judged by the function's share of CPU time in a profile instead.

### 2. Profile, then read the code

- **simpleperf** on the phone with frame-pointer call graphs. A small script aggregates `report-sample` output to answer "which callees of function X eat the time" and "who calls this leaf".
- **Ghidra** (headless) for decompiling the hot functions. `libtq.so` keeps all its symbol names, which helps enormously.
- **Small probes** in the agent (call counters, timers on one call site) confirm a theory before writing a patch. For example, "how many `createStream` calls per second, which files, how long each" turned a 3% line in the profile into a concrete list of 65 sound files.

### 3. Patch at runtime, carefully

Everything is applied at runtime into the running game. No game files are modified.

- **Code patches use one atomic 4-byte write.** A small stub is allocated within ±128 MB of the target. It holds `ldr x16, #8; br x16; .quad <new function>` plus the relocated first instruction of the original. The function entry is then switched with one `b stub` instruction, which is atomic for threads that might be running it.
- **Library calls are redirected by swapping a GOT pointer** (an atomic 8-byte write), for example `FMOD_System_CreateSound` and `FMOD_Sound_Release`. Nothing in FMOD itself is patched.
- **New logic is written in C** (Frida's CModule, compiled on the device), or as hand-written ARM64 where a function returns a struct through `x8`, or where results must be bit-identical.
- **Every patch verifies the bytes it expects first.** If something doesn't match, it switches itself off and reports instead of guessing.
- **Every patch has its own off switch.** Touch a file in the module folder (`noplt`, `nosnd`, `nostrm`, `noslot`, `nouneg`, `noabbox`, `nogetend`, `nomenu`) and it's skipped on the next start. Since 2.1 the same can be done from the in-game menu.

### 4. Ship it as a Magisk module

A boot service waits for the game process, then injects the patch script once with `frida-inject`. It writes a status file you can read afterwards. Each module version came with a dry-run script (inject into a running game without installing), an install script that keeps the previous version as a backup, and a one-line rollback.

---

## Lessons about Frida inside an Android game

These cost the most time, so here they are if you try something similar:

1. **The game's anti-tamper library (`libpairipcore`) kills the process after repeated injections.** Inject once per process. Restart the game between experiments instead of re-attaching.
2. **CModule global variables were read-only in this Frida build.** Writing to them crashes with `SEGV_ACCERR`, and that turns into a silent hang. Keep all mutable state in memory allocated from JavaScript and passed in as `extern` symbols.
3. **Don't change Interceptor hooks from the JS thread while the game thread is inside them, and never call `Interceptor.flush()`.** Both deadlocked the game. Change hooks only on the game thread, never revert them, and switch features off with a flag.
4. **Don't hook functions that audio threads call from JavaScript.** FMOD's own threads plus Frida's JS lock deadlocked. Use C, and redirect GOT slots instead of using Interceptor.
5. **No JS exception handlers or symbol lookups on a crashing thread.** They take locks and turn a crash into a hang. Snapshot module ranges at start and report crashes lock-free.
6. **Never put two Interceptor hooks less than 16 bytes apart.** The first one overwrites the second.
7. **If the agent stops answering, `adb forward` can block adbd entirely.** Run `adb forward --remove-all`.
8. **Ghidra shows PLT stub addresses for some internal calls.** Resolve the real function through the dynamic symbol table.
9. **`Module.enumerateImports()` crashed the game** for a library mapped straight from the APK, inside Frida's ELF parser. Reading the relocations from the mapped dynamic section yourself is simple and safe.
10. **Long loops are slow in Frida's JavaScript engine.** Scanning 2.4 million instructions took 44 s in JavaScript and 0.3 s in a CModule.
11. **A near allocation for every hooked function can fail at random.** Allocate one pool of stub pages near the middle of the library once, and take pages from it.
12. **A second injection into a running game still gets it killed** by the anti-tamper library. Diagnostics have to come from the one injected script, for example through a status file.

---

## Making it work on other game versions (module v2.0)

The first versions of the module had addresses baked in for 3.0.5339. Version 2.0 finds everything at runtime and checks before it touches anything:

- **Functions by name.** `libtq.so` exports every symbol, so `ABBox::GetIntersection`, `SlotManager::CalculateSlotPositions` and the rest are resolved by their mangled names.
- **Library calls by import name.** GOT slots come from the `JUMP_SLOT`/`GLOB_DAT` relocations in the mapped dynamic section.
- **The call-rewrite list (patch 1) is computed on the phone.** The module reads the program headers, finds PLT stubs by their instruction pattern, takes function ranges from `.eh_frame_hdr`, and rewrites only calls whose GOT entry points back into the game library. Offline, this finds all 116,717 calls of the old hand-built list, plus 2,136 more in functions the old builder skipped.
  - **When it runs:** the scan happens once per game version, in the background a few seconds after the game reaches its main menu. It takes about 3.7 s, and the game stays playable meanwhile; the faster calls switch on when it finishes. The result is cached under the library's build-id, so later launches load it in a few milliseconds.
- **Every patch checks a fingerprint first.** For each patch, the module hashes the functions whose layout it relies on (structure offsets, call order, exact arithmetic), with relocation-dependent fields masked out: calls to other functions, page addresses, literal loads. If the game is rebuilt but those functions didn't change, the hash still matches and the patch applies. If one of them changed, only that patch is skipped, and the reason is written to a status file.
- **The graphics tweaks from the test setup are not included.** They use fixed offsets for one game build and keep copies of a few original instructions for their checks, so they stay out of the public module. The public module contains no game code: functions are found by name, and fingerprints are only hashes.
- **No version check in the boot service.** The module injects into any version and lets each patch decide.

This was tested by simulating an unknown build, with one fingerprint corrupted on purpose. The ray-box patch switched itself off and said why, and everything else still applied. The status file from that test (shortened):

```json
{
  "module": "2.0",
  "buildId": "71b29157d3c140d74ad13563013ffb300dda63ac",
  "patches": {
    "snd":    { "state": "active" },
    "slot":   { "state": "active" },
    "uneg":   { "state": "active" },
    "abbox":  { "state": "skipped", "reason": "changed _ZNK4GAME5ABBox15GetIntersectionERKNS_3RayE (7fea5668)" },
    "strm":   { "state": "active" },
    "getend": { "state": "active" },
    "plt":    { "state": "active", "sites": 118851, "cached": true, "applied": 118851, "skippedGot": 0, "skippedMismatch": 0 }
  },
  "fingerprints": {
    "_ZNK4GAME5ABBox15GetIntersectionERKNS_3RayE": "7fea5668",
    "_ZNK4GAME10PathRecast7Segment6GetEndEv": "5adcfaad",
    "...": "one entry per checked function"
  }
}
```

The file is at `/data/user/0/com.hg.titanquestultimate/cache/tq-v2-status.json`. If you run another game version and a patch says `skipped`, the fingerprints in that file are what's needed to check the changed function and add your build to the list of known ones.

## In-game options menu (module 2.1)

A small **Perf** button sits at the top of the screen, to the right of the pause button. Tapping it opens a panel over the game:

- **Engine patches (left).** Every patch from the table above can be switched on or off. Most switch live. The direct-call rewrite and the ray-box test change machine code at startup, so they apply on the next launch; the panel marks them "restart".
- **Graphics (right).** These are switches the engine has but the mobile settings don't show. They apply live and are re-applied every frame, so the game's own settings screen doesn't undo them. Measured in the town of Rhodes:

| Switch | What it does | Measured effect |
|---|---|---|
| Shadows (experimental) | Real shadow maps. Needs a hidden game option (#9) besides the engine flag. | Draw calls 485 → 784, faces 209k → 439k: looks great, costs a lot |
| Grass | Grass clumps | −33 draw calls, −2.5k faces |
| Water | Water surfaces | −13 draw calls |
| Particle effects | Spell and ambient particles | Emitters 24 → 0, −31 draw calls |
| Fog, decals (blood, scorch marks) | Environment fog, ground decals | Depends on the scene |
| See-through objects | Fading of trees and walls in front of the hero | Visual only |
| Detailed terrain / lighting | Higher-quality terrain and lighting shaders | Visual only |
| Full-res textures | Full texture resolution instead of half | More memory |

- **The panel title shows the current FPS**, so the cost of each switch is visible right away.
- **Settings are kept** in `cache/tq-perf-menu.json` and come back on the next launch. "Reset graphics" returns the graphics switches to the game's values.
- **Switches that do nothing on mobile were left out.** Bloom, colour grading and anti-aliasing are compiled out of the mobile build (their getters return a constant), and reflections had no measurable effect.

How it works:

- **Drawing.** The panel is drawn by a small C module hooked into the game's frame present (`SwappyGL_swap`, through the game library's GOT, on the game thread). It uses its own shader and one texture (a glyph atlas), makes one draw call, and restores the GL state afterwards.
- **Touch.** The game doesn't read touch from events. It polls finger positions every frame (`SDL_GetNumTouchFingers` / `SDL_GetTouchFinger`) for each of three touch devices. The menu hooks those two imports and hides any finger that starts on the button, or anywhere while the panel is open. The game never sees taps meant for the menu.
- **Turning shadows on** sets the game's own shadows option. While they're on, the game may save that option to its settings file.

## Want to try it?

**Download:** [github.com/SlopPort/tq-android-perf](https://github.com/SlopPort/tq-android-perf) (the installable zip is on the [Releases page](https://github.com/SlopPort/tq-android-perf/releases/tag/v2.1)).

**Requirements:** a rooted **arm64** phone with Magisk, and your own installed copy of Titan Quest for Android (`com.hg.titanquestultimate`). The module ships `frida-inject` for arm64. It's meant for single-player; the benchmark tools (god mode, monster spawning) are test tools for single-player only.

**What to expect on versions other than 3.0.5339:**
- The call rewrite (patch 1, the biggest gain) should work on any arm64 build.
- The other patches apply where their fingerprints match.

**Limits:**
- The 32-bit (armeabi-v7a) build would need a separate port.
- The PC version is a different binary entirely.

**Before installing:** back up your saves. This is unofficial and experimental, so use it at your own risk.

**Not included and not to be shared:** the game's own files. Everything here patches your own installed copy in memory.

### Install

1. Download `tq-android-perf-2.1.zip` from this repository's **Releases** page (or build it: `python module/build.py`).
2. In the Magisk app: **Modules → Install from storage**, pick the zip, then reboot.
3. Start Titan Quest. The patches apply a few seconds after the main menu appears. On the first launch of a game version
   the call-rewrite scan adds about 4 seconds in the background; later launches use the cached result.
4. Check what applied:

   ```bash
   adb shell su -c cat /data/user/0/com.hg.titanquestultimate/cache/tq-v2-status.json
   ```

5. Switches: create an empty file in `/data/adb/modules/tq_autopatch/` and restart the game.
   - `noplt`, `nosnd`, `nostrm`, `noslot`, `nouneg`, `noabbox`, `nogetend` turn off one patch each.
   - `nomenu` hides the in-game options menu.
   - The module's **Action** button in Magisk pauses or resumes all patches.

To uninstall, remove the module in Magisk and reboot.

### Credits

- [Frida](https://frida.re/) for the instrumentation toolkit.
- THQ Nordic / HandyGames for Titan Quest. This is an unofficial, non-commercial fan project, not affiliated with or endorsed by them. It contains no game files, code or assets.

## Repository layout

| Path | What it is |
|---|---|
| `module/` | Magisk module source (v2.1; `patch.js` is the whole patch script, unminified) and `build.py` that produces the installable zip |
| `module/src/` | Sources of the in-game menu: `overlay.c` (drawing and touch, a Frida CModule), `overlay-glue.js`, `make_font.py` |
| `tools/benchmark/` | The benchmark harness: `tqbench.py`, the Frida agent, A/B scripts, scenarios and routes |
| `tools/analysis/` | Fingerprints, the offline PLT scan, the ray-box emulator test, assembly stub generators |

License: MIT (see `LICENSE`). Third-party notices: `THIRD-PARTY.md`.
