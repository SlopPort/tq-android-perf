# Elysium-area experiments: resolution, CPU attribution and PLT calls

Date: 2026-11-06. Status: exploratory; no accepted optimization result or 30 FPS guarantee.

## Test scope

One rooted Redmi Note 8 running LineageOS/Android 16 and game build 3.0.5364. The test location displayed the region name Etolia. The reported ~13 FPS problem has not yet been reproduced exactly. Results do not establish behavior on other devices or builds, including an untested Google Play installation.

The harness restores the same private save snapshot before each process, enters the character through screenshot-gated controls, applies the same five-second joystick input and requests the same group of 12 Melinoe enemies (8 Blade Dancers and 4 Blood Witches). The test player uses god mode. Normal combat, allied guards and retaliation still change the live population. This is not yet a deterministic combat fixture.

Frame values below are Android SurfaceFlinger presentation intervals for the game BLAST surface. They are neither GPU execution times nor CPU subsystem durations. Overlapping ring snapshots are deduplicated; zero/pending timestamps are excluded and continuity gaps are flagged. The game retains its 30 FPS cap and the display is 60 Hz, so intervals cluster around 33.3 and 50 ms. P99 from short windows is exploratory; P99.9 is not used here. Observed FPS is 1000 divided by the arithmetic mean of the valid presentation intervals in milliseconds. Each table row gives the number of intervals above 41.67 ms and its actual valid-interval denominator. A sustained 24 FPS cadence corresponds to intervals no longer than approximately 41.67 ms; the threshold counts do not establish a 24 FPS minimum.

No accepted run has yet passed all scene-equivalence, measurement-overhead and thermal-control checks. Population snapshots bracket a wider period than the exact frame window because they include setup and recovery. They must not be interpreted as exact in-window death counts.

## Display-resolution A-B-A-B

A: native 2340 x 1080 screenshot dimensions. B: Android display-size override, 1872 x 864 (80% per dimension, 36% fewer output pixels). The lower output dimensions were verified; the game's internal render-target dimensions were not independently traced. All native Perf patches and the shared add-on overlay were off. Each measured window was 10 seconds.

| Run | Variant | Observed FPS | Median ms | P95 ms | P99 ms | Worst ms | Intervals >41.67 ms / valid intervals |
|---|---|---:|---:|---:|---:|---:|---:|
| 1 | A | 22.73 | 49.92 | 50.32 | 66.96 | 100.12 | 131 / 224 |
| 2 | B | 23.73 | 49.71 | 50.17 | 66.70 | 66.87 | 117 / 233 |
| 3 | A | 25.30 | 33.47 | 50.11 | 50.23 | 66.88 | 91 / 248 |
| 4 | B | 23.24 | 33.52 | 50.17 | 66.85 | 400.11 | 103 / 229 |

The first pair favored B by about 1 FPS; the second favored A by about 2 FPS. This does not demonstrate a repeatable resolution benefit. All four trials changed live population. The last B trial contained a 400 ms interval. An independent screenshot review found the lower-resolution world broadly readable, with uncertainty around crowded and translucent characters; scenes were not pixel-aligned and motion readability remains unverified. Native display resolution was restored.

## CPU attribution

A separate fresh scene was sampled for about 20 seconds with `simpleperf`, 200 Hz, `cpu-clock` and frame-pointer call graphs. It recorded 4,672 samples, zero reported sample loss and 7.17% call-chain errors. This diagnostic adds unmeasured overhead and is not an optimization benchmark.

- The Main Thread accounted for 86.11% of sampled process CPU time when grouped by thread name. The inclusive `Game::Run` chain covered 74.34% of all samples; both use all process samples as their denominator, but the thread grouping includes work without a recoverable `Game::Run` call chain. They should not be confused.
- Inclusive chains included engine update, entity/animation update, forward rendering and lighting. Inclusive percentages overlap and must not be added.
- PLT stubs accounted for approximately 6% self samples. Sound creation was another candidate, around 6% inclusive samples.
- Twenty GPU busy/total sysfs samples averaged about 43.7% utilization (range 31.7-47.5%) at a reported 820 MHz. This is driver telemetry, not a GPU frame-time trace or proof that every stall is CPU-bound.

Together, these observations support testing main-thread work before pursuing more resolution cuts. They do not yet attribute the longest individual frames or prove synchronous resource loading as their cause.

## PLT-only A-B-A-B

Both variants used native resolution and the same module-hosting path. A disabled all native patches; B enabled only direct PLT calls. Sound, stream, attack-slot, uniform, ray-box and path-end-point patches remained off, as did the overlay. Runtime per-process status was checked before measurement: PLT `off` for A, `active` for B, other patch/menu states `off`. Each measured window was 20 seconds.

| Run | Variant | Observed FPS | Median ms | P95 ms | P99 ms | Worst ms | Intervals >41.67 ms / valid intervals |
|---|---|---:|---:|---:|---:|---:|---:|
| 1 | A | 24.63 | 33.45 | 50.08 | 50.32 | 66.69 | 207 / 482 |
| 2 | B | 28.56 | 33.34 | 50.02 | 50.11 | 50.21 | 57 / 560 |
| 3 | A | 23.54 | 33.59 | 50.14 | 66.67 | 333.48 | 227 / 460 |
| 4 | B | 26.83 | 33.35 | 50.04 | 50.19 | 99.87 | 120 / 526 |

Both pairs favored B: approximately +3.9 and +3.3 observed FPS. This is promising evidence, not an accepted causal result: live population and combat evolution differed, collector overhead and thermal drift were not controlled independently, and only two pairs were collected. The requested 30 FPS with a 24 FPS floor is not established.

## Save and UI checks

An isolated copy was tested through world entry and an explicit save. At that checkpoint, all 1,081 original save-file hashes were unchanged while the benchmark copy changed. A second hash comparison after both A-B-A-B series again found all 1,081 original files unchanged. These checkpoints do not prove coverage of every save API.

A separate UI comparison showed normal-sized pause buttons after disabling the entire Traders module and restarting with Perf already paused. This implicates the shared overlay path but does not identify the exact GL/input operation or constitute a completed overlay repair. Traders remains disabled during these diagnostics. Module flags and native display size were restored after the PLT series; the diagnostic save-routing loader remains installed on the test device until explicit cleanup.

## Next checks

1. Validate route endpoints and track the test group separately from all loaded monsters; reduce combat-state variance.
2. Compare collector/profiler overhead with matched controls and capture thermal/clock conditions per run.
3. Repeat the PLT test with longer and counterbalanced runs, then test the sound cache as one additional factor.
4. Correlate long frames with CPU scheduling, resource loads and GPU waits; regression-check real combat and pause/menu rendering.

Only an English summary of original measurements is published here. No APKs, game libraries, maps, assets, saves, credentials or raw reverse-engineering dumps accompany this report.

## Follow-up: restore sound-build gates and test the sample cache

The installed source still used the 5339 sound-function lengths and correctly skipped the cache on 5364. The earlier reviewed 5364 sound ABI and cache implementation were rechecked: the cache code was unchanged, and eight full-length normalized fingerprints were independently recomputed from the local ELF. The source now selects those lengths/hashes only for the matching build ID. Other builds retain the previous table; modified fingerprints are still rejected. Shared sound/stream entries are covered, but the stream cache remained off in this experiment. This is a compatibility-table restoration, not a new cache algorithm.

The first attempted series stopped before measuring B because sound was skipped. It is excluded below. A fresh complete series used PLT in both variants: A = PLT only; B = PLT plus sample cache. Other native patches and the overlay were off, at native resolution. Each window was 20 seconds.

| Run | Variant | Observed FPS | Median ms | P95 ms | P99 ms | Worst ms | Intervals >41.67 ms / valid intervals |
|---|---|---:|---:|---:|---:|---:|---:|
| 1 | A | 28.59 | 33.35 | 50.02 | 50.16 | 83.24 | 55 / 560 |
| 2 | B | 29.35 | 33.34 | 33.61 | 50.00 | 317.03 | 8 / 573 |
| 3 | A | 28.08 | 33.35 | 50.04 | 50.18 | 100.04 | 76 / 550 |
| 4 | B | 29.97 | 33.34 | 33.53 | 33.73 | 50.02 | 2 / 586 |

Both pairs favored the cache, by approximately 0.8 and 1.9 observed FPS. The final B process reported 430 cache hits, 136 misses, no bypasses, evictions or full-cache events over its launch (not exclusively the timed window). Its PID matched that recorded B trial. This confirms reuse in that process; it does not establish audio correctness or long-session memory behavior. No audible regression check was completed.

Boundary clocks and thermal snapshots were added. GPU clock was 820 MHz at the recorded boundaries; reported GPU temperatures ranged from 42.5 to 45.8 C. These snapshots do not establish continuous thermal control. Population snapshots were moved closer to the frame window: roughly 3.0-3.4 seconds before its first poll and 1.6-2.1 seconds after its last poll, including command/readout time. Live populations still changed, so scene equivalence remains unproven. The earlier B trial had a 317 ms interval; the last B trial had a 50 ms maximum. The 24 FPS floor remains unestablished.

The source passed Node syntax validation and mocked build-gate tests for both tables, changed-fingerprint rejection and rejection of a changed function shared by sound and stream. The device source hash matched the local candidate. These checks do not replace runtime audio and memory regressions. Original module flag states were restored after the series; no prebuilt module release is included with this source update.

## Follow-up: observer polling calibration

Twelve consecutive two-second windows used order ABBA repeated three times. A read the SurfaceFlinger ring only at window boundaries. B additionally polled every 0.75 seconds. Both variants shared the endpoint readout costs; Perf remained paused. There were no detected ring-continuity gaps. Per-window intervals were pooled without joining timestamps across unobserved gaps.

| Observer | Valid intervals | Pooled observed FPS | Intervals >41.67 ms |
|---|---:|---:|---:|
| Boundary reads only | 326 | 26.04 | 98 |
| Extra 0.75-second polling | 322 | 25.89 | 100 |

The difference was about 0.15 FPS, amid a scene that became faster over time. Short counterbalanced blocks reduce simple time-order bias but do not remove changing combat or population. This is not proof of zero overhead, a rigorous overhead bound, or a long-tail validation. It does not measure the shared endpoint costs or the separate CPU profiler overhead.


## Follow-up: named loads and verified game-thread identity

Two diagnostic loading traces recorded resource-loader entry/exit wall times. These timings include JavaScript callback, clock and (in the second trace) bounded filename-read overhead. Nested root/internal durations overlap and must not be added. Probes were removed by restarting with an untraced loader after each run.

The first trace contained a 56.27 ms root load with return address in `Armor::ResetArmorGender`, overlapping a presented interval of 83.56 ms. Static analysis shows a tail-call chain through `Armor::ChangeArmorMesh` and `Resource::EnsureAvailable`; the recorded return address is an outer caller, not a direct loading call site. The resource filename was not captured in that trace. Temporal overlap alone does not establish causation or explain the earlier 317 ms interval.

The second trace captured filenames during live calls using checked, read-only getters, capped at 512 bytes. It had 30 root calls and 45 internal calls over setup, measurement and recovery, with no dropped records, unfinished calls or metadata errors. In its actual 20-second presentation window, eight root calls on threads named `Main Thread` lasted at most 0.734 ms, mostly for effect textures. Slower dissolve-shader, relic and item-sparkle loads occurred outside that window. Presented FPS was 29.81, P99 49.84 ms and worst 50.06 ms. The long armor load did not recur; this does not establish that loading stalls are solved.

Thread-name matching has an important limitation: multiple native threads inherit the name `Main Thread`. Therefore name-grouped percentages in the earlier profile and thread names in the loading traces cannot independently prove the identity of the game/render thread. A subsequent setup callback captured the native thread ID directly at checked `Game::UpdateCamera` entry, without retaining a per-frame setup hook.

A new 20-second CPU profile, with PLT and sound cache active and other patches/menu disabled, then attributed 84.46% of all process CPU-clock samples to that observed game thread. There were 4,614 samples, none lost, and 8.52% callchain errors. Inclusive sampled costs on that thread were: render 37.19%, engine update 30.84%, light rendering 17.01%, monster update 12.92%, mesh animation update 4.75%, and `EnsureAvailable` 1.97%. These percentages share an all-process denominator and overlap along call chains; they are not additive subsystem timings. The profile supports investigating sustained renderer/simulation costs alongside occasional loading, rather than assuming all slow frames come from synchronous loads.

That profiled run presented 29.23 FPS, median 33.34 ms, P95 33.68 ms, P99 50.16 ms and worst 66.98 ms. Profiling overhead remains unmeasured. Loaded live-monster counts changed from 202 to 196, so this is attribution evidence, not an accepted optimization comparison. Lighting was already set to low quality according to the native getter; no lighting-quality setter was invoked. Original module flags and native output resolution were restored afterward. Diagnostic save isolation remains active locally; ordinary launch has not yet been returned to the original saves. The 30 FPS / 24 FPS floor and gameplay/UI regression gates remain open.


## Follow-up: light cardinality, affinity rejection and a heavier workload

A read-only probe at the checked multiple-light render pass observed 1,708 invocations, each with two entries: one raw light type 0 and one type 1. Its thread ID matched the setup callback at `Game::UpdateCamera`. Type labels and full shader semantics remain unverified. Capture included setup and recovery around the measured window. These are cardinality observations with unmeasured probe overhead, not timings or evidence that two decorative lights can safely be removed. No light reduction was applied.

A separate ABAB series tried allowing the observed game thread on all eight CPUs (A) versus CPUs 4-7 (B), holding PLT and sound cache active and other patches/menu off. Presented FPS was 29.12 / 29.89 / 29.97 / 29.51; P99 was 50.18 / 33.71 / 33.61 / 50.02 ms. The paired FPS differences reversed sign (+0.76, -0.46). More importantly, the effective affinity readback changed after setup in every run: A started at mask `ff` and ended at `5f`; B started at `f0` and ended at `30`. CPU hotplug, cpuset restrictions or another writer were not distinguished. Thus this did not establish a controlled, fixed-affinity comparison. Population and other comparison gates also failed. No permanent affinity rule was installed; fresh processes and original module flags were restored.

The original 12-enemy workload often reached the 30 FPS cap with PLT and sound cache active, so a separate calibration spawned 36 enemies of the same two types from the same isolated seed and route. A checked object-ID getter now tracks IDs first observed synchronously across spawn commands, with bounded native enumeration and duplicate-ID rejection. It does not retain object pointers. Indirect objects created during those calls remain a possible identification limitation.

In the first native validation, 36 new monster IDs were observed after 36 spawn calls. All 36 were present and alive at both measurement boundaries; the full loaded live-monster count still changed from 226 to 221. The 20-second workload presented 20.81 FPS, median 50.00 ms, P95 66.66 ms, P99 66.87 ms and worst 99.97 ms. This supplies a heavier workload with a stable test-group count at its boundaries, not proof of an equivalent surrounding scene or reproduction of the original 13 FPS case. Graphics quality was unchanged. Independent still-image readability review was partial: terrain remained distinct, but crowd effects and columns/foliage obscured some actors; motion readability was not tested.

A following exploratory CPU profile of that workload recorded 4,743 samples, none lost, with 6.54% callchain errors. The directly observed game thread accounted for 83.98% of all process CPU-clock samples. Inclusive costs on that thread included engine update 34.87%, render 32.17%, monster update 18.70%, and character collision separation 6.54%. Costs overlap and share the all-process denominator. This motivates inspecting collision/update work without disabling AI or changing collision behavior. Presented FPS was 22.33, P99 66.86 ms and worst 83.51 ms; this is not an improvement comparison with the unprofiled run. At approximately one-second sampling cadence, all 20 CPU-availability snapshots reported online CPUs 0-7, game-thread allowed CPUs 0-7 and `/top-app` membership. Transient changes could be missed, and the earlier affinity changes remain unexplained.

An earlier attempt at this profile was rejected before CPU recording: a setup request was incorrectly issued during the quiet window and timed out. The corrected run reused the thread ID already captured during setup, without issuing a new setup request inside the quiet window. Profiling overhead, changing surrounding populations, exact scene alignment and gameplay/UI regressions remain open gates. Neither the heavier-workload results nor the rejected affinity experiment establishes the 24 FPS floor.


## Follow-up: negative uniform-lookup cache on the heavier workload

This ABAB series held PLT and sound cache active and changed only the existing negative uniform-lookup cache flag. All other native patches and the shared menu were off, at native output resolution, with the same isolated seed, route and 36 spawn calls. Both shader-helper fingerprints matched the checked 5364 library. No cache algorithm was changed. A five-second wait after setup replaced the earlier two-second wait to let root-notification toasts expire before frame collection; the quiet period was extended accordingly. This makes the boundary population snapshot farther from the first frame poll. Comparisons with older series are not controlled comparisons.

| Run | Cache | Observed FPS | P99 ms | Worst ms | Test group alive, before/after |
|---|---|---:|---:|---:|---:|
| 1 | A: off | 22.38 | 50.33 | 66.77 | 36 / 36 |
| 2 | B: on | 22.84 | 66.51 | 116.70 | 36 / 36 |
| 3 | A: off | 20.64 | 66.94 | 300.19 | 36 / 32 |
| 4 | B: on | 22.70 | 66.67 | 116.70 | 36 / 36 |

Both descriptive FPS differences favored B (+0.46 and +2.05), but long-frame behavior did not improve consistently. The test-group deaths in run 3, changing surrounding populations, unverified exact scene equivalence, thermal drift and observer costs prevent causal acceptance. Boundary availability snapshots reported online and game-thread allowed CPUs 0-7 with top-app membership; these are not continuous controls. The 24 FPS floor remains unmet in this workload. Original flags and native output resolution were restored, followed by a fresh process.

The final B process reported 3,099,297 cache calls, 496 driver queries, 337,091 cached negative results and 124 row clears. The status PID matched that recorded run. These are launch-lifetime counters, not counts isolated to the 20-second frame window; they demonstrate cache use, not a speedup by themselves. Independent still-image world review found no evident missing terrain/materials or major readability regression between sampled A/B images. Crowd effects and foliage obscured actors in both, and stills do not establish animation, UI, intermittent rendering or gameplay correctness.

A new host-native semantic test extracts the actual authored `UNIFORM_C` body from the module and compiles it with fixed-width types and fake GL callbacks. It passed positive/negative hits, invalid indices, disabled mode, program/index separation, the program-name bound, and invalidation on link, binary replacement and deletion followed by program-name reuse. This tests the C cache logic; it does not validate Frida redirection, Android ABI behavior or a real GL driver. Compiler outputs are temporary and are not distributed.
