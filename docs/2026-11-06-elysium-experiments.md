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
