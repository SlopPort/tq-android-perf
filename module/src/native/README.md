# Native patches (module 2.5)

C sources of the four native patches added in 2.5. They are independent C reimplementations of the same arithmetic as the game's functions, written from observing the engine's behaviour. No game code or disassembly is included here.

| File | Patch key | Replaces |
|---|---|---|
| `bone.c` | `bone` | `SkeletalPose::GetBoneCoords` and `GraphicsMesh::GetAbsCoords` (bone and attachment-point transforms), as straight-line code instead of calls to small matrix helpers |
| `findpair.c` | `names` | `SmallNameMap::FindPair` for three value types (bone, attachment-point and int lookups by name): same probe sequence, 16-byte key compare as two 64-bit loads |
| `misc.c` | `misc` | The 16-byte `Name` equality helper, the `std::string` equality helper (8 bytes per step), and RTTI `IsA` / `HasBase` as one loop |
| `res.c` | `res` | `Resource::EnsureAvailable`, fused with the bookkeeping it calls (mark-as-used, frame counter, access counter): same loads, stores and calls in the same order |

## Build

Requires an installed Android NDK (tested with r30) and Python 3.

```bash
export ANDROID_NDK_HOME=/path/to/android-ndk
python build_blob.py misc.c
```

This writes `misc.blob.json` with the code bytes (`code`) and symbol offsets (`symbols`). `patch.js` embeds these as `MISC_CODE` / `MISC_SYM` (likewise `BONE_*`, `NAMES_*` from `findpair.c`, `RES_*`). At runtime `patch.js` copies the blob to a newly allocated page, fills the context block and redirects the game function to the matching symbol.

## Compile flags

- `-ffp-contract=off`: stops the compiler from fusing multiplies and adds into FMA instructions, so the floating-point operations happen in the same order and with the same rounding as in the game. Results are bit-identical.
- `-fno-pic` / `-fno-pie`, with a linker script that puts code first and the `.ctx` section (the context block: function pointers, counters, flags) at the end: the blob is copied to an arbitrary page, so it must not depend on a GOT or relocations. Code reaches the context block with PC-relative addressing, which stays valid as long as code and context are copied together.
- `-ffreestanding`, `-fno-builtin`, no stack protector, no unwind tables, `-mno-outline-atomics`: the blob is self-contained and calls nothing that isn't in its context block.

## Compatibility and check mode

Each patch checks byte fingerprints of the game functions it replaces for game build 3.0.5364 and switches itself off on other builds. The state is reported in `cache/tq-v14-status.json`.

`bone`, `findpair` (`names`) and `misc` have a check mode (menu-file keys `bonecheck`, `namescheck`, `misccheck` set to `true` in `cache/tq-perf-menu.json`): both the game's function and the replacement run, and differences are counted. It is slower and meant for verification only.
