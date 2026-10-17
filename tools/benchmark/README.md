# TQ Bench

A controlled benchmark and test arena for Titan Quest on Android, driven from a PC over adb.
It injects a Frida agent into the game (as a small TCP server), drives the in-game developer console
(god mode, fixed time of day, spawning monsters), walks a recorded route, removes the FPS cap and records
frame times. `tqbench.py --help` lists the commands. The detailed manual is in Polish: `README.pl.md`.

Requirements: rooted phone, `adb`, Python 3, and `frida-inject` for android-arm64 on the phone at
`/data/adb/modules/tq_autopatch/injector` (installed by the module) or another path given to `tqbench.py`.

Typical use:

```bash
python tqbench.py launch
python tqbench.py run --label base --repeat 3 --fresh --scenario-file scenarios/walk-road.json
python tqbench.py run --label test --repeat 3 --fresh --scenario-file scenarios/walk-road.json --opt abboxfast
python tqbench.py compare base test
python ab.py --rounds 3 --variant base= --variant fast="--opt abboxfast" --common "--scenario-file scenarios/walk-road-casters-plague.json"
```

Function addresses in the agent are for game version 3.0.5339; the module itself (../../module) is version-aware.
Screen coordinates for taps assume a 2340x1080 display.
