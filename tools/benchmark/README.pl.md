# TQ Bench: kontrolowany benchmark i arena testowa Titan Quest (Android)

Narzędzie do powtarzalnego pomiaru FPS i czasów klatek w `com.hg.titanquestultimate` 3.0.5339
oraz do sterowania wbudowaną konsolą deweloperską z PC (spawn mobów i efektów, god mode, stała pora dnia).
Cały cykl, od uruchomienia gry i załadowania postaci po pomiar, działa bez dotykania telefonu.

## Wynik najważniejszy: powtarzalność

| Scenariusz | 3 próby (avg FPS) | Rozrzut |
|---|---|---|
| Stare ręczne trasy „od fontanny” (30 FPS cap) | 24,2 / 27,5 / 29,0 | ±9% |
| `walk` po nagranej trasie `road`, bez limitu FPS | 50,53 / 50,71 / 50,89 | ±0,4% |
| `combat-casters` (8 magów + umiejętności gracza, świeży proces) | 40,3 / 42,4 / 44,2 | ±4,5% |

Poprawki optymalizacyjne testuj na `walk` (lub `idle`). `combat` służy jako test stresowy na przycięcia
(`low1%`, `>50ms`) i wymaga więcej prób, bo AI, śmierć mobów i liczba emiterów są losowe.

## Szybki start

```bash
python tqbench.py launch                 # uruchom grę i załaduj postać (lub --restart)
python tqbench.py probe                  # sprawdź hooki i obiekty silnika

# trasa marszowa: nagranie z automatycznym sterowaniem joystickiem (od areny jingyang)
python tqbench.py arena save jingyang    # zapamiętaj miejsce postaci
python tqbench.py record --route road --arena jingyang --seconds 90 --spacing 5 \
    --drive right:1500,up:5000,upright:2000,down:5500,left:1800

# A/B
python tqbench.py run --route road --label base --repeat 3 --time 12
#   ... włącz poprawkę ...
python tqbench.py run --route road --label patch --repeat 3 --time 12
python tqbench.py compare base patch

# stres: magowie + umiejętności gracza, świeży proces przed każdą próbą
python tqbench.py run --arena jingyang --label combat --duration 30 --warmup 10 --time 12 --repeat 3 --fresh \
    --spawn records/creature/monster/dragonian/as_wyrmmage_40.dbr:2 records/creature/monster/ghost/as_ghostcaster_36.dbr:2 \
            records/creature/monster/ichthian/bs_shaman_39.dbr:2 records/creature/monster/ichthian/bs_bonecaster_39.dbr:2 \
    --tap 2042,886@2000 2042,679@2500 2141,635@3000 2147,785@700
```

Gdzie idzie czas: `--perfetto` zapisuje ślad Perfetto (sched, częstotliwości CPU, Adreno, atrace gfx)
dokładnie w oknie pomiaru, do `results/<label>/run-NNN.perfetto-trace`. Do otwarcia w ui.perfetto.dev
albo w istniejących skryptach `../analyze-*.py`.

Pełny przykład interleaved A/B na świeżych procesach: `ab_autopatch.py` (autopatch włączony vs wstrzymany).
Wnioski z pomiarów: `findings-2026-10-17.md`.

## Limit klatek: domyślnie zdjęty

Gra ma `fpsLimit = 1` (odświeżanie/2 = 30 FPS), a Swappy wyrównuje każdą klatkę do wielokrotności VSync.
Przy pracy CPU ~19–34 ms na klatkę oznacza to, że **poprawa z 33 do 25 ms nie zmieniłaby wyniku 30 FPS**.
Dlatego `run` domyślnie:
- ustawia `FPS_LIMIT = 0` (`MobileUtils::SetFPSLimited`; 0 = brak, 1 = 1/2, 2 = 1/3, 3 = 1/4 odświeżania),
- omija pacing Swappy: podmienia `SwappyGL_swap` na `eglSwapInterval(0)` + `eglSwapBuffers`,
- po próbie przywraca oba ustawienia. `options.txt` pozostaje nietknięty.

Sprawdzone: bez renderu świata gra osiąga 78 FPS, więc w silniku nie ma ukrytego limitu 60.
`--vsync` zostawia pacing Swappy, a `--fps-limit N` wybiera limit. Poza benchmarkiem: `python tqbench.py fps [0-3]`.

## Metryki (`results/<label>/run-NNN.json`)

- `avg_fps`, `frame_ms.p50/p95/p99/max`, `low_1pct_fps`, `over_ms.50/100`: z odstępów między `eglSwapBuffers`.
- `swap_ms`: czas wewnątrz swapa. `non_swap_ms_mean`: praca CPU na klatkę (bez czekania na VSync). To najczulsza metryka do A/B.
- `engine`: liczniki silnika próbkowane co 0,5 s (te same co nakładka `gr.Stats`): trójkąty, draw calle, światła,
  cienie, odbicia, emitery i smugi cząsteczek, liczba obiektów, wolny VRAM. Pokazują, *co* było rysowane, więc różnicę
  w FPS przy różnej scenie widać od razu.
- `fps_timeline`, `worst_frames`, `thermal_before/after`, `laps`, `progress`, `distance`.

## Jak to działa

```
tqbench.py ──(raz na proces gry) su frida-inject -e──> serwer w grze (tq-bench-agent.js)
tqbench.py ──adb forward tcp:27099──> JSON po liniach; zadania wykonywane na wątku gry (hook Game::UpdateCamera)
  steps  – konsola, teleport, czas, spawn, god, fps, uncap, stats …   (console / spawn / arena / fps)
  run    – teleport → rozgrzewka (+spawn) → pomiar (+walker / taps) → przywrócenie
  record – zapis trasy z indeksami regionów; probe – kontrola
crash: hooki na BackTraceUtil::NativeCrashSignalHandler, FatalError, exit/_exit/abort → tq-bench-crash.json
```

Mechanizmy silnika (szczegóły: `../custom-map-feasibility.md`, `../ghidra-evidence/*.txt`):

| Mechanizm | Zastosowanie / ustalenie |
|---|---|
| `WidgetConsole` (`Game+0x60`), `HandleCommand` | 60 komend deweloperskich (`console --list`). Komendy mają prefiksy (`g.God`), a host rozwija krótkie nazwy. |
| `Game::TeleportPlayer`, `SetGodMode`, `Spawn` | Arena, nieśmiertelność, potwory i efekty (`records "wzorzec"`, 60 820 rekordów w bazie). |
| `AmbianceManager::SetTime/SetTimeEnabled` | Stała pora dnia (`--time`). |
| `GraphicsEngine::GetStats`, `+0x168..0x174` | Liczniki renderu w wynikach. |
| `ControllerPlayer::ForceState("MoveTo")` | Własny walker po trasie. |
| `DebugControllerPlayerScriptLoopPath` | **Nie działa w wersji mobilnej**: stan `MoveTo` po dojściu nigdy się nie kończy, więc pętla czeka w nieskończoność. Zastąpiony własnym walkerem. |

## Pułapki, które już kosztowały crash lub czas

- **pairip (`libpairipcore.so+0x418e0`, adres `0xf821000251b849`)**: ochrona anty-tamper zabija proces
  po wielokrotnych wstrzyknięciach (6.10, 9.10, 17.10). Zasada: jedno wstrzyknięcie na proces. `tqbench.py`
  podmienia agenta tylko po zmianie jego kodu, a do serii używaj `--fresh`.
- **Zgadywanie ABI** (`GetExecutingStateName` zwraca `std::string` przez wartość) zabiło grę 17.10. Wołamy tylko
  funkcje o zweryfikowanych sygnaturach.
- **`std::string` dla silnika**: napisy ≤22 znaków muszą być w trybie short libc++, bo inaczej np. `GetState` ich nie znajduje.
- **Postać zginęła** raz po próbie walki, gdy god mode wrócił do „wyłączony” (odzyskano XP z grobu, strata ~1 tys. XP).
  Teraz przy `--spawn` god mode zostaje włączony po próbie.
- Gra łapie własne segfaulty i kończy się `_exit` (bez tombstone'a). Raport daje dopiero hook agenta.
  Archiwum raportów: `crashes/`.
- `MoveTo` do punktu, w którym postać już stoi, nigdy się nie kończy. Walker zaczyna więc od punktu 1, a na końcu wymusza `Idle`.

## Zasady uczciwych porównań

1. Ta sama trasa/arena, parametry, pora dnia (`--time`) i limit FPS.
2. Co najmniej 3 próby. `compare` daje werdykt `BETTER`/`WORSE` tylko przy 95% CI nieobejmującym zera.
3. Przeplataj warianty, jeśli przełączają się bez restartu. Inaczej mierz oba na świeżych procesach.
4. Nie dotykaj ekranu w trakcie próby (poza `--tap`).
