#!/usr/bin/env python3
"""Controlled Titan Quest (Android) performance benchmark host.

  python tqbench.py probe
  python tqbench.py record --route agora --seconds 120      (walk the loop yourself)
  python tqbench.py stop-record
  python tqbench.py run --route agora --label base --repeat 3
  python tqbench.py compare base patched

The game must be running with a character loaded and standing in the world.
See README.md.
"""
import argparse, hashlib, json, pathlib, re, socket, statistics, subprocess, sys, time, random

ADB = 'adb'
PKG = 'com.hg.titanquestultimate'
VERSION_CODE = '30005339'
CACHE = f'/data/user/0/{PKG}/cache/'
INJECTOR = '/data/adb/modules/tq_autopatch/injector'
HERE = pathlib.Path(__file__).resolve().parent
AGENT = HERE / 'tq-bench-agent.js'
ROUTES = HERE / 'routes'
RESULTS = HERE / 'results'
SCENARIOS = HERE / 'scenarios'
ARENAS = HERE / 'arenas'
CRASHES = HERE / 'crashes'
RECORD_NAMES = HERE.parent / 'game-data' / 'record-names.txt'
BSLASH = '\\'


# ------------------------------------------------------------------ device helpers
class DeviceTimeout(SystemExit):
    pass


def sh(cmd, check=True, root=True, timeout=120):
    args = [ADB, 'exec-out', 'su', '-c', cmd] if root else [ADB, 'exec-out', cmd]
    try:
        r = subprocess.run(args, capture_output=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        # adb shell/su on this phone sometimes hangs for minutes; surface it as a normal failure.
        raise DeviceTimeout(f'device command timed out after {timeout}s: {cmd[:80]}')
    out = r.stdout.decode('utf-8', 'replace')
    if check and r.returncode != 0:
        raise SystemExit(f'device command failed ({r.returncode}): {cmd}\n{out}{r.stderr.decode(errors="replace")}')
    return out


def game_pid():
    pid = sh(f'pidof {PKG}', check=False).strip()
    if not pid.isdigit():
        raise SystemExit('Game is not running. Start it and load a character first.')
    return int(pid)


def check_version():
    out = sh(f'dumpsys package {PKG} | grep versionCode=', check=False)
    if f'versionCode={VERSION_CODE} ' not in out:
        raise SystemExit(f'Unsupported game version (expected {VERSION_CODE}): {out.strip()}')


def foreground_ok():
    out = sh('dumpsys window | grep -E "mCurrentFocus|mFocusedApp"', check=False)
    return PKG in out


def thermal():
    """Max CPU-ish thermal zone temperature (deg C) plus clocks snapshot."""
    out = sh('for z in /sys/class/thermal/thermal_zone*; do echo "$(cat $z/type 2>/dev/null) $(cat $z/temp 2>/dev/null)"; done; '
             'for p in /sys/devices/system/cpu/cpufreq/policy*; do echo "FREQ $p $(cat $p/scaling_cur_freq) $(cat $p/scaling_max_freq)"; done; '
             'echo "GPU $(cat /sys/class/kgsl/kgsl-3d0/gpuclk 2>/dev/null) $(cat /sys/class/kgsl/kgsl-3d0/max_gpuclk 2>/dev/null)"; '
             'dumpsys battery | grep -E "temperature|level"', check=False)
    zones, freqs, cpu = {}, {}, []
    gpu = None
    batt = {}
    for line in out.splitlines():
        parts = line.split()
        if not parts:
            continue
        if parts[0] == 'FREQ' and len(parts) >= 4:
            freqs[parts[1].rsplit('/', 1)[-1]] = {'cur_khz': int(parts[2]), 'max_khz': int(parts[3])}
        elif parts[0] == 'GPU':
            gpu = parts[1:]
        elif ':' in line:
            k, v = line.split(':', 1)
            batt[k.strip()] = v.strip()
        elif len(parts) == 2 and parts[1].lstrip('-').isdigit():
            t = int(parts[1]) / (1000 if abs(int(parts[1])) > 1000 else 1)
            zones[parts[0]] = t
            if re.search(r'cpu|tsens|cluster|gpu', parts[0], re.I):
                cpu.append(t)
    return {'max_soc_c': max(cpu) if cpu else None, 'zones': zones, 'cpufreq': freqs, 'gpu': gpu,
            'battery_temp_c': int(batt['temperature']) / 10 if batt.get('temperature', '').isdigit() else None,
            'battery_level': batt.get('level')}


def wait_cool(max_c, timeout):
    t0 = time.time()
    while True:
        th = thermal()
        temp = th['max_soc_c']
        if temp is None or temp <= max_c:
            return th
        if time.time() - t0 > timeout:
            print(f'  ! still {temp:.1f} C after {timeout}s cool-down, continuing (marked in result)')
            th['cooldown_timeout'] = True
            return th
        print(f'  cooling: SoC {temp:.1f} C > {max_c} C, waiting...', end='\r')
        time.sleep(10)


def read_device_json(path):
    out = sh(f'cat {path} 2>/dev/null', check=False)
    try:
        return json.loads(out) if out.strip() else None
    except json.JSONDecodeError:
        return None


# ------------------------------------------------------------------ agent server
PORT = 27099
_req_id = 0


class GameDied(SystemExit):
    pass


def _connect(timeout=3):
    s = socket.create_connection(('127.0.0.1', PORT), timeout=timeout)
    return s


def _recv_line(s):
    data = b''
    while not data.endswith(b'\n'):
        chunk = s.recv(4096)
        if not chunk:
            return None
        data += chunk
    return data


def _ping():
    try:
        with _connect(2) as s:
            s.sendall(b'{"id":0,"op":"ping"}\n')
            data = _recv_line(s)
            return json.loads(data)['result'] if data else None
    except (OSError, ValueError, KeyError):
        return None


def ensure_server():
    """One injection per game process: reuse a live server, otherwise inject it."""
    pid = game_pid()
    subprocess.run([ADB, 'forward', f'tcp:{PORT}', f'tcp:{PORT}'], check=True, capture_output=True)
    version = hashlib.sha1(AGENT.read_bytes()).hexdigest()[:12]
    st = _ping()
    if st and st.get('pid') == pid and st.get('version') == version:
        return pid
    if st and st.get('pid') == pid:
        # Older agent build in this process: ask it to detach and free the port.
        with _connect() as sock:
            sock.sendall(b'{"id":-2,"op":"shutdown"}\n')
            reply = json.loads(_recv_line(sock) or b'{}').get('result') or {}
        if not reply.get('ok'):
            raise SystemExit('running agent is outdated and cannot be replaced (busy or no shutdown support); restart the game')
        time.sleep(1)
    check_version()
    # Keep the previous process's crash report (if any) instead of deleting it.
    old = read_device_json(CACHE + 'tq-bench-crash.json')
    if old:
        CRASHES.mkdir(exist_ok=True)
        (CRASHES / f"crash-{old.get('pid')}-{time.strftime('%Y%m%d-%H%M%S')}.json").write_text(json.dumps(old, indent=1), encoding='utf-8')
        print(f"archived crash report of PID {old.get('pid')} to {CRASHES}")
    sh(f'rm -f {CACHE}tq-bench-crash.json {CACHE}tq-bench-server.json', check=False)
    script = 'const PARAMS = ' + json.dumps({'port': PORT, 'version': version}) + ';\n' + AGENT.read_text(encoding='utf-8')
    local = HERE / '.build' / 'tq-bench-server.js'
    local.parent.mkdir(exist_ok=True)
    local.write_text(script, encoding='utf-8')
    remote = '/data/local/tmp/tq-bench-server.js'
    subprocess.run([ADB, 'push', str(local), remote], check=True, capture_output=True)
    print(f'injecting benchmark server into PID {pid} ...')
    try:
        out = sh(f'{INJECTOR} -p {pid} -s {remote} -e', check=False, timeout=60)
    except DeviceTimeout:
        out = ''   # the injector may still have loaded the agent; the ping loop below decides
    if 'rror' in out:
        raise SystemExit('injection failed:\n' + out)
    for _ in range(40):
        st = _ping()
        if st and st.get('pid') == pid and st.get('version') == version:
            return pid
        time.sleep(0.5)
    info = read_device_json(CACHE + 'tq-bench-server.json')
    raise SystemExit(f'server did not answer after injection: {info}')


def crash_report():
    """Why the game died, from the agent's crash hooks and last breadcrumb."""
    return {'crash': read_device_json(CACHE + 'tq-bench-crash.json'),
            'breadcrumb': read_device_json(CACHE + 'tq-bench-breadcrumb.json')}


def request(req, on_progress=None, timeout=600):
    """Send one job to the server; returns its result or raises on error / game death."""
    global _req_id
    pid = ensure_server()
    # Unique across host invocations: the server keeps finished results by id for re-fetching.
    _req_id = _req_id + 1 if _req_id else int(time.time() * 1000) % 1_000_000_000
    req = {**req, 'id': _req_id}
    err = 'connection closed'
    try:
        with _connect() as s:
            s.settimeout(timeout)
            s.sendall((json.dumps(req) + '\n').encode())
            buf = b''
            while True:
                chunk = s.recv(65536)
                if not chunk:
                    break
                buf += chunk
                while b'\n' in buf:
                    line, buf = buf.split(b'\n', 1)
                    msg = json.loads(line)
                    if 'progress' in msg:
                        if on_progress:
                            on_progress(msg['progress'])
                        continue
                    if msg.get('error'):
                        raise SystemExit(f"{req['op']} failed: {msg['error']}")
                    return msg.get('result')
    except (OSError, ValueError) as e:
        err = e
    time.sleep(1.5)
    t_end = time.time() + timeout
    while sh(f'pidof {PKG}', check=False).strip() == str(pid):
        # The adb-forwarded connection dropped but the game lives: the job keeps running in the
        # agent, so re-fetch its result instead of failing the run.
        try:
            subprocess.run([ADB, 'forward', f'tcp:{PORT}', f'tcp:{PORT}'], capture_output=True)
            with _connect() as s:
                s.sendall((json.dumps({'id': -3, 'op': 'result', 'of': req['id']}) + '\n').encode())
                st = json.loads(_recv_line(s) or b'{}').get('result') or {}
            if st.get('ready'):
                msg = st['message']
                print(f'\n  (connection dropped: {err}; result recovered)')
                if msg.get('error'):
                    raise SystemExit(f"{req['op']} failed: {msg['error']}")
                return msg.get('result')
        except (OSError, ValueError):
            pass
        if time.time() > t_end:
            raise SystemExit(f'lost connection to server ({err}); game alive but no result before timeout')
        time.sleep(2)
    print('\nGAME PROCESS DIED. Crash report:')
    print(json.dumps(crash_report(), indent=1)[:8000])
    raise GameDied('game died during ' + req['op'])


def show_progress(p):
    print('  ' + ' '.join(f'{k}={v}' for k, v in p.items()).ljust(88), end='\r')


# ------------------------------------------------------------------ statistics
def pct(sorted_v, q):
    if not sorted_v:
        return None
    k = (len(sorted_v) - 1) * q
    lo = int(k)
    hi = min(lo + 1, len(sorted_v) - 1)
    return sorted_v[lo] + (sorted_v[hi] - sorted_v[lo]) * (k - lo)


def frame_stats(ts_ms, swap_ms, duration_ms):
    iv = [b - a for a, b in zip(ts_ms, ts_ms[1:])]
    if len(iv) < 10:
        return {'error': 'too few frames', 'frames': len(ts_ms)}
    s = sorted(iv)
    worst1 = s[-max(1, len(s) // 100):]
    sw = sorted(swap_ms)
    per_sec = {}
    for t in ts_ms:
        per_sec[int(t // 1000)] = per_sec.get(int(t // 1000), 0) + 1
    timeline = [per_sec.get(i, 0) for i in range(int(duration_ms // 1000))]
    return {
        'frames': len(ts_ms),
        'avg_fps': round(1000 / statistics.mean(iv), 3),
        'frame_ms': {k: round(v, 3) for k, v in {
            'mean': statistics.mean(iv), 'p50': pct(s, .5), 'p90': pct(s, .9), 'p95': pct(s, .95),
            'p99': pct(s, .99), 'max': s[-1], 'stdev': statistics.pstdev(iv)}.items()},
        'low_1pct_fps': round(1000 / statistics.mean(worst1), 3),
        'over_ms': {str(t): sum(1 for x in iv if x > t) for t in (34, 50, 100, 200)},
        'swap_ms': {'mean': round(statistics.mean(sw), 3), 'p95': round(pct(sw, .95), 3), 'max': round(sw[-1], 3)},
        # Time between swaps not spent inside eglSwapBuffers: CPU-side frame work (game+render submission).
        'non_swap_ms_mean': round(statistics.mean(iv) - statistics.mean(swap_ms[:-1]), 3),
        'fps_timeline': timeline,
        'worst_frames': sorted(({'t_s': round(ts_ms[i + 1] / 1000, 2), 'ms': round(iv[i], 1)}
                                for i in sorted(range(len(iv)), key=lambda i: iv[i])[-10:]), key=lambda x: -x['ms']),
    }


ENGINE_KEYS = ('faces', 'drawCalls', 'lights', 'shadowCasting', 'reflections', 'emitters', 'trails', 'objects', 'vramFreeMB')


def engine_summary(samples):
    """Mean/max of the engine's own render counters sampled every 0.5 s (gr.Stats numbers)."""
    if not samples:
        return None
    out = {}
    for k in ENGINE_KEYS:
        v = [s[k] for s in samples if k in s]
        if v:
            out[k] = {'mean': round(statistics.mean(v), 1), 'max': max(v)}
    return out


# ------------------------------------------------------------------ commands
def load_route(name):
    p = ROUTES / f'{name}.json'
    if not p.exists():
        raise SystemExit(f'route {p} not found; record one first')
    return json.loads(p.read_text(encoding='utf-8'))


def cmd_probe(a):
    res = request({'op': 'probe', 'durationSec': a.seconds})
    print(json.dumps(res, indent=2))
    if not foreground_ok():
        print('note: game window does not look focused')


JOYSTICK = (292, 825)   # on-screen joystick centre, 2340x1080 landscape
DIRS = {'up': (0, -120), 'down': (0, 120), 'left': (-120, 0), 'right': (120, 0),
        'upleft': (-85, -85), 'upright': (85, -85), 'downleft': (-85, 85), 'downright': (85, 85)}


def record_driven(a):
    """Record while steering the joystick with adb, e.g. --drive right:1500,up:5000,down:5500,left:1800."""
    import threading
    out = {}
    th = threading.Thread(target=lambda: out.update(r=request(
        {'op': 'record', 'durationSec': a.seconds, 'spacing': a.spacing}, timeout=a.seconds + 90)))
    th.start()
    time.sleep(2)
    for leg in a.drive.split(','):
        d, _, ms = leg.partition(':')
        dx, dy = DIRS[d.strip()]
        x, y = JOYSTICK
        subprocess.run([ADB, 'shell', 'input', 'swipe', str(x), str(y), str(x + dx), str(y + dy), str(int(ms or 2000))], check=True)
    time.sleep(1)
    with _connect() as sock:
        sock.sendall(b'{"id":-1,"op":"stop"}\n')
        _recv_line(sock)
    th.join()
    if 'r' not in out:
        raise SystemExit('recording failed')
    return out['r']


def cmd_record(a):
    print(f'Recording route "{a.route}": walk your loop now (ends after {a.seconds}s or `tqbench.py stop-record`).')
    print('Tip: end close to where you started; the run loops from the last point back to the first.')
    if a.arena:
        exec_steps([{'op': 'teleport', 'world': load_arena(a.arena)['world']}, {'op': 'wait', 'frames': 90}], show=False)
    if a.drive:
        res = record_driven(a)
    else:
        res = request({'op': 'record', 'durationSec': a.seconds, 'spacing': a.spacing}, show_progress, timeout=a.seconds + 90)
    print()
    ROUTES.mkdir(exist_ok=True)
    route = {'name': a.route, 'recorded': time.strftime('%Y-%m-%d %H:%M:%S'), 'pid': game_pid(),
             'spacing': a.spacing, 'points': res['points'], 'regions': res.get('regions'),
             'note': 'World-space coordinates (region-local + Region::GetOffsetFromWorld).'}
    out = ROUTES / f'{a.route}.json'
    out.write_text(json.dumps(route, indent=1), encoding='utf-8')
    length = sum(((p[0] - q[0]) ** 2 + (p[2] - q[2]) ** 2) ** .5 for p, q in zip(route['points'], route['points'][1:] + route['points'][:1]))
    print(f'saved {out} - {len(route["points"])} points, loop length ~{length:.0f} units')


def cmd_stop_record(a):
    # Answered immediately by the server (not queued behind the running record job).
    subprocess.run([ADB, 'forward', f'tcp:{PORT}', f'tcp:{PORT}'], check=True, capture_output=True)
    with _connect() as sock:
        sock.sendall(b'{"id":-1,"op":"stop"}\n')
        print(_recv_line(sock).decode().strip())


PERFETTO_CFG = '''buffers {{ size_kb: 65536 fill_policy: RING_BUFFER }}
duration_ms: {duration_ms}
data_sources {{ config {{ name: "linux.process_stats" process_stats_config {{ scan_all_processes_on_start: true }} }} }}
data_sources {{ config {{ name: "linux.ftrace" ftrace_config {{
ftrace_events: "sched/sched_switch"
ftrace_events: "sched/sched_waking"
ftrace_events: "power/cpu_frequency"
ftrace_events: "kgsl/kgsl_pwrlevel"
ftrace_events: "kgsl/adreno_cmdbatch_submitted"
ftrace_events: "kgsl/adreno_cmdbatch_retired"
atrace_categories: "gfx"
atrace_apps: "{pkg}"
buffer_size_kb: 4096
drain_period_ms: 250
}} }} }}
'''


class PerfettoCapture:
    """Perfetto trace started exactly when the measured phase begins (same window as the frame stats)."""

    def __init__(self, enabled, duration_s, remote):
        self.enabled, self.duration_s, self.remote, self.proc = enabled, duration_s, remote, None

    def start(self):
        if not self.enabled or self.proc:
            return
        cfg = PERFETTO_CFG.format(duration_ms=int(self.duration_s * 1000), pkg=PKG)
        local = HERE / '.build' / 'tq-bench-perfetto.pbtxt'
        local.write_text(cfg, encoding='utf-8')
        subprocess.run([ADB, 'push', str(local), '/data/local/tmp/tq-bench-perfetto.pbtxt'], capture_output=True)
        self.proc = subprocess.Popen([ADB, 'exec-out', 'su', '-c',
                                      f'perfetto --txt -c /data/local/tmp/tq-bench-perfetto.pbtxt -o {self.remote}'],
                                     stdout=subprocess.PIPE, stderr=subprocess.STDOUT)

    def finish(self, local_path):
        if not self.proc:
            return None
        try:
            self.proc.wait(timeout=self.duration_s + 30)
        except subprocess.TimeoutExpired:
            self.proc.kill()
        r = subprocess.run([ADB, 'pull', self.remote, str(local_path)], capture_output=True)
        sh(f'rm -f {self.remote}', check=False)
        return str(local_path) if r.returncode == 0 else None


class SimpleperfCapture:
    """CPU sampling profile (simpleperf, frame-pointer call graphs) over exactly the measured window.
    The report is filtered to the game/render thread afterwards."""

    def __init__(self, enabled, duration_s, remote, freq=1000):
        self.enabled, self.duration_s, self.remote, self.freq, self.proc = enabled, duration_s, remote, freq, None

    def start(self):
        if not self.enabled or self.proc:
            return
        pid = game_pid()
        self.proc = subprocess.Popen([ADB, 'exec-out', 'su', '-c',
                                      f'simpleperf record -p {pid} -e cpu-clock -f {self.freq} --call-graph fp '
                                      f'--duration {self.duration_s} -o {self.remote}'],
                                     stdout=subprocess.PIPE, stderr=subprocess.STDOUT)

    def finish(self, outdir, n, tid):
        if not self.proc:
            return None
        try:
            self.proc.wait(timeout=self.duration_s + 60)
        except subprocess.TimeoutExpired:
            self.proc.kill()
        tids = f'--tids {tid}' if tid else ''
        rep_self = sh(f'simpleperf report -i {self.remote} {tids} --sort dso,symbol --percent-limit 0.3 2>/dev/null', check=False)
        rep_children = sh(f'simpleperf report -i {self.remote} {tids} --children --sort symbol --percent-limit 1 2>/dev/null', check=False)
        (outdir / f'run-{n:03d}.simpleperf-self.txt').write_text(rep_self, encoding='utf-8')
        (outdir / f'run-{n:03d}.simpleperf-children.txt').write_text(rep_children, encoding='utf-8')
        subprocess.run([ADB, 'pull', self.remote, str(outdir / f'run-{n:03d}.perf.data')], capture_output=True)
        sh(f'rm -f {self.remote}', check=False)
        return str(outdir / f'run-{n:03d}.simpleperf-self.txt')


class Tapper:
    """Press on-screen buttons (e.g. player skills) on a fixed schedule during the measured phase.
    Spec: 'X,Y@periodMs' in device pixels (2340x1080 landscape)."""

    def __init__(self, specs):
        import threading
        self.specs = []
        for spec in specs:
            xy, _, per = spec.partition('@')
            x, y = (int(v) for v in xy.split(','))
            self.specs.append((x, y, int(per or 1500) / 1000))
        self.stop_event = threading.Event()
        self.thread = threading.Thread(target=self._run, daemon=True)
        self.started = False

    def start(self):
        if self.specs and not self.started:
            self.started = True
            self.thread.start()

    def _run(self):
        t0 = time.time()
        due = [t0 + i * 0.25 for i in range(len(self.specs))]   # stagger buttons
        while not self.stop_event.is_set():
            now = time.time()
            for i, (x, y, per) in enumerate(self.specs):
                if now >= due[i]:
                    subprocess.run([ADB, 'shell', 'input', 'swipe', str(x), str(y), str(x), str(y), '80'], capture_output=True)
                    due[i] += per
            self.stop_event.wait(0.05)

    def stop(self):
        self.stop_event.set()
        if self.started:
            self.thread.join(timeout=5)


def cmd_run(a):
    scenario = {}
    if a.scenario_file:
        scenario = json.loads(pathlib.Path(a.scenario_file).read_text(encoding='utf-8'))
    if a.arena:
        arena = load_arena(a.arena)
        route = {'name': 'arena:' + a.arena, 'points': [arena['world']]}
        scen = 'idle'
    else:
        route = load_route(a.route or scenario.get('route'))
        scen = scenario.get('scenario', a.scenario)
    points = route['points']
    outdir = RESULTS / a.label
    outdir.mkdir(parents=True, exist_ok=True)
    existing = len(list(outdir.glob('run-*.json')))
    for i in range(a.repeat):
        n = existing + i + 1
        print(f'== {a.label} run {n} ({i + 1}/{a.repeat})')
        if not foreground_ok():
            print('  ! game does not look focused - keep the screen on and the game in front')
        if a.fresh:
            # Clean world (no leftover spawns) and a single agent injection per process.
            cmd_launch(argparse.Namespace(restart=True, menu_wait=25))
            time.sleep(a.settle)
        before = wait_cool(a.max_temp, a.cool_timeout)
        params = {
            'op': 'run', 'scenario': scen,
            'route': points if scen == 'walk' else points[:1],
            'regions': (route.get('regions') if scen == 'walk' else (route.get('regions') or [None])[:1]) if route.get('regions') else None,
            'durationSec': scenario.get('durationSec', a.duration), 'warmupSec': scenario.get('warmupSec', a.warmup),
            'renderOnlyPlayer': scenario.get('renderOnlyPlayer', a.render_only_player),
            'god': scenario.get('god', True), 'spawn': scenario.get('spawn') or spawn_list(a.spawn),
            'timeOfDay': scenario.get('timeOfDay', a.time),
            'fpsLimit': scenario.get('fpsLimit', a.fps_limit),
            'opts': [{'name': o.split(':')[0], 'threshold': float(o.split(':')[1]) if ':' in o and o.split(':')[1].replace('.', '', 1).isdigit() else None,
                      'passthrough': o.endswith(':passthrough')} for o in (a.opt or [])],
            'uncap': scenario.get('uncap', not a.vsync),
            # Spawned monsters outlive the run; keep the character immortal afterwards.
            'restoreGod': not (scenario.get('spawn') or a.spawn),
        }
        pid = ensure_server()
        prepare_opts(params['opts'])
        try:
            taps = scenario.get('taps') or a.tap or []
            tapper = Tapper(taps)
            trace = PerfettoCapture(a.perfetto, params['durationSec'], f'/data/local/tmp/tq-bench-{a.label}-{n}.perfetto-trace')
            prof = SimpleperfCapture(a.simpleperf, params['durationSec'], f'/data/local/tmp/tq-bench-{a.label}-{n}.perf.data')
            def progress(p):
                if p.get('phase') == 'measuring':
                    trace.start()
                    prof.start()
                    tapper.start()
                show_progress(p)
            res = {}
            try:
                res = request(params, progress, timeout=params['durationSec'] + params['warmupSec'] + 120)
            finally:
                tapper.stop()
                trace_file = trace.finish(outdir / f'run-{n:03d}.perfetto-trace')
                prof_file = prof.finish(outdir, n, (res or {}).get('tickThread'))
            params['taps'] = taps
            res['error'] = None
        except GameDied:
            raise
        except SystemExit as e:
            res = {'error': str(e)}
        print()
        after = thermal()
        if res.get('error'):
            print('  ERROR: ' + res['error'])
        stats = frame_stats(res.get('frameTimestampsMs', []), res.get('swapDurationsMs', []), res.get('measuredMs', 0)) \
            if not res.get('error') else None
        if stats and 'error' not in stats:
            stats['engine'] = engine_summary(res.get('engineSamples'))
        rec = {'label': a.label, 'run': n, 'time': time.strftime('%Y-%m-%d %H:%M:%S'), 'pid': pid,
               'route': route['name'], 'params': {k: v for k, v in params.items() if k not in ('route', 'op')},
               'error': res.get('error'), 'laps': res.get('laps'), 'reissues': res.get('reissues'), 'progress': res.get('progress'),
               'stats': stats, 'thermal_before': before, 'thermal_after': after,
               'notes': a.note, 'raw': {'frameTimestampsMs': res.get('frameTimestampsMs'), 'swapDurationsMs': res.get('swapDurationsMs'),
                                         'engineSamples': res.get('engineSamples')}}
        rec['optResults'] = res.get('optResults')
        if a.perfetto:
            rec['perfetto_trace'] = locals().get('trace_file')
        if a.simpleperf:
            rec['simpleperf_report'] = locals().get('prof_file')
        (outdir / f'run-{n:03d}.json').write_text(json.dumps(rec), encoding='utf-8')
        if stats and 'error' not in stats:
            print(f"  avg {stats['avg_fps']:.2f} fps | p50 {stats['frame_ms']['p50']:.1f} ms | p95 {stats['frame_ms']['p95']:.1f} ms"
                  f" | 1% low {stats['low_1pct_fps']:.1f} fps | >50ms {stats['over_ms']['50']} | laps {res.get('laps')}"
                  f" | SoC {before['max_soc_c']}->{after['max_soc_c']} C")
            e = stats.get('engine') or {}
            if e:
                print('  engine: ' + ' | '.join(f"{k} {e[k]['mean']:g} (max {e[k]['max']:g})" for k in
                                                ('faces', 'drawCalls', 'emitters', 'lights', 'objects') if k in e))
        if res.get('error'):
            break
        if i + 1 < a.repeat and a.pause:
            time.sleep(a.pause)
    summarize(a.label)


def runs_of(label):
    runs = [json.loads(p.read_text(encoding='utf-8')) for p in sorted((RESULTS / label).glob('run-*.json'))]
    return [r for r in runs if r.get('stats') and 'error' not in r['stats']]


METRICS = [('avg_fps', lambda s: s['avg_fps'], True), ('p50_ms', lambda s: s['frame_ms']['p50'], False),
           ('p95_ms', lambda s: s['frame_ms']['p95'], False), ('p99_ms', lambda s: s['frame_ms']['p99'], False),
           ('low1%_fps', lambda s: s['low_1pct_fps'], True), ('>50ms', lambda s: s['over_ms']['50'], False),
           ('swap_ms', lambda s: s['swap_ms']['mean'], False), ('nonswap_ms', lambda s: s['non_swap_ms_mean'], False)]


def summarize(label):
    runs = runs_of(label)
    if not runs:
        print('no valid runs')
        return
    print(f'\n{label}: {len(runs)} valid run(s)')
    for name, f, _ in METRICS:
        v = [f(r['stats']) for r in runs]
        print(f'  {name:11} median {statistics.median(v):8.2f}   range {min(v):8.2f} .. {max(v):8.2f}')


def bootstrap_diff(a, b, n=5000, seed=1):
    rnd = random.Random(seed)
    d = sorted(statistics.median(rnd.choices(b, k=len(b))) - statistics.median(rnd.choices(a, k=len(a))) for _ in range(n))
    return d[int(.025 * n)], d[int(.975 * n)]


def cmd_compare(a):
    A, B = runs_of(a.base), runs_of(a.other)
    if not A or not B:
        raise SystemExit('both labels need valid runs')
    print(f'{a.base} ({len(A)} runs)  vs  {a.other} ({len(B)} runs)\n')
    print(f'{"metric":11} {"base":>9} {"other":>9} {"change":>8}   95% CI of change (bootstrap)   verdict')
    lines = []
    for name, f, higher_better in METRICS:
        va, vb = [f(r['stats']) for r in A], [f(r['stats']) for r in B]
        ma, mb = statistics.median(va), statistics.median(vb)
        rel = (mb - ma) / ma * 100 if ma else float('nan')
        if len(A) >= 3 and len(B) >= 3:
            lo, hi = bootstrap_diff(va, vb)
            ci = f'[{lo:+8.2f}, {hi:+8.2f}]'
            if lo > 0 or hi < 0:
                better = (lo > 0) == higher_better
                verdict = 'BETTER' if better else 'WORSE'
            else:
                verdict = 'no clear difference'
        else:
            ci, verdict = '(need >=3 runs each)'.ljust(20), 'insufficient runs'
        line = f'{name:11} {ma:9.2f} {mb:9.2f} {rel:+7.1f}%   {ci:28}   {verdict}'
        lines.append(line)
        print(line)
    # Workload sanity: same route, same duration, similar progress.
    la = [r.get('laps') for r in A]; lb = [r.get('laps') for r in B]
    ra = {r['route'] for r in A} | {r['route'] for r in B}
    print(f'\nroutes: {sorted(ra)}  laps base {la} other {lb}')
    if len(ra) > 1:
        print('WARNING: different routes - not comparable')
    # Rendered workload (engine counters): a variant that draws less changes these, not just FPS.
    print('\nengine workload (median of run means)   base -> other')
    for k in ('faces', 'drawCalls', 'emitters', 'lights', 'shadowCasting', 'objects'):
        va = [r['stats']['engine'][k]['mean'] for r in A if (r['stats'].get('engine') or {}).get(k)]
        vb = [r['stats']['engine'][k]['mean'] for r in B if (r['stats'].get('engine') or {}).get(k)]
        if va and vb:
            ma, mb = statistics.median(va), statistics.median(vb)
            print(f'  {k:14} {ma:12.1f} -> {mb:12.1f}  ({(mb - ma) / ma * 100 if ma else 0:+.1f}%)')


# ------------------------------------------------------------------ dev console / arena
def exec_steps(steps, show=True):
    res = request({'op': 'steps', 'steps': steps}, timeout=60 + 2 * len(steps))
    if show:
        for st in res.get('steps', []):
            step = st['step']
            head = step.get('cmd') or ' '.join(f'{k}={v}' for k, v in step.items())
            if step.get('cmd') and st.get('resolved') and st['resolved'] != step['cmd']:
                head += f'  (-> {st["resolved"]})'
            extra = ' '.join(f'{k}={st[k]}' for k in ('world', 'time', 'god', 'error') if k in st)
            print(f'> {head}  {extra}')
    return res


def cmd_console(a):
    steps = []
    if a.show:
        steps.append({'op': 'show'})
    for c in a.commands:
        steps += [{'cmd': c}, {'op': 'wait', 'frames': 4}]
    if a.list:
        steps.append({'op': 'commands'})
    res = exec_steps(steps)
    if a.list:
        print('\n'.join(res['steps'][-1]['commands']))


def spawn_list(specs):
    out = []
    for spec in specs or []:
        rec, _, count = spec.partition(':')
        out.append({'record': rec.replace(BSLASH, '/'), 'count': int(count or 1)})
    return out


def load_arena(name):
    path = ARENAS / f'{name}.json'
    if not path.exists():
        raise SystemExit(f'no arena {path}; stand somewhere and run: tqbench.py arena save {name}')
    return json.loads(path.read_text(encoding='utf-8'))


def tap(x, y):
    # A 120 ms press: SDL ignores the zero-length taps of `input tap`.
    subprocess.run([ADB, 'shell', 'input', 'swipe', str(x), str(y), str(x), str(y), '120'], check=True)


def cmd_launch(a):
    """(Re)start the game and load the last-selected character (2340x1080 landscape layout)."""
    if a.restart:
        sh(f'am force-stop {PKG}')
        time.sleep(2)
    running = bool(sh(f'pidof {PKG}', check=False).strip())
    in_world = False
    if running:
        try:
            request({'op': 'probe', 'durationSec': 1}, timeout=30)
            in_world = True
        except SystemExit:
            pass
    if not in_world:
        if not running:
            sh(f'am start -n {PKG}/com.hg.titanquest.MainActivity')
            time.sleep(a.menu_wait)
        tap(1986, 207)       # main menu: "Start game"
        time.sleep(6)
        tap(2071, 1041)      # character screen: "Start" (keeps the selected character and difficulty)
    t0 = time.time()
    while time.time() - t0 < 120:
        time.sleep(5)
        try:
            st = request({'op': 'probe', 'durationSec': 1}, timeout=30)
            print(f"in world: PID {game_pid()}, {st['framesPerSec']:.1f} fps, god={st['godMode']}")
            return
        except SystemExit as e:
            print('  waiting for world...', str(e)[:80])
    raise SystemExit('character did not load within 2 minutes; check the screen')


def cmd_route_make(a):
    """Generate a closed loop around a saved arena (no manual walking). Unreachable points show
    up as 'Player stuck at route point N' during a run; lower --radius or record by hand then."""
    import math
    c = load_arena(a.arena)['world']
    pts = [[round(c[0] + a.radius * math.cos(2 * math.pi * i / a.points), 2), c[1],
            round(c[2] + a.radius * math.sin(2 * math.pi * i / a.points), 2)] for i in range(a.points)]
    ROUTES.mkdir(exist_ok=True)
    out = ROUTES / f'{a.route}.json'
    out.write_text(json.dumps({'name': a.route, 'generated_from_arena': a.arena, 'radius': a.radius,
                               'recorded': time.strftime('%Y-%m-%d %H:%M:%S'), 'points': pts}, indent=1), encoding='utf-8')
    print(f'saved {out}: {a.points} points, radius {a.radius} around {c}')


PLT_BLOB = HERE / 'plt-bypass.bin'            # sites inside dynamic-symbol functions
PLT_BLOB_FULL = HERE / 'plt-bypass-full.bin'  # + functions found by Ghidra (outlined/local helpers)


def push_app_file(local, name):
    """Copy a file into the game's cache dir, readable by the app (owner + SELinux label of an app file)."""
    ensure_server()   # guarantees the app-created reference file tq-bench-server.json exists
    tmp = f'/data/local/tmp/{name}'
    subprocess.run([ADB, 'push', str(local), tmp], check=True, capture_output=True)
    # toybox chown has no --reference; the setgid cache dir already gives the group and SELinux label.
    sh(f'cp {tmp} {CACHE}{name} && chown "$(stat -c %u:%g {CACHE})" {CACHE}{name} && chmod 640 {CACHE}{name} && rm -f {tmp}')


def prepare_opts(opts):
    for o in opts or []:
        name = o['name'] if isinstance(o, dict) else o
        if name in ('pltbypass', 'pltbypassfull'):
            blob = PLT_BLOB_FULL if name == 'pltbypassfull' else PLT_BLOB
            if not blob.exists():
                raise SystemExit(f'{blob.name} missing: see plt_bypass_build.py')
            push_app_file(blob, 'tq-bench-plt-bypass.bin')


def cmd_opt(a):
    prepare_opts([a.name])
    step = {'op': 'opt', 'name': a.name, 'on': a.state == 'on'}
    if a.threshold is not None:
        step['threshold'] = a.threshold
    if getattr(a, 'verify', False):
        step['verify'] = True
    if getattr(a, 'passthrough', False):
        step['passthrough'] = True
    if getattr(a, 'ttl_ms', None):
        step['ttlMs'] = a.ttl_ms
    step['op'] = 'opt'
    print(json.dumps(request(step, timeout=120), indent=1))


def cmd_fps(a):
    st = exec_steps([{'op': 'fps', 'limit': a.limit} if a.limit is not None else {'op': 'fps'}], show=False)['steps'][0]
    names = {0: 'off (display refresh)', 1: 'refresh/2', 2: 'refresh/3', 3: 'refresh/4'}
    print(f"FPS limit: {names.get(st['before'])} -> {names.get(st['fpsLimit'])}  (session only; options.txt untouched)")


def cmd_server(a):
    pid = ensure_server()
    print(json.dumps(_ping(), indent=1))


def cmd_crash(a):
    print(json.dumps(crash_report(), indent=1))


def spawn_steps(specs):
    steps = []
    for spec in specs or []:
        rec, _, count = spec.partition(':')
        steps += [{'op': 'spawn', 'record': rec.replace(BSLASH, '/'), 'count': int(count or 1)}, {'op': 'wait', 'frames': 10}]
    return steps


def cmd_spawn(a):
    exec_steps(spawn_steps(a.records))


def cmd_arena(a):
    ARENAS.mkdir(exist_ok=True)
    path = ARENAS / f'{a.name}.json'
    if a.action == 'save':
        res = exec_steps([{'op': 'pos'}, {'op': 'state'}], show=False)
        world = res['steps'][0]['world']
        arena = {'name': a.name, 'world': world, 'saved': time.strftime('%Y-%m-%d %H:%M:%S'),
                 'time_of_day_at_save': res['steps'][1].get('time')}
        if path.exists():
            arena = {**json.loads(path.read_text(encoding='utf-8')), **arena}
        path.write_text(json.dumps(arena, indent=1), encoding='utf-8')
        print(f'saved arena {a.name} at {world}')
        return
    arena = load_arena(a.name)
    # Saved defaults in the arena file apply unless overridden on the command line.
    hour = a.time if a.time is not None else arena.get('hour')
    steps = [{'op': 'teleport', 'world': arena['world']}, {'op': 'wait', 'frames': 60}]
    if not a.no_god:
        steps.append({'op': 'god', 'on': True})
    if hour is not None:
        steps.append({'op': 'time', 'hour': hour, 'frozen': not a.run_time})
    if a.envfx is not None:
        steps.append({'op': 'envfx', 'on': a.envfx == 'on'})
    steps += spawn_steps(a.spawn or arena.get('spawn'))
    steps.append({'op': 'state'})
    exec_steps(steps)


def cmd_records(a):
    if not RECORD_NAMES.exists():
        raise SystemExit(f'{RECORD_NAMES} missing (extract from split_AP_database.apk, see README)')
    pat = re.compile(a.pattern, re.I)
    hits = [n for n in RECORD_NAMES.read_text().splitlines() if pat.search(n)]
    for n in hits[:a.limit]:
        print(n.replace(BSLASH, '/'))
    if len(hits) > a.limit:
        print(f'... {len(hits) - a.limit} more')


def main():
    global ADB
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('--adb', default=ADB)
    sp = ap.add_subparsers(dest='cmd', required=True)
    p = sp.add_parser('probe', help='read-only check that hooks and engine objects resolve')
    p.add_argument('--seconds', type=int, default=5)
    p = sp.add_parser('record', help='record a route while you walk it')
    p.add_argument('--route', required=True)
    p.add_argument('--seconds', type=int, default=120)
    p.add_argument('--spacing', type=float, default=8.0, help='min distance between route points (world units)')
    p.add_argument('--arena', help='teleport to this saved arena before recording')
    p.add_argument('--drive', help='steer the joystick automatically: dir:ms,... (up/down/left/right/upleft/...)')
    sp.add_parser('stop-record')
    p = sp.add_parser('run', help='run the benchmark')
    p.add_argument('--route')
    p.add_argument('--label', required=True, help='variant name, e.g. base / grass-off / patch-v4')
    p.add_argument('--scenario', choices=['walk', 'idle'], default='walk')
    p.add_argument('--scenario-file', help='JSON scenario (overrides scenario/duration/warmup/spawn)')
    p.add_argument('--duration', type=int, default=60)
    p.add_argument('--warmup', type=int, default=10)
    p.add_argument('--repeat', type=int, default=3)
    p.add_argument('--pause', type=int, default=5, help='seconds between repeats (on top of cool-down)')
    p.add_argument('--max-temp', type=float, default=99.0, help='optionally wait until hottest SoC zone <= this before each run (off by default; temps and clocks are always recorded)')
    p.add_argument('--cool-timeout', type=int, default=600)
    p.add_argument('--render-only-player', action='store_true', help='diagnostic: skip world rendering')
    p.add_argument('--arena', help='stand at a saved arena instead of walking a route (idle scenario)')
    p.add_argument('--spawn', nargs='*', help='RECORD[:COUNT] spawned during warmup')
    p.add_argument('--time', type=float, help='freeze time of day at this hour during the run')
    p.add_argument('--fps-limit', type=int, default=0, choices=[0, 1, 2, 3],
                   help='engine FPS_LIMIT during the run: 0 = off (display refresh, default), 1 = 1/2, 2 = 1/3, 3 = 1/4; restored after')
    p.add_argument('--vsync', action='store_true',
                   help='keep Swappy frame pacing (default: bypass it with eglSwapInterval 0 so frame times are not rounded to vsync multiples)')
    p.add_argument('--tap', nargs='*', help='press buttons during measurement: X,Y@periodMs (device px), e.g. player skills')
    p.add_argument('--opt', nargs='*', help='session-only engine optimizations to enable for the run, e.g. slotcache:1.0')
    p.add_argument('--fresh', action='store_true', help='restart the game before every run (needed with --spawn and repeats)')
    p.add_argument('--perfetto', action='store_true', help='record a Perfetto trace over exactly the measured window')
    p.add_argument('--simpleperf', action='store_true', help='CPU profile (1 kHz, fp call graphs) over the measured window; adds overhead')
    p.add_argument('--settle', type=int, default=10, help='seconds to idle after a fresh load before cooling/measuring')
    p.add_argument('--note', default='')
    p = sp.add_parser('compare')
    p.add_argument('base')
    p.add_argument('other')
    p = sp.add_parser('summary')
    p.add_argument('label')
    p = sp.add_parser('console', help='run developer console commands in the game, e.g. "God true" "gr.Stats true"')
    p.add_argument('commands', nargs='*')
    p.add_argument('--show', action='store_true', help='also open the console on the phone screen')
    p.add_argument('--list', action='store_true', help='list registered console commands')
    p = sp.add_parser('spawn', help='spawn records at the player: RECORD[:COUNT] ...')
    p.add_argument('records', nargs='+')
    p = sp.add_parser('arena', help='save / go to a fixed test arena')
    p.add_argument('action', choices=['save', 'go'])
    p.add_argument('name')
    p.add_argument('--time', type=float, help='time of day to set (frozen unless --run-time)')
    p.add_argument('--run-time', action='store_true')
    p.add_argument('--envfx', choices=['on', 'off'], help='weather/environment particle effects')
    p.add_argument('--spawn', nargs='*', help='RECORD[:COUNT] to spawn after arriving')
    p.add_argument('--no-god', action='store_true')
    sp.add_parser('server', help='inject (if needed) and ping the in-game server')
    p = sp.add_parser('route-make', help='generate a circular route around a saved arena')
    p.add_argument('route')
    p.add_argument('--arena', required=True)
    p.add_argument('--radius', type=float, default=12)
    p.add_argument('--points', type=int, default=8)
    p = sp.add_parser('opt', help='toggle a session-only engine optimization (slotcache, pltbypass)')
    p.add_argument('name', choices=['slotcache', 'slotnative', 'pltbypass', 'pltbypassfull', 'floorcache', 'throttle', 'soundcache', 'uniformneg', 'abboxfast', 'streamcache', 'getendcache', 'getobjcache', 'regionfast'])
    p.add_argument('--verify', action='store_true')
    p.add_argument('--passthrough', action='store_true')
    p.add_argument('--ttl-ms', type=float)
    p.add_argument('state', choices=['on', 'off'])
    p.add_argument('--threshold', type=float)
    p = sp.add_parser('fps', help='show or set the engine FPS limit for this session')
    p.add_argument('limit', type=int, nargs='?', choices=[0, 1, 2, 3])
    p = sp.add_parser('launch', help='start the game and load the selected character')
    p.add_argument('--restart', action='store_true', help='force-stop the game first')
    p.add_argument('--menu-wait', type=int, default=25)
    sp.add_parser('crash', help='show the last crash report written by the agent')
    p = sp.add_parser('records', help='search game database record names (regex)')
    p.add_argument('pattern')
    p.add_argument('--limit', type=int, default=40)
    a = ap.parse_args()
    ADB = a.adb
    if a.cmd == 'run' and not (a.route or a.scenario_file or a.arena):
        ap.error('run needs --route, --arena or --scenario-file')
    {'probe': cmd_probe, 'record': cmd_record, 'stop-record': cmd_stop_record, 'run': cmd_run,
     'compare': cmd_compare, 'summary': lambda a: summarize(a.label), 'console': cmd_console,
     'spawn': cmd_spawn, 'arena': cmd_arena, 'records': cmd_records,
     'server': cmd_server, 'crash': cmd_crash, 'launch': cmd_launch, 'fps': cmd_fps, 'opt': cmd_opt, 'route-make': cmd_route_make}[a.cmd](a)


if __name__ == '__main__':
    main()
