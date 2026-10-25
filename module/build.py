"""Build the installable Magisk zip: module files + frida-inject (arm64).

  python build.py                       # downloads frida-inject from the official Frida GitHub release
  python build.py --injector path/to/frida-inject

The module was tested with Frida 17.22.1.
"""
import argparse, io, lzma, pathlib, urllib.request, zipfile

FRIDA = '17.22.1'
URL = f'https://github.com/frida/frida/releases/download/{FRIDA}/frida-inject-{FRIDA}-android-arm64.xz'
HERE = pathlib.Path(__file__).parent
FILES = ['module.prop', 'customize.sh', 'service.sh', 'action.sh', 'patch.js', 'skip_mount',
         'META-INF/com/google/android/update-binary', 'META-INF/com/google/android/updater-script']

ap = argparse.ArgumentParser()
ap.add_argument('--injector', help='existing frida-inject binary for android-arm64')
ap.add_argument('--out', default=str(HERE.parent / 'dist' / 'tq-android-perf-2.3.1.zip'))
a = ap.parse_args()

if a.injector:
    inj = pathlib.Path(a.injector).read_bytes()
else:
    print('downloading', URL)
    inj = lzma.decompress(urllib.request.urlopen(URL).read())
out = pathlib.Path(a.out)
out.parent.mkdir(parents=True, exist_ok=True)
with zipfile.ZipFile(out, 'w', zipfile.ZIP_DEFLATED) as z:
    for f in FILES:
        z.write(HERE / f, f)
    z.writestr('injector', inj)
print('built', out)
