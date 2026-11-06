"""Compile a C file into a flat arm64 blob with NDK clang: python build_blob.py bone.c
The *_CODE / *_SYM arrays in patch.js were produced this way from the .c files in this folder.
Prints JSON {code:[bytes], symbols:{name:offset}} to <name>.blob.json. Data (.ctx) is placed last.
ANDROID_NDK_HOME (or ANDROID_NDK_ROOT) must point at an installed Android NDK (tested with r30)."""
import subprocess, sys, pathlib, json, glob, os
src = pathlib.Path(sys.argv[1]).resolve()
ndk_root = os.environ.get('ANDROID_NDK_HOME') or os.environ.get('ANDROID_NDK_ROOT')
if not ndk_root: sys.exit('set ANDROID_NDK_HOME to your Android NDK directory')
ndk = pathlib.Path(sorted(glob.glob(os.path.join(ndk_root, 'toolchains', 'llvm', 'prebuilt', '*', 'bin')))[-1])
ext = '.exe' if os.name == 'nt' else ''
cc, lld, objcopy, nm = (str(ndk / (n + ext)) for n in ('clang', 'ld.lld', 'llvm-objcopy', 'llvm-nm'))
out = src.with_suffix('')
lds = out.with_suffix('.lds')
lds.write_text('SECTIONS { . = 0; .text : { *(.text.a) *(.text.b) *(.text*) *(.rodata*) } . = ALIGN(16); .ctx : { *(.ctx) } /DISCARD/ : { *(.comment) *(.note*) *(.eh_frame*) } }\n')
o = str(out) + '.o'; elf = str(out) + '.elf'; binf = str(out) + '.bin'
subprocess.run([cc, '--target=aarch64-linux-android30', '-O2', '-ffp-contract=off', '-ffreestanding', '-fno-builtin', '-fno-pic', '-fno-pie',
                '-fno-stack-protector', '-fno-strict-aliasing', '-fno-asynchronous-unwind-tables', '-fno-unwind-tables', '-mno-outline-atomics',
                '-c', str(src), '-o', o], check=True)
subprocess.run([lld, '-T', str(lds), '-o', elf, o, '--no-dynamic-linker', '-static', '-nostdlib', '-e', '0'], check=True)
subprocess.run([objcopy, '-O', 'binary', elf, binf], check=True)
syms = {}
for line in subprocess.run([nm, elf], capture_output=True, text=True, check=True).stdout.splitlines():
    a, t, n = line.split()
    syms[n] = int(a, 16)
code = list(pathlib.Path(binf).read_bytes())
json.dump({'code': code, 'symbols': syms}, open(str(out) + '.blob.json', 'w'))
print(len(code), {k: hex(v) for k, v in syms.items()})
