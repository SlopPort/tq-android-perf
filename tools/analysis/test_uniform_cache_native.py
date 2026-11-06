"""Execute the actual UNIFORM_C cache logic with fake GL callbacks on a host C compiler.
Validates cache/invalidation semantics, not Frida hooks, Android ABI or real GL drivers.
Temporary compiler outputs stay outside the repository.
"""
import os, pathlib, re, shutil, subprocess, tempfile

ROOT = pathlib.Path(__file__).resolve().parents[2]
source = (ROOT / 'module/patch.js').read_text(encoding='utf8')
match = re.search(r'const UNIFORM_C = `([^`]+)`;', source)
if not match:
    raise SystemExit('UNIFORM_C source not found')
body = match.group(1).replace('#include <glib.h>', """
#include <stdint.h>
typedef uint8_t guint8;
typedef uint32_t guint32;
typedef uint64_t guint64;
typedef int32_t gint32;
typedef int64_t glong;
typedef uint64_t gulong;
""")
tests = r'''
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
static int driver_calls, location = -1, links, binaries, deletes;
static int fake_get(guint32 program, const char *name) {
  (void)program; (void)name; driver_calls++; return location;
}
static void fake_link(guint32 program) {(void)program; links++; location = 4;}
static void fake_binary(guint32 program, guint32 fmt, const void *p, gint32 n) {
  (void)program; (void)fmt; (void)p; (void)n; binaries++; location = 13;
}
static void fake_delete(guint32 program) {(void)program; deletes++;}
static const char *fake_name(glong idx) {(void)idx; return "missing_uniform";}
int (*gl_get)(guint32, const char *) = fake_get;
void (*gl_link)(guint32) = fake_link;
void (*gl_binary)(guint32,guint32,const void*,gint32) = fake_binary;
void (*gl_delete)(guint32) = fake_delete;
const char *(*i2n)(glong) = fake_name;
int enabled = 1;
guint64 st[4];
guint8 neg[NP * 16];
#define CHECK(x) do { if (!(x)) {fprintf(stderr,"FAIL line %d: %s\n",__LINE__,#x);return 1;} } while(0)
static void reset_slots(guint8 *self) {memset(self,255,1024);}
int main(void) {
  guint8 *self = malloc(1024); CHECK(self != NULL); reset_slots(self);
  CHECK(sizeof(glong)==8 && sizeof(guint32)==4);
  CHECK(gul(self,1,-1)==-1 && gul(self,1,109)==-1 && driver_calls==0);
  *(int *)(self+0xe4)=7;
  CHECK(gul(self,1,0)==7 && driver_calls==0); reset_slots(self);
  CHECK(gul(self,1,0)==-1 && driver_calls==1);
  CHECK(gul(self,1,0)==-1 && driver_calls==1 && st[2]==1);
  CHECK(gul(self,1,1)==-1 && driver_calls==2);
  CHECK(gul(self,2,0)==-1 && driver_calls==3);
  enabled=0; CHECK(gul(self,1,0)==-1 && driver_calls==4); enabled=1;
  link_hook(1); CHECK(links==1); reset_slots(self);
  CHECK(gul(self,1,0)==4 && driver_calls==5);
  location=-1; reset_slots(self); CHECK(gul(self,3,0)==-1);
  binary_hook(3,0,NULL,0); CHECK(binaries==1); reset_slots(self);
  CHECK(gul(self,3,0)==13);
  location=-1; reset_slots(self); CHECK(gul(self,4,0)==-1);
  delete_hook(4); CHECK(deletes==1); location=11; reset_slots(self);
  CHECK(gul(self,4,0)==11);
  location=-1; reset_slots(self); int before=driver_calls;
  CHECK(gul(self,NP,0)==-1 && gul(self,NP,0)==-1 && driver_calls==before+2);
  before=driver_calls; CHECK(gul(self,5,108)==-1);
  CHECK(gul(self,5,108)==-1 && driver_calls==before+1);
  free(self); puts("PASS: actual C cache bounds, positive/negative hits, disabled mode, program/index separation, link/binary/delete invalidation and program-name reuse. Host fake-GL test only."); return 0;
}
'''
compiler = shutil.which('gcc')
if not compiler:
    raise SystemExit('gcc is required for this native semantic test')
env = os.environ.copy()
env['PATH'] = str(pathlib.Path(compiler).parent) + os.pathsep + env.get('PATH','')
with tempfile.TemporaryDirectory(prefix='tq-uniform-test-') as temp:
    c = pathlib.Path(temp)/'test.c'
    exe = pathlib.Path(temp)/('test.exe' if os.name=='nt' else 'test')
    c.write_text(body + tests, encoding='utf8')
    subprocess.run([compiler,'-std=c11','-O2','-Wall','-Wextra','-Werror',str(c),'-o',str(exe)], check=True, env=env)
    subprocess.run([str(exe)], check=True, env=env)
