#!/system/bin/sh
# tq-android-perf: injects the patch script once per game process. Each patch checks function fingerprints
# and switches itself off on unknown builds. State: /data/user/0/com.hg.titanquestultimate/cache/tq-v2-status.json
MODDIR=${0%/*}
umask 077
while [ "$(getprop sys.boot_completed)" != 1 ]; do sleep 3; done
if [ -f "$MODDIR/worker.pid" ]; then
 old=$(cat "$MODDIR/worker.pid")
 case "$old" in *[!0-9]*|'') ;; *)
  if [ -r "/proc/$old/cmdline" ] && tr '\000' ' ' < "/proc/$old/cmdline" | grep -Fq "$MODDIR/service.sh"; then exit 0; fi;;
 esac
fi
echo $$ > "$MODDIR/worker.pid"
trap 'rm -f "$MODDIR/worker.pid"' EXIT
last=''
while [ ! -f "$MODDIR/disable" ] && [ ! -f "$MODDIR/remove" ]; do
 # tq_mods (Titan Quest Mods loader) injects this module's scripts in its own single injection: stand back.
 M=/data/adb/modules/tq_mods
 if [ -f "$M/service.sh" ] && [ ! -f "$M/disable" ] && [ ! -f "$M/remove" ]; then sleep 4; continue; fi
 pid=$(pidof com.hg.titanquestultimate)
 case "$pid" in *[!0-9]*|'') sleep 4; continue;; esac
 start=$(sed 's/.*) //' "/proc/$pid/stat" 2>/dev/null | cut -d' ' -f20)
 key="$pid:$start"
 if [ "$key" = "$last" ] || [ -f "$MODDIR/paused" ]; then sleep 4; continue; fi
 last="$key"
 # Once per process, even on error. Never stack hooks or retry a partial publication.
 if [ -f "$MODDIR/handled" ] && [ "$(cat "$MODDIR/handled")" = "$key" ]; then sleep 4; continue; fi
 echo "$key" > "$MODDIR/handled"
 params='{"mode":"apply"}'
 for f in plt snd slot uneg abbox strm getend menu; do
  [ -f "$MODDIR/no$f" ] || params=$(echo "$params" | sed "s/}\$/,\"$f\":true}/")
 done
 # Add-ons from other modules (tq-addon.js, e.g. tq_traders) join this one injection: a second injection would
 # get the game killed.
 cat "$MODDIR/patch.js" > "$MODDIR/run.js"
 for a in /data/adb/modules/*/tq-addon.js; do
  d=${a%/*}
  [ -f "$a" ] && [ ! -f "$d/disable" ] && [ ! -f "$d/remove" ] && { echo; cat "$a"; } >> "$MODDIR/run.js"
 done
 echo "Patching PID $pid" > "$MODDIR/status.log"
 "$MODDIR/injector" -p "$pid" -s "$MODDIR/run.js" -P "$params" -e >> "$MODDIR/status.log" 2>&1
 sleep 4
done
