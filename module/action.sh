#!/system/bin/sh
MODDIR=${0%/*}
if [ -f "$MODDIR/paused" ]; then
 rm -f "$MODDIR/paused"
 echo 'Patches enabled. Close and restart the game.'
else
 touch "$MODDIR/paused"
 echo 'Patches disabled. Close and restart the game.'
fi
