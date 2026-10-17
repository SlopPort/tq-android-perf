[ "$ARCH" = arm64 ] || abort "This module needs an arm64 (64-bit ARM) Android device"
set_perm_recursive "$MODPATH" 0 0 0755 0644
set_perm "$MODPATH/injector" 0 0 0700
set_perm "$MODPATH/service.sh" 0 0 0700
set_perm "$MODPATH/action.sh" 0 0 0700
ui_print "- Start Titan Quest; patches apply a few seconds after the main menu appears."
ui_print "- Status: /data/user/0/com.hg.titanquestultimate/cache/tq-v2-status.json"
