#!/bin/bash
# tw_notify <title> <message> [sound] [key]  -> rate-limited via bin/notify
tw_notify() {
  local title=$1 msg=$2 sound=${3:-Basso} key=${4:-$1}
  /bin/bash "$TW_HOME/bin/notify" "$key" "$title" "$msg" "$sound" || tw_log notify.failed warn msg="$msg"
}
