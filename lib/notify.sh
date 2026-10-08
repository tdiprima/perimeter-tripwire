#!/bin/bash
# macOS notifications via osascript.
# tw_notify <title> <message> [sound]
tw_notify() {
  local title=$1 msg=$2 sound=${3:-Basso}
  title=${title//\"/\\\"}; msg=${msg//\"/\\\"}
  osascript -e "display notification \"$msg\" with title \"$title\" subtitle \"Perimeter Tripwire\" sound name \"$sound\"" 2>/dev/null \
    || tw_log notify.failed warn msg="$msg"
}
