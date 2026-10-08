#!/bin/bash
# Optional evidence capture on local auth failure (stage 6).
# Webcam photo if `imagesnap` (brew) is installed; otherwise a screenshot.
# Both need a one-time TCC permission (Camera / Screen Recording) for bash.
TW_SNAPSHOT="${TW_SNAPSHOT:-1}"
tw_snapshot() {
  [ "$TW_SNAPSHOT" = 1 ] || return 0
  local d="$TW_LOG_DIR/snapshots" base; mkdir -p "$d"; chmod 700 "$d"
  base="$d/$(date +%Y%m%dT%H%M%S)-$1"
  if command -v imagesnap >/dev/null 2>&1; then
    imagesnap -q -w 1 "$base-cam.jpg" >/dev/null 2>&1 && tw_log snapshot info file="$base-cam.jpg"
  fi
  /usr/sbin/screencapture -x -t jpg "$base-screen.jpg" >/dev/null 2>&1 && tw_log snapshot info file="$base-screen.jpg"
}
