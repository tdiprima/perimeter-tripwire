#!/bin/bash
# Stage 6: log rotation, capture pruning, permissions. Runs at most once an hour.
TW_HK_STATE="$TW_STATE_DIR/housekeeping.last"
TW_ROTATE_MB="${TW_ROTATE_MB:-20}"      # rotate events.jsonl / daemon.log above this size
TW_KEEP_ROTATED="${TW_KEEP_ROTATED:-5}"
TW_KEEP_DAYS="${TW_KEEP_DAYS:-30}"      # honeypot captures / snapshots older than this are deleted

tw_hk_rotate() {
  local f=$1 i
  [ -f "$f" ] || return 0
  (( $(stat -f%z "$f") > TW_ROTATE_MB * 1048576 )) || return 0
  for (( i=TW_KEEP_ROTATED-1; i>=1; i-- )); do [ -f "$f.$i" ] && mv "$f.$i" "$f.$((i+1))"; done
  cp "$f" "$f.1" && : > "$f"        # copy+truncate so open writers keep working
  chmod 600 "$f" "$f.1"
  tw_log housekeeping.rotated info file="$f"
}

tw_mod_housekeeping() {
  local now; now=$(date +%s)
  if [ -f "$TW_HK_STATE" ] && (( now - $(stat -f%m "$TW_HK_STATE") < 3600 )); then return 0; fi
  touch "$TW_HK_STATE"
  chmod 700 "$TW_LOG_DIR" "$TW_STATE_DIR"; chmod 600 "$TW_EVENTS" 2>/dev/null
  tw_hk_rotate "$TW_EVENTS"
  tw_hk_rotate "$TW_LOG_DIR/daemon.log"
  find "$TW_LOG_DIR/honeypot" "$TW_LOG_DIR/snapshots" -type f -mtime +"$TW_KEEP_DAYS" -delete 2>/dev/null
  find "$TW_STATE_DIR/ipcache" "$TW_STATE_DIR/notify" -type f -mtime +30 -delete 2>/dev/null
  find "$TW_STATE_DIR" -maxdepth 1 -name 'hp.*' -type f -mtime +1 -delete 2>/dev/null
}
