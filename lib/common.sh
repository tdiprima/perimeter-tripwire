#!/bin/bash
# Shared config, paths, logging.
TW_NAME="perimeter-tripwire"
TW_HOME="${TW_HOME:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"
TW_LOG_DIR="${TW_LOG_DIR:-$HOME/Library/Logs/$TW_NAME}"
TW_EVENTS="$TW_LOG_DIR/events.jsonl"
TW_STATE_DIR="${TW_STATE_DIR:-$HOME/Library/Application Support/$TW_NAME}"
TW_INTERVAL="${TW_INTERVAL:-30}"          # seconds between poll cycles
TW_HEARTBEAT="${TW_HEARTBEAT:-3600}"      # seconds between heartbeat log lines

mkdir -p "$TW_LOG_DIR" "$TW_STATE_DIR"
chmod 700 "$TW_LOG_DIR" "$TW_STATE_DIR"

tw_now() { date -u +"%Y-%m-%dT%H:%M:%SZ"; }

# JSON-escape a string (quotes, backslashes, control chars).
tw_json_str() {
  local s=$1
  s=${s//\\/\\\\}; s=${s//\"/\\\"}
  s=${s//$'\n'/\\n}; s=${s//$'\r'/\\r}; s=${s//$'\t'/\\t}
  if [[ $s == *[[:cntrl:]]* ]]; then   # rare: escape the remaining C0 controls as \u00XX
    local i c
    for i in 1 2 3 4 5 6 7 8 11 12 14 15 16 17 18 19 20 21 22 23 24 25 26 27 28 29 30 31; do
      c=$(printf "\\$(printf '%03o' "$i")"); [[ $s == *"$c"* ]] && s=${s//"$c"/$(printf '\\u%04x' "$i")}
    done
  fi
  printf '"%s"' "$s"
}

# tw_log <type> <severity> key=value ... -> appends one JSON line to events.jsonl
tw_log() {
  local type=$1 sev=$2; shift 2
  local line="{\"ts\":$(tw_json_str "$(tw_now)"),\"type\":$(tw_json_str "$type"),\"severity\":$(tw_json_str "$sev")"
  local kv
  for kv in "$@"; do
    line+=",$(tw_json_str "${kv%%=*}"):$(tw_json_str "${kv#*=}")"
  done
  line+="}"
  printf '%s\n' "$line" >> "$TW_EVENTS"
  printf '%s %s %s\n' "$(tw_now)" "$sev" "$type $*" >&2
}
