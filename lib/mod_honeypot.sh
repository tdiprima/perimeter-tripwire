#!/bin/bash
# Stage 4: keep the honeypot (bin/honeypot.py, stdlib python3 from Xcode CLT) alive.
# TW_HP_PORTS format: "port=banner|port=banner" ; banner may use \r\n escapes.
# Ports must be >1024 (daemon is not root).
TW_HP_PORTS="${TW_HP_PORTS:-2222=SSH-2.0-OpenSSH_9.9\\r\\n|8080=HTTP/1.1 200 OK\\r\\nServer: nginx\\r\\n\\r\\n|6379=-ERR\\r\\n|3389=}"
TW_HP_ENABLED="${TW_HP_ENABLED:-1}"
TW_HP_PID="$TW_STATE_DIR/honeypot.pid"
TW_HP_PY="${TW_HP_PY:-/usr/bin/python3}"

tw_hp_stop_all() {
  local pid; pid=$(cat "$TW_HP_PID" 2>/dev/null)
  [ -n "$pid" ] && kill "$pid" 2>/dev/null
  rm -f "$TW_HP_PID"
}

tw_mod_honeypot() {
  [ "$TW_HP_ENABLED" = 1 ] || return 0
  local pid; pid=$(cat "$TW_HP_PID" 2>/dev/null)
  if [ -n "$pid" ] && kill -0 "$pid" 2>/dev/null; then return 0; fi
  if [ ! -x "$TW_HP_PY" ]; then tw_log honeypot.disabled warn reason="no $TW_HP_PY"; TW_HP_ENABLED=0; return 0; fi
  "$TW_HP_PY" -I "$TW_HOME/bin/honeypot.py" "$TW_EVENTS" "$TW_LOG_DIR/honeypot" "$TW_STATE_DIR" "$TW_HP_PORTS" \
      >>"$TW_LOG_DIR/daemon.log" 2>&1 &
  echo $! > "$TW_HP_PID"
  tw_log honeypot.start info pid="$!" ports="$TW_HP_PORTS"
}
