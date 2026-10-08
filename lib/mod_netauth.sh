#!/bin/bash
# Stage 3: remote login attempts (SSH, Screen Sharing/VNC) from the unified log.
# sshd lines are info-level, so this poll uses --info.
TW_NA_STATE="$TW_STATE_DIR/netauth.last"
TW_NA_PRED='(process BEGINSWITH "sshd" AND (
      eventMessage BEGINSWITH "Failed " OR eventMessage BEGINSWITH "Invalid user"
   OR eventMessage BEGINSWITH "Accepted " OR eventMessage CONTAINS "maximum authentication attempts"
   OR eventMessage CONTAINS "Too many authentication failures"))
  OR (process == "screensharingd" AND eventMessage CONTAINS "Authentication:")'

tw_mod_netauth() {
  local start now
  now=$(date "+%Y-%m-%d %H:%M:%S")
  if [ -f "$TW_NA_STATE" ]; then start=$(cat "$TW_NA_STATE")
  else start=$(date -v-5M "+%Y-%m-%d %H:%M:%S"); fi

  local raw
  if ! raw=$(/usr/bin/log show --info --start "$start" --end "$now" --style compact --predicate "$TW_NA_PRED" 2>/dev/null); then
    printf '%s' "$start" > "$TW_NA_STATE"     # keep the window; retry it next poll
    tw_log log.error warn module=netauth start="$start"
    return 0
  fi
  printf '%s' "$now" > "$TW_NA_STATE"
  raw=$(printf '%s\n' "$raw" | grep -v '^Timestamp')
  [ -z "$raw" ] && return 0

  local n_fail=0 n_ok=0 line ts proc msg type sev user ip port method ips=""
  while IFS= read -r line; do
    ts="${line%% *} ${line#* }"; ts=${ts:0:23}
    proc=$(printf '%s' "$line" | awk '{print $4}' | sed 's/\[.*//')
    msg=${line#*] }
    user=""; ip=""; port=""; method=""
    case "$proc" in
      sshd*)
        # "Failed password for invalid user X from IP port N ssh2" / "Accepted publickey for X from IP port N ssh2"
        ip=$(printf '%s' "$msg" | sed -n 's/.* from \([0-9a-fA-F.:]*\) port \([0-9]*\).*/\1/p')
        port=$(printf '%s' "$msg" | sed -n 's/.* from [0-9a-fA-F.:]* port \([0-9]*\).*/\1/p')
        user=$(printf '%s' "$msg" | sed -n 's/.* for \(invalid user \)\{0,1\}\([^ ]*\) from .*/\2/p')
        [ -z "$user" ] && user=$(printf '%s' "$msg" | sed -n 's/^Invalid user \([^ ]*\) from .*/\1/p')
        method=$(printf '%s' "$msg" | awk '/^(Failed|Accepted) /{print $2}')
        case "$msg" in
          Accepted*) type=ssh.login; sev=info; n_ok=$((n_ok+1)) ;;
          "Invalid user"*) continue ;;   # the matching "Failed ... invalid user" line follows
          *) type=ssh.failed; sev=alert; n_fail=$((n_fail+1)) ;;
        esac ;;
      screensharingd)
        # "Authentication: FAILED :: User Name: X :: Viewer Address: IP :: Type: DH"
        user=$(printf '%s' "$msg" | sed -n 's/.*User Name: \([^:]*\) ::.*/\1/p' | sed 's/ *$//')
        ip=$(printf '%s' "$msg" | sed -n 's/.*Viewer Address: \([^ :]*\).*/\1/p')
        case "$msg" in
          *SUCCEEDED*) type=vnc.login; sev=info; n_ok=$((n_ok+1)) ;;
          *) type=vnc.failed; sev=alert; n_fail=$((n_fail+1)) ;;
        esac ;;
      *) continue ;;
    esac
    local -a geo=(); local who=""
    if [ -n "$ip" ]; then
      while IFS= read -r kv; do geo+=("$kv"); done < <(tw_enrich_kv "$ip")
      who=$(tw_enrich_summary "$ip")
      [[ " $ips " != *" $ip "* ]] && ips+="$ip ($who) "
    fi
    tw_log "$type" "$sev" when="$ts" user="$user" ip="$ip" port="$port" method="$method" process="$proc" msg="$msg" "${geo[@]}"
  done <<< "$raw"

  if (( n_fail > 0 )); then
    tw_notify "Remote login attempt" "$n_fail failed remote auth attempt(s) from: ${ips:-?}" Sosumi
  elif (( n_ok > 0 )); then
    tw_notify "Remote login succeeded" "$n_ok remote login(s) from: ${ips:-?}" Glass
  fi
}
