#!/bin/bash
# Stage 2: local authentication failures from the unified log.
# Catches: login window / lock screen password failures, sudo failures,
# any PAM client (su, login, sshd, screensharingd) rejecting a password,
# and Touch ID mismatches. opendirectoryd failures that coincide with akd (Apple ID /
# iCloud) re-verifying its cached copy of the login password are a stale credential,
# not an intruder: they are logged as warn with source=akd and get a quieter notice.
TW_LA_STATE="$TW_STATE_DIR/localauth.last"
TW_LA_PRED='(subsystem == "com.apple.opendirectoryd" AND eventMessage CONTAINS "Authentication failed for")
  OR (process == "sudo" AND eventMessage CONTAINS "incorrect password attempt")
  OR (eventMessage CONTAINS "The authtok is incorrect")
  OR (process == "akd" AND eventMessage CONTAINS "Verify basic credentials")
  OR (process == "biometrickitd" AND (eventMessage CONTAINS[c] "match failed" OR eventMessage CONTAINS[c] "no match" OR eventMessage CONTAINS[c] "biometry failed"))'

tw_la_user_from_uuid() {
  dscl . -search /Users GeneratedUID "$1" 2>/dev/null | awk 'NR==1{print $1}'
}

tw_mod_localauth() {
  local start now
  now=$(date "+%Y-%m-%d %H:%M:%S")
  if [ -f "$TW_LA_STATE" ]; then start=$(cat "$TW_LA_STATE")
  else start=$(date -v-5M "+%Y-%m-%d %H:%M:%S"); fi

  local raw
  if ! raw=$(/usr/bin/log show --start "$start" --end "$now" --style compact --predicate "$TW_LA_PRED" 2>/dev/null); then
    printf '%s' "$start" > "$TW_LA_STATE"     # keep the window; retry it next poll
    tw_log log.error warn module=localauth start="$start"
    return 0
  fi
  printf '%s' "$now" > "$TW_LA_STATE"
  raw=$(printf '%s\n' "$raw" | grep -v '^Timestamp')
  [ -z "$raw" ] && return 0

  local console_user active_ttys src_procs
  console_user=$(stat -f%Su /dev/console 2>/dev/null)
  active_ttys=$(who | awk '{print $1"@"$2}' | tr '\n' ' ')
  # PAM clients that rejected a password in this window -> likely source of the opendirectoryd failures.
  src_procs=$(printf '%s\n' "$raw" | grep -F 'The authtok is incorrect' | awk '{print $4}' | sed 's/\[.*//' | sort -u | tr '\n' ',' | sed 's/,$//')
  # akd re-checking its cached login password -> OD failures without a PAM client are its doing.
  local akd_check=0
  printf '%s\n' "$raw" | grep -q 'akd\[.*Verify basic credentials' && akd_check=1
  [ -z "$src_procs" ] && (( akd_check )) && src_procs=akd

  local n=0 n_akd=0 line ts proc msg uuid user sev type extra
  while IFS= read -r line; do
    ts="${line%% *} ${line#* }"; ts=${ts:0:23}
    proc=$(printf '%s' "$line" | awk '{print $4}' | sed 's/\[.*//')
    msg=${line#*] }
    case "$msg" in
      *"Authentication failed for"*)
        uuid=$(printf '%s' "$msg" | sed -n 's/.*(\([0-9A-F-]\{36\}\)).*/\1/p')
        user=$(tw_la_user_from_uuid "$uuid"); user=${user:-unknown}
        type=localauth.failed; sev=alert
        [ "$src_procs" = akd ] && sev=warn
        extra="source=${src_procs:-loginwindow/lockscreen}"
        ;;
      *"incorrect password attempt"*)
        type=sudo.failed; sev=alert
        user=$(printf '%s' "$msg" | awk '{print $1}')
        extra="detail=$(printf '%s' "$msg" | sed 's/^[^:]*: //')"
        ;;
      *"authtok is incorrect"*|*"Verify basic credentials"*)
        continue ;;   # already folded into source= on the opendirectoryd event
      *)
        type=touchid.failed; sev=alert; user=$console_user; extra="detail=$msg" ;;
    esac
    tw_log "$type" "$sev" when="$ts" user="$user" process="$proc" console_user="$console_user" sessions="$active_ttys" "$extra"
    n=$((n+1)); [ "$sev" = warn ] && n_akd=$((n_akd+1))
  done <<< "$raw"

  (( n == 0 )) && return 0
  if [ "$src_procs" = akd ] && (( n == n_akd )); then
    tw_notify "Stale iCloud password" "Apple ID (akd) rejected $n cached login password check(s). Open System Settings > Apple Account and re-enter your Mac password." Basso
  else
    tw_snapshot localauth
    tw_notify "Login attempt blocked" "$n failed auth attempt(s) via ${src_procs:-loginwindow/lockscreen}. Console user: $console_user." Sosumi
  fi
}
