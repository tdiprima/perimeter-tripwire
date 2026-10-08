#!/bin/bash
# tw_enrich <ip> -> sets TW_E_* variables (rdns, asn, asname, org, country, class, mac, note)
# tw_enrich_kv <ip> -> prints key=value args prefixed with "geo_" for tw_log
# tw_enrich_summary <ip> -> one-line human summary for notifications
tw_enrich() {
  local k v; unset "${!TW_E_@}" 2>/dev/null
  while IFS='=' read -r k v; do [ -n "$k" ] && printf -v "TW_E_$k" '%s' "$v"; done \
    < <(/bin/bash "$TW_HOME/bin/enrich-ip" "$1" 2>/dev/null)
}
tw_enrich_kv() {
  /bin/bash "$TW_HOME/bin/enrich-ip" "$1" 2>/dev/null | grep -vE '^ip=' | sed 's/^/geo_/'
}
tw_enrich_summary() {
  tw_enrich "$1"
  case "${TW_E_scope:-}" in
    loopback) echo "this Mac (localhost)" ;;
    lan)      echo "LAN ${TW_E_rdns:-$1}${TW_E_mac:+ mac $TW_E_mac}${TW_E_note:+ – $TW_E_note}" ;;
    *)        echo "${TW_E_asn:+AS$TW_E_asn }${TW_E_org:-${TW_E_asname:-unknown}}, ${TW_E_country:-??} [${TW_E_class:-?}]${TW_E_rdns:+ $TW_E_rdns}" ;;
  esac
}
