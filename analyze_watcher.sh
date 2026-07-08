#!/usr/bin/env bash
# Watcher analysis engine — extracts IPs from captured payloads, looks up
# ASN/geo data via ipinfo.io, and flags known cloud providers as automated.

set -euo pipefail

LOG_FILE="${WATCHER_ANALYTICS_LOG:-/var/log/watcher_analytics.log}"

# Read full multi-line payload from stdin (not just first line)
INCOMING_PAYLOAD=$(cat)

# Pull the first IP-shaped string out of the payload
DETECTED_IP=$(echo "${INCOMING_PAYLOAD}" | grep -oE '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' | head -n 1)

if [[ -z "${DETECTED_IP}" ]]; then
    exit 0
fi

# Query routing data to find the owner
NETWORK_INFO=$(curl -s --max-time 10 "https://ipinfo.io/${DETECTED_IP}/json") || {
    echo "[-] Failed to query ipinfo.io for ${DETECTED_IP}" >&2
    exit 1
}

# BSD grep (macOS) lacks -P; use sed for JSON field extraction
ASN=$(echo "${NETWORK_INFO}" | sed -n 's/.*"org"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p')
GEO=$(echo "${NETWORK_INFO}" | sed -n 's/.*"city"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p')
COUNTRY=$(echo "${NETWORK_INFO}" | sed -n 's/.*"country"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p')
ASN="${ASN:-UNKNOWN}"
GEO="${GEO:-UNKNOWN}"
COUNTRY="${COUNTRY:-UNKNOWN}"

# Flag known cloud ASNs vs. residential origin
IS_BOT=false
if echo "${ASN}" | grep -Eiq "amazon|google|digitalocean|linode|hetzner|ovh|azure|cloudflare"; then
    IS_BOT=true
fi

{
    echo "--- WATCHER REPORT ---"
    echo "TARGET IP: ${DETECTED_IP}"
    echo "ORIGIN ASN: ${ASN}"
    echo "LOCATION: ${GEO}, ${COUNTRY}"
    echo "AUTOMATED CLOUD INSTANCE: ${IS_BOT}"
    echo "TIMESTAMP: $(date +"%Y-%m-%d %H:%M:%S")"
    echo "----------------------"
} >> "${LOG_FILE}"
