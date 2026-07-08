#!/usr/bin/env bash
# Honeypot listener — captures raw payloads from anything connecting to a decoy port.
# Logs connection data and passes payload to analyze_watcher.sh for OSINT lookup.

set -euo pipefail

LISTEN_PORT="${TRIPWIRE_PORT:-8888}"
LOG_FILE="${TRIPWIRE_LOG:-/var/log/watcher_tripwire.log}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if ! command -v nc &> /dev/null; then
    echo "[-] netcat (nc) is required but not installed." >&2
    exit 1
fi

touch "${LOG_FILE}"
chmod 600 "${LOG_FILE}"

echo "[+] Tripwire activated on port ${LISTEN_PORT}..."

while true; do
    # Capture payload — timestamp taken AFTER connection arrives, not before
    # BSD netcat (macOS): no -p with -l
    RAW_DATA=$(nc -l "${LISTEN_PORT}" -w 3 2>&1) || true
    TIMESTAMP=$(date +"%Y-%m-%d %H:%M:%S")

    if [[ -n "${RAW_DATA}" ]]; then
        {
            echo "========================================="
            echo "TIMESTAMP: ${TIMESTAMP}"
            echo "RAW PAYLOAD:"
            echo "${RAW_DATA}"
            echo "========================================="
        } >> "${LOG_FILE}"

        # Kick off async analysis without blocking the listener
        echo "${RAW_DATA}" | "${SCRIPT_DIR}/analyze_watcher.sh" &
    fi
done
