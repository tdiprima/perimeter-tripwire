#!/usr/bin/env bash
# Local filesystem sentinel — monitors home directory for suspicious file writes
# that look like telemetry, analytics, or tracking activity.
# Uses fswatch (macOS) for real-time filesystem event detection.

set -euo pipefail

MONITOR_DIR="${SENTINEL_MONITOR_DIR:-$HOME}"
SENTINEL_LOG="${SENTINEL_LOG:-/var/log/sentinel_filesystem.log}"

if ! command -v fswatch &> /dev/null; then
    echo "[-] fswatch required. Install with:" >&2
    echo "    brew install fswatch" >&2
    exit 1
fi

touch "${SENTINEL_LOG}"
chmod 600 "${SENTINEL_LOG}"

echo "[+] Local sentinel active. Monitoring ${MONITOR_DIR}..."

fswatch --recursive --event Created --event Updated "${MONITOR_DIR}" | while read -r FILE; do
    # Skip known-safe development noise
    if echo "${FILE}" | grep -qE '\.cache|\.git/|node_modules|__pycache__'; then
        continue
    fi

    # Flag files that look like telemetry or tracking — match specific telemetry patterns,
    # not overly broad terms like "config" which catch legitimate files
    if echo "${FILE}" | grep -qiE 'telemetry|analytics|metrics|tracking|\.beacon|phoneHome|usage[-_]?data|crash[-_]?report'; then
        CURRENT_TIME=$(date +"%H:%M:%S")
        echo "[${CURRENT_TIME}] WARNING: suspicious file activity: ${FILE}" >> "${SENTINEL_LOG}"

        if [[ -f "${FILE}" ]]; then
            chmod 000 "${FILE}"
            echo "[${CURRENT_TIME}] CRITICAL: quarantined ${FILE}, permissions zeroed." >> "${SENTINEL_LOG}"
        fi
    fi
done
