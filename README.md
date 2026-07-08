# perimeter-tripwire

Zero-dependency bash scripts for defensive network monitoring on macOS. Three tools that log, analyze, and respond to unwanted probes against your infrastructure.

Aggressive observation instead of passive mitigation.

## What's Included

| Script | Purpose |
|---|---|
| `tripwire.sh` | Honeypot listener on a decoy port. Captures raw payloads from anything that connects. |
| `analyze_watcher.sh` | OSINT engine. Extracts IPs from captured payloads, queries ipinfo.io for ASN/geo data, flags known cloud providers. |
| `sentinel.sh` | Filesystem monitor. Watches your home directory for telemetry, analytics, or tracking files written by applications. Quarantines suspicious writes by zeroing permissions. |

## Requirements

- **OS**: macOS
- **Built-in tools** (ship with macOS):
  - `nc` (BSD netcat) — for `tripwire.sh`
  - `curl` — for `analyze_watcher.sh`
- **Homebrew package**:
  - `fswatch` — for `sentinel.sh`

### Install dependencies

```bash
brew install fswatch
```

That's it. `nc` and `curl` are already on your Mac.

## How to Run

### 1. Tripwire Honeypot

Listens on a port and logs raw connection data.

```bash
# Default: port 8888, log to /var/log/watcher_tripwire.log
sudo ./tripwire.sh

# Custom port and log location (no sudo needed)
TRIPWIRE_PORT=9999 TRIPWIRE_LOG=./tripwire.log ./tripwire.sh
```

**Test it** (from another terminal):

```bash
echo "GET / HTTP/1.1" | nc localhost 8888
```

Check the log:

```bash
cat /var/log/watcher_tripwire.log
```

You should see the timestamp and the raw payload `GET / HTTP/1.1`.

### 2. Watcher Analyzer

Normally called automatically by `tripwire.sh`. To test standalone:

```bash
echo "Connection from 8.8.8.8 on port 443" | sudo ./analyze_watcher.sh
```

Check the output:

```bash
sudo cat /var/log/watcher_analytics.log
```

Expected output:

```
--- WATCHER REPORT ---
TARGET IP: 8.8.8.8
ORIGIN ASN: AS15169 Google LLC
LOCATION: Mountain View, US
AUTOMATED CLOUD INSTANCE: true
TIMESTAMP: 2026-07-08 14:32:01
----------------------
```

> **Note:** ipinfo.io allows 50,000 free requests/month. If you need more, set a token via the API docs.

### 3. Filesystem Sentinel

Watches your home directory for suspicious telemetry-related file writes.

```bash
# Default: monitors $HOME, logs to /var/log/sentinel_filesystem.log
sudo ./sentinel.sh

# Custom directory and log (no sudo needed)
SENTINEL_MONITOR_DIR=~/Documents SENTINEL_LOG=./sentinel.log ./sentinel.sh
```

**Test it** (from another terminal):

```bash
touch ~/telemetry_test_file
```

Check the log:

```bash
sudo cat /var/log/sentinel_filesystem.log
```

You should see a WARNING line and a CRITICAL quarantine line. The test file will have no permissions:

```bash
ls -la ~/telemetry_test_file
# ----------  1 user  staff  0 Jul  8 14:33 /Users/user/telemetry_test_file
```

Clean up:

```bash
chmod 644 ~/telemetry_test_file && rm ~/telemetry_test_file
```

## Running in the Background

```bash
# Quick background run
nohup sudo ./tripwire.sh &
nohup sudo ./sentinel.sh &
```

For persistent background operation, you can create a macOS launchd plist. Place it in `~/Library/LaunchAgents/` for user-level or `/Library/LaunchDaemons/` for system-level.

## Environment Variables

| Variable | Default | Script | Description |
|---|---|---|---|
| `TRIPWIRE_PORT` | `8888` | tripwire.sh | Port to listen on |
| `TRIPWIRE_LOG` | `/var/log/watcher_tripwire.log` | tripwire.sh | Tripwire log path |
| `WATCHER_ANALYTICS_LOG` | `/var/log/watcher_analytics.log` | analyze_watcher.sh | Analytics log path |
| `SENTINEL_MONITOR_DIR` | `$HOME` | sentinel.sh | Directory to monitor |
| `SENTINEL_LOG` | `/var/log/sentinel_filesystem.log` | sentinel.sh | Sentinel log path |

## Troubleshooting

### "Address already in use" on tripwire.sh

Something else is bound to the port:

```bash
lsof -i :8888
# Then either kill it or pick a different port:
TRIPWIRE_PORT=9999 ./tripwire.sh
```

### analyze_watcher.sh returns UNKNOWN for all fields

- **No internet access**: `curl` can't reach ipinfo.io. Check with `curl -s https://ipinfo.io/8.8.8.8/json`.
- **Rate limited**: ipinfo.io free tier caps at 50k requests/month. Check if you're getting a 429 response.
- **No IP in payload**: The analyzer only works when the captured payload contains an IP address. Raw TCP connections with no text payload produce nothing to extract.

### sentinel.sh exits immediately

- **fswatch not installed**: `brew install fswatch`
- **Permission denied**: macOS may require granting Full Disk Access to Terminal (or your terminal app) in System Settings > Privacy & Security > Full Disk Access.

### sentinel.sh quarantined a legitimate file

Restore permissions:

```bash
chmod 644 /path/to/quarantined/file
```

The sentinel matches specific telemetry-related patterns: `telemetry`, `analytics`, `metrics`, `tracking`, `.beacon`, `phoneHome`, `usage_data`, `crash_report`. If a legitimate file matches, rename it or add an exclusion to the grep pattern in sentinel.sh.

### "Permission denied" writing to /var/log

Either run with `sudo`, or use local log paths:

```bash
TRIPWIRE_LOG=./tripwire.log ./tripwire.sh
WATCHER_ANALYTICS_LOG=./analytics.log
SENTINEL_LOG=./sentinel.log ./sentinel.sh
```

### macOS firewall blocks incoming connections

If the tripwire can't accept connections, check System Settings > Network > Firewall. Either disable it temporarily for testing or add an exception for your terminal app.

## Security Notes

- Log files are created with `chmod 600` (owner-only read/write).
- `analyze_watcher.sh` sends detected IPs to ipinfo.io over HTTPS. For fully offline operation, replace the `curl` call with a local GeoIP database lookup (e.g., MaxMind's GeoLite2).
- `sentinel.sh` quarantines files by setting `chmod 000`. This is intentionally aggressive. For logging-only mode without quarantine, comment out the `chmod 000` line.
- These scripts are defensive monitoring tools for infrastructure you own. Do not point them at systems you don't control.
