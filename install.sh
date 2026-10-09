#!/bin/bash

# Exit immediately when a command fails
set -e

HERE="$(cd "$(dirname "$0")" && pwd)"
LABEL="com.$(id -un).perimeter-tripwire"
PLIST="$HOME/Library/LaunchAgents/$LABEL.plist"
LOGDIR="$HOME/Library/Logs/perimeter-tripwire"

# launchd cannot read ~/Desktop (TCC), so run from a copy under Application Support.
APP="$HOME/Library/Application Support/perimeter-tripwire"

mkdir -p "$LOGDIR" "$HOME/Library/LaunchAgents" "$APP"
rsync -a --delete "$HERE/bin" "$HERE/lib" "$APP/"
chmod +x "$APP/bin/tripwire"

cat > "$PLIST" <<P
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>Label</key><string>$LABEL</string>
  <key>ProgramArguments</key><array>
    <string>/bin/bash</string><string>$APP/bin/tripwire</string><string>run</string>
  </array>
  <key>EnvironmentVariables</key><dict>
    <key>PATH</key><string>/usr/bin:/bin:/usr/sbin:/sbin</string>
  </dict>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><true/>
  <key>ThrottleInterval</key><integer>10</integer>
  <key>StandardOutPath</key><string>$LOGDIR/daemon.log</string>
  <key>StandardErrorPath</key><string>$LOGDIR/daemon.log</string>
</dict></plist>
P

launchctl bootout "gui/$(id -u)/$LABEL" 2>/dev/null && sleep 5 || true
launchctl bootstrap "gui/$(id -u)" "$PLIST"
echo "installed $LABEL"
launchctl print "gui/$(id -u)/$LABEL" | grep -E 'state|pid' | head -3
