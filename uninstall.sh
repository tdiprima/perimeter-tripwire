#!/bin/bash
LABEL="com.$(id -un).perimeter-tripwire"
launchctl bootout "gui/$(id -u)/$LABEL" 2>/dev/null
rm -f "$HOME/Library/LaunchAgents/$LABEL.plist"
echo "removed $LABEL (logs kept in ~/Library/Logs/perimeter-tripwire)"
