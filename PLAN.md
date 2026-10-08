# Perimeter Tripwire — Plan

Goal: a zero-dependency (bash + macOS built-ins) monitor that survives reboots,
detects attempts to get into this MacBook, identifies the source, logs everything,
and alerts via macOS notification (`osascript`).

Two attack surfaces are covered:
- **Local**: failed logins at the login window / lock screen, failed `sudo`, failed Touch ID. (Stage 2: `lib/mod_localauth.sh`; `tripwire scan` runs modules once.)
- **Network**: SSH / screen-sharing login attempts (Stage 3: `lib/mod_netauth.sh`) and port probes against a honeypot listener.

## Layout
```
bin/tripwire        main daemon (loop, runs enabled modules)
bin/honeypot.py     fake-service listener (stage 4), supervised by lib/mod_honeypot.sh
lib/common.sh       config, paths, JSON logging
lib/notify.sh       osascript notifications
lib/<module>.sh     one file per detector (added per stage)
install.sh          copies bin/ lib/ to ~/Library/Application Support/perimeter-tripwire (launchd cannot read ~/Desktop), writes plist, loads it
uninstall.sh        unloads + removes plist
~/Library/Logs/perimeter-tripwire/events.jsonl   all events (one JSON per line)
~/Library/Logs/perimeter-tripwire/daemon.log     stdout/stderr
```

## Stages
1. **Foundation** — layout, config, JSON logger, notifier, launchd service with
   KeepAlive + RunAtLoad, install/uninstall, heartbeat. Verify it survives `launchctl kickstart`.
2. **Local login detection** — poll the unified log (`log show --last`) for failed
   authentication: loginwindow / screensaver unlock, `sudo` failures, Touch ID failures.
   Log event (user targeted, source process, timestamp, console user) and notify.
3. **Network login detection** — watch `sshd` / `screensharingd` auth failures in the
   unified log; capture remote IP and username; notify.
4. **Honeypot listener** — `bin/honeypot.py` (stdlib python3 from Xcode CLT; `nc` cannot report the peer address) on tempting unprivileged
   port(s); capture the first bytes of the handshake, source IP/port, close immediately.
5. **De-anonymize** — enrich every remote IP: reverse DNS, `whois` ASN/org/country,
   with a local cache; flag cloud/scanner ranges vs. residential; include in alert text.
6. **Hardening & reporting** — log rotation, rate-limit alerts (no notification storms),
   `tripwire report` summary command, optional webcam snapshot on local failures.
