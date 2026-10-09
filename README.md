# Perimeter Tripwire

Zero-dependency macOS login/intrusion monitor (bash + built-ins + system python3).
Survives reboots via launchd. Logs everything to `~/Library/Logs/perimeter-tripwire/events.jsonl`,
alerts with macOS notifications.

```
./install.sh                 # install + start launchd agent (copies bin/ lib/ to ~/Library/Application Support)
./uninstall.sh
bin/tripwire status          # daemon + honeypot state, last event
bin/tripwire report [days]   # summary: counts, top sources, local failures, remote logins
bin/tripwire who <ip>        # rDNS / ASN / org / country / LAN MAC
bin/tripwire scan            # run all detectors once, in the foreground
bin/tripwire tail            # follow events.jsonl
bin/tripwire test            # log + notification smoke test
```

Detects: login-window / lock-screen / sudo password failures, Touch ID mismatches,
SSH and Screen Sharing failures *and* successes, and probes against fake services
(ports 2222, 8080, 6379, 3389). Every remote IP is enriched (rDNS, ASN, whois org,
country, cloud/scanner/residential class, LAN MAC).

Tuning: set env vars in the launchd plist `EnvironmentVariables` dict —
`TW_INTERVAL`, `TW_HP_PORTS`, `TW_HP_ENABLED`, `TW_NOTIFY_COOLDOWN`, `TW_NOTIFY_MAX`,
`TW_SNAPSHOT`, `TW_AKD_NOTIFY` (1 = notify on akd stale-password checks; off by default), `TW_ROTATE_MB`, `TW_KEEP_DAYS`. After editing: `./install.sh`.
See PLAN.md for the stage-by-stage design.

## Lessons learned

Things that bit me and weren't obvious:

1. **`nc` can't be a honeypot on macOS.** The plan was `nc -l <port>` as a zero-dependency
   listener. macOS's `nc` never reports the peer address in listen mode (`-v` prints nothing),
   and it exits the instant the client disconnects, so a quick port scan is gone before `lsof`
   can catch who it was. Switched to a stdlib Python socket server, where `accept()` hands you
   the peer directly.

2. **launchd agents can't read `~/Desktop`.** The first install pointed the plist at the repo on
   the Desktop and launchd got `Operation not permitted` forever. Desktop, Documents, and
   Downloads are TCC-protected, and a background agent never gets the permission prompt.
   `install.sh` now copies `bin/` and `lib/` to `~/Library/Application Support/` and runs from there.

3. **`launchctl bootout` returns before the job is actually gone.** `bootout` followed
   immediately by `bootstrap` fails with `Bootstrap failed: 5: Input/output error` because the
   old instance is still tearing down. A short sleep between them fixes it.

4. **`log` is a zsh builtin.** `log show` inside a script silently does the wrong thing; call
   `/usr/bin/log` explicitly. Also, sshd's auth messages are info-level, so you need `--info`
   to see them at all.

## Tests

```
tests/run.sh                      # whole suite (bash 3.2 + system python3; no network, no real notifications)
tests/run.sh -p test_notify.py    # one file
```

Every test runs in a throwaway HOME/log/state dir with stubbed `log`, `osascript`, `dscl`, `who`,
`dig`, `whois`, `arp`, `route`, `launchctl` and `screencapture`, so fixtures are replayed instead of
touching the real unified log, Notification Center, the network or launchd. The honeypot tests bind
real loopback sockets on free ports.

<!--
The akd stale-password notification is now off by default (events are still logged as warn in events.jsonl). Set TW_AKD_NOTIFY=1 in the plist if you ever want it back.
-->

<br>
