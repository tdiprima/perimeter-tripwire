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
`TW_SNAPSHOT`, `TW_ROTATE_MB`, `TW_KEEP_DAYS`. After editing: `./install.sh`.
See PLAN.md for the stage-by-stage design.
