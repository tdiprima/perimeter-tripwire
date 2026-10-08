# If Someone Gets In

Trigger: an `ssh.login` / `vnc.login` event you didn't make, or local auth failures
followed by activity you don't recognize (`bin/tripwire report 1`).

## 1. Cut access now
- Turn off Wi‑Fi / unplug Ethernet.
- Kill their sessions: `who` then `sudo pkill -u <user>` (or `sudo pkill -t <tty>`).
- Disable remote access: `sudo systemsetup -setremotelogin off`; System Settings → General → Sharing → turn off Screen Sharing / Remote Management.

## 2. Preserve evidence before changing anything
```
bin/tripwire report 7 > ~/Desktop/incident-report.txt
cp -R ~/Library/Logs/perimeter-tripwire ~/Desktop/incident-logs
sudo log collect --last 2h --output ~/Desktop/incident.logarchive
```
Copy these to an external drive or another machine.

## 3. See what they did
- Logins: `last`, `who`
- Live connections: `sudo lsof -i -nP`
- Persistence: `launchctl list`, `ls ~/Library/LaunchAgents /Library/LaunchAgents /Library/LaunchDaemons`, `crontab -l`
- Added SSH keys: `cat ~/.ssh/authorized_keys`
- Shell history: `~/.zsh_history`, `~/.bash_history`
- New admin users: `dscl . -read /Groups/admin GroupMembership`
- Identify the source: `bin/tripwire who <ip>`

## 4. Change credentials — from a different, trusted device
- Mac login password, Apple ID (and sign out other devices)
- Anything with saved sessions in Keychain / browsers (email, bank, GitHub, cloud)
- Revoke/rotate SSH keys and API tokens that lived on this Mac

## 5. If you can't fully account for their actions
Assume compromise: back up documents only, erase the Mac, reinstall macOS, restore files
(not apps or settings), then re-run `./install.sh` here.

## 6. Report
- Abuse contact from `bin/tripwire who <ip>` (`abuse=` line)
- Your institution's security team if this is a work machine
- Law enforcement if there was theft or extortion

## Prevention checklist
- [ ] Remote Login off unless needed (`sudo systemsetup -setremotelogin off`)
- [ ] Firewall on, stealth mode on
- [ ] FileVault on
- [ ] Require password immediately after sleep / screen saver
- [ ] Lock screen when stepping away (Ctrl‑Cmd‑Q)

<!--
sudo systemsetup -setremotelogin off
sudo /usr/libexec/ApplicationFirewall/socketfilterfw --setglobalstate on
sudo /usr/libexec/ApplicationFirewall/socketfilterfw --setstealthmode on

Note: once the firewall is on, macOS will prompt to allow incoming connections for Python (the honeypot). Click Allow or the honeypot ports go silent.
-->

<br>
