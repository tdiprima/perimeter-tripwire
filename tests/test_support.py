"""TEST-5: enrichment (bin/enrich-ip, lib/enrich.sh), reporting (bin/report.py), install/uninstall/daemon lifecycle."""
import datetime, json, os, plistlib, signal, stat, subprocess, time, unittest
from helpers import Sandbox, BIN, LIB, ROOT, PY, set_mtime

ENRICH = os.path.join(BIN, "enrich-ip")
CYMRU = "AS      | IP | BGP Prefix | CC | Registry | Allocated | AS Name\n%s | %s | %s | %s | arin | 2010-01-01 | %s\n"


class EnrichTest(unittest.TestCase):
    def setUp(self):
        self.sb = Sandbox()
        self.cache = os.path.join(self.sb.state, "ipcache")

    def tearDown(self):
        self.sb.close()

    def enrich(self, ip, **env):
        r = self.sb.run(["/bin/bash", ENRICH, ip], **env)
        return r.returncode, dict(l.split("=", 1) for l in r.stdout.splitlines() if "=" in l)

    def summary(self, ip):
        return self.sb.bash(f"source {LIB}/common.sh; source {LIB}/enrich.sh; tw_enrich_summary '{ip}'", check=True).stdout.strip()

    def test_public_ip_full_attribution_and_classes(self):
        cases = {
            "203.0.113.5": ("15169", "203.0.113.0/24", "US", "GOOGLE, US", "OrgName: Google LLC\nNetName: GOOGLE\ncountry: US\nOrgAbuseEmail: abuse@google.com\n", "cloud"),
            "198.51.100.7": ("398324", "198.51.100.0/24", "US", "CENSYS-ARIN-01, US", "OrgName: Censys, Inc.\n", "scanner"),
            "192.0.2.9": ("7922", "192.0.2.0/24", "US", "COMCAST-7922, US", "OrgName: Comcast Cable Communications, LLC\nOrgAbuseEmail: abuse@comcast.net\n", "residential"),
            "100.64.1.1": ("", "", "", "", "descr: Some ISP\ncountry: DE\nabuse-mailbox: abuse@example.de\n", "other"),
        }
        for ip, (asn, prefix, cc, asname, rir, cls) in cases.items():
            self.sb.whois(ip, CYMRU % (asn or "NA", ip, prefix or "NA", cc or "NA", asname or "NA"), rir)
        self.sb.out("dig", "scanner.censys-scanner.com.\n", key="198.51.100.7")
        rc, g = self.enrich("203.0.113.5")
        self.assertEqual(rc, 0)
        self.assertEqual(g, {"ip": "203.0.113.5", "scope": "public", "rdns": "", "asn": "15169", "asname": "GOOGLE, US", "prefix": "203.0.113.0/24",
                             "org": "Google LLC", "netname": "GOOGLE", "country": "US", "abuse": "abuse@google.com", "class": "cloud"})
        self.assertEqual(self.summary("203.0.113.5"), "AS15169 Google LLC, US [cloud]")
        _, g = self.enrich("198.51.100.7")
        self.assertEqual((g["class"], g["rdns"]), ("scanner", "scanner.censys-scanner.com"))
        self.assertEqual(self.summary("198.51.100.7"), "AS398324 Censys, Inc., US [scanner] scanner.censys-scanner.com")
        _, g = self.enrich("192.0.2.9")
        self.assertEqual((g["class"], g["abuse"]), ("residential", "abuse@comcast.net"))
        _, g = self.enrich("100.64.1.1")
        self.assertEqual((g["asn"], g["asname"], g["org"], g["country"], g["abuse"], g["class"]), ("NA", "NA", "Some ISP", "NA", "abuse@example.de", "other"))

    def test_cymru_miss_blanks_asn(self):
        self.sb.whois("203.0.113.9", "AS | IP | BGP Prefix | CC | Registry | Allocated | AS Name\nAS | 203.0.113.9 | | | | | \n", "country: FR\n")
        _, g = self.enrich("203.0.113.9")
        self.assertEqual((g["asn"], g["asname"], g["country"], g["class"]), ("", "", "FR", "other"))
        self.assertEqual(self.summary("203.0.113.9"), "unknown, FR [other]")

    def test_loopback_lan_and_private_ranges_skip_whois(self):
        self.sb.out("route", "   route to: default\n    gateway: 10.1.2.1\n")
        self.sb.out("arp", "? (10.1.2.1) at 0:11:22:33:44:55 on en0 ifscope [ethernet]\n", key="10.1.2.1")
        self.sb.out("dig", "router.lan.\n", key="10.1.2.1")
        expect = {"127.0.0.1": "loopback", "::1": "loopback", "0.0.0.0": "loopback",
                  "10.1.2.1": "lan", "172.16.0.1": "lan", "172.31.255.255": "lan", "192.168.0.1": "lan", "169.254.1.1": "lan", "fe80::1": "lan",
                  "172.32.0.1": "public", "11.0.0.1": "public", "2001:db8::1": "public"}
        for ip, scope in expect.items():
            _, g = self.enrich(ip)
            self.assertEqual(g["scope"], scope, ip)
            self.assertEqual(g["class"], {"loopback": "local", "lan": "lan-device", "public": "other"}[scope], ip)
        self.assertEqual(len([c for c in self.sb.calls_of("whois") if c.startswith("-h")]), 3)
        _, g = self.enrich("10.1.2.1")
        self.assertEqual((g["mac"], g["note"], g["rdns"]), ("0:11:22:33:44:55", "default gateway (your router)", "router.lan"))
        self.assertEqual(self.summary("10.1.2.1"), "LAN router.lan mac 0:11:22:33:44:55 – default gateway (your router)")
        self.assertEqual(self.summary("127.0.0.1"), "this Mac (localhost)")
        self.assertEqual(self.summary("192.168.0.1"), "LAN 192.168.0.1")

    def test_invalid_input(self):
        rc, g = self.enrich("not an ip")
        self.assertEqual(rc, 0)
        self.assertEqual((g["ip"], g["scope"], g["class"]), ("not an ip", "public", "other"))
        r = self.sb.run(["/bin/bash", ENRICH])
        self.assertNotEqual(r.returncode, 0)
        self.assertEqual(self.sb.calls_of("dig"), ["+short +time=2 +tries=1 -x not an ip"])

    def test_cache_hit_expiry_and_atomic_write(self):
        self.sb.whois("203.0.113.5", CYMRU % ("15169", "203.0.113.5", "203.0.113.0/24", "US", "GOOGLE, US"), "OrgName: Google LLC\n")
        _, g1 = self.enrich("203.0.113.5", TW_ENRICH_TTL="100")
        self.assertEqual(len(self.sb.calls_of("whois")), 2)
        cf = os.path.join(self.cache, "203.0.113.5")
        self.assertTrue(os.path.exists(cf))
        self.assertEqual(sorted(os.listdir(self.cache)), ["203.0.113.5"])    # no .tmp left behind
        self.sb.whois("203.0.113.5", CYMRU % ("1", "203.0.113.5", "x", "ZZ", "CHANGED"), "OrgName: Changed\n")
        _, g2 = self.enrich("203.0.113.5", TW_ENRICH_TTL="100")
        self.assertEqual(g2, g1)
        self.assertEqual(len(self.sb.calls_of("whois")), 2)
        set_mtime(cf, time.time() - 99)
        self.enrich("203.0.113.5", TW_ENRICH_TTL="100")
        self.assertEqual(len(self.sb.calls_of("whois")), 2)
        set_mtime(cf, time.time() - 101)
        _, g3 = self.enrich("203.0.113.5", TW_ENRICH_TTL="100")
        self.assertEqual(len(self.sb.calls_of("whois")), 4)
        self.assertEqual((g3["asn"], g3["org"]), ("1", "Changed"))

    def test_who_command(self):
        r = self.sb.tripwire("who", "127.0.0.1", "192.168.5.5")
        self.assertEqual(r.returncode, 0)
        self.assertIn("ip=127.0.0.1\nscope=loopback", r.stdout)
        self.assertIn("summary=this Mac (localhost)", r.stdout)
        self.assertIn("summary=LAN 192.168.5.5", r.stdout)


class ReportTest(unittest.TestCase):
    def setUp(self):
        self.sb = Sandbox()
        self.now = datetime.datetime.utcnow()

    def tearDown(self):
        self.sb.close()

    def ts(self, hours_ago):
        return (self.now - datetime.timedelta(hours=hours_ago)).strftime("%Y-%m-%dT%H:%M:%SZ")

    def report(self, days=None):
        argv = [PY, "-I", os.path.join(BIN, "report.py"), self.sb.events_path] + ([str(days)] if days is not None else [])
        r = self.sb.run(argv)
        self.assertEqual(r.returncode, 0, r.stderr)
        return r.stdout

    def test_malformed_records_are_skipped(self):
        good = {"ts": self.ts(1), "type": "ssh.failed", "severity": "alert", "ip": "203.0.113.5", "geo_org": "Google LLC", "geo_class": "cloud", "geo_country": "US"}
        self.sb.write_events_bytes(b"this is not json\n\n" + b'{"type":"no-ts","severity":"alert"}\n' + b'{"ts":"yesterday","type":"bad-ts"}\n'
                                   + b'{"ts":"2026-10-08T00:00:00","type":"bad-ts-fmt"}\n' + b"\xff\xfe binary junk\n" + b'{"ts":"' + b"\n"
                                   + json.dumps(good).encode() + b"\n" + b'{"truncated":')
        out = self.report()
        self.assertIn("last 1 day(s), 1 events", out)
        self.assertIn("     1  ssh.failed", out)
        self.assertNotIn("no-ts", out); self.assertNotIn("bad-ts", out)

    def test_date_cutoff(self):
        self.sb.write_events([
            {"ts": self.ts(1), "type": "a", "severity": "info"},
            {"ts": self.ts(23), "type": "b", "severity": "info"},
            {"ts": self.ts(25), "type": "c", "severity": "info"},
            {"ts": self.ts(24 * 3 + 1), "type": "d", "severity": "info"},
        ])
        self.assertIn("last 1 day(s), 2 events", self.report())
        self.assertIn("last 2 day(s), 3 events", self.report(2))
        self.assertIn("last 0.5 day(s), 1 events", self.report(0.5))
        out = self.report(10)
        self.assertIn("last 10 day(s), 4 events", out)
        for t in "abcd": self.assertIn(f"     1  {t}", out)

    def test_sections_counts_and_attribution(self):
        self.sb.write_events([
            {"ts": self.ts(2), "type": "ssh.failed", "severity": "alert", "ip": "203.0.113.5", "when": "2026-10-08 10:00:00.000", "geo_org": "Google LLC", "geo_class": "cloud", "geo_country": "US"},
            {"ts": self.ts(2), "type": "ssh.failed", "severity": "alert", "ip": "203.0.113.5", "when": "2026-10-08 10:00:01.000", "geo_class": "cloud"},
            {"ts": self.ts(2), "type": "honeypot.hit", "severity": "alert", "ip": "203.0.113.5", "port": 2222, "geo_asname": "GOOGLE"},
            {"ts": self.ts(2), "type": "honeypot.hit", "severity": "alert", "ip": "198.51.100.7", "port": 8080, "geo_rdns": "scan.example", "geo_class": "scanner"},
            {"ts": self.ts(2), "type": "ssh.login", "severity": "info", "ip": "10.0.0.2", "user": "alice", "when": "2026-10-08 11:00:00.000", "geo_class": "lan-device"},
            {"ts": self.ts(2), "type": "vnc.login", "severity": "info", "ip": "203.0.113.5", "user": "alice", "when": "2026-10-08 11:30:00.000", "geo_org": "Google LLC"},
            {"ts": self.ts(2), "type": "sudo.failed", "severity": "alert", "user": "bob", "when": "2026-10-08 12:00:00.000", "process": "sudo", "detail": "1 incorrect password attempt ; TTY=ttys000"},
            {"ts": self.ts(2), "type": "localauth.failed", "severity": "alert", "user": "alice", "when": "2026-10-08 12:01:00.000", "source": "screensharingd"},
            {"ts": self.ts(2), "type": "touchid.failed", "severity": "alert", "user": "alice", "when": "2026-10-08 12:02:00.000", "process": "biometrickitd", "detail": "Match failed"},
            {"ts": self.ts(2), "type": "daemon.heartbeat", "severity": "info"},
        ])
        out = self.report()
        lines = out.splitlines()
        self.assertEqual(lines[0], "Perimeter Tripwire report — last 1 day(s), 10 events")
        self.assertEqual(lines[lines.index("By type:") + 1].split(), ["2", "ssh.failed"])
        self.assertIn("     2  honeypot.hit", out)
        self.assertIn("     1  daemon.heartbeat", out)
        top = [l for l in lines if l.startswith("      3  203.0.113.5")]
        self.assertEqual(len(top), 1)
        self.assertRegex(top[0], r"203\.0\.113\.5\s+cloud\s+US\s+Google LLC\s+ssh\.failed×2, honeypot\.hit×1")
        self.assertRegex(out, r"      1  198\.51\.100\.7\s+scanner\s+scan\.example\s+honeypot\.hit×1")
        self.assertIn("Local auth failures:", out)
        self.assertIn("  2026-10-08 12:00:00  sudo.failed      user=bob source=sudo 1 incorrect password attempt ; TTY=ttys000", out)
        self.assertIn("  2026-10-08 12:01:00  localauth.failed user=alice source=screensharingd", out)
        self.assertIn("  2026-10-08 12:02:00  touchid.failed   user=alice source=biometrickitd Match failed", out)
        self.assertIn("Successful remote logins:", out)
        self.assertIn("  2026-10-08 11:00:00  ssh.login user=alice from 10.0.0.2 (lan-device)", out)
        self.assertIn("  2026-10-08 11:30:00  vnc.login user=alice from 203.0.113.5 (Google LLC)", out)

    def test_empty_and_sectionless(self):
        self.sb.write_events([{"ts": self.ts(1), "type": "daemon.start", "severity": "info"}])
        out = self.report()
        self.assertIn("1 events", out)
        for s in ("Top sources", "Local auth failures", "Successful remote logins"):
            self.assertNotIn(s, out)

    def test_tripwire_report_passthrough(self):
        self.sb.write_events([{"ts": self.ts(30), "type": "x", "severity": "info"}])
        self.assertIn("last 1 day(s), 0 events", self.sb.tripwire("report").stdout)
        self.assertIn("last 2 day(s), 1 events", self.sb.tripwire("report", "2").stdout)


class InstallTest(unittest.TestCase):
    def setUp(self):
        self.sb = Sandbox()
        self.sb.stub("sleep", "#!/bin/bash\nprintf '%s\\n' \"$*\" >> \"$T_CALLS/sleep.calls\"\n")
        self.user = subprocess.run(["id", "-un"], capture_output=True, text=True).stdout.strip()
        self.uid = os.getuid()
        self.label = f"com.{self.user}.perimeter-tripwire"
        self.app = os.path.join(self.sb.home, "Library/Application Support/perimeter-tripwire")
        self.plist = os.path.join(self.sb.home, f"Library/LaunchAgents/{self.label}.plist")
        self.logdir = os.path.join(self.sb.home, "Library/Logs/perimeter-tripwire")

    def tearDown(self):
        self.sb.close()

    def install(self, **env):
        return self.sb.run(["/bin/bash", os.path.join(ROOT, "install.sh")], **env)

    def test_fresh_install(self):
        r = self.install()
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(r.stdout.splitlines()[0], f"installed {self.label}")
        self.assertIn("state = running", r.stdout)
        self.assertTrue(os.access(os.path.join(self.app, "bin/tripwire"), os.X_OK))
        for f in ("bin/honeypot.py", "bin/notify", "bin/enrich-ip", "bin/report.py", "lib/common.sh", "lib/mod_netauth.sh"):
            self.assertTrue(os.path.exists(os.path.join(self.app, f)), f)
        self.assertFalse(os.path.exists(os.path.join(self.app, "install.sh")))
        with open(self.plist, "rb") as f:
            p = plistlib.load(f)
        self.assertEqual(p["Label"], self.label)
        self.assertEqual(p["ProgramArguments"], ["/bin/bash", os.path.join(self.app, "bin/tripwire"), "run"])
        self.assertTrue(p["KeepAlive"] and p["RunAtLoad"])
        self.assertEqual(p["ThrottleInterval"], 10)
        self.assertEqual(p["StandardOutPath"], os.path.join(self.logdir, "daemon.log"))
        self.assertEqual(p["EnvironmentVariables"]["PATH"], "/usr/bin:/bin:/usr/sbin:/sbin")
        self.assertTrue(os.path.isdir(self.logdir))
        self.assertEqual(self.sb.calls_of("launchctl"), [
            f"bootout gui/{self.uid}/{self.label}", f"bootstrap gui/{self.uid} {self.plist}", f"print gui/{self.uid}/{self.label}"])
        self.assertEqual(self.sb.calls_of("sleep"), [])   # bootout of a not-loaded agent fails -> no wait

    def test_reinstall_restarts_and_syncs_changes(self):
        self.install()
        stale = os.path.join(self.app, "lib/mod_stale.sh"); open(stale, "w").close()
        self.sb.clear_calls("launchctl")
        r = self.install(T_BOOTOUT_RC="0")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertFalse(os.path.exists(stale))                 # --delete removes what the repo no longer has
        self.assertEqual(self.sb.calls_of("sleep"), ["5"])        # waits for the old agent to exit before bootstrap
        self.assertEqual([c.split()[0] for c in self.sb.calls_of("launchctl")], ["bootout", "bootstrap", "print"])
        with open(os.path.join(self.app, "lib/common.sh")) as a, open(os.path.join(ROOT, "lib/common.sh")) as b:
            self.assertEqual(a.read(), b.read())

    def test_bootstrap_failure_aborts(self):
        self.sb.stub("launchctl", "#!/bin/bash\n[ \"$1\" = bootstrap ] && exit 5\nexit 1\n")
        r = self.install()
        self.assertNotEqual(r.returncode, 0)
        self.assertNotIn("installed", r.stdout)

    def test_uninstall_preserves_logs(self):
        self.install()
        os.makedirs(self.logdir, exist_ok=True)
        ev = os.path.join(self.logdir, "events.jsonl")
        with open(ev, "w") as f: f.write("{}\n")
        self.sb.clear_calls("launchctl")
        r = self.sb.run(["/bin/bash", os.path.join(ROOT, "uninstall.sh")], T_BOOTOUT_RC="0")
        self.assertEqual(r.returncode, 0)
        self.assertEqual(r.stdout.strip(), f"removed {self.label} (logs kept in ~/Library/Logs/perimeter-tripwire)")
        self.assertEqual(self.sb.calls_of("launchctl"), [f"bootout gui/{self.uid}/{self.label}"])
        self.assertFalse(os.path.exists(self.plist))
        self.assertTrue(os.path.exists(ev))
        self.assertTrue(os.path.exists(self.app))


class DaemonTest(unittest.TestCase):
    def setUp(self):
        self.sb = Sandbox()
        self.sb.log_fixture()

    def tearDown(self):
        self.sb.close()

    def test_run_arms_polls_and_stops_cleanly_on_term(self):
        p = self.sb.spawn(["/bin/bash", os.path.join(BIN, "tripwire"), "run"], TW_INTERVAL="1", TW_HEARTBEAT="1")
        self.sb.wait_events(lambda evs: any(e["type"] == "daemon.heartbeat" for e in evs), timeout=15)
        (start,) = self.sb.events("daemon.start")
        self.assertEqual((start["pid"], start["interval"]), (str(p.pid), "1"))
        self.assertEqual(self.sb.notifications()[0], {"title": "Tripwire armed", "message": f"Monitoring {os.uname().nodename}.", "sound": "Pop"})
        self.assertGreaterEqual(len(self.sb.calls_of("log")), 2)      # both unified-log modules polled
        p.send_signal(signal.SIGTERM)
        self.assertEqual(p.wait(timeout=10), 0)
        self.assertEqual(len(self.sb.events("daemon.stop")), 1)

    def test_scan_runs_every_module_once(self):
        r = self.sb.tripwire("scan")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(r.stdout.splitlines(), [f"running tw_mod_{m}" for m in ("honeypot", "housekeeping", "localauth", "netauth")])
        self.assertEqual(len(self.sb.calls_of("log")), 2)

    def test_usage_on_bad_command(self):
        r = self.sb.tripwire("bogus")
        self.assertEqual(r.returncode, 1)
        self.assertTrue(r.stdout.startswith("usage:"))


if __name__ == "__main__":
    unittest.main()
