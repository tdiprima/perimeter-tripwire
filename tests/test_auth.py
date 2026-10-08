"""TEST-1: authentication detection (lib/mod_localauth.sh, lib/mod_netauth.sh)."""
import os, re, unittest
from helpers import Sandbox

UUID = "21CD598F-85AA-4379-8A99-94E27126C666"
OD_FAIL = f'2026-10-08 14:00:01.123 E  opendirectoryd[123:456] [com.apple.opendirectoryd:auth] Authentication failed for "alice" ({UUID}) - wrong password'
AUTHTOK = '2026-10-08 14:00:01.100 E  screensharingd[300:7] The authtok is incorrect'
SUDO = '2026-10-08 14:00:02.000 E  sudo[200:1] bob : 1 incorrect password attempt ; TTY=ttys000 ; PWD=/Users/bob ; USER=root ; COMMAND=/bin/ls'
TOUCHID = '2026-10-08 14:00:03.500 Df biometrickitd[400:9] [com.apple.biometrickitd:match] Match failed for finger 2'


def log_args(call):
    a = call.split()
    return {"start": " ".join(a[a.index("--start") + 1:a.index("--start") + 3]),
            "end": " ".join(a[a.index("--end") + 1:a.index("--end") + 3])}


class LocalAuthTest(unittest.TestCase):
    def setUp(self):
        self.sb = Sandbox()
        self.sb.dscl_map(**{UUID: "alice"})
        self.sb.out("who", "alice            console      Oct  5 17:55\nalice            ttys000      Oct  8 11:17\n")

    def tearDown(self):
        self.sb.close()

    def test_replays_fixtures_into_exact_events_and_one_alert(self):
        self.sb.log_fixture(AUTHTOK, OD_FAIL, SUDO, TOUCHID)
        self.sb.module("localauth", T_CONSOLE_USER="alice")
        evs = self.sb.events()
        self.assertEqual([e["type"] for e in evs], ["localauth.failed", "sudo.failed", "touchid.failed"])
        self.assertTrue(all(e["severity"] == "alert" for e in evs))
        la, su, ti = evs
        self.assertEqual(la["when"], "2026-10-08 14:00:01.123")
        self.assertEqual(la["user"], "alice")
        self.assertEqual(la["process"], "opendirectoryd")
        self.assertEqual(la["source"], "screensharingd")      # PAM client folded into the OD failure
        self.assertEqual(la["console_user"], "alice")
        self.assertEqual(la["sessions"], "alice@console alice@ttys000 ")
        self.assertEqual(su["user"], "bob")
        self.assertEqual(su["process"], "sudo")
        self.assertEqual(su["detail"], "1 incorrect password attempt ; TTY=ttys000 ; PWD=/Users/bob ; USER=root ; COMMAND=/bin/ls")
        self.assertEqual(ti["user"], "alice")
        self.assertEqual(ti["process"], "biometrickitd")
        self.assertIn("Match failed for finger 2", ti["detail"])
        self.assertEqual(self.sb.notifications(), [{
            "title": "Login attempt blocked",
            "message": "3 failed auth attempt(s) via screensharingd. Console user: alice.",
            "sound": "Sosumi"}])
        self.assertEqual(self.sb.calls_of("dscl"), [f". -search /Users GeneratedUID {UUID}"])

    def test_unknown_uuid_and_lockscreen_source(self):
        self.sb.log_fixture(OD_FAIL.replace(UUID, "00000000-0000-0000-0000-000000000000"))
        self.sb.module("localauth")
        (e,) = self.sb.events()
        self.assertEqual(e["user"], "unknown")
        self.assertEqual(e["source"], "loginwindow/lockscreen")
        self.assertIn("via loginwindow/lockscreen", self.sb.notifications()[0]["message"])

    def test_quiet_window_logs_nothing_and_sends_nothing(self):
        self.sb.log_fixture()
        self.sb.module("localauth")
        self.assertEqual(self.sb.events(), [])
        self.assertEqual(self.sb.notifications(), [])
        self.assertEqual(len(self.sb.calls_of("log")), 1)

    def test_first_poll_looks_back_five_minutes(self):
        self.sb.log_fixture()
        self.sb.module("localauth")
        a = log_args(self.sb.calls_of("log")[0])
        from datetime import datetime
        delta = datetime.strptime(a["end"], "%Y-%m-%d %H:%M:%S") - datetime.strptime(a["start"], "%Y-%m-%d %H:%M:%S")
        self.assertEqual(delta.total_seconds(), 300)

    def test_adjacent_polling_windows_are_contiguous_and_lose_nothing(self):
        self.sb.log_fixture(SUDO)
        self.sb.module("localauth")
        self.sb.log_fixture(SUDO.replace("14:00:02.000", "14:00:40.000"))
        self.sb.module("localauth")
        first, second = (log_args(c) for c in self.sb.calls_of("log"))
        self.assertEqual(second["start"], first["end"])
        self.assertEqual([e["when"] for e in self.sb.events()], ["2026-10-08 14:00:02.000", "2026-10-08 14:00:40.000"])
        self.assertEqual(len(self.sb.notifications()), 1)   # second alert falls inside the per-key cooldown
        with open(os.path.join(self.sb.state, "notify", "suppressed")) as f:
            self.assertEqual(f.read().strip(), "1")

    def test_failed_log_read_does_not_consume_the_window(self):
        self.sb.rc("log", 1)
        self.sb.module("localauth")
        self.sb.rc("log", None)
        self.sb.log_fixture(SUDO)
        self.sb.module("localauth")
        first, second = (log_args(c) for c in self.sb.calls_of("log"))
        self.assertEqual(second["start"], first["start"], "window consumed by a failed `log show`; events in it are lost")
        self.assertEqual(len(self.sb.events("sudo.failed")), 1)

    def test_snapshot_taken_on_local_failure_when_enabled(self):
        self.sb.log_fixture(SUDO)
        self.sb.module("localauth", TW_SNAPSHOT="1")
        self.assertEqual(len(self.sb.calls_of("screencapture")), 1)
        (snap,) = self.sb.events("snapshot")
        self.assertTrue(snap["file"].startswith(os.path.join(self.sb.logs, "snapshots")))
        self.assertTrue(snap["file"].endswith("-localauth-screen.jpg"))


SSH_INVALID = '2026-10-08 14:00:00.900 I  sshd-session[500:1] Invalid user admin from 203.0.113.5 port 51234'
SSH_FAIL_INVALID = '2026-10-08 14:00:01.000 I  sshd-session[500:1] Failed password for invalid user admin from 203.0.113.5 port 51234 ssh2'
SSH_OK_V6 = '2026-10-08 14:00:02.000 I  sshd[501:1] Accepted publickey for alice from 2001:db8::1 port 2222 ssh2: ED25519 SHA256:abc'
SSH_FAIL_LL = '2026-10-08 14:00:03.000 I  sshd[502:1] Failed password for alice from fe80::1 port 1111 ssh2'
VNC_FAIL = '2026-10-08 14:00:04.000 Df screensharingd[600:1] Authentication: FAILED :: User Name: Bob Smith :: Viewer Address: 192.168.1.9 :: Type: DH'
VNC_OK = '2026-10-08 14:00:05.000 Df screensharingd[600:1] Authentication: SUCCEEDED :: User Name: alice :: Viewer Address: 10.0.0.2 :: Type: DH'
CYMRU = "AS      | IP               | BGP Prefix          | CC | Registry | Allocated  | AS Name\n15169   | 203.0.113.5      | 203.0.113.0/24      | US | arin     | 2000-01-01 | GOOGLE, US\n"
RIR = "NetName:        GOOGLE\nOrgName:        Google LLC\nOrgAbuseEmail:  abuse@google.com\n"


class NetAuthTest(unittest.TestCase):
    def setUp(self):
        self.sb = Sandbox()
        self.sb.whois("203.0.113.5", CYMRU, RIR)
        self.sb.out("arp", "? (fe80::1) at aa:bb:cc:dd:ee:ff on en0 ifscope [ethernet]\n", key="fe80::1")
        self.sb.out("arp", "? (192.168.1.9) at 0:1c:42:0:0:8 on en0 ifscope [ethernet]\n", key="192.168.1.9")
        self.sb.out("dig", "host9.lan.\n", key="192.168.1.9")

    def tearDown(self):
        self.sb.close()

    def test_replays_ssh_and_vnc_fixtures_including_ipv6(self):
        self.sb.log_fixture(SSH_INVALID, SSH_FAIL_INVALID, SSH_OK_V6, SSH_FAIL_LL, VNC_FAIL, VNC_OK)
        self.sb.module("netauth")
        evs = self.sb.events()
        self.assertEqual([(e["type"], e["severity"]) for e in evs], [
            ("ssh.failed", "alert"), ("ssh.login", "info"), ("ssh.failed", "alert"),
            ("vnc.failed", "alert"), ("vnc.login", "info")])
        a, b, c, d, e = evs
        self.assertEqual((a["user"], a["ip"], a["port"], a["method"], a["process"]), ("admin", "203.0.113.5", "51234", "password", "sshd-session"))
        self.assertEqual((a["geo_scope"], a["geo_asn"], a["geo_org"], a["geo_country"], a["geo_class"], a["geo_abuse"]),
                         ("public", "15169", "Google LLC", "US", "cloud", "abuse@google.com"))
        self.assertEqual(a["msg"], "Failed password for invalid user admin from 203.0.113.5 port 51234 ssh2")
        self.assertEqual((b["user"], b["ip"], b["port"], b["method"], b["when"]), ("alice", "2001:db8::1", "2222", "publickey", "2026-10-08 14:00:02.000"))
        self.assertEqual(b["geo_scope"], "public")
        self.assertEqual((c["user"], c["ip"], c["port"], c["geo_scope"], c["geo_mac"], c["geo_class"]),
                         ("alice", "fe80::1", "1111", "lan", "aa:bb:cc:dd:ee:ff", "lan-device"))
        self.assertEqual((d["user"], d["ip"], d["geo_scope"], d["geo_rdns"], d["geo_mac"]), ("Bob Smith", "192.168.1.9", "lan", "host9.lan", "0:1c:42:0:0:8"))
        self.assertEqual((e["user"], e["ip"], e["geo_scope"]), ("alice", "10.0.0.2", "lan"))
        (n,) = self.sb.notifications()
        self.assertEqual(n["title"], "Remote login attempt")
        self.assertEqual(n["sound"], "Sosumi")
        self.assertTrue(n["message"].startswith("3 failed remote auth attempt(s) from: "))
        self.assertIn("203.0.113.5 (AS15169 Google LLC, US [cloud])", n["message"])
        self.assertIn("fe80::1 (LAN fe80::1 mac aa:bb:cc:dd:ee:ff)", n["message"])
        self.assertIn("192.168.1.9 (LAN host9.lan mac 0:1c:42:0:0:8)", n["message"])

    def test_success_only_window_sends_login_notice(self):
        self.sb.log_fixture(VNC_OK, SSH_OK_V6)
        self.sb.module("netauth")
        self.assertEqual([e["type"] for e in self.sb.events()], ["vnc.login", "ssh.login"])
        (n,) = self.sb.notifications()
        self.assertEqual((n["title"], n["sound"]), ("Remote login succeeded", "Glass"))
        self.assertTrue(n["message"].startswith("2 remote login(s) from: 10.0.0.2 (LAN 10.0.0.2) 2001:db8::1 ("))

    def test_repeated_source_is_listed_once_in_alert(self):
        self.sb.log_fixture(SSH_FAIL_INVALID, SSH_FAIL_INVALID.replace("51234", "51235"), SSH_FAIL_INVALID.replace("51234", "51236"))
        self.sb.module("netauth")
        self.assertEqual(len(self.sb.events("ssh.failed")), 3)
        (n,) = self.sb.notifications()
        self.assertEqual(n["message"].count("203.0.113.5"), 1, n["message"])

    def test_lockout_lines_and_unknown_processes(self):
        self.sb.log_fixture(
            '2026-10-08 14:00:01.000 I  sshd[1:1] error: maximum authentication attempts exceeded for root from 203.0.113.5 port 4000 ssh2 [preauth]',
            '2026-10-08 14:00:02.000 I  sshd[1:1] Disconnecting authenticating user root 203.0.113.5 port 4000: Too many authentication failures [preauth]',
            '2026-10-08 14:00:03.000 I  loginwindow[2:1] Failed password for nobody from 1.2.3.4 port 1 ssh2')
        self.sb.module("netauth")
        evs = self.sb.events()
        self.assertEqual([e["type"] for e in evs], ["ssh.failed", "ssh.failed"])
        self.assertEqual((evs[0]["user"], evs[0]["ip"], evs[0]["port"]), ("root", "203.0.113.5", "4000"))
        self.assertEqual(self.sb.notifications()[0]["message"][:2], "2 ")

    def test_quiet_window_and_contiguous_polls(self):
        self.sb.log_fixture()
        self.sb.module("netauth")
        self.sb.module("netauth")
        self.assertEqual(self.sb.events(), [])
        self.assertEqual(self.sb.notifications(), [])
        c1, c2 = self.sb.calls_of("log")
        self.assertIn("--info", c1)
        self.assertEqual(log_args(c2)["start"], log_args(c1)["end"])

    def test_failed_log_read_does_not_consume_the_window(self):
        self.sb.rc("log", 1)
        self.sb.module("netauth")
        self.sb.rc("log", None)
        self.sb.log_fixture(SSH_FAIL_LL)
        self.sb.module("netauth")
        c1, c2 = (log_args(c) for c in self.sb.calls_of("log"))
        self.assertEqual(c2["start"], c1["start"], "window consumed by a failed `log show`; events in it are lost")
        self.assertEqual(len(self.sb.events("ssh.failed")), 1)

    def test_enrichment_is_cached_per_ip(self):
        self.sb.log_fixture(SSH_FAIL_INVALID, SSH_FAIL_INVALID.replace("51234", "51235"))
        self.sb.module("netauth")
        self.assertEqual(len([c for c in self.sb.calls_of("whois") if c.startswith("-h")]), 1)


if __name__ == "__main__":
    unittest.main()
