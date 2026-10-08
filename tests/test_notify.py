"""TEST-4: alert suppression and delivery (bin/notify, lib/notify.sh, bin/tripwire test)."""
import os, subprocess, time, unittest
from helpers import Sandbox, BIN, LIB, set_mtime

NOTIFY = os.path.join(BIN, "notify")


class NotifyTest(unittest.TestCase):
    def setUp(self):
        self.sb = Sandbox()
        self.d = os.path.join(self.sb.state, "notify")

    def tearDown(self):
        self.sb.close()

    def notify(self, key, title="T", msg="M", sound=None, **env):
        args = [NOTIFY, key, title, msg] + ([sound] if sound else [])
        e = {"TW_NOTIFY_COOLDOWN": "120", "TW_NOTIFY_MAX": "8", "TW_NOTIFY_WINDOW": "60"}; e.update(env)
        return self.sb.run(["/bin/bash"] + args, **e)

    def suppressed(self):
        try:
            with open(os.path.join(self.d, "suppressed")) as f: return int(f.read())
        except OSError: return 0

    def test_first_alert_is_delivered_exactly(self):
        r = self.notify("k1", 'Login "blocked"', 'He said "no"', "Sosumi")
        self.assertEqual(r.returncode, 0)
        self.assertEqual(self.sb.notifications(), [{"title": 'Login \\"blocked\\"', "message": 'He said \\"no\\"', "sound": "Sosumi"}])
        self.assertTrue(os.path.exists(os.path.join(self.d, "k.k1")))
        with open(os.path.join(self.d, "window")) as f: self.assertEqual(f.read().strip(), "1")

    def test_default_sound_and_key_sanitising(self):
        self.notify("Remote login attempt/./x")
        self.assertEqual(self.sb.notifications()[0]["sound"], "Basso")
        self.assertTrue(os.path.exists(os.path.join(self.d, "k.Remote_login_attempt_._x")))

    def test_per_key_cooldown_boundaries(self):
        self.notify("k"); self.notify("k")
        self.assertEqual(len(self.sb.notifications()), 1)
        self.assertEqual(self.suppressed(), 1)
        kf = os.path.join(self.d, "k.k")
        set_mtime(kf, time.time() - 119); self.notify("k")
        self.assertEqual(len(self.sb.notifications()), 1)
        self.assertEqual(self.suppressed(), 2)
        set_mtime(kf, time.time() - 121); self.notify("k")
        self.assertEqual(len(self.sb.notifications()), 2)
        self.assertEqual(self.sb.notifications()[1]["message"], "M (+2 earlier alert(s) suppressed; see events.jsonl)")
        self.assertFalse(os.path.exists(os.path.join(self.d, "suppressed")))
        self.notify("other")                                      # different key is independent
        self.assertEqual(self.sb.notifications()[2]["message"], "M")

    def test_global_window_cap_and_expiry(self):
        for i in range(10):
            self.notify(f"k{i}", TW_NOTIFY_MAX="3")
        self.assertEqual(len(self.sb.notifications()), 3)
        self.assertEqual(self.suppressed(), 7)
        win = os.path.join(self.d, "window")
        with open(win) as f: self.assertEqual(f.read().strip(), "3")
        set_mtime(win, time.time() - 59); self.notify("late1", TW_NOTIFY_MAX="3")
        self.assertEqual(len(self.sb.notifications()), 3)
        set_mtime(win, time.time() - 60); self.notify("late2", TW_NOTIFY_MAX="3")
        self.assertEqual(len(self.sb.notifications()), 4)
        self.assertEqual(self.sb.notifications()[3]["message"], "M (+8 earlier alert(s) suppressed; see events.jsonl)")
        with open(win) as f: self.assertEqual(f.read().strip(), "1")

    def test_simultaneous_notifications_conserve_the_total(self):
        n = 20
        procs = [self.sb.spawn(["/bin/bash", NOTIFY, f"k{i}", "T", "M"], TW_NOTIFY_MAX="8", TW_NOTIFY_WINDOW="60", TW_NOTIFY_COOLDOWN="120")
                 for i in range(n)]
        for p in procs: self.assertEqual(p.wait(), 0)
        sent = len(self.sb.notifications())
        self.assertGreaterEqual(sent, 1)
        self.assertLessEqual(sent, 8)
        flushed = sum(int(m["message"].split("(+")[1].split()[0]) for m in self.sb.notifications() if "(+" in m["message"])
        self.assertEqual(sent + self.suppressed() + flushed, n)

    def test_delivery_failure_is_reported_to_caller_and_logged(self):
        self.sb.rc("osascript", 1)
        r = self.notify("k")
        self.assertNotEqual(r.returncode, 0)
        self.assertEqual(len(self.sb.calls_of("osascript")), 1)
        self.sb.bash(f"source {LIB}/common.sh; source {LIB}/notify.sh; tw_notify 'Title' 'the message' Pop", check=True)
        (e,) = self.sb.events("notify.failed")
        self.assertEqual((e["severity"], e["msg"]), ("warn", "the message"))

    def test_suppressed_alert_does_not_report_failure(self):
        self.notify("k")
        self.sb.rc("osascript", 1)
        self.assertEqual(self.notify("k").returncode, 0)   # suppressed, osascript never ran
        self.assertEqual(len(self.sb.calls_of("osascript")), 1)


class SmokeCommandTest(unittest.TestCase):
    def setUp(self):
        self.sb = Sandbox()

    def tearDown(self):
        self.sb.close()

    def test_test_command_logs_and_delivers(self):
        r = self.sb.tripwire("test")
        self.assertEqual(r.returncode, 0)
        self.assertEqual(r.stdout.strip(), f"ok: {self.sb.events_path}")
        self.assertEqual(self.sb.events("test")[0]["msg"], "manual test")
        self.assertEqual(self.sb.notifications(), [{"title": "Tripwire test", "message": "Logging and notifications work.", "sound": "Basso"}])

    def test_test_command_records_delivery_failure(self):
        self.sb.rc("osascript", 1)
        r = self.sb.tripwire("test")
        self.assertEqual(len(self.sb.events("notify.failed")), 1, "notification failure must be logged, not silently swallowed")
        self.assertTrue(r.stdout.startswith("ok:"))


if __name__ == "__main__":
    unittest.main()
