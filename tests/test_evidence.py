"""TEST-2: evidence integrity (lib/common.sh tw_log, lib/mod_housekeeping.sh)."""
import os, subprocess, time, unittest
from helpers import Sandbox, LIB, BIN, PY, set_mtime

SRC = f"source {LIB}/common.sh"


class JsonLogTest(unittest.TestCase):
    def setUp(self):
        self.sb = Sandbox()

    def tearDown(self):
        self.sb.close()

    def test_basic_record_shape(self):
        self.sb.bash(f'{SRC}; tw_log ssh.failed alert user=bob ip=1.2.3.4', check=True)
        (e,) = self.sb.events()
        self.assertEqual((e["type"], e["severity"], e["user"], e["ip"]), ("ssh.failed", "alert", "bob", "1.2.3.4"))
        self.assertRegex(e["ts"], r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")
        self.assertTrue(os.path.exists(self.sb.events_path))
        self.assertEqual(oct(os.stat(self.sb.logs).st_mode & 0o777), "0o700")

    def test_values_with_quotes_backslashes_equals_and_whitespace_round_trip(self):
        val = 'say "hi" \\ back=slash\ttab\r\nnewline'
        self.sb.bash(f'{SRC}; tw_log t info "msg=$1" "empty=" "k=v=w"', check=True)
        self.sb.bash(f'{SRC}; tw_log t info "msg=$1"', check=True)
        self.sb.run(["/bin/bash", "-c", f"{SRC}; tw_log t info \"msg=$1\"", "_", val])
        evs = self.sb.events()
        self.assertEqual(len(evs), 3)
        self.assertEqual(evs[0]["empty"], "")
        self.assertEqual(evs[0]["k"], "v=w")
        self.assertEqual(evs[2]["msg"], val)

    def test_control_characters_still_yield_parseable_json(self):
        val = "esc\x1b[0m bell\x07 soh\x01 end"
        self.sb.run(["/bin/bash", "-c", f"{SRC}; tw_log t info \"msg=$1\"", "_", val])
        (e,) = self.sb.events()
        self.assertEqual(e["msg"], val)

    def test_concurrent_bash_and_python_writers_never_interleave(self):
        n_bash, n_py, per = 8, 2, 60
        script = f'{SRC}; for i in $(seq 1 {per}); do tw_log concurrent info writer="$1" i="$i" pad="{"x" * 300}"; done'
        procs = [self.sb.spawn(["/bin/bash", "-c", script, "_", f"b{i}"]) for i in range(n_bash)]
        py = f'''import json,sys
for i in range({per}):
    with open(sys.argv[1],"a") as f: f.write(json.dumps({{"ts":"2026-10-08T00:00:00Z","type":"concurrent","severity":"info","writer":sys.argv[2],"i":str(i),"pad":"y"*300}})+"\\n")'''
        procs += [self.sb.spawn([PY, "-I", "-c", py, self.sb.events_path, f"p{i}"]) for i in range(n_py)]
        for p in procs:
            self.assertEqual(p.wait(), 0)
        evs = self.sb.events("concurrent")
        self.assertEqual(len(evs), (n_bash + n_py) * per)
        seen = {(e["writer"], e["i"]) for e in evs}
        self.assertEqual(len(seen), (n_bash + n_py) * per)
        self.assertTrue(all(len(e["pad"]) == 300 for e in evs))


class HousekeepingTest(unittest.TestCase):
    def setUp(self):
        self.sb = Sandbox()
        os.makedirs(self.sb.logs)
        os.makedirs(self.sb.state)
        self.hk = os.path.join(self.sb.state, "housekeeping.last")

    def tearDown(self):
        self.sb.close()

    def run_hk(self, **env):
        if os.path.exists(self.hk):
            set_mtime(self.hk, time.time() - 7200)   # force: last run > 1h ago
        self.sb.module("housekeeping", **env)

    def fill(self, path, size, byte=b"{\"type\":\"filler\"}\n"):
        with open(path, "wb") as f:
            f.write((byte * (size // len(byte) + 1))[:size])

    def test_runs_at_most_once_per_hour(self):
        self.fill(self.sb.events_path, 2 * 1048576)
        self.sb.module("housekeeping", TW_ROTATE_MB="1")   # first run: no state file -> runs
        self.assertTrue(os.path.exists(self.sb.events_path + ".1"))
        self.fill(self.sb.events_path, 2 * 1048576)
        self.sb.module("housekeeping", TW_ROTATE_MB="1")   # within the hour -> skipped
        self.assertFalse(os.path.exists(self.sb.events_path + ".2"))
        self.assertEqual(os.path.getsize(self.sb.events_path), 2 * 1048576)

    def test_rotation_threshold_is_strictly_above_limit(self):
        self.fill(self.sb.events_path, 1048576)
        self.run_hk(TW_ROTATE_MB="1")
        self.assertFalse(os.path.exists(self.sb.events_path + ".1"))
        self.assertEqual(os.path.getsize(self.sb.events_path), 1048576)
        self.fill(self.sb.events_path, 1048577)
        with open(self.sb.events_path, "rb") as f:
            original = f.read()
        self.run_hk(TW_ROTATE_MB="1")
        with open(self.sb.events_path + ".1", "rb") as f:
            self.assertEqual(f.read(), original)              # evidence preserved byte for byte
        (ev,) = self.sb.events("housekeeping.rotated")       # new file holds only the rotation record
        self.assertEqual(ev["file"], self.sb.events_path)
        self.assertEqual(oct(os.stat(self.sb.events_path + ".1").st_mode & 0o777), "0o600")
        self.assertEqual(oct(os.stat(self.sb.events_path).st_mode & 0o777), "0o600")

    def test_rotation_chain_keeps_n_generations(self):
        for i, content in ((1, b"gen1\n"), (2, b"gen2\n")):
            with open(f"{self.sb.events_path}.{i}", "wb") as f:
                f.write(content)
        self.fill(self.sb.events_path, 1048577)
        self.run_hk(TW_ROTATE_MB="1", TW_KEEP_ROTATED="2")
        with open(self.sb.events_path + ".2", "rb") as f:
            self.assertEqual(f.read(), b"gen1\n")
        self.assertEqual(os.path.getsize(self.sb.events_path + ".1"), 1048577)
        self.assertFalse(os.path.exists(self.sb.events_path + ".3"))

    def test_daemon_log_rotates_too(self):
        dl = os.path.join(self.sb.logs, "daemon.log")
        self.fill(dl, 1048577, b"log line\n")
        self.run_hk(TW_ROTATE_MB="1")
        self.assertTrue(os.path.exists(dl + ".1"))
        self.assertEqual(os.path.getsize(dl), 0)

    def test_retention_deletes_only_expired_evidence(self):
        # BSD find's `-mtime +N` matches files older than N+1 full days, so the real cutoff is KEEP_DAYS+1.
        day = 86400
        now = time.time()
        dirs = {d: os.path.join(self.sb.logs, d) for d in ("honeypot", "snapshots")}
        dirs.update({d: os.path.join(self.sb.state, d) for d in ("ipcache", "notify")})
        for d in dirs.values():
            os.makedirs(d)
        files = {}
        for d in ("honeypot", "snapshots"):
            for name, age in (("old", 31 * day + 7200), ("edge", 30 * day + 7200), ("new", day)):
                p = os.path.join(dirs[d], name); open(p, "w").close(); set_mtime(p, now - age); files[(d, name)] = p
        for d in ("ipcache", "notify"):
            for name, age in (("old", 32 * day), ("new", 29 * day)):
                p = os.path.join(dirs[d], name); open(p, "w").close(); set_mtime(p, now - age); files[(d, name)] = p
        for name, age in (("hp.1.2.3.4.22", 2 * day), ("hp.5.6.7.8.22", 3600), ("netauth.last", 10 * day)):
            p = os.path.join(self.sb.state, name); open(p, "w").close(); set_mtime(p, now - age); files[("state", name)] = p
        self.sb.write_events([{"ts": "2020-01-01T00:00:00Z", "type": "ancient", "severity": "alert"}])
        set_mtime(self.sb.events_path, now - 400 * day)
        self.run_hk(TW_KEEP_DAYS="30")
        gone = {k for k, p in files.items() if not os.path.exists(p)}
        self.assertEqual(gone, {("honeypot", "old"), ("snapshots", "old"), ("ipcache", "old"), ("notify", "old"), ("state", "hp.1.2.3.4.22")})
        self.assertEqual(self.sb.events("ancient")[0]["type"], "ancient")   # events.jsonl is never pruned

    def test_custom_keep_days(self):
        d = os.path.join(self.sb.logs, "honeypot"); os.makedirs(d)
        p = os.path.join(d, "cap"); open(p, "w").close(); set_mtime(p, time.time() - 9 * 86400)
        self.run_hk(TW_KEEP_DAYS="7")
        self.assertFalse(os.path.exists(p))

    def test_permissions_are_tightened(self):
        os.chmod(self.sb.logs, 0o755); os.chmod(self.sb.state, 0o755)
        open(self.sb.events_path, "w").close(); os.chmod(self.sb.events_path, 0o644)
        self.run_hk()
        self.assertEqual(oct(os.stat(self.sb.logs).st_mode & 0o777), "0o700")
        self.assertEqual(oct(os.stat(self.sb.state).st_mode & 0o777), "0o700")
        self.assertEqual(oct(os.stat(self.sb.events_path).st_mode & 0o777), "0o600")


if __name__ == "__main__":
    unittest.main()
