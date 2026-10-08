"""TEST-3: hostile honeypot clients (bin/honeypot.py) and its supervisor (lib/mod_honeypot.sh)."""
import os, signal, socket, threading, time, unittest
from helpers import Sandbox, BIN, PY, free_port

HP = os.path.join(BIN, "honeypot.py")
MAX_BYTES, RECV = 4096, 1024


class HoneypotBase(unittest.TestCase):
    hold = "0.5"

    def setUp(self):
        self.sb = Sandbox()
        os.makedirs(self.sb.logs); os.makedirs(self.sb.state)
        self.cap = os.path.join(self.sb.logs, "honeypot")
        self.p1, self.p2 = free_port(), free_port()

    def tearDown(self):
        self.sb.close()

    def start(self, spec=None, **env):
        spec = spec or f"{self.p1}=SSH-2.0-Test\\r\\n|{self.p2}="
        self.proc = self.sb.spawn([PY, "-I", HP, self.sb.events_path, self.cap, self.sb.state, spec], TW_HP_HOLD=self.hold, **env)
        listening = [x for x in spec.split("|") if "=" in x]
        self.sb.wait_events(lambda evs: len([e for e in evs if e["type"] in ("honeypot.listen", "honeypot.port_busy")]) == len(listening))
        return self.proc

    def connect(self, port=None, timeout=5):
        s = socket.create_connection(("127.0.0.1", port or self.p1), timeout=timeout)
        return s

    def drain(self, s):
        """Read until the server closes; return everything received."""
        buf = b""
        while True:
            try:
                c = s.recv(4096)
            except socket.timeout:
                break
            except OSError:
                break
            if not c:
                break
            buf += c
        return buf

    def hits(self, n, timeout=10):
        return [e for e in self.sb.wait_events(lambda evs: len([e for e in evs if e["type"] == "honeypot.hit"]) >= n, timeout) if e["type"] == "honeypot.hit"]

    def send_all(self, s, data):
        try:
            s.sendall(data)
        except OSError:
            pass   # server closed early (capture limit) -> expected


class HoneypotTest(HoneypotBase):
    def test_banner_capture_and_peer_attribution(self):
        self.start()
        s = self.connect()
        lport = s.getsockname()[1]
        self.assertEqual(s.recv(64), b"SSH-2.0-Test\r\n")
        self.send_all(s, b"SSH-2.0-evil\r\n")
        self.drain(s); s.close()
        (h,) = self.hits(1)
        self.assertEqual((h["ip"], h["src_port"], h["port"], h["bytes"], h["severity"]), ("127.0.0.1", lport, self.p1, 14, "alert"))
        self.assertEqual(h["payload"], "SSH-2.0-evil..")
        self.assertEqual(h["hex"], b"SSH-2.0-evil\r\n".hex())
        self.assertEqual((h["geo_scope"], h["geo_class"]), ("loopback", "local"))
        self.assertLess(h["duration"], float(self.hold) + 1)
        caps = os.listdir(self.cap)
        self.assertEqual(len(caps), 1)
        self.assertTrue(caps[0].endswith(f"-{self.p1}-127.0.0.1-{lport}.bin"))
        with open(os.path.join(self.cap, caps[0]), "rb") as f:
            self.assertEqual(f.read(), b"SSH-2.0-evil\r\n")
        self.assertEqual(oct(os.stat(self.cap).st_mode & 0o777), "0o700")
        (n,) = self.sb.wait_notifications(1)
        self.assertEqual(n["title"], f"Honeypot hit on port {self.p1}")
        self.assertEqual(n["message"], "127.0.0.1 (this Mac (localhost)) sent 14 bytes: SSH-2.0-evil..")

    def test_oversized_payload_is_bounded(self):
        self.start()
        s = self.connect()
        self.send_all(s, b"A" * 200_000)
        self.drain(s); s.close()
        (h,) = self.hits(1)
        self.assertGreaterEqual(h["bytes"], MAX_BYTES)
        self.assertLess(h["bytes"], MAX_BYTES + RECV)
        self.assertEqual(len(h["payload"]), 256)
        self.assertEqual(len(h["hex"]), 128)
        (cap,) = os.listdir(self.cap)
        self.assertEqual(os.path.getsize(os.path.join(self.cap, cap)), h["bytes"])

    def test_binary_payload_is_logged_as_valid_json_and_captured_verbatim(self):
        self.start()
        data = bytes(range(256)) * 2
        s = self.connect(); self.send_all(s, data); self.drain(s); s.close()
        (h,) = self.hits(1)
        self.assertEqual(h["bytes"], 512)
        self.assertEqual(h["payload"], "".join(chr(c) if 32 <= c < 127 else "." for c in range(256)))
        self.assertEqual(h["hex"], data[:64].hex())
        (cap,) = os.listdir(self.cap)
        with open(os.path.join(self.cap, cap), "rb") as f:
            self.assertEqual(f.read(), data)

    def test_immediate_disconnect_and_empty_banner(self):
        self.start()
        s = self.connect(self.p2); s.close()
        (h,) = self.hits(1)
        self.assertEqual((h["bytes"], h["payload"], h["hex"], h["port"]), (0, "", "", self.p2))
        self.assertEqual(os.listdir(self.cap), [])        # nothing captured -> no file
        self.assertEqual(len(self.sb.wait_notifications(1)), 1)   # still alerts on a bare probe

    def test_slow_client_is_dropped_after_hold(self):
        self.start()
        s = self.connect(timeout=float(self.hold) + 3)
        t0 = time.time()
        s.recv(64)
        self.assertEqual(self.drain(s), b"")              # server hangs up, client never times out
        elapsed = time.time() - t0
        self.assertGreaterEqual(elapsed, float(self.hold) - 0.1)
        self.assertLess(elapsed, float(self.hold) + 2)
        s.close()
        (h,) = self.hits(1)
        self.assertEqual(h["bytes"], 0)

    def test_concurrent_clients_are_attributed_independently(self):
        self.start()
        n = 12; ports = {}
        def client(i):
            s = self.connect(); ports[i] = s.getsockname()[1]
            self.send_all(s, f"client-{i}".encode()); self.drain(s); s.close()
        ts = [threading.Thread(target=client, args=(i,)) for i in range(n)]
        [t.start() for t in ts]; [t.join() for t in ts]
        hs = self.hits(n)
        self.assertEqual(len(hs), n)
        self.assertEqual({h["src_port"]: h["payload"] for h in hs}, {ports[i]: f"client-{i}" for i in range(n)})
        self.assertEqual(len(os.listdir(self.cap)), n)

    def test_keeps_accepting_after_hostile_clients(self):
        self.start()
        s = self.connect(); self.send_all(s, b"\x00" * 100_000); s.close()      # oversized, abandoned
        s = self.connect(); s.close()                                             # instant drop
        half = self.connect(timeout=float(self.hold) + 3)                         # slow, still open
        s = self.connect()
        self.assertEqual(s.recv(64), b"SSH-2.0-Test\r\n")
        self.send_all(s, b"still here"); self.drain(s); s.close()
        self.drain(half); half.close()
        hs = self.hits(4)
        self.assertIn("still here", [h["payload"] for h in hs])
        self.assertIsNone(self.proc.poll())

    def test_notification_cooldown_per_ip_and_port(self):
        self.start(TW_HP_COOLDOWN="300")
        for port in (self.p1, self.p1, self.p2):
            s = self.connect(port); self.send_all(s, b"x"); self.drain(s); s.close()
        self.hits(3)
        self.sb.wait_notifications(2); time.sleep(0.5)
        self.assertEqual([n["title"] for n in self.sb.notifications()],
                         [f"Honeypot hit on port {self.p1}", f"Honeypot hit on port {self.p2}"])
        self.assertTrue(os.path.exists(os.path.join(self.sb.state, f"hp.127.0.0.1.{self.p1}")))

    def test_occupied_port_is_reported_and_the_rest_still_serve(self):
        blocker = socket.socket(); blocker.bind(("0.0.0.0", self.p1)); blocker.listen(1)
        try:
            self.start()
            (busy,) = self.sb.events("honeypot.port_busy")
            self.assertEqual((busy["port"], busy["severity"]), (self.p1, "warn"))
            self.assertIn("in use", busy["error"].lower())
            self.assertEqual([e["port"] for e in self.sb.events("honeypot.listen")], [self.p2])
            s = self.connect(self.p2); self.send_all(s, b"hi"); self.drain(s); s.close()
            self.assertEqual(self.hits(1)[0]["port"], self.p2)
        finally:
            blocker.close()

    def test_all_ports_busy_exits_nonzero(self):
        blocker = socket.socket(); blocker.bind(("0.0.0.0", self.p1)); blocker.listen(1)
        try:
            p = self.sb.spawn([PY, "-I", HP, self.sb.events_path, self.cap, self.sb.state, f"{self.p1}=x"])
            self.assertEqual(p.wait(timeout=10), 1)
        finally:
            blocker.close()

    def test_malformed_spec_items_are_ignored(self):
        self.start(f"garbage|{self.p1}=hello\\r\\n")
        self.assertEqual([e["port"] for e in self.sb.events("honeypot.listen")], [self.p1])
        s = self.connect(); self.assertEqual(s.recv(64), b"hello\r\n"); s.close()

    def test_sigterm_stops_cleanly(self):
        self.start()
        self.proc.send_signal(signal.SIGTERM)
        self.assertEqual(self.proc.wait(timeout=10), 0)


class HoneypotEnrichmentTimeoutTest(HoneypotBase):
    """Slow test (~20-30s): enrich-ip hangs, honeypot must still log the hit and serve others."""
    hold = "0.2"

    def test_enrichment_timeout_does_not_block_logging_or_service(self):
        self.sb.stub("dig", "#!/bin/bash\nsleep 40\n")
        self.start()
        s = self.connect(); self.send_all(s, b"slow-geo"); self.drain(s); s.close()
        time.sleep(1)
        self.assertEqual(self.sb.events("honeypot.hit"), [])          # stuck in enrichment, not yet logged
        s = self.connect(); self.assertEqual(s.recv(64), b"SSH-2.0-Test\r\n"); s.close()   # service continues
        hs = self.hits(2, timeout=45)
        slow = [h for h in hs if h["payload"] == "slow-geo"][0]
        self.assertEqual(slow["bytes"], 8)
        self.assertFalse([k for k in slow if k.startswith("geo_")])  # no attribution, but the evidence is there
        self.assertIn("(unknown, ?? [?])", self.sb.wait_notifications(1)[0]["message"])


class SupervisorTest(unittest.TestCase):
    def setUp(self):
        self.sb = Sandbox()
        self.fake_py = os.path.join(self.sb.tmp, "fakepython")
        with open(self.fake_py, "w") as f:
            f.write("#!/bin/bash\nprintf '%s\\n' \"$*\" >> \"$T_CALLS/fakepython.calls\"\nexec sleep 300\n")
        os.chmod(self.fake_py, 0o755)
        self.pidfile = os.path.join(self.sb.state, "honeypot.pid")

    def tearDown(self):
        pid = self.read_pid()
        if pid:
            try: os.kill(pid, signal.SIGKILL)
            except OSError: pass
        self.sb.close()

    def read_pid(self):
        try:
            with open(self.pidfile) as f: return int(f.read())
        except (OSError, ValueError): return None

    def run_mod(self):
        before = len(self.sb.calls_of("fakepython"))
        self.sb.module("honeypot", TW_HP_ENABLED="1", TW_HP_PY=self.fake_py, TW_HP_PORTS="2222=x")
        for _ in range(60):   # the fake interpreter records its argv in the background
            if len(self.sb.calls_of("fakepython")) > before or len(self.sb.events("honeypot.start")) == before: break
            time.sleep(0.05)

    def test_starts_once_then_restarts_after_death(self):
        self.run_mod()
        pid = self.read_pid()
        self.assertTrue(pid and os.kill(pid, 0) is None)
        (st,) = self.sb.events("honeypot.start")
        self.assertEqual((st["pid"], st["ports"]), (str(pid), "2222=x"))
        args = self.sb.calls_of("fakepython")[0].split()
        self.assertEqual(args[:2], ["-I", os.path.join(BIN, "honeypot.py")])
        self.assertEqual(args[2:], [self.sb.events_path, os.path.join(self.sb.logs, "honeypot"), self.sb.state, "2222=x"])
        self.run_mod()
        self.assertEqual(self.read_pid(), pid)
        self.assertEqual(len(self.sb.events("honeypot.start")), 1)
        os.kill(pid, signal.SIGKILL)
        for _ in range(60):
            try: os.kill(pid, 0); time.sleep(0.05)
            except OSError: break
        self.run_mod()
        self.assertNotEqual(self.read_pid(), pid)
        self.assertEqual(len(self.sb.events("honeypot.start")), 2)

    def test_disabled_and_missing_interpreter(self):
        self.sb.module("honeypot", TW_HP_ENABLED="0", TW_HP_PY=self.fake_py)
        self.assertEqual(self.sb.events(), [])
        self.sb.module("honeypot", TW_HP_ENABLED="1", TW_HP_PY="/nonexistent/python3")
        (e,) = self.sb.events()
        self.assertEqual((e["type"], e["severity"], e["reason"]), ("honeypot.disabled", "warn", "no /nonexistent/python3"))

    def test_stop_all_kills_and_clears_pidfile(self):
        self.run_mod()
        pid = self.read_pid()
        self.sb.tripwire("stop-honeypot")
        time.sleep(0.3)
        self.assertFalse(os.path.exists(self.pidfile))
        with self.assertRaises(OSError):
            os.kill(pid, 0)


if __name__ == "__main__":
    unittest.main()
