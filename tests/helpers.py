"""Test harness for perimeter-tripwire.

Every test runs inside a Sandbox: a throwaway HOME / log dir / state dir, a PATH
of stub binaries (who, dscl, dig, whois, arp, route, launchctl, ...) that record
their arguments and replay canned output, and a BASH_ENV file that overrides the
absolute-path binaries the scripts call (/usr/bin/log, /usr/bin/osascript,
/usr/sbin/screencapture) with recording functions. Nothing touches the real
unified log, Notification Center, the network, or launchd.
"""
import json, os, re, shutil, socket, subprocess, tempfile, time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BIN = os.path.join(ROOT, "bin")
LIB = os.path.join(ROOT, "lib")
PY = "/usr/bin/python3"
LOG_HEADER = "Timestamp               Ty Process[PID:TID]\n"

# Generic stub: record "$*", replay $T_CALLS/<name>.out[.<last-arg>], exit with $T_CALLS/<name>.rc.
STUB = """#!/bin/bash
n=%(name)s
a="$*"; printf '%%s\\n' "${a//$'\\n'/ }" >> "$T_CALLS/$n.calls"
k=$(printf '%%s' "${!#}" | tr -c 'A-Za-z0-9.:_-' '_')
if [ -f "$T_CALLS/$n.out.$k" ]; then cat "$T_CALLS/$n.out.$k"
elif [ -f "$T_CALLS/$n.out" ]; then cat "$T_CALLS/$n.out"; fi
[ -f "$T_CALLS/$n.rc" ] && exit "$(cat "$T_CALLS/$n.rc")"
exit 0
"""

BASH_ENV = r"""
__tw_stub() {
  local n=$1 a; shift; a="$*"
  printf '%s\n' "${a//$'\n'/ }" >> "$T_CALLS/$n.calls"
  if [ -f "$T_CALLS/$n.out" ]; then cat "$T_CALLS/$n.out"; fi
  [ -f "$T_CALLS/$n.rc" ] && return "$(cat "$T_CALLS/$n.rc")"
  return 0
}
/usr/bin/log() { __tw_stub log "$@"; }
/usr/bin/osascript() { __tw_stub osascript "$@"; }
/usr/sbin/screencapture() { __tw_stub screencapture "$@"; }
"""

STAT = """#!/bin/bash
if [ "$1" = "-f%Su" ] && [ "$2" = "/dev/console" ]; then echo "${T_CONSOLE_USER:-alice}"; exit 0; fi
exec /usr/bin/stat "$@"
"""

DSCL = """#!/bin/bash
printf '%s\\n' "$*" >> "$T_CALLS/dscl.calls"
[ "$2" = "-search" ] || exit 0
u=$(awk -v id="$5" '$1==id{print $2}' "$T_CALLS/dscl.map" 2>/dev/null)
[ -n "$u" ] && printf '%s\\t\\tGeneratedUID = (\\n    "%s"\\n)\\n' "$u" "$5"
exit 0
"""

WHOIS = """#!/bin/bash
printf '%s\\n' "$*" >> "$T_CALLS/whois.calls"
if [ "$1" = -h ]; then f=cymru; else f=rir; fi
ip=${!#}; ip=${ip##* }
[ -f "$T_CALLS/whois.$f.$ip" ] && cat "$T_CALLS/whois.$f.$ip"
exit 0
"""

LAUNCHCTL = """#!/bin/bash
printf '%s\\n' "$*" >> "$T_CALLS/launchctl.calls"
case "$1" in
  bootout) exit "${T_BOOTOUT_RC:-1}" ;;
  print) printf '\\tstate = running\\n\\tpid = 4242\\n' ;;
esac
exit 0
"""

NOTIF_RE = re.compile(r'display notification "(.*)" with title "(.*)" subtitle "Perimeter Tripwire" sound name "(.*)"$')


class Sandbox:
    def __init__(self):
        self.tmp = tempfile.mkdtemp(prefix="twtest.")
        self.home = os.path.join(self.tmp, "home")
        self.logs = os.path.join(self.tmp, "logs")
        self.state = os.path.join(self.tmp, "state")
        self.stubs = os.path.join(self.tmp, "stubs")
        self.calls = os.path.join(self.tmp, "calls")
        for d in (self.home, self.stubs, self.calls):
            os.makedirs(d)
        self.bash_env = os.path.join(self.tmp, "bash_env.sh")
        with open(self.bash_env, "w") as f:
            f.write(BASH_ENV)
        # bash ignores BASH_ENV (and reads ~/.bashrc instead) when stdin is a socket, so cover both.
        with open(os.path.join(self.home, ".bashrc"), "w") as f:
            f.write(f'source "{self.bash_env}"\n')
        self.events_path = os.path.join(self.logs, "events.jsonl")
        for n in ("who", "dig", "arp", "route", "imagesnap", "rsync"):
            self.stub(n)
        os.remove(os.path.join(self.stubs, "rsync"))      # real rsync is fine; keep others
        os.remove(os.path.join(self.stubs, "imagesnap"))  # absent -> snapshot falls back to screencapture
        self.stub("stat", STAT)
        self.stub("dscl", DSCL)
        self.stub("whois", WHOIS)
        self.stub("launchctl", LAUNCHCTL)
        self.procs = []

    def close(self):
        for p in self.procs:
            if p.poll() is None:
                p.kill()
                p.wait()
        shutil.rmtree(self.tmp, ignore_errors=True)

    # -- stubs -----------------------------------------------------------
    def stub(self, name, script=None):
        p = os.path.join(self.stubs, name)
        with open(p, "w") as f:
            f.write(script if script is not None else STUB % {"name": name})
        os.chmod(p, 0o755)

    def out(self, name, text, key=None):
        fn = f"{name}.out" if key is None else f"{name}.out.{re.sub(r'[^A-Za-z0-9.:_-]', '_', key)}"
        with open(os.path.join(self.calls, fn), "w") as f:
            f.write(text)

    def rc(self, name, code):
        p = os.path.join(self.calls, f"{name}.rc")
        if code is None:
            if os.path.exists(p):
                os.remove(p)
        else:
            with open(p, "w") as f:
                f.write(str(code))

    def calls_of(self, name):
        p = os.path.join(self.calls, f"{name}.calls")
        if not os.path.exists(p):
            return []
        with open(p) as f:
            return f.read().splitlines()

    def clear_calls(self, name):
        p = os.path.join(self.calls, f"{name}.calls")
        if os.path.exists(p):
            os.remove(p)

    def log_fixture(self, *lines):
        self.out("log", LOG_HEADER + "".join(l + "\n" for l in lines))

    def dscl_map(self, **uuid_to_user):
        with open(os.path.join(self.calls, "dscl.map"), "a") as f:
            for uuid, user in uuid_to_user.items():
                f.write(f"{uuid} {user}\n")

    def whois(self, ip, cymru="", rir=""):
        with open(os.path.join(self.calls, f"whois.cymru.{ip}"), "w") as f:
            f.write(cymru)
        with open(os.path.join(self.calls, f"whois.rir.{ip}"), "w") as f:
            f.write(rir)

    # -- running ---------------------------------------------------------
    def env(self, **extra):
        e = {
            "PATH": self.stubs + ":/usr/bin:/bin:/usr/sbin:/sbin",
            "HOME": self.home, "TMPDIR": self.tmp, "LANG": "C", "LC_ALL": "C",
            "TW_LOG_DIR": self.logs, "TW_STATE_DIR": self.state,
            "TW_SNAPSHOT": "0", "TW_HP_ENABLED": "0",
            "BASH_ENV": self.bash_env, "T_CALLS": self.calls,
        }
        e.update({k: str(v) for k, v in extra.items()})
        return e

    def bash(self, script, check=False, **extra):
        r = self.run(["/bin/bash", "-c", script], **extra)
        if check and r.returncode != 0:
            raise AssertionError(f"bash failed rc={r.returncode}\n{script}\n{r.stdout}\n{r.stderr}")
        return r

    def run(self, argv, **extra):
        return subprocess.run(argv, cwd=ROOT, env=self.env(**extra), stdin=subprocess.DEVNULL,
                              capture_output=True, text=True, timeout=120)

    def module(self, name, **extra):
        src = "; ".join(f"source {LIB}/{f}" for f in ("common.sh", "notify.sh", "enrich.sh", "snapshot.sh", f"mod_{name}.sh"))
        return self.bash(f"{src}; tw_mod_{name}", check=True, **extra)

    def tripwire(self, *args, **extra):
        return self.bash(" ".join(["/bin/bash", os.path.join(BIN, "tripwire")] + [f"'{a}'" for a in args]), **extra)

    def spawn(self, argv, **extra):
        p = subprocess.Popen(argv, cwd=ROOT, env=self.env(**extra), stdin=subprocess.DEVNULL,
                             stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        self.procs.append(p)
        return p

    # -- results ---------------------------------------------------------
    def raw_events(self):
        if not os.path.exists(self.events_path):
            return []
        with open(self.events_path, "rb") as f:
            return f.read().decode("utf-8", "surrogateescape").splitlines()

    def events(self, type_=None):
        evs = []
        for line in self.raw_events():
            try:
                evs.append(json.loads(line))
            except ValueError as e:
                raise AssertionError(f"unparseable events.jsonl line: {line!r}: {e}")
        if type_:
            evs = [e for e in evs if e["type"] == type_]
        return evs

    def wait_events(self, pred, timeout=10):
        deadline = time.time() + timeout
        while time.time() < deadline:
            try:
                evs = self.events()
            except AssertionError:
                evs = []
            if pred(evs):
                return evs
            time.sleep(0.05)
        raise AssertionError(f"timed out waiting for events; have {self.events()}")

    def wait_notifications(self, n, timeout=5):
        deadline = time.time() + timeout
        while time.time() < deadline and len(self.calls_of("osascript")) < n:
            time.sleep(0.05)
        return self.notifications()

    def notifications(self):
        res = []
        for c in self.calls_of("osascript"):
            m = NOTIF_RE.search(c)
            if not m:
                raise AssertionError(f"unexpected osascript call: {c!r}")
            res.append({"message": m.group(1), "title": m.group(2), "sound": m.group(3)})
        return res

    def write_events(self, records):
        os.makedirs(self.logs, exist_ok=True)
        with open(self.events_path, "w") as f:
            for r in records:
                f.write(r if isinstance(r, str) else json.dumps(r))
                f.write("\n")

    def write_events_bytes(self, data):
        os.makedirs(self.logs, exist_ok=True)
        with open(self.events_path, "wb") as f:
            f.write(data)


def free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


def set_mtime(path, when):
    os.utime(path, (when, when))
