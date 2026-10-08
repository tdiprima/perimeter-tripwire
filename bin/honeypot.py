#!/usr/bin/python3
"""Perimeter Tripwire honeypot: fake services on tempting ports (stdlib only).
Accepts a connection, sends a banner, captures what the client sends for a few
seconds, logs peer + payload as JSON, drops the connection. Never serves anything.
usage: honeypot.py <events.jsonl> <capture-dir> <state-dir> "port=banner|port=banner"
"""
import datetime, json, os, select, signal, socket, subprocess, sys, time

EVENTS, CAP_DIR, STATE_DIR, SPEC = sys.argv[1:5]
HOLD = float(os.environ.get("TW_HP_HOLD", "3"))
COOLDOWN = int(os.environ.get("TW_HP_COOLDOWN", "300"))
MAX_BYTES = 4096

def now(): return datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")

def log(type_, sev, **kv):
    rec = {"ts": now(), "type": type_, "severity": sev}; rec.update(kv)
    with open(EVENTS, "a") as f: f.write(json.dumps(rec) + "\n")
    print(f"{rec['ts']} {sev} {type_} " + " ".join(f"{k}={v}" for k, v in kv.items()), flush=True)

def notify(title, msg, sound="Sosumi"):
    msg = msg.replace("\\", "\\\\").replace('"', '\\"'); title = title.replace('"', '\\"')
    subprocess.run(["/usr/bin/osascript", "-e",
        f'display notification "{msg}" with title "{title}" subtitle "Perimeter Tripwire" sound name "{sound}"'],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

def should_notify(ip, port):
    stamp = os.path.join(STATE_DIR, f"hp.{ip}.{port}")
    try:
        if time.time() - os.path.getmtime(stamp) < COOLDOWN: return False
    except FileNotFoundError: pass
    open(stamp, "w").close(); return True

ENRICH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "enrich-ip")

def enrich(ip):
    try:
        out = subprocess.run(["/bin/bash", ENRICH, ip], capture_output=True, text=True, timeout=20).stdout
    except Exception:
        return {}
    d = dict(l.split("=", 1) for l in out.splitlines() if "=" in l)
    d.pop("ip", None); return {"geo_" + k: v for k, v in d.items()}

def summary(g):
    sc = g.get("geo_scope")
    if sc == "loopback": return "this Mac (localhost)"
    if sc == "lan": return f"LAN {g.get('geo_rdns') or ''} mac {g.get('geo_mac') or '?'} {g.get('geo_note') or ''}".strip()
    asn = g.get("geo_asn"); org = g.get("geo_org") or g.get("geo_asname") or "unknown"
    return f"{'AS'+asn+' ' if asn else ''}{org}, {g.get('geo_country') or '??'} [{g.get('geo_class') or '?'}]"

def handle(conn, addr, port, banner):
    ip, sport = addr[0], addr[1]
    t0 = time.time(); data = b""
    try:
        conn.settimeout(0.5)
        if banner:
            try: conn.sendall(banner)
            except OSError: pass
        while time.time() - t0 < HOLD and len(data) < MAX_BYTES:
            try:
                chunk = conn.recv(1024)
                if not chunk: break
                data += chunk
            except socket.timeout: continue
            except OSError: break
    finally:
        try: conn.close()
        except OSError: pass
    printable = "".join(c if 32 <= ord(c) < 127 else "." for c in data[:256].decode("latin-1"))
    geo = enrich(ip)
    log("honeypot.hit", "alert", ip=ip, src_port=sport, port=port, bytes=len(data),
        duration=round(time.time() - t0, 2), payload=printable, hex=data[:64].hex(), **geo)
    if data:
        fn = f"{datetime.datetime.now().strftime('%Y%m%dT%H%M%S')}-{port}-{ip}.bin"
        with open(os.path.join(CAP_DIR, fn), "wb") as f: f.write(data)
    if should_notify(ip, port):
        notify(f"Honeypot hit on port {port}", f"{ip} ({summary(geo)}) sent {len(data)} bytes: {printable[:40]}")

def main():
    os.makedirs(CAP_DIR, exist_ok=True); os.chmod(CAP_DIR, 0o700)
    listeners = {}
    for item in SPEC.split("|"):
        if "=" not in item: continue
        p, b = item.split("=", 1)
        port = int(p); banner = b.encode().decode("unicode_escape").encode("latin-1")
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            s.bind(("0.0.0.0", port)); s.listen(16)
        except OSError as e:
            log("honeypot.port_busy", "warn", port=port, error=str(e)); s.close(); continue
        listeners[s] = (port, banner)
        log("honeypot.listen", "info", port=port)
    if not listeners: sys.exit(1)
    signal.signal(signal.SIGTERM, lambda *_: sys.exit(0))
    while True:
        ready, _, _ = select.select(list(listeners), [], [], 5)
        for s in ready:
            port, banner = listeners[s]
            try: conn, addr = s.accept()
            except OSError: continue
            if os.fork() == 0:   # child handles the client so the loop never blocks
                for l in listeners: l.close()
                try: handle(conn, addr, port, banner)
                finally: os._exit(0)
            conn.close()
        try:
            while os.waitpid(-1, os.WNOHANG)[0]: pass
        except ChildProcessError: pass

if __name__ == "__main__": main()
