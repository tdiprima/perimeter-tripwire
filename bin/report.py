#!/usr/bin/python3
"""Summarize events.jsonl. usage: report.py <events.jsonl> [days]"""
import collections, datetime, json, sys
path = sys.argv[1]; days = float(sys.argv[2]) if len(sys.argv) > 2 else 1
since = datetime.datetime.utcnow() - datetime.timedelta(days=days)
ev = []
for line in open(path, errors="replace"):
    try: r = json.loads(line)
    except ValueError: continue
    try: ts = datetime.datetime.strptime(r["ts"], "%Y-%m-%dT%H:%M:%SZ")
    except (KeyError, ValueError): continue
    if ts >= since: r["_ts"] = ts; ev.append(r)
print(f"Perimeter Tripwire report — last {days:g} day(s), {len(ev)} events\n")
by_type = collections.Counter(r["type"] for r in ev)
print("By type:")
for t, n in by_type.most_common(): print(f"  {n:6}  {t}")
alerts = [r for r in ev if r.get("severity") == "alert"]
ips = collections.defaultdict(lambda: {"n": 0, "types": collections.Counter(), "geo": {}})
for r in alerts:
    ip = r.get("ip")
    if not ip: continue
    e = ips[ip]; e["n"] += 1; e["types"][r["type"]] += 1
    for k, v in r.items():
        if k.startswith("geo_") and v: e["geo"][k[4:]] = v
if ips:
    print("\nTop sources:")
    for ip, e in sorted(ips.items(), key=lambda kv: -kv[1]["n"])[:15]:
        g = e["geo"]; who = g.get("org") or g.get("asname") or g.get("rdns") or ""
        tag = g.get("class", "?"); cc = g.get("country", "")
        print(f"  {e['n']:5}  {ip:<18} {tag:<12} {cc:<3} {who[:40]:<40} " + ", ".join(f"{t}×{n}" for t, n in e["types"].items()))
local = [r for r in alerts if r["type"] in ("localauth.failed", "sudo.failed", "touchid.failed")]
if local:
    print("\nLocal auth failures:")
    for r in local[-20:]:
        print(f"  {r.get('when','')[:19]}  {r['type']:<16} user={r.get('user','')} source={r.get('source', r.get('process',''))} {r.get('detail','')[:60]}")
logins = [r for r in ev if r["type"] in ("ssh.login", "vnc.login")]
if logins:
    print("\nSuccessful remote logins:")
    for r in logins[-20:]: print(f"  {r.get('when','')[:19]}  {r['type']} user={r.get('user')} from {r.get('ip')} ({r.get('geo_org') or r.get('geo_class','')})")
