"""Checks that every httpx result is in a raijin-probe result.

A result is one httpx JSON line: its URL (with the method when it is not GET) and what it answered:
status, title, content length, webserver, tech, content type (left out when text/html), CDN, error, and where it redirects
(final_url when httpx followed it, location otherwise) and its IPs when the host is a name. The URL must
be in the locations of a finding or group whose fields equal the result's fields.

usage: python verify.py <httpx.jsonl> <raijin.json>
"""
import ipaddress, json, sys
from urllib.parse import urlsplit

raw, out = sys.argv[1], sys.argv[2]
o = json.load(open(out))


def is_ip(host):
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def error_text(e):
    err = (e.get("error") or "").strip()
    u = urlsplit(e["url"])
    port = str(u.port) if u.port else ("443" if u.scheme == "https" else "80")
    if err.startswith(port + " "):
        err = err[len(port) + 1:]
    return err


entries = {}
for kind in ("findings", "groups"):
    for x in o[kind]:
        fields = (x.get("status", 0), x.get("title", ""), x.get("length", 0), x.get("server", ""),
                  tuple(sorted(x.get("tech", []))), x.get("type", ""), x.get("cdn", ""), x.get("error", ""))
        for loc in x.get("locations", []):
            entries.setdefault(loc, set()).add(fields)

miss = []
n = 0
for line in open(raw):
    line = line.strip()
    if not line.startswith("{"):
        continue
    e = json.loads(line)
    e.setdefault("url", e.get("input", ""))
    if not e["url"]:
        continue
    n += 1
    loc = e["url"]
    m = (e.get("method") or "").upper()
    if m and m != "GET":
        loc = m + " " + loc
    if e.get("final_url") and e["final_url"] != e["url"]:
        loc += " -> " + e["final_url"]
    elif e.get("location"):
        loc += " -> " + e["location"]
    host = urlsplit(e["url"]).hostname or ""
    if e.get("a") and not is_ip(host):
        loc += " [" + ", ".join(e["a"]) + "]"
    failed = e.get("failed") or not e.get("status_code")
    err = (error_text(e) or "no response") if failed else ""
    ctype = e.get("content_type", "")
    ctype = "" if ctype == "text/html" else ("none" if not ctype and not failed else ctype)
    cdn = (e.get("cdn_name") or "yes") if e.get("cdn") else ""
    fields = (e.get("status_code", 0), (e.get("title") or "").strip(), e.get("content_length", 0), e.get("webserver", ""),
              tuple(sorted(e.get("tech") or [])), ctype, cdn, err)
    if fields not in entries.get(loc, set()):
        miss.append((loc, fields))
print(f"{n} httpx results, {len(miss)} missing from output", "truncated" if o.get("budget") else "")
for m in miss[:5]:
    print("  MISSING", m)
