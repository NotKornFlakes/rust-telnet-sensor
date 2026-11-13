#!/usr/bin/env python3
"""Ask URLhaus and AbuseIPDB whether they already knew the honeypot's download addresses and IPs.

Run it by hand from the repository root:

    python3 analysis/threat_intel_lookup.py           # shows what it would look up, sends nothing
    python3 analysis/threat_intel_lookup.py --send    # does the lookups after you type yes
    python3 analysis/threat_intel_lookup.py --first-reporter --send   # who reported each IP first
    python3 analysis/threat_intel_lookup.py --older-reports --send    # settle what the lists can't

What it sends, and nothing else:
  - URLhaus, with your Auth-Key: each download address to the URL lookup
    (POST https://urlhaus-api.abuse.ch/v1/url/), and each address's server, the host name or IP
    and nothing more, to the host lookup (POST https://urlhaus-api.abuse.ch/v1/host/).
  - AbuseIPDB, with your API key: each visitor IP to the check lookup
    (GET https://api.abuseipdb.com/api/v2/check).

It never submits or reports anything, never contacts a download address or any other host, and
refuses redirects. It never sends log contents: no commands, usernames, passwords or times.
Passwords are read once, only to leave out your own test visits, as the notebook does.

Keys come from the URLHAUS_AUTH_KEY and ABUSEIPDB_KEY environment variables, or it asks for them
without echoing. They're never written down or printed.

With --first-reporter it looks up, instead, each IP that analysis/report_abuseipdb.py recorded
in ~/honeypot-logs/abuseipdb/reported.json, with the same AbuseIPDB check, and says who reported
it first: us, someone else, or can't tell. Our report is the one with the exact comment and
categories we recorded, dated when the reporter ran or at the attack time it sent (AbuseIPDB may
use either), and any other report from the same account counts as ours too. AbuseIPDB lists
only the newest 100 reports per IP, so when it has more than it lists and ours is the earliest
listed, or isn't listed at all, the answer is "can't tell": the missing ones are older. "First"
means first in the past year, the furthest back AbuseIPDB goes. Other reporters' comments are
never shown or saved.

With --older-reports it makes one more check for each IP the others couldn't settle. One is an IP
with more reports than the newest 100 AbuseIPDB lists, all of the listed ones from after the
honeypot first saw it. That check asks only how many reports came in since a day or more before
the honeypot first saw the IP (maxAgeInDays, with no report details). If the year check counted
more, the rest are older, so the IP was reported before. It does the same for an IP you reported
where --first-reporter couldn't tell who was first, counting from the earliest date AbuseIPDB may
give your report. Reports only pile up, so the surplus is a lower bound, unless some were deleted
in between.

Results go to ~/honeypot-logs/intel/lookups.json, readable only by you. They hold full IPs and
addresses, so safety rule 4 applies: never commit or publish the file. Entries older than 30 days
are dropped each time this runs, matching KEEP_DAYS in deploy/daily-logs.sh. The notebook reads
the file and turns every IP and address into an opaque ID straight away.
"""

import argparse
import getpass
import ipaddress
import json
import math
import os
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from collections import Counter
from datetime import datetime, timedelta, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import abuse_review  # noqa: E402

LOG_DIR = Path.home() / "honeypot-logs"
OUT_FILE = LOG_DIR / "intel" / "lookups.json"
KEEP_DAYS = 30  # the same as deploy/daily-logs.sh
OWN_TEST_PASSWORD = "not-on-the-list"  # my own test visits used this password
REPORT_DAYS = 365  # the longest look-back AbuseIPDB allows
FREE_DAILY_CHECKS = 1000
# AbuseIPDB's check lists only the newest 100 reports for one IP. Its docs say 10,000, but in the
# Nov 10 lookups no list held more than 100, and every IP with more listed exactly 100.
LISTED_REPORTS_CAP = 100
MARGIN_DAYS = 1  # --older-reports counts from a day further back, in case AbuseIPDB rounds days
# Our report is dated when the reporter ran, give or take the clocks, or at the attack time it sent.
# The reporter records its start time, and a long run sends its last report a while later.
CLOCK_SLACK = timedelta(minutes=5)
RUN_LENGTH = timedelta(hours=1)

URLHAUS_URL = "https://urlhaus-api.abuse.ch/v1/url/"
URLHAUS_HOST = "https://urlhaus-api.abuse.ch/v1/host/"
ABUSEIPDB_CHECK = "https://api.abuseipdb.com/api/v2/check"
# The only requests this script can make. Anything else is refused before it's sent.
ALLOWED = {("POST", URLHAUS_URL), ("POST", URLHAUS_HOST), ("GET", ABUSEIPDB_CHECK)}
USER_AGENT = "honeypot-lookup/1"


class NoRedirects(urllib.request.HTTPRedirectHandler):
    """A redirect could point anywhere, including a download address, so none are followed."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None  # urllib then raises HTTPError for the 3xx response


OPENER = urllib.request.build_opener(NoRedirects)


def call(method, endpoint, headers, query=None, form=None):
    """Make one allowed lookup and return its JSON. Refuses any other endpoint."""
    if (method, endpoint) not in ALLOWED:
        raise SystemExit(f"Refused {method} {endpoint}: it isn't one of the three lookup endpoints.")
    url = endpoint + ("?" + query if query else "")
    body = urllib.parse.urlencode(form).encode() if form is not None else None
    request = urllib.request.Request(url, data=body, method=method,
                                     headers={"User-Agent": USER_AGENT, **headers})
    with OPENER.open(request, timeout=30) as response:
        return json.load(response), response.headers


def now():
    return datetime.now(timezone.utc)


def parse_time(text):
    """URLhaus writes '2019-01-19 01:33:26 UTC', AbuseIPDB '2019-07-23T17:29:38+00:00'."""
    if not text:
        return None
    text = text.strip()
    if text.endswith(" UTC"):
        return datetime.strptime(text, "%Y-%m-%d %H:%M:%S UTC").replace(tzinfo=timezone.utc)
    return datetime.fromisoformat(text)


def defang(text):
    """For the screen: no full IPs and no working links."""
    text = re.sub(r"\b(\d{1,3})\.(\d{1,3})\.\d{1,3}\.\d{1,3}\b", r"\1[.]\2[.]x[.]x", text)
    text = re.sub(r"(?i)\bhttp", "hxxp", text)
    text = re.sub(r"(hxxps?://)([A-Za-z0-9.-]+)", lambda m: m[1] + m[2].replace(".", "[.]"), text)
    return re.sub(r"(?<=/)(?=[A-Za-z0-9]*\d)(?=[A-Za-z0-9]*[A-Za-z])[A-Za-z0-9]{8,}(?=/)", "<id>", text)


def is_public_ip(text):
    try:
        return ipaddress.ip_address(text).is_global
    except ValueError:
        return False


def server_of(address):
    """The host part of a download address, read from its text. Nothing is contacted.

    Returns (host, reason): reason is set when the address shouldn't be looked up at all.
    """
    if "://" not in address:  # a bare host, as tftp takes it
        host = address.strip()
        if not re.fullmatch(r"[A-Za-z0-9.-]+", host):
            return None, "not a plain host name"
    else:
        try:
            parts = urllib.parse.urlsplit(address)
            host = parts.hostname
        except ValueError:
            return None, "can't be read as a URL"
        if parts.scheme.lower() not in ("http", "https"):
            return None, "not an http or https address"
        if "@" in parts.netloc:
            return None, "it holds a user name or password"
        if parts.query or parts.fragment:
            return None, "it has a query string, which can carry the target's details"
        if not host:
            return None, "no host"
    if re.fullmatch(r"[\d.]+", host) and not is_public_ip(host):
        return None, "its server isn't a public IP"
    return host.lower(), None


def read_logs(log_dir):
    """Visitor IPs and download addresses, each with the first time the honeypot saw it."""
    raw = []
    for path in sorted(log_dir.glob("visits-*.jsonl")):
        with path.open(encoding="utf-8", errors="replace") as f:
            for line in f:
                try:
                    raw.append(json.loads(line))
                except json.JSONDecodeError:
                    pass  # a line cut off while the log was being copied
    own = {v["source_ip"] for v in raw if v.get("password") == OWN_TEST_PASSWORD}
    ips, addresses, left_out = {}, {}, Counter()
    for v in raw:
        ip, seen = v["source_ip"], datetime.fromtimestamp(v["time"], timezone.utc)
        if ip in own:
            continue
        if not is_public_ip(ip):
            left_out["non-public IP"] += 1
            continue
        ips[ip] = min(ips.get(ip, seen), seen)
        for address in (v.get("shell") or {}).get("urls") or []:
            addresses[address] = min(addresses.get(address, seen), seen)
    return ips, addresses, len(own), left_out


SECTIONS = ("urlhaus", "abuseipdb", "first_reporter", "abuseipdb_older", "first_reporter_older")


def load_results(path):
    if not path.exists():
        return {"format": 1, **{section: {} for section in SECTIONS}}
    data = json.loads(path.read_text())
    cutoff = now() - timedelta(days=KEEP_DAYS)
    for section in SECTIONS:
        data[section] = {k: r for k, r in data.get(section, {}).items()
                         if parse_time(r["checked_at"]) >= cutoff}
    return data


def save_results(path, data):
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chmod(path.parent, 0o700)
    temp = path.with_suffix(".tmp")
    fd = os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        json.dump(data, f, indent=1, sort_keys=True)
    os.replace(temp, path)


def get_key(variable, name):
    key = os.environ.get(variable) or getpass.getpass(f"{name} key (not shown, not saved): ")
    if not key.strip():
        raise SystemExit(f"No {name} key given.")
    return key.strip()


def urlhaus_lookups(addresses, key, results):
    """One URL lookup per http(s) address and one host lookup per server."""
    hosts = {}
    for address, (host, first_seen) in addresses.items():
        record = {"checked_at": now().isoformat(), "first_seen_here": first_seen.isoformat(),
                  "kind": "url" if "://" in address else "host"}
        if record["kind"] == "url":
            data, _ = call("POST", URLHAUS_URL, {"Auth-Key": key}, form={"url": address})
            payloads = data.get("payloads") or []
            added = parse_time(data.get("date_added"))
            record["url"] = {
                "status": data.get("query_status"), "date_added": data.get("date_added"),
                "before_us": bool(added and added < first_seen), "url_status": data.get("url_status"),
                "last_online": data.get("last_online"), "threat": data.get("threat"),
                "tags": data.get("tags") or [], "payloads": len(payloads),
                "signatures": sorted({p["signature"] for p in payloads if p.get("signature")}),
                "reference": data.get("urlhaus_reference"),
            }
            time.sleep(1)
        if host not in hosts:
            data, _ = call("POST", URLHAUS_HOST, {"Auth-Key": key}, form={"host": host})
            hosts[host] = data
            time.sleep(1)
        data = hosts[host]
        seen = parse_time(data.get("firstseen"))
        record["host"] = {
            # The documentation's own example spells the status key "query_staus".
            "status": data.get("query_status") or data.get("query_staus"),
            "firstseen": data.get("firstseen"), "before_us": bool(seen and seen < first_seen),
            "url_count": data.get("url_count"), "reference": data.get("urlhaus_reference"),
        }
        results["urlhaus"][address] = record
        print(f"  {defang(address)}: URL {record.get('url', {}).get('status', '(not a URL)')}, "
              f"server {record['host']['status']}")


def abuseipdb_checks(ips, key, results, out_file, limit):
    done, remaining = 0, None
    for ip, first_seen in ips.items():
        if done >= limit:
            print(f"  Stopped at --limit {limit}.")
            break
        query = urllib.parse.urlencode({"ipAddress": ip, "maxAgeInDays": REPORT_DAYS}) + "&verbose"
        try:
            data, headers = call("GET", ABUSEIPDB_CHECK, {"Key": key, "Accept": "application/json"},
                                 query=query)
        except urllib.error.HTTPError as e:
            if e.code == 429:
                reset = e.headers.get("X-RateLimit-Reset")
                when = datetime.fromtimestamp(int(reset), timezone.utc).strftime("%b %d %H:%M UTC") if reset else "later"
                print(f"  AbuseIPDB's daily limit is used up. Run this again after {when}; it carries on "
                      "where it stopped.")
                break
            raise
        d = data["data"]
        times = sorted(t for t in (parse_time(r.get("reportedAt")) for r in d.get("reports") or []) if t)
        results["abuseipdb"][ip] = {
            "checked_at": now().isoformat(), "first_seen_here": first_seen.isoformat(),
            "score": d.get("abuseConfidenceScore"), "total_reports": d.get("totalReports"),
            "distinct_users": d.get("numDistinctUsers"), "last_reported": d.get("lastReportedAt"),
            "first_reported": times[0].isoformat() if times else None,
            "reports_before_us": sum(t < first_seen for t in times),
            "usage_type": d.get("usageType"), "is_tor": d.get("isTor"),
            "is_whitelisted": d.get("isWhitelisted"),
        }
        done += 1
        remaining = headers.get("X-RateLimit-Remaining", remaining)
        if done % 25 == 0:
            save_results(out_file, results)
            print(f"  {done} checked…")
        time.sleep(0.2)
    print(f"  {done} IPs checked this run." + (f" AbuseIPDB says {remaining} checks are left today."
                                              if remaining is not None else ""))


def first_reporter(ours, data):
    """Who reported an IP first, from a verbose check lookup and our own record of reporting it.

    The result holds times, counts and a verdict, never another reporter's comment or details.
    """
    d = data.get("data") or {}
    reports = [r for r in d.get("reports") or [] if parse_time(r.get("reportedAt"))]
    total = d.get("totalReports") or 0
    reported_at, attack = parse_time(ours["reported_at"]), parse_time(ours.get("timestamp"))
    categories = set(ours.get("categories") or [])

    def at(r):
        return parse_time(r["reportedAt"])

    def looks_ours(r):
        if r.get("comment") != ours.get("comment") or set(r.get("categories") or []) != categories:
            return False  # the comments are public, so the time has to match as well
        sent = reported_at - CLOCK_SLACK <= at(r) <= reported_at + RUN_LENGTH
        return sent or (attack is not None and abs(at(r) - attack) <= CLOCK_SLACK)

    result = {"our_report_at": ours["reported_at"], "listed": len(reports), "total_reports": total,
              "ours_found": False, "others_before_us": None, "first_other_at": None}
    matches = sorted((r for r in reports if looks_ours(r)), key=lambda r: abs(at(r) - reported_at))
    if not matches:
        if len(reports) < total:
            return {**result, "first": "can't tell",
                    "why": f"our report isn't among the {len(reports)} newest that AbuseIPDB lists, of {total:,}"}
        return {**result, "first": "can't tell", "why": "our report isn't listed"}
    mine = matches[0]
    our_id = mine.get("reporterId")

    def is_ours(r):
        return r is mine or (our_id is not None and r.get("reporterId") == our_id)

    our_first = min(at(r) for r in reports if is_ours(r))
    others = sorted(at(r) for r in reports if not is_ours(r) and at(r) < our_first)
    result.update(ours_found=True, others_before_us=len(others),
                  first_other_at=others[0].isoformat() if others else None)
    if others:
        return {**result, "first": "someone else",
                "why": f"{len(others)} report(s) from others before ours, the first on {others[0]:%b %d}"}
    if len(reports) < total:
        return {**result, "first": "can't tell",
                "why": f"AbuseIPDB lists only the newest {LISTED_REPORTS_CAP} reports and has {total:,} for this IP, "
                       "so older ones may be missing"}
    return {**result, "first": "us", "why": "no listed report from anyone else before ours"}


def first_reporter_checks(todo, key, results, out_file, limit):
    done, remaining = 0, None
    for ip, ours in todo.items():
        if done >= limit:
            print(f"  Stopped at --limit {limit}.")
            break
        query = urllib.parse.urlencode({"ipAddress": ip, "maxAgeInDays": REPORT_DAYS}) + "&verbose"
        try:
            data, headers = call("GET", ABUSEIPDB_CHECK, {"Key": key, "Accept": "application/json"},
                                 query=query)
        except urllib.error.HTTPError as e:
            if e.code == 429:
                reset = (e.headers or {}).get("X-RateLimit-Reset")
                when = datetime.fromtimestamp(int(reset), timezone.utc).strftime("%b %d %H:%M UTC") if reset else "later"
                print(f"  AbuseIPDB's daily limit is used up. Run this again after {when}; it carries on "
                      "where it stopped.")
                break
            raise
        results["first_reporter"][ip] = {"checked_at": now().isoformat(), **first_reporter(ours, data)}
        done += 1
        remaining = headers.get("X-RateLimit-Remaining", remaining)
        if done % 25 == 0:
            save_results(out_file, results)
            print(f"  {done} checked…")
        time.sleep(0.2)
    print(f"  {done} IPs checked this run." + (f" AbuseIPDB says {remaining} checks are left today."
                                              if remaining is not None else ""))


def days_back(since, at):
    """maxAgeInDays for a count that starts at least MARGIN_DAYS before `since`, within the year."""
    return max(1, min(math.ceil((at - since) / timedelta(days=1)) + MARGIN_DAYS, REPORT_DAYS))


def count_older(year_total, recent_total, days):
    """What a count over the last `days` days says about the reports from before that window.

    year_total comes from an earlier check of the whole year, recent_total from a later one over
    `days` days. Reports only pile up, so any surplus in the year is older than the window. A
    window as long as the year shows nothing that way.
    """
    surplus = year_total - recent_total if days < REPORT_DAYS else 0
    return {"days": days, "year_total": year_total, "recent_total": recent_total,
            "older": surplus > 0, "older_at_least": max(surplus, 0)}


def older_todo(results, ours):
    """The checks --older-reports would make: (section, IP) -> (since, year total, year check time)."""
    todo = {}
    for ip, r in results["abuseipdb"].items():
        if (r.get("total_reports") or 0) > LISTED_REPORTS_CAP and not r.get("reports_before_us"):
            if results["abuseipdb_older"].get(ip, {}).get("year_checked_at") != r["checked_at"]:
                todo[("abuseipdb_older", ip)] = (parse_time(r["first_seen_here"]), r["total_reports"],
                                                 r["checked_at"])
    for ip, r in results["first_reporter"].items():
        o = ours.get(ip)
        if (r["first"] == "can't tell" and r["listed"] < r["total_reports"] and o
                and o["reported_at"] == r["our_report_at"]
                and results["first_reporter_older"].get(ip, {}).get("year_checked_at") != r["checked_at"]):
            # AbuseIPDB may date our report at the attack time we sent, which came first.
            since = min(t for t in (parse_time(o["reported_at"]), parse_time(o.get("timestamp"))) if t)
            todo[("first_reporter_older", ip)] = (since, r["total_reports"], r["checked_at"])
    return todo


def older_reports_checks(todo, key, results, out_file, limit):
    done, remaining = 0, None
    for (section, ip), (since, year_total, year_checked_at) in todo.items():
        if done >= limit:
            print(f"  Stopped at --limit {limit}.")
            break
        at = now()
        days = days_back(since, at)
        query = urllib.parse.urlencode({"ipAddress": ip, "maxAgeInDays": days})  # no verbose
        try:
            data, headers = call("GET", ABUSEIPDB_CHECK, {"Key": key, "Accept": "application/json"},
                                 query=query)
        except urllib.error.HTTPError as e:
            if e.code == 429:
                reset = (e.headers or {}).get("X-RateLimit-Reset")
                when = datetime.fromtimestamp(int(reset), timezone.utc).strftime("%b %d %H:%M UTC") if reset else "later"
                print(f"  AbuseIPDB's daily limit is used up. Run this again after {when}; it carries on "
                      "where it stopped.")
                break
            raise
        results[section][ip] = {"checked_at": at.isoformat(), "since": since.isoformat(),
                                "year_checked_at": year_checked_at,
                                **count_older(year_total, data["data"].get("totalReports") or 0, days)}
        done += 1
        remaining = headers.get("X-RateLimit-Remaining", remaining)
        if done % 25 == 0:
            save_results(out_file, results)
            print(f"  {done} checked…")
        time.sleep(0.2)
    print(f"  {done} IPs checked this run." + (f" AbuseIPDB says {remaining} checks are left today."
                                              if remaining is not None else ""))


def older_reports_main(args):
    results = load_results(args.out)
    record = args.logs / "abuseipdb" / "reported.json"
    ours = json.loads(record.read_text()).get("reports", {}) if record.exists() else {}
    ips = read_logs(args.logs)[0]
    unchecked = sum(ip not in results["abuseipdb"] for ip in ips)
    if unchecked:
        print(f"{unchecked} IP{'s' if unchecked != 1 else ''} in the logs {'have' if unchecked != 1 else 'has'} "
              "no year check yet. Run this without --older-reports first, then again with it.")
    todo = older_todo(results, ours)
    n_seen = sum(section == "abuseipdb_older" for section, _ in todo)
    n = min(len(todo), args.limit)
    print(f"AbuseIPDB: {n} check{'s' if n != 1 else ''}, one per IP: {n_seen} whose {LISTED_REPORTS_CAP} listed "
          f"reports all came after the honeypot first saw them, and {len(todo) - n_seen} you reported where it "
          "couldn't be told who was first. Each asks only how many reports came in since a day or more before "
          f"that moment, with no report details. A free account has {FREE_DAILY_CHECKS:,} checks a day; a later "
          "run carries on where this one stops.")
    if not todo:
        print("\nNothing new to look up.")
        return
    if not args.send:
        print("\nNothing was sent. Add --send to do these lookups.")
        return
    if not args.yes and input("\nSend these lookups? Type yes: ").strip().lower() != "yes":
        print("Nothing was sent.")
        return
    try:
        older_reports_checks(todo, get_key("ABUSEIPDB_KEY", "AbuseIPDB API"), results, args.out, args.limit)
    except urllib.error.HTTPError as e:
        print(f"Stopped: {e.code} {e.reason} from AbuseIPDB. 401 or 403 usually means a wrong key.",
              file=sys.stderr)
    except urllib.error.URLError as e:
        print(f"Stopped: couldn't reach AbuseIPDB ({e.reason}).", file=sys.stderr)
    finally:
        save_results(args.out, results)

    print(f"\nSaved to {args.out}. IPs masked to two numbers:")
    found = {}
    for (section, ip), (_, _, year_checked_at) in todo.items():
        r = results[section].get(ip)
        if r and r["year_checked_at"] == year_checked_at:
            found.setdefault(section, []).append(r)
            what = ("reported before the honeypot saw it" if section == "abuseipdb_older"
                    else "someone else reported it before you")
            verdict = what if r["older"] else "still can't tell"
            print(f"  {abuse_review.mask(ip):15} {r['recent_total']:>6,} in the last {r['days']} days, "
                  f"{r['year_total']:,} in the year: {verdict}")
    for section, label in (("abuseipdb_older", "Reported before the honeypot first saw them"),
                           ("first_reporter_older", "Someone else first, where it couldn't be told")):
        rs = found.get(section, [])
        if rs:
            older = sum(r["older"] for r in rs)
            print(f"{label}: shown for {older} of {len(rs)}, still can't tell for {len(rs) - older}.")


def first_reporter_main(args):
    record = args.logs / "abuseipdb" / "reported.json"
    if not record.exists():
        raise SystemExit(f"No reports recorded at {record}. analysis/report_abuseipdb.py writes it.")
    ours = json.loads(record.read_text()).get("reports", {})
    results = load_results(args.out)
    checked = results["first_reporter"]
    # Each IP is checked once after our latest report of it. A newer report means a new check.
    todo = {ip: o for ip, o in ours.items()
            if args.refresh or checked.get(ip, {}).get("our_report_at") != o["reported_at"]}
    print(f"AbuseIPDB: {min(len(todo), args.limit)} of the {len(ours)} IPs you reported to check for who "
          f"reported them first, each asking for {REPORT_DAYS} days of reports. A free account has "
          f"{FREE_DAILY_CHECKS:,} checks a day; a later run carries on where this one stops.")
    if not todo:
        print("\nNothing new to look up.")
        return
    if not args.send:
        print("\nNothing was sent. Add --send to do these lookups.")
        return
    if not args.yes and input("\nSend these lookups? Type yes: ").strip().lower() != "yes":
        print("Nothing was sent.")
        return
    try:
        first_reporter_checks(todo, get_key("ABUSEIPDB_KEY", "AbuseIPDB API"), results, args.out, args.limit)
    except urllib.error.HTTPError as e:
        print(f"Stopped: {e.code} {e.reason} from AbuseIPDB. 401 or 403 usually means a wrong key.",
              file=sys.stderr)
    except urllib.error.URLError as e:
        print(f"Stopped: couldn't reach AbuseIPDB ({e.reason}).", file=sys.stderr)
    finally:
        save_results(args.out, results)

    found = {ip: checked[ip] for ip in ours if checked.get(ip, {}).get("our_report_at") == ours[ip]["reported_at"]}
    print(f"\nSaved to {args.out}. IPs masked to two numbers:")
    for ip, r in sorted(found.items(), key=lambda kv: (kv[1]["first"], kv[0])):
        print(f"  {abuse_review.mask(ip):15} {r['first']:13} {r['why']}")
    counts = Counter(r["first"] for r in found.values())
    us, others, unknown = counts["us"], counts["someone else"], counts["can't tell"]
    print(f"First to report, in the past year: us for {us} of {len(found)}, someone else for {others}, "
          f"can't tell for {unknown}.")


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--send", action="store_true", help="do the lookups (without it, nothing is sent)")
    parser.add_argument("--yes", action="store_true", help="don't ask before sending")
    parser.add_argument("--only", choices=["urlhaus", "abuseipdb"], help="use only one service")
    parser.add_argument("--refresh", action="store_true", help="look up again what's already in the results")
    parser.add_argument("--limit", type=int, default=FREE_DAILY_CHECKS, help="most AbuseIPDB checks this run")
    parser.add_argument("--logs", type=Path, default=LOG_DIR)
    parser.add_argument("--out", type=Path, default=OUT_FILE)
    parser.add_argument("--first-reporter", action="store_true",
                        help="check who reported each IP in reported.json first, instead of the usual lookups")
    parser.add_argument("--older-reports", action="store_true",
                        help="count, for the IPs the lists can't settle, the reports from before, instead")
    args = parser.parse_args(argv)
    if args.first_reporter and args.older_reports:
        parser.error("use --first-reporter or --older-reports, not both")
    if args.first_reporter:
        return first_reporter_main(args)
    if args.older_reports:
        return older_reports_main(args)

    ips, found, own_count, left_out = read_logs(args.logs)
    results = load_results(args.out)
    addresses, skipped = {}, []
    for address, first_seen in sorted(found.items(), key=lambda kv: kv[1]):
        host, reason = server_of(address)
        if reason:
            skipped.append((address, reason))
        else:
            addresses[address] = (host, first_seen)
    if not args.refresh:
        addresses = {a: v for a, v in addresses.items() if a not in results["urlhaus"]}
        ips = {ip: t for ip, t in ips.items() if ip not in results["abuseipdb"]}
    use_urlhaus, use_abuseipdb = args.only in (None, "urlhaus"), args.only in (None, "abuseipdb")

    print(f"Left out: {own_count} of my own test IPs and every address only they used"
          + "".join(f", {n} visits from a {why}" for why, n in left_out.items()) + ".")
    for address, reason in skipped:
        print(f"Won't look up {defang(address)}: {reason}.")
    already = len(results["urlhaus"]) + len(results["abuseipdb"])
    if already and not args.refresh:
        print(f"Already in {args.out} from the last {KEEP_DAYS} days, so not looked up again: "
              f"{len(results['urlhaus'])} addresses, {len(results['abuseipdb'])} IPs (--refresh redoes them).")
    if use_urlhaus:
        n_hosts = len({h for h, _ in addresses.values()})
        n_urls = sum("://" in a for a in addresses)
        print(f"\nURLhaus: {n_urls} URL lookups and {n_hosts} server lookups.")
        for address, (_, first_seen) in addresses.items():
            print(f"  {defang(address):70} first seen here {first_seen:%b %d %H:%M} UTC")
    if use_abuseipdb:
        n = min(len(ips), args.limit)
        print(f"\nAbuseIPDB: {n} IP checks, each asking for {REPORT_DAYS} days of reports. A free account "
              f"has {FREE_DAILY_CHECKS:,} a day; a later run carries on where this one stops.")
    if not ((use_urlhaus and addresses) or (use_abuseipdb and ips)):
        print("\nNothing new to look up.")
        return
    if not args.send:
        print("\nNothing was sent. Add --send to do these lookups.")
        return
    if not args.yes and input("\nSend these lookups? Type yes: ").strip().lower() != "yes":
        print("Nothing was sent.")
        return

    try:
        if use_urlhaus and addresses:
            print("\nURLhaus:")
            urlhaus_lookups(addresses, get_key("URLHAUS_AUTH_KEY", "URLhaus Auth-Key"), results)
            save_results(args.out, results)
        if use_abuseipdb and ips:
            print("\nAbuseIPDB:")
            abuseipdb_checks(ips, get_key("ABUSEIPDB_KEY", "AbuseIPDB API"), results, args.out, args.limit)
    except urllib.error.HTTPError as e:
        print(f"Stopped: {e.code} {e.reason} from {urllib.parse.urlsplit(e.url).hostname}. "
              "401 or 403 usually means a wrong key.", file=sys.stderr)
    except urllib.error.URLError as e:
        print(f"Stopped: couldn't reach the service ({e.reason}).", file=sys.stderr)
    finally:
        save_results(args.out, results)

    u, a = results["urlhaus"].values(), results["abuseipdb"].values()
    print(f"\nSaved to {args.out}.")
    if u:
        known = sum(r.get("url", {}).get("status") == "ok" or r["host"]["status"] == "ok" for r in u)
        early = sum(r.get("url", {}).get("before_us") or r["host"]["before_us"] for r in u)
        print(f"URLhaus knew {known} of {len(u)} addresses (the URL or its server), {early} before the honeypot saw them.")
    if a:
        reported = sum((r["total_reports"] or 0) > 0 for r in a)
        early = sum(r["reports_before_us"] > 0 for r in a)
        print(f"AbuseIPDB had reports from the past {REPORT_DAYS} days for {reported} of {len(a)} IPs, "
              f"{early} of them from before the honeypot first saw the IP.")


if __name__ == "__main__":
    main()
