#!/usr/bin/env python3
"""Build the list of IPs to consider reporting to AbuseIPDB, from the last day of logs.

deploy/daily-logs.sh runs this after its log check. You can also run it by hand from the
repository root:

    python3 analysis/abuse_review.py            # builds the list and shows it, masked
    python3 analysis/abuse_review.py --no-dns   # the same, without reverse DNS lookups
    python3 analysis/abuse_review.py --since 2026-11-08T03:28Z   # everything since then

A candidate is an IP that got into the fake shell in the last 24 hours, or since the time given
with --since, such as the last run when you've missed a few days. The time is UTC unless it names
another zone, and it can't be more than KEEP_DAYS back, because older logs are deleted. Left out:
your own test IPs (any IP that ever used the test password), anything that isn't a public IP, and
any IP the reporter recorded as reported in the last 7 days, however long the window.

Research scanners such as Shodan and Censys are marked "skip", found by Censys's published ranges
or by a reverse DNS name that resolves back to the same IP, so a PTR record alone can't fake one.
The reverse lookups go to your usual DNS resolver, and the IP's owner may see a query for it.

This never reports or sends anything: there's no HTTP code here at all. The full list goes to
~/honeypot-logs/abuseipdb/review.json, readable only by you, and the screen shows IPs masked to
two numbers. analysis/report_abuseipdb.py reads the list and does the reporting, after you
confirm. The list holds IPs, counts and times, and never a password, command or address from the
logs.
"""

import argparse
import ipaddress
import json
import os
import queue
import socket
import sys
import threading
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

LOG_DIR = Path.home() / "honeypot-logs"
KEEP_DAYS = 30  # the same as deploy/daily-logs.sh
RECENT_DAYS = 7  # an IP reported this recently isn't proposed again
WINDOW = timedelta(hours=24)
OWN_TEST_PASSWORD = "not-on-the-list"  # my own test visits used this password
DNS_TIMEOUT = 20  # seconds for all the reverse lookups together
DNS_THREADS = 16

CATEGORY_NAMES = {18: "Brute-Force", 23: "IoT Targeted"}
# AbuseIPDB's categories (https://www.abuseipdb.com/categories) for what an IP did. Every IP here
# logged in with a factory-default login on an IoT-style telnet service, so all get the same two.
ACTIVITY_CATEGORIES = {
    "login only": [18, 23],
    "commands": [18, 23],
    "download attempt": [18, 23],
}

# Censys's published scanning ranges, from https://docs.censys.com/docs/opt-out-of-data-collection
# (checked 2026-11-08). They change, so check the page now and then.
SCANNER_NETWORKS = [(ipaddress.ip_network(net), "Censys (published range)") for net in (
    "66.132.148.0/24", "66.132.153.0/24", "66.132.159.0/24", "66.132.172.0/24", "66.132.186.0/24",
    "66.132.195.0/24", "66.132.224.0/24", "162.142.125.0/24", "167.94.138.0/24", "167.94.145.0/24",
    "167.94.146.0/24", "167.248.133.0/24", "199.45.154.0/24", "199.45.155.0/24", "206.168.34.0/24",
    "206.168.35.0/24", "2602:80d:1000:b0cc:e::/80", "2620:96:e000:b0cc:e::/80", "2602:80d:1003::/112",
    "2602:80d:1004::/112",
)]
# Research scanners that name their machines under these domains. Not a complete list: add to it.
SCANNER_DOMAINS = ("shodan.io", "censys-scanner.com", "shadowserver.org", "binaryedge.ninja",
                   "stretchoid.com", "internet-measurement.com", "onyphe.net")


def now():
    return datetime.now(timezone.utc)


def is_public_ip(text):
    try:
        return ipaddress.ip_address(text).is_global
    except ValueError:
        return False


def mask(ip):
    """The first two parts of an address, as everything else in this project shows them."""
    address = ipaddress.ip_address(ip)
    if address.version == 4:
        return ".".join(ip.split(".")[:2]) + ".x.x"
    groups = address.compressed.split(":")
    return ":".join(groups[:2]) + ":x:x"


def read_visits(log_dir):
    visits = []
    for path in sorted(Path(log_dir).glob("visits-*.jsonl")):
        with path.open(encoding="utf-8", errors="replace") as f:
            for line in f:
                try:
                    visits.append(json.loads(line))
                except json.JSONDecodeError:
                    pass  # a line cut off while the log was being copied
    return visits


def own_ips(visits):
    """Every IP that ever used my test password. The one use of passwords here."""
    return {v["source_ip"] for v in visits if v.get("password") == OWN_TEST_PASSWORD}


def parse_time(text):
    return datetime.fromisoformat(text)


def load_reported(path, at):
    """What the reporter recorded, minus entries older than KEEP_DAYS."""
    path = Path(path)
    if not path.exists():
        return {}
    reports = json.loads(path.read_text()).get("reports", {})
    cutoff = at - timedelta(days=KEEP_DAYS)
    return {ip: r for ip, r in reports.items() if parse_time(r["reported_at"]) >= cutoff}


def reported_recently(reported, at, days=RECENT_DAYS):
    cutoff = at - timedelta(days=days)
    return {ip for ip, r in reported.items() if parse_time(r["reported_at"]) >= cutoff}


def forward_confirmed_name(ip, gethostbyaddr=socket.gethostbyaddr, getaddrinfo=socket.getaddrinfo):
    """The IP's reverse DNS name, but only if that name resolves back to the same IP."""
    try:
        name = gethostbyaddr(ip)[0]
        forward = {info[4][0] for info in getaddrinfo(name, None)}
    except (OSError, UnicodeError):
        return None
    return name.rstrip(".").lower() if ip in forward else None


def scanner_of(ip, resolve):
    address = ipaddress.ip_address(ip)
    for network, label in SCANNER_NETWORKS:
        if address.version == network.version and address in network:
            return label
    name = resolve(ip)
    if name:
        for domain in SCANNER_DOMAINS:
            if name == domain or name.endswith("." + domain):
                return f"{domain} (reverse DNS)"
    return None


def dns_resolver(ips):
    """Forward-confirmed names for all the IPs, giving up after DNS_TIMEOUT seconds in total.

    The threads are daemons, so a lookup that hangs can't stop the script from finishing. An IP
    whose lookup didn't finish in time just isn't recognised as a scanner.
    """
    todo, names = queue.Queue(), {}
    for ip in ips:
        todo.put(ip)

    def work():
        while True:
            try:
                ip = todo.get_nowait()
            except queue.Empty:
                return
            names[ip] = forward_confirmed_name(ip)

    threads = [threading.Thread(target=work, daemon=True) for _ in range(DNS_THREADS)]
    for t in threads:
        t.start()
    deadline = time.monotonic() + DNS_TIMEOUT
    for t in threads:
        t.join(max(0, deadline - time.monotonic()))
    return dict(names).get


def activity_of(sessions):
    if any((v.get("shell") or {}).get("urls") for v in sessions):
        return "download attempt"
    if any(c.strip() for v in sessions for c in (v.get("shell") or {}).get("commands") or []):
        return "commands"
    return "login only"


def build_review(visits, at, reported, resolve, since=None):
    """The review list as a dict. Nothing from the logs goes in except IPs, counts and times.

    The window is the last 24 hours, or from `since` when it's given.
    """
    start = at - WINDOW if since is None else since
    own = own_ips(visits)
    recent = reported_recently(reported, at)
    by_ip, left_out = {}, {"own test IPs": set(), "not a public IP": set(), "reported in the last 7 days": set()}
    for v in visits:
        when = datetime.fromtimestamp(v["time"], timezone.utc)
        if v.get("outcome") != "logged_in" or not start <= when <= at:
            continue
        ip = v["source_ip"]
        if ip in own:
            left_out["own test IPs"].add(ip)
        elif not is_public_ip(ip):
            left_out["not a public IP"].add(ip)
        elif ip in recent:
            left_out["reported in the last 7 days"].add(ip)
        else:
            by_ip.setdefault(ip, []).append(v)

    candidates = []
    for ip, sessions in by_ip.items():
        times = sorted(datetime.fromtimestamp(v["time"], timezone.utc) for v in sessions)
        activity = activity_of(sessions)
        scanner = scanner_of(ip, resolve)
        candidates.append({
            "ip": ip, "sessions": len(sessions), "activity": activity,
            "categories": ACTIVITY_CATEGORIES[activity],
            "first_seen": times[0].isoformat(), "last_seen": times[-1].isoformat(),
            "scanner": scanner, "skip": scanner is not None,
        })
    candidates.sort(key=lambda c: (-c["sessions"], c["first_seen"], c["ip"]))
    return {
        "format": 1, "built_at": at.isoformat(), "window_start": start.isoformat(),
        "window_end": at.isoformat(), "left_out": {k: len(v) for k, v in left_out.items()},
        "candidates": candidates,
    }


def window_of(review):
    """The review's start and end, and whether it's the usual last 24 hours."""
    start, end = parse_time(review["window_start"]), parse_time(review["window_end"])
    return start, end, end - start == WINDOW


def describe_categories(categories):
    return ", ".join(f"{c} {CATEGORY_NAMES.get(c, '?')}" for c in categories)


def candidate_line(number, c):
    """One masked line for a candidate. Shared with the reporter so both number them the same."""
    sessions = f"{c['sessions']} session" + ("" if c["sessions"] == 1 else "s")
    line = (f"#{number:<3} {'skip' if c['skip'] else 'report':6} {mask(c['ip']):15} {sessions:12} "
            f"{c['activity']:17} {describe_categories(c['categories'])}")
    return line + (f"  (research scanner: {c['scanner']})" if c["scanner"] else "")


def summary_lines(review, path):
    found = review["candidates"]
    to_report = sum(not c["skip"] for c in found)
    left = ", ".join(f"{n} {why}" for why, n in review["left_out"].items())
    start, _, daily = window_of(review)
    window = "last 24 hours" if daily else f"since {start:%b %d %H:%M} UTC"
    lines = [f"AbuseIPDB review list, {window}: {len(found)} IP(s) got into the fake shell. "
             f"{to_report} to report, {len(found) - to_report} skipped by default.",
             f"  Left out: {left}."]
    lines += [f"  {candidate_line(i, c)}" for i, c in enumerate(found, 1)]
    lines.append(f"  Full IPs are only in {path}. Nothing was sent. To report them, run "
                 "python3 analysis/report_abuseipdb.py --send")
    return lines


def save_private(path, data):
    """Write JSON readable only by you, in a folder only you can open."""
    path = Path(path)
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chmod(path.parent, 0o700)
    temp = path.with_suffix(".tmp")
    fd = os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        json.dump(data, f, indent=1, sort_keys=True)
    os.chmod(temp, 0o600)
    os.replace(temp, path)


def parse_since(text):
    """A --since value: an ISO 8601 date or time, read as UTC unless it names another zone."""
    try:
        when = datetime.fromisoformat(text)
    except ValueError:
        raise argparse.ArgumentTypeError(f"{text!r} isn't a date or time, such as 2026-11-08 or 2026-11-08T03:28Z")
    return when.replace(tzinfo=timezone.utc) if when.tzinfo is None else when.astimezone(timezone.utc)


def main(argv=None, now=now):
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--logs", type=Path, default=LOG_DIR, help="the folder deploy/daily-logs.sh copies to")
    parser.add_argument("--no-dns", action="store_true", help="skip the reverse DNS lookups for scanners")
    parser.add_argument("--since", type=parse_since, metavar="TIME",
                        help="cover everything since this UTC date or time, instead of the last 24 hours")
    args = parser.parse_args(argv)
    at = now() if callable(now) else now
    if args.since is not None and args.since > at:
        parser.error("--since is in the future")
    if args.since is not None and args.since < at - timedelta(days=KEEP_DAYS):
        parser.error(f"--since can't be more than {KEEP_DAYS} days back, because older logs are deleted")
    start = at - WINDOW if args.since is None else args.since
    folder = args.logs / "abuseipdb"
    visits = read_visits(args.logs)
    record = folder / "reported.json"
    reported = load_reported(record, at)
    # The record holds full IPs, so it follows KEEP_DAYS even on days nothing is reported.
    if record.exists() and len(reported) != len(json.loads(record.read_text()).get("reports", {})):
        save_private(record, {"format": 1, "reports": reported})
    if args.no_dns:
        resolve = lambda ip: None  # noqa: E731
    else:
        ips = {v["source_ip"] for v in visits if v.get("outcome") == "logged_in" and is_public_ip(v["source_ip"])
               and start <= datetime.fromtimestamp(v["time"], timezone.utc) <= at}
        resolve = dns_resolver(sorted(ips))
    review = build_review(visits, at, reported, resolve, args.since)
    save_private(folder / "review.json", review)
    print("\n".join(summary_lines(review, folder / "review.json")))


if __name__ == "__main__":
    sys.exit(main())
