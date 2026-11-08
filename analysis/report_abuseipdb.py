#!/usr/bin/env python3
"""Report the IPs on the daily review list to AbuseIPDB, after you confirm.

Run it by hand from the repository root, in your own terminal:

    python3 analysis/report_abuseipdb.py          # shows what it would report, sends nothing
    python3 analysis/report_abuseipdb.py --send   # asks you to confirm, then for your API key

deploy/daily-logs.sh builds the list (analysis/abuse_review.py). This script shows it with IPs
masked to two numbers, lets you leave out any by number, and asks you to type yes. Only then does
it ask for your AbuseIPDB API key, without echoing it. The key is never written down or printed.

What each report sends, and nothing else (POST https://api.abuseipdb.com/api/v2/report):
  - the IP,
  - categories 18 Brute-Force and 23 IoT Targeted, the same for every IP,
  - a fixed comment for what the IP did, one of the three sentences in COMMENTS below, so it never
    holds a password, a command, an address, the honeypot's IP or any other IP,
  - the time it was first seen in the last day, as the time of the attack.

Before sending, every entry is checked again: it must be a public IP, not one of your own test
IPs (read from the logs), with a known activity, known categories and a readable time. Research
scanners stay skipped unless you add --include-scanners.

AbuseIPDB's rules are kept: no personal information in comments, a pause between reports, at most
--limit reports a run (a free account allows 1,000 a day), and it stops when the daily limit is
reached or the key is refused. An IP reported in the last 15 minutes is refused by AbuseIPDB, and
this script skips it and carries on.

Every report that goes through is recorded straight away in
~/honeypot-logs/abuseipdb/reported.json, readable only by you, and an IP recorded in the last 7
days is never reported again. Entries older than 30 days are dropped, matching KEEP_DAYS.
"""

import argparse
import getpass
import json
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import abuse_review  # noqa: E402

REPORT_URL = "https://api.abuseipdb.com/api/v2/report"
# The only request this script can make. Anything else is refused before it's sent.
ALLOWED = {("POST", REPORT_URL)}
USER_AGENT = "honeypot-report/1"
PAUSE_SECONDS = 1.5
FREE_DAILY_REPORTS = 1000

# The only comments ever sent. They hold no log values, as the README's reporting rule says, and
# name the device type, as AbuseIPDB asks for category 23.
COMMENTS = {
    "login only": "Telnet honeypot posing as an IoT device: logged in with a factory-default "
                  "username and password, then sent no commands.",
    "commands": "Telnet honeypot posing as an IoT device: logged in with a factory-default "
                "username and password, then sent shell commands.",
    "download attempt": "Telnet honeypot posing as an IoT device: logged in with a factory-default "
                        "username and password, then tried to download and run a file from another server.",
}


class NoRedirects(urllib.request.HTTPRedirectHandler):
    """A redirect could point anywhere, so none are followed."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None  # urllib then raises HTTPError for the 3xx response


OPENER = urllib.request.build_opener(NoRedirects)


def call(method, endpoint, headers, form):
    """Make the one allowed request and return its JSON. Refuses any other endpoint."""
    if (method, endpoint) not in ALLOWED:
        raise SystemExit(f"Refused {method} {endpoint}: it isn't AbuseIPDB's report endpoint.")
    request = urllib.request.Request(endpoint, data=urllib.parse.urlencode(form).encode(), method=method,
                                     headers={"User-Agent": USER_AGENT, **headers})
    with OPENER.open(request, timeout=30) as response:
        return json.load(response), response.headers


def post_report(form, key):
    return call("POST", REPORT_URL, {"Key": key, "Accept": "application/json"}, form)


def now():
    return datetime.now(timezone.utc)


def safe_mask(ip):
    try:
        return abuse_review.mask(ip)
    except (ValueError, TypeError):
        return "(not an IP)"


def mask_text(text):
    """An error message from AbuseIPDB, safe for the screen: it can repeat the IP."""
    text = re.sub(r"(?<!\d)(\d{1,3})\.(\d{1,3})\.\d{1,3}\.\d{1,3}(?!\d)", r"\1.\2.x.x", text)
    return "".join(ch for ch in text if " " <= ch <= "~")[:160]


def refusal(candidate, own):
    """Why an entry on the list can't be reported at all, or None if it can."""
    ip = candidate.get("ip")
    if not isinstance(ip, str) or not abuse_review.is_public_ip(ip):
        return "not a public IP"
    if ip in own:
        return "your own test IP"
    if candidate.get("activity") not in COMMENTS:
        return "unknown activity"
    categories = candidate.get("categories")
    if (not isinstance(categories, list) or not categories
            or not all(isinstance(c, int) and c in abuse_review.CATEGORY_NAMES for c in categories)):
        return "unknown category"
    try:
        datetime.fromisoformat(candidate.get("first_seen"))
    except (TypeError, ValueError):
        return "unreadable time"
    return None


def plan(review, own, reported, at, include_scanners=False, leave_out=()):
    """Split the list into what would be sent and what wouldn't, with reasons."""
    recent = abuse_review.reported_recently(reported, at)
    send, held, seen = [], [], set()
    for number, c in enumerate(review.get("candidates", []), 1):
        reason = refusal(c, own)
        if reason:
            held.append((number, c, f"refused: {reason}"))
        elif c["ip"] in recent:
            held.append((number, c, f"already reported on {reported[c['ip']]['reported_at'][:10]}"))
        elif c["ip"] in seen:
            held.append((number, c, "listed twice"))
        elif c.get("skip") and not include_scanners:
            held.append((number, c, f"research scanner ({c.get('scanner')}), skipped unless --include-scanners"))
        elif number in leave_out:
            held.append((number, c, "left out by you"))
        else:
            seen.add(c["ip"])
            form = {"ip": c["ip"], "categories": ",".join(str(n) for n in c["categories"]),
                    "comment": COMMENTS[c["activity"]], "timestamp": c["first_seen"]}
            send.append((number, c, form))
    return send, held


def show(send, held):
    for number, c, _ in send:
        print(f"  {abuse_review.candidate_line(number, c)}")
    for number, c, reason in held:
        print(f"  #{number:<3} held   {safe_mask(c.get('ip')):15} {reason}")
    for activity in sorted({c["activity"] for _, c, _ in send}):
        print(f"  Comment for {activity}: \"{COMMENTS[activity]}\"")


def error_detail(error):
    try:
        body = json.loads(error.read() or b"{}")
        return " ".join(str(e.get("detail", "")) for e in body.get("errors", []))
    except (ValueError, AttributeError, OSError):
        return ""


def send_reports(send, key, post, record_path, reported, at, sleep):
    """Report each IP in turn, recording each success straight away. Returns how many went."""
    sent = 0
    for i, (number, c, form) in enumerate(send):
        if i:
            sleep(PAUSE_SECONDS)
        label = f"#{number} {abuse_review.mask(c['ip'])}"
        try:
            data, headers = post(form, key)
        except urllib.error.HTTPError as e:
            detail = error_detail(e)
            if e.code == 429 and "15 minutes" in detail:
                print(f"  {label}: reported by you in the last 15 minutes, so AbuseIPDB refused it. Skipped.")
                continue
            if e.code == 429:
                reset = (e.headers or {}).get("X-RateLimit-Reset")
                when = (datetime.fromtimestamp(int(reset), timezone.utc).strftime("%b %d %H:%M UTC")
                        if reset and str(reset).isdigit() else "later")
                print(f"  Stopped at {label}: AbuseIPDB's daily limit is used up. Run this again after {when}.")
            elif e.code in (401, 403):
                print(f"  Stopped at {label}: AbuseIPDB refused the key ({e.code}).")
            else:
                print(f"  Stopped at {label}: AbuseIPDB answered {e.code}. {mask_text(detail)}")
            break
        except urllib.error.URLError as e:
            print(f"  Stopped at {label}: couldn't reach AbuseIPDB ({mask_text(str(e.reason))}).")
            break
        reported[c["ip"]] = {
            "reported_at": at.isoformat(), "categories": c["categories"], "activity": c["activity"],
            "comment": form["comment"], "timestamp": form["timestamp"],
            "score": (data.get("data") or {}).get("abuseConfidenceScore"),
        }
        abuse_review.save_private(record_path, {"format": 1, "reports": reported})
        sent += 1
        print(f"  {label}: reported, confidence score now {reported[c['ip']]['score']}.")
        if str(headers.get("X-RateLimit-Remaining", "")) == "0":
            print("  Stopped: that was the last report AbuseIPDB allows today.")
            break
    return sent


def parse_numbers(text):
    numbers = set()
    for part in re.split(r"[,\s]+", text.strip()):
        if part:
            if not part.isdigit():
                raise ValueError(part)
            numbers.add(int(part))
    return numbers


def main(argv=None, post=post_report, ask=input, ask_key=getpass.getpass, sleep=time.sleep, now=now):
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--send", action="store_true", help="report after you confirm (without it, nothing is sent)")
    parser.add_argument("--include-scanners", action="store_true", help="report research scanners too")
    parser.add_argument("--limit", type=int, default=FREE_DAILY_REPORTS, help="most reports this run")
    parser.add_argument("--logs", type=Path, default=abuse_review.LOG_DIR)
    args = parser.parse_args(argv)
    at = now() if callable(now) else now
    folder = args.logs / "abuseipdb"
    review_path, record_path = folder / "review.json", folder / "reported.json"

    if not review_path.exists():
        raise SystemExit(f"No review list at {review_path}. Run deploy/daily-logs.sh first.")
    review = json.loads(review_path.read_text())
    own = abuse_review.own_ips(abuse_review.read_visits(args.logs))
    reported = abuse_review.load_reported(record_path, at)

    send, held = plan(review, own, reported, at, args.include_scanners)
    print(f"Review list built {review.get('built_at', '?')[:16]} UTC, for the 24 hours before it. "
          f"{len(send)} to report, {len(held)} held back.")
    show(send, held)
    if not send:
        print("Nothing to report. Nothing was sent.")
        return
    if not args.send:
        print("Nothing was sent. Add --send to report these after you confirm.")
        return

    try:
        leave_out = parse_numbers(ask("\nNumbers to leave out (such as 3, 7), or Enter for none: "))
    except ValueError as e:
        print(f"Couldn't read {e}. Nothing was sent.")
        return
    if leave_out:
        send, held = plan(review, own, reported, at, args.include_scanners, leave_out)
    if len(send) > args.limit:
        print(f"Only the first {args.limit} will be sent this run (--limit).")
        send = send[:args.limit]
    if not send:
        print("Nothing left to report. Nothing was sent.")
        return
    if ask(f"Report {len(send)} IP(s) to AbuseIPDB? Type yes: ").strip().lower() != "yes":
        print("Nothing was sent.")
        return
    key = ask_key("AbuseIPDB API key (not shown, not saved): ").strip()
    if not key:
        print("No key given. Nothing was sent.")
        return
    sent = send_reports(send, key, post, record_path, reported, at, sleep)
    print(f"Reported {sent} of {len(send)}. Recorded in {record_path}.")


if __name__ == "__main__":
    sys.exit(main())
