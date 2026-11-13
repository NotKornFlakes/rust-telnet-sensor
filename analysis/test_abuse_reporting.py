"""Tests for the AbuseIPDB review list (abuse_review.py) and reporter (report_abuseipdb.py).

Run from the repository root:

    python3 -m unittest discover -s analysis -p 'test_*.py'

Nothing here touches the network: DNS and HTTP are replaced with fakes, and every file goes in a
temporary folder.
"""

import contextlib
import io
import json
import os
import re
import socket
import stat
import sys
import tempfile
import threading
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import abuse_review  # noqa: E402
import report_abuseipdb  # noqa: E402

NOW = datetime(2026, 11, 8, 2, 0, tzinfo=timezone.utc)
FULL_IPV4 = re.compile(r"(?<!\d)\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(?!\d)")

# Python treats the documentation ranges (192.0.2.0/24 and the like) as not global, so they'd be
# filtered out. These are well-known public DNS resolvers instead: global, and nothing here
# contacts them.
A, B, C, D = "1.1.1.1", "8.8.8.8", "9.9.9.9", "208.67.222.222"


def hours_ago(h):
    return int((NOW - timedelta(hours=h)).timestamp())


def visit(ip, hours, outcome="logged_in", commands=None, urls=None, password="admin"):
    v = {"time": hours_ago(hours), "source_ip": ip, "outcome": outcome, "username": "root",
         "password": password, "telnet": "fffb01"}
    if outcome == "logged_in":
        v["shell"] = {"commands": list(commands or []), "urls": list(urls or []), "ended": "left",
                      "reply_bytes": 6}
    return v


def no_dns(ip):
    return None


def build(visits, reported=None, resolve=no_dns):
    return abuse_review.build_review(visits, NOW, reported or {}, resolve)


def ips_of(review):
    return [c["ip"] for c in review["candidates"]]


class PublicTestAddresses(unittest.TestCase):
    def test_the_test_addresses_count_as_public(self):
        # If Python ever stops treating these as global, every other test would pass vacuously.
        for ip in (A, B, C, D):
            self.assertTrue(abuse_review.is_public_ip(ip), ip)


class ReviewListTests(unittest.TestCase):
    def test_only_ips_that_got_into_the_shell_in_the_last_day_are_candidates(self):
        review = build([visit(A, 1), visit(B, 1, outcome="attempted"), visit(C, 25)])
        self.assertEqual(ips_of(review), [A])

    def test_own_test_ips_are_left_out_even_when_the_test_visit_is_older(self):
        visits = [visit(A, 1), visit(B, 1), visit(B, 24 * 10, outcome="attempted", password="not-on-the-list")]
        review = build(visits)
        self.assertEqual(ips_of(review), [A])
        self.assertEqual(review["left_out"]["own test IPs"], 1)

    def test_non_public_ips_are_left_out(self):
        review = build([visit("127.0.0.1", 1), visit("10.0.0.5", 1), visit(A, 1)])
        self.assertEqual(ips_of(review), [A])
        self.assertEqual(review["left_out"]["not a public IP"], 2)

    def test_ips_reported_in_the_last_seven_days_are_left_out_and_older_ones_come_back(self):
        reported = {A: {"reported_at": (NOW - timedelta(days=6)).isoformat()},
                    B: {"reported_at": (NOW - timedelta(days=8)).isoformat()}}
        review = build([visit(A, 1), visit(B, 1)], reported)
        self.assertEqual(ips_of(review), [B])
        self.assertEqual(review["left_out"]["reported in the last 7 days"], 1)

    def test_activity_and_categories_follow_what_the_ip_did(self):
        visits = [visit(A, 1), visit(B, 1, commands=["uname -m"]),
                  visit(C, 1, commands=["cd /tmp"]), visit(C, 2, commands=["wget x"], urls=["http://h/x"]),
                  visit(D, 1, commands=["", " "])]
        got = {c["ip"]: (c["activity"], c["categories"]) for c in build(visits)["candidates"]}
        self.assertEqual(got[A], ("login only", [18, 23]))
        self.assertEqual(got[B], ("commands", [18, 23]))
        self.assertEqual(got[C], ("download attempt", [18, 23]))
        self.assertEqual(got[D], ("login only", [18, 23]), "blank lines aren't commands")

    def test_sessions_and_first_seen_count_only_the_last_day(self):
        review = build([visit(A, 1), visit(A, 3), visit(A, 5), visit(A, 30)])
        (c,) = review["candidates"]
        self.assertEqual(c["sessions"], 3)
        self.assertEqual(c["first_seen"], (NOW - timedelta(hours=5)).isoformat())
        self.assertEqual(c["last_seen"], (NOW - timedelta(hours=1)).isoformat())

    def test_since_widens_the_window_and_keeps_the_seven_day_rule(self):
        reported = {B: {"reported_at": (NOW - timedelta(days=2)).isoformat()},
                    C: {"reported_at": (NOW - timedelta(days=8)).isoformat()}}
        visits = [visit(A, 1), visit(A, 50), visit(B, 30), visit(C, 60), visit(D, 80)]
        review = abuse_review.build_review(visits, NOW, reported, no_dns, since=NOW - timedelta(hours=72))
        self.assertEqual(ips_of(review), [A, C])
        self.assertEqual(review["candidates"][0]["sessions"], 2)
        self.assertEqual(review["candidates"][0]["first_seen"], (NOW - timedelta(hours=50)).isoformat())
        self.assertEqual(review["left_out"]["reported in the last 7 days"], 1)
        self.assertEqual(review["window_start"], (NOW - timedelta(hours=72)).isoformat())

    def test_busiest_ips_come_first(self):
        review = build([visit(A, 1), visit(B, 1), visit(B, 2)])
        self.assertEqual(ips_of(review), [B, A])

    def test_a_published_censys_range_is_skipped_by_default(self):
        (c,) = build([visit("162.142.125.10", 1)])["candidates"]
        self.assertTrue(c["skip"])
        self.assertIn("Censys", c["scanner"])

    def test_a_forward_confirmed_scanner_name_is_skipped_by_default(self):
        names = {A: "census7.shodan.io", B: "host-1.example.net"}
        got = {c["ip"]: c for c in build([visit(A, 1), visit(B, 1)], resolve=names.get)["candidates"]}
        self.assertTrue(got[A]["skip"])
        self.assertIn("shodan.io", got[A]["scanner"])
        self.assertFalse(got[B]["skip"])
        self.assertIsNone(got[B]["scanner"])

    def test_a_lookalike_domain_is_not_a_scanner(self):
        (c,) = build([visit(A, 1)], resolve=lambda ip: "shodan.io.attacker.example")["candidates"]
        self.assertIsNone(c["scanner"])

    def test_shadowservers_io_domain_counts_as_a_scanner(self):
        (c,) = build([visit(A, 1)], resolve=lambda ip: "scanner-1.shadowserver.io")["candidates"]
        self.assertTrue(c["skip"])
        self.assertIn("shadowserver.io", c["scanner"])

    def test_the_review_list_holds_no_passwords_commands_or_addresses(self):
        visits = [visit(A, 1, commands=["wget http://192.0.2.200/x.sh"], urls=["http://192.0.2.200/x.sh"],
                        password="hunter2-secret")]
        text = json.dumps(build(visits))
        for leaked in ("hunter2-secret", "wget", "192.0.2.200", '"root"'):
            self.assertNotIn(leaked, text)


class ForwardConfirmedNameTests(unittest.TestCase):
    def lookup(self, ptr, forward):
        def gethostbyaddr(ip):
            if ptr is None:
                raise socket.herror("no PTR")
            return ptr, [], [ip]

        def getaddrinfo(name, port):
            return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (ip, 0)) for ip in forward]

        return abuse_review.forward_confirmed_name(A, gethostbyaddr, getaddrinfo)

    def test_a_name_that_resolves_back_to_the_ip_is_returned(self):
        self.assertEqual(self.lookup("census1.shodan.io", [A]), "census1.shodan.io")

    def test_a_name_that_resolves_elsewhere_is_ignored(self):
        self.assertIsNone(self.lookup("census1.shodan.io", [B]))

    def test_no_ptr_record_gives_none(self):
        self.assertIsNone(self.lookup(None, []))


class SummaryTests(unittest.TestCase):
    def review(self):
        visits = [visit(A, 1), visit(B, 1, commands=["id"]), visit(B, 2),
                  visit(C, 1, urls=["http://h/x"], commands=["wget"]), visit("162.142.125.10", 1)]
        return build(visits)

    def test_summary_shows_no_full_ip(self):
        text = "\n".join(abuse_review.summary_lines(self.review(), Path("/x/review.json")))
        self.assertIsNone(FULL_IPV4.search(text), text)
        for ip in (A, B, C):
            self.assertIn(abuse_review.mask(ip), text)

    def test_each_line_names_sessions_activity_and_categories(self):
        lines = abuse_review.summary_lines(self.review(), Path("/x/review.json"))
        line_b = next(l for l in lines if abuse_review.mask(B) in l)
        self.assertRegex(line_b, r"\b2 sessions\b")
        self.assertIn("commands", line_b)
        self.assertIn("18 Brute-Force", line_b)
        self.assertIn("23 IoT Targeted", line_b)
        line_scanner = next(l for l in lines if "162.142.x.x" in l)
        self.assertIn("skip", line_scanner)
        self.assertIn("Censys", line_scanner)

    def test_the_summary_names_the_window(self):
        daily = abuse_review.summary_lines(self.review(), Path("/x/review.json"))[0]
        self.assertIn("last 24 hours", daily)
        longer = abuse_review.build_review([visit(A, 1)], NOW, {}, no_dns, since=NOW - timedelta(hours=70))
        first = abuse_review.summary_lines(longer, Path("/x/review.json"))[0]
        self.assertIn("since Nov 05 04:00 UTC", first)
        self.assertNotIn("24 hours", first)

    def test_masking(self):
        self.assertEqual(abuse_review.mask("8.8.8.8"), "8.8.x.x")
        self.assertEqual(abuse_review.mask("2001:db8:1:2::5"), "2001:db8:x:x")


class ReviewMainTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.logs = Path(self.tmp.name) / "honeypot-logs"
        self.logs.mkdir()
        lines = [visit(A, 1, commands=["id"]), visit(B, 2), visit(B, 30)]
        (self.logs / "visits-2026-11-08.jsonl").write_text("".join(json.dumps(v) + "\n" for v in lines)
                                                          + '{"time": 1, "cut off')
        self.out = self.logs / "abuseipdb" / "review.json"

    def tearDown(self):
        self.tmp.cleanup()

    def run_main(self, *extra):
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            abuse_review.main(["--logs", str(self.logs), "--no-dns", *extra], now=NOW)
        return stdout.getvalue()

    def test_full_ips_go_only_to_a_private_file(self):
        shown = self.run_main()
        self.assertIsNone(FULL_IPV4.search(shown), shown)
        saved = json.loads(self.out.read_text())
        self.assertEqual(sorted(c["ip"] for c in saved["candidates"]), sorted([A, B]))
        self.assertEqual(stat.S_IMODE(os.stat(self.out).st_mode), 0o600)
        self.assertEqual(stat.S_IMODE(os.stat(self.out.parent).st_mode), 0o700)

    def test_no_dns_makes_no_lookups(self):
        original = abuse_review.forward_confirmed_name

        def refuse(*args, **kwargs):
            raise AssertionError("looked up a name with --no-dns")

        abuse_review.forward_confirmed_name = refuse
        try:
            self.run_main()
        finally:
            abuse_review.forward_confirmed_name = original

    def test_it_reads_what_the_reporter_recorded(self):
        record = self.logs / "abuseipdb" / "reported.json"
        record.parent.mkdir(mode=0o700)
        record.write_text(json.dumps({"format": 1, "reports": {A: {"reported_at": (NOW - timedelta(days=1)).isoformat()}}}))
        self.run_main()
        saved = json.loads(self.out.read_text())
        self.assertEqual([c["ip"] for c in saved["candidates"]], [B])

    def test_since_covers_everything_back_to_that_time(self):
        self.run_main("--since", (NOW - timedelta(hours=48)).isoformat())
        saved = json.loads(self.out.read_text())
        self.assertEqual(saved["window_start"], (NOW - timedelta(hours=48)).isoformat())
        (b,) = [c for c in saved["candidates"] if c["ip"] == B]
        self.assertEqual(b["sessions"], 2, "the visit 30 hours ago is inside the window")

    def test_since_takes_a_date_or_a_time_and_reads_it_as_utc(self):
        for text, start in [("2026-11-07", datetime(2026, 11, 7, tzinfo=timezone.utc)),
                            ("2026-11-06T03:28", datetime(2026, 11, 6, 3, 28, tzinfo=timezone.utc)),
                            ("2026-11-06T03:28Z", datetime(2026, 11, 6, 3, 28, tzinfo=timezone.utc)),
                            ("2026-11-05T22:28-05:00", datetime(2026, 11, 6, 3, 28, tzinfo=timezone.utc))]:
            self.run_main("--since", text)
            self.assertEqual(json.loads(self.out.read_text())["window_start"], start.isoformat(), text)

    def test_since_refuses_a_time_in_the_future_or_older_than_the_logs_are_kept(self):
        for text, why in [((NOW + timedelta(hours=1)).isoformat(), "in the future"),
                          ((NOW - timedelta(days=31)).isoformat(), "30 days"),
                          ("last week", "date")]:
            errors = io.StringIO()
            with self.assertRaises(SystemExit, msg=text), contextlib.redirect_stderr(errors):
                self.run_main("--since", text)
            self.assertIn(why, errors.getvalue(), text)
            self.assertNotIn("unrecognized arguments", errors.getvalue())
            self.assertFalse(self.out.exists(), f"a list was saved for {text}")

    def test_since_looks_up_scanner_names_for_the_whole_window(self):
        original, looked_up = abuse_review.forward_confirmed_name, []
        abuse_review.forward_confirmed_name = lambda ip: looked_up.append(ip)
        try:
            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout):
                abuse_review.main(["--logs", str(self.logs), "--since", (NOW - timedelta(hours=48)).isoformat()],
                                  now=NOW)
        finally:
            abuse_review.forward_confirmed_name = original
        self.assertEqual(sorted(set(looked_up)), sorted([A, B]))

    def test_the_daily_run_drops_record_entries_older_than_30_days(self):
        record = self.logs / "abuseipdb" / "reported.json"
        abuse_review.save_private(record, {"format": 1, "reports": {
            C: {"reported_at": (NOW - timedelta(days=31)).isoformat()},
            D: {"reported_at": (NOW - timedelta(days=2)).isoformat()}}})
        self.run_main()
        self.assertEqual(list(json.loads(record.read_text())["reports"]), [D])
        self.assertEqual(stat.S_IMODE(os.stat(record).st_mode), 0o600)


class ScannerListTests(unittest.TestCase):
    """--scanners: every visitor checked for research scanners, saved for the notebook."""
    CENSYS = "162.142.125.10"

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.logs = Path(self.tmp.name) / "honeypot-logs"
        self.logs.mkdir()
        lines = [visit(A, 1, commands=["id"]), visit(B, 2, outcome="attempted"), visit(self.CENSYS, 3, outcome="silent"),
                 visit(C, 30, outcome="attempted"), visit(D, 4, password="not-on-the-list"), visit("10.0.0.5", 1)]
        (self.logs / "visits-2026-11-08.jsonl").write_text("".join(json.dumps(v) + "\n" for v in lines))
        self.out = self.logs / "intel" / "scanners.json"
        self.names = {B: "scanner-1.shadowserver.io", C: "host-1.example.net"}
        self.looked_up, self.original = [], abuse_review.forward_confirmed_name

        def fake(ip):
            self.looked_up.append(ip)
            return self.names.get(ip)

        abuse_review.forward_confirmed_name = fake

    def tearDown(self):
        abuse_review.forward_confirmed_name = self.original
        self.tmp.cleanup()

    def run_main(self, *extra):
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            abuse_review.main(["--logs", str(self.logs), "--scanners", *extra], now=NOW)
        return stdout.getvalue()

    def saved(self):
        return json.loads(self.out.read_text())["ips"]

    def test_every_visitor_is_checked_whatever_it_did(self):
        self.run_main("--since", (NOW - timedelta(hours=48)).isoformat())
        saved = self.saved()
        self.assertEqual(sorted(saved), sorted([A, B, C, self.CENSYS]), "not my test IP, not a private one")
        self.assertIsNone(saved[A]["scanner"])
        self.assertIsNone(saved[C]["scanner"])
        self.assertIn("shadowserver.io", saved[B]["scanner"])
        self.assertIn("Censys", saved[self.CENSYS]["scanner"])
        self.assertTrue(all(r["checked"] for r in saved.values()))

    def test_without_since_it_covers_the_last_day(self):
        self.run_main()
        self.assertEqual(sorted(self.saved()), sorted([A, B, self.CENSYS]))

    def test_an_ip_in_a_published_range_needs_no_lookup(self):
        self.run_main()
        self.assertEqual(sorted(self.looked_up), sorted([A, B]))

    def test_the_file_is_private_and_the_screen_shows_no_full_ip(self):
        shown = self.run_main()
        self.assertIsNone(FULL_IPV4.search(shown), shown)
        self.assertIn("2 of the 3 IPs", shown)
        self.assertEqual(stat.S_IMODE(os.stat(self.out).st_mode), 0o600)
        self.assertEqual(stat.S_IMODE(os.stat(self.out.parent).st_mode), 0o700)
        self.assertFalse((self.logs / "abuseipdb" / "review.json").exists(), "it builds no review list")

    def test_a_lookup_that_does_not_finish_in_time_is_saved_as_unchecked(self):
        release = threading.Event()

        def slow_for_a(ip):
            if ip == A:
                release.wait(5)
            return self.names.get(ip)

        abuse_review.forward_confirmed_name = slow_for_a
        timeout, abuse_review.SCANNER_LIST_DNS_TIMEOUT = abuse_review.SCANNER_LIST_DNS_TIMEOUT, 0.2
        try:
            shown = self.run_main()
        finally:
            release.set()
            abuse_review.SCANNER_LIST_DNS_TIMEOUT = timeout
        saved = self.saved()
        self.assertFalse(saved[A]["checked"])
        self.assertTrue(saved[B]["checked"])
        self.assertIn("1 reverse lookup didn't finish", shown)

    def test_no_dns_checks_only_the_published_ranges(self):
        self.run_main("--no-dns")
        saved = self.saved()
        self.assertEqual(self.looked_up, [])
        self.assertTrue(saved[self.CENSYS]["checked"])
        self.assertFalse(saved[A]["checked"])
        self.assertIsNone(saved[B]["scanner"], "without a lookup its name isn't known")


class FakePost:
    """Stands in for the HTTP call. Records what would have been sent, never sends it."""

    def __init__(self, errors=None):
        self.calls, self.errors = [], errors or {}

    def __call__(self, form, key):
        self.calls.append((dict(form), key))
        error = self.errors.get(form["ip"])
        if error:
            raise error()
        return {"data": {"ipAddress": form["ip"], "abuseConfidenceScore": 100}}, {"X-RateLimit-Remaining": "999"}


def http_error(code, detail=""):
    import email.message
    import urllib.error

    def make():
        body = json.dumps({"errors": [{"detail": detail, "status": code}]}).encode()
        return urllib.error.HTTPError(report_abuseipdb.REPORT_URL, code, "error", email.message.Message(),
                                      io.BytesIO(body))
    return make


class Answers:
    def __init__(self, *answers):
        self.answers, self.asked = list(answers), []

    def __call__(self, prompt=""):
        self.asked.append(prompt)
        if not self.answers:
            raise AssertionError(f"asked more than expected: {prompt!r}")
        return self.answers.pop(0)


def refuse_key(prompt=""):
    raise AssertionError("asked for the key")


KEY = "test-key-should-never-appear-anywhere"
SCANNER = "162.142.125.10"


class ReporterTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.logs = Path(self.tmp.name) / "honeypot-logs"
        self.logs.mkdir()
        self.visits = [visit(A, 1), visit(A, 2), visit(B, 3, commands=["id"]), visit(SCANNER, 1),
                       visit(C, 2, urls=["http://h/x"], commands=["wget"]),
                       visit(D, 40, outcome="attempted", password="not-on-the-list")]
        self.write_logs(self.visits)
        self.save_review(build(self.visits))
        self.sleeps = []

    def tearDown(self):
        self.tmp.cleanup()

    def write_logs(self, visits):
        (self.logs / "visits-2026-11-08.jsonl").write_text("".join(json.dumps(v) + "\n" for v in visits))

    def save_review(self, review):
        abuse_review.save_private(self.logs / "abuseipdb" / "review.json", review)

    def record(self):
        path = self.logs / "abuseipdb" / "reported.json"
        return json.loads(path.read_text())["reports"] if path.exists() else {}

    def run_main(self, *args, answers=(), post=None, ask_key=refuse_key):
        post = post or FakePost()
        ask = Answers(*answers)
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stdout):
            report_abuseipdb.main(["--logs", str(self.logs), *args], post=post, ask=ask, ask_key=ask_key,
                                  sleep=self.sleeps.append, now=NOW)
        return post, ask, stdout.getvalue()

    def sent_ips(self, post):
        return [form["ip"] for form, _ in post.calls]

    def test_comments_are_fixed_sentences_with_no_ip_or_number(self):
        self.assertEqual(set(report_abuseipdb.COMMENTS), set(abuse_review.ACTIVITY_CATEGORIES))
        for comment in report_abuseipdb.COMMENTS.values():
            self.assertTrue(comment.startswith("Telnet honeypot"), comment)
            self.assertNotRegex(comment, r"\d")
            self.assertLessEqual(len(comment), 200)

    def test_without_send_nothing_is_sent_and_no_key_is_asked(self):
        post, ask, shown = self.run_main()
        self.assertEqual(post.calls, [])
        self.assertEqual(ask.asked, [])
        self.assertIn("Nothing was sent", shown)
        self.assertIsNone(FULL_IPV4.search(shown), shown)

    def test_it_says_which_window_the_list_covers(self):
        _, _, shown = self.run_main()
        self.assertIn("for the 24 hours before it", shown)
        self.save_review(abuse_review.build_review(self.visits, NOW, {}, no_dns, since=NOW - timedelta(hours=70)))
        _, _, shown = self.run_main()
        self.assertIn("covering Nov 05 04:00 to Nov 08 02:00 UTC", shown)
        self.assertNotIn("24 hours", shown)

    def test_cancelling_sends_nothing_and_never_asks_for_the_key(self):
        post, _, shown = self.run_main("--send", answers=("", "no"))
        self.assertEqual(post.calls, [])
        self.assertIn("Nothing was sent", shown)

    def test_confirmed_reports_go_out_once_each_with_a_fixed_comment(self):
        post, _, shown = self.run_main("--send", answers=("", "yes"), ask_key=lambda prompt="": KEY)
        self.assertEqual(sorted(self.sent_ips(post)), sorted([A, B, C]))
        forms = {form["ip"]: form for form, _ in post.calls}
        self.assertEqual(forms[A], {"ip": A, "categories": "18,23", "comment": report_abuseipdb.COMMENTS["login only"],
                                    "timestamp": (NOW - timedelta(hours=2)).isoformat()})
        self.assertEqual(forms[B]["comment"], report_abuseipdb.COMMENTS["commands"])
        self.assertEqual(forms[C]["categories"], "18,23")
        self.assertEqual(forms[C]["comment"], report_abuseipdb.COMMENTS["download attempt"])
        self.assertTrue(all(key == KEY for _, key in post.calls))
        self.assertNotIn(KEY, shown)
        self.assertIsNone(FULL_IPV4.search(shown), shown)

    def test_what_was_sent_is_recorded_and_never_sent_again(self):
        self.run_main("--send", answers=("", "yes"), ask_key=lambda prompt="": KEY)
        record = self.record()
        self.assertEqual(sorted(record), sorted([A, B, C]))
        self.assertEqual(record[A]["categories"], [18, 23])
        self.assertEqual(record[A]["comment"], report_abuseipdb.COMMENTS["login only"])
        self.assertEqual(record[A]["reported_at"], NOW.isoformat())
        path = self.logs / "abuseipdb" / "reported.json"
        self.assertEqual(stat.S_IMODE(os.stat(path).st_mode), 0o600)
        self.assertNotIn(KEY, path.read_text())

        post, _, shown = self.run_main("--send")
        self.assertEqual(post.calls, [])
        self.assertIn("already reported", shown)

    def test_scanners_are_skipped_unless_included(self):
        post, _, _ = self.run_main("--send", answers=("", "yes"), ask_key=lambda prompt="": KEY)
        self.assertNotIn(SCANNER, self.sent_ips(post))
        (self.logs / "abuseipdb" / "reported.json").unlink()
        post, _, _ = self.run_main("--send", "--include-scanners", answers=("", "yes"), ask_key=lambda prompt="": KEY)
        self.assertIn(SCANNER, self.sent_ips(post))

    def test_numbers_you_leave_out_are_not_sent(self):
        review = json.loads((self.logs / "abuseipdb" / "review.json").read_text())
        second = review["candidates"][1]["ip"]
        post, _, _ = self.run_main("--send", answers=("2", "yes"), ask_key=lambda prompt="": KEY)
        self.assertNotIn(second, self.sent_ips(post))
        self.assertEqual(len(post.calls), 2)

    def test_entries_that_fail_the_checks_are_refused(self):
        review = build(self.visits)
        base = review["candidates"][0]
        review["candidates"] = [
            {**base, "ip": "10.1.2.3"},                    # not public
            {**base, "ip": D},                              # own test IP, from the logs
            {**base, "ip": A, "activity": "something else"},
            {**base, "ip": B, "categories": [18, 99]},
            {**base, "ip": B, "categories": [18, 20, 23]},  # Exploited Host isn't used
            {**base, "ip": C, "first_seen": "yesterday"},
        ]
        self.save_review(review)
        post, _, shown = self.run_main("--send")
        self.assertEqual(post.calls, [])
        for reason in ("not a public IP", "your own test IP", "unknown activity", "unknown category",
                       "unreadable time"):
            self.assertIn(reason, shown)

    def test_the_daily_limit_stops_the_run_and_keeps_what_was_sent(self):
        order = [c["ip"] for c in build(self.visits)["candidates"] if not c["skip"]]
        post = FakePost({order[1]: http_error(429, "Daily rate limit of 1000 requests exceeded")})
        _, _, shown = self.run_main("--send", answers=("", "yes"), post=post, ask_key=lambda prompt="": KEY)
        self.assertEqual(self.sent_ips(post), order[:2])
        self.assertEqual(list(self.record()), order[:1])
        self.assertIn("daily limit", shown)

    def test_the_fifteen_minute_rule_skips_only_that_ip(self):
        order = [c["ip"] for c in build(self.visits)["candidates"] if not c["skip"]]
        post = FakePost({order[0]: http_error(429, "You can only report the same IP address once in 15 minutes.")})
        self.run_main("--send", answers=("", "yes"), post=post, ask_key=lambda prompt="": KEY)
        self.assertEqual(self.sent_ips(post), order)
        self.assertEqual(sorted(self.record()), sorted(order[1:]))

    def test_a_rejected_key_stops_the_run(self):
        order = [c["ip"] for c in build(self.visits)["candidates"] if not c["skip"]]
        post = FakePost({order[0]: http_error(401, "Authentication failed")})
        _, _, shown = self.run_main("--send", answers=("", "yes"), post=post, ask_key=lambda prompt="": KEY)
        self.assertEqual(self.sent_ips(post), order[:1])
        self.assertEqual(self.record(), {})
        self.assertNotIn(KEY, shown)

    def test_it_pauses_between_reports(self):
        self.run_main("--send", answers=("", "yes"), ask_key=lambda prompt="": KEY)
        self.assertEqual(len(self.sleeps), 2)
        self.assertTrue(all(s >= 1 for s in self.sleeps))

    def test_limit_caps_the_reports_in_one_run(self):
        post, _, _ = self.run_main("--send", "--limit", "1", answers=("", "yes"), ask_key=lambda prompt="": KEY)
        self.assertEqual(len(post.calls), 1)

    def test_a_missing_review_list_says_how_to_make_one(self):
        (self.logs / "abuseipdb" / "review.json").unlink()
        with self.assertRaises(SystemExit) as stop:
            self.run_main()
        self.assertIn("daily-logs.sh", str(stop.exception))

    def test_only_the_report_endpoint_can_be_called(self):
        class NoNetwork:
            def open(self, *args, **kwargs):
                raise AssertionError("a request got past the allow-list")

        original, report_abuseipdb.OPENER = report_abuseipdb.OPENER, NoNetwork()
        try:
            for method, url in [("GET", "https://api.abuseipdb.com/api/v2/check"), ("POST", "https://example.com/"),
                                ("POST", "http://api.abuseipdb.com/api/v2/report")]:
                with self.assertRaises(SystemExit):
                    report_abuseipdb.call(method, url, {}, {})
        finally:
            report_abuseipdb.OPENER = original

    def test_redirects_are_never_followed(self):
        self.assertIsNone(report_abuseipdb.NoRedirects().redirect_request(None, None, 302, "", {}, "https://x/"))


if __name__ == "__main__":
    unittest.main()
