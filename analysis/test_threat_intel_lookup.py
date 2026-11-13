"""Tests for threat_intel_lookup.py's --first-reporter option: who reported each IP to AbuseIPDB first.

Run from the repository root:

    python3 -m unittest discover -s analysis -p 'test_*.py'

Nothing here touches the network: the lookup is replaced with a fake, and every file goes in a
temporary folder.
"""

import contextlib
import io
import json
import os
import re
import stat
import sys
import tempfile
import unittest
import urllib.error
import urllib.parse
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent))

import threat_intel_lookup as til  # noqa: E402

FULL_IPV4 = re.compile(r"(?<!\d)\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(?!\d)")
OUR_COMMENT = ("Telnet honeypot posing as an IoT device: logged in with a factory-default username and "
               "password, then sent shell commands.")
REPORTED_AT = datetime(2026, 11, 8, 3, 32, 4, tzinfo=timezone.utc)
ATTACK_TIME = datetime(2026, 11, 7, 10, 15, 0, tzinfo=timezone.utc)
OUR_ID = 4242
# Public, so the script would look them up, and nothing here contacts them.
A, B = "1.1.1.1", "8.8.8.8"


def ours():
    return {"reported_at": REPORTED_AT.isoformat(), "timestamp": ATTACK_TIME.isoformat(),
            "comment": OUR_COMMENT, "categories": [18, 23], "activity": "commands"}


def report(when, reporter, comment="Telnet brute force", categories=(18,)):
    return {"reportedAt": when.isoformat(), "reporterId": reporter, "comment": comment,
            "categories": list(categories), "reporterCountryCode": "US"}


def our_report(when=REPORTED_AT + timedelta(seconds=40)):
    return report(when, OUR_ID, OUR_COMMENT, (18, 23))


def check_data(reports, total=None):
    return {"data": {"totalReports": len(reports) if total is None else total, "reports": reports,
                     "abuseConfidenceScore": 50}}


def verdict(reports, total=None):
    return til.first_reporter(ours(), check_data(reports, total))


class FirstReporterTests(unittest.TestCase):
    def test_we_were_first_when_no_listed_report_comes_before_ours(self):
        got = verdict([report(REPORTED_AT + timedelta(hours=5), 7), our_report()])
        self.assertEqual(got["first"], "us")
        self.assertTrue(got["ours_found"])
        self.assertEqual(got["others_before_us"], 0)

    def test_someone_else_was_first_when_their_report_comes_before_ours(self):
        early = REPORTED_AT - timedelta(days=3)
        got = verdict([our_report(), report(early, 7), report(REPORTED_AT - timedelta(hours=1), 8)])
        self.assertEqual(got["first"], "someone else")
        self.assertEqual(got["others_before_us"], 2)
        self.assertEqual(got["first_other_at"], early.isoformat())

    def test_our_report_is_recognised_when_dated_by_the_attack_time_we_sent(self):
        got = verdict([our_report(ATTACK_TIME), report(ATTACK_TIME + timedelta(hours=2), 7)])
        self.assertTrue(got["ours_found"])
        self.assertEqual(got["first"], "us")

    def test_the_same_comment_at_another_time_is_not_ours(self):
        # The comments are public in the repository, so someone else could send the same one.
        copy = report(REPORTED_AT - timedelta(days=2), 99, OUR_COMMENT, (18, 23))
        got = verdict([copy, our_report()])
        self.assertEqual(got["first"], "someone else")
        self.assertEqual(got["others_before_us"], 1)

    def test_a_different_comment_at_our_time_is_not_ours(self):
        got = verdict([report(REPORTED_AT + timedelta(seconds=40), 7, "SSH brute force", (18, 23))])
        self.assertFalse(got["ours_found"])
        self.assertEqual(got["first"], "can't tell")
        self.assertIn("isn't listed", got["why"])

    def test_an_earlier_report_from_our_own_account_still_counts_as_us(self):
        older = report(REPORTED_AT - timedelta(days=9), OUR_ID, OUR_COMMENT, (18, 23))
        got = verdict([older, our_report(), report(REPORTED_AT - timedelta(days=1), 7)])
        self.assertEqual(got["first"], "us")
        self.assertEqual(got["others_before_us"], 0)

    def test_a_capped_list_with_ours_earliest_listed_is_unknown(self):
        # AbuseIPDB lists only the newest 100 reports, so older ones can be missing from the list.
        got = verdict([our_report(), report(REPORTED_AT + timedelta(hours=1), 7)], total=150)
        self.assertEqual(got["first"], "can't tell")
        self.assertIn("only the newest 100", got["why"])
        self.assertIn("150", got["why"])
        self.assertEqual(got["listed"], 2)
        self.assertEqual(got["total_reports"], 150)

    def test_ours_missing_from_a_capped_list_says_the_newer_ones_pushed_it_out(self):
        newer = [report(REPORTED_AT + timedelta(hours=h), 7) for h in (1, 2)]
        got = verdict(newer, total=150)
        self.assertEqual(got["first"], "can't tell")
        self.assertFalse(got["ours_found"])
        self.assertIn("isn't among the 2 newest", got["why"])
        self.assertIn("150", got["why"])

    def test_the_listed_reports_cap_is_100(self):
        # Checked against the Nov 10 lookups: no list held more than 100, and every IP with more
        # than 100 reports listed exactly 100, the newest.
        self.assertEqual(til.LISTED_REPORTS_CAP, 100)

    def test_a_capped_list_still_shows_someone_else_first_when_they_are_listed_before_us(self):
        got = verdict([our_report(), report(REPORTED_AT - timedelta(days=1), 7)], total=12000)
        self.assertEqual(got["first"], "someone else")

    def test_no_reports_at_all_is_unknown(self):
        got = verdict([])
        self.assertFalse(got["ours_found"])
        self.assertEqual(got["first"], "can't tell")

    def test_the_result_holds_no_comments_or_reporter_details(self):
        hostile = report(REPORTED_AT - timedelta(days=1), 7, "\x1b[31m see 9.9.9.9 \x1b[0m", (18,))
        text = json.dumps(verdict([hostile, our_report()]))
        for leaked in ("9.9.9.9", "\x1b", "see", "reporterCountryCode", "US"):
            self.assertNotIn(leaked, text)


class FirstReporterMainTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.logs = Path(self.tmp.name) / "honeypot-logs"
        self.out = self.logs / "intel" / "lookups.json"
        record = self.logs / "abuseipdb" / "reported.json"
        record.parent.mkdir(parents=True)
        record.write_text(json.dumps({"format": 1, "reports": {A: ours(), B: ours()}}))
        self.calls = []

    def tearDown(self):
        self.tmp.cleanup()

    def fake_call(self, answers):
        def call(method, endpoint, headers, query=None, form=None):
            self.calls.append((method, endpoint, query, form))
            ip = dict(p.split("=", 1) if "=" in p else (p, "") for p in query.split("&"))["ipAddress"]
            return answers[ip], {"X-RateLimit-Remaining": "990"}
        return call

    def run_main(self, *args, answers=None):
        stdout = io.StringIO()
        with (mock.patch.object(til, "call", self.fake_call(answers or {})),
              mock.patch.object(til, "now", lambda: REPORTED_AT + timedelta(days=2)),
              mock.patch.object(til.time, "sleep", lambda s: None),
              mock.patch.dict(os.environ, {"ABUSEIPDB_KEY": "test-key-never-shown"}),
              contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stdout)):
            til.main(["--first-reporter", "--logs", str(self.logs), "--out", str(self.out), *args])
        return stdout.getvalue()

    def test_without_send_nothing_is_sent(self):
        shown = self.run_main()
        self.assertEqual(self.calls, [])
        self.assertIn("Nothing was sent", shown)
        self.assertIsNone(FULL_IPV4.search(shown), shown)

    def test_it_sends_only_the_ip_to_the_check_lookup_and_saves_privately(self):
        hostile = report(REPORTED_AT - timedelta(days=1), 7, "\x1b[31m see 9.9.9.9", (18,))
        answers = {A: check_data([our_report()]), B: check_data([hostile, our_report()])}
        shown = self.run_main("--send", "--yes", answers=answers)
        self.assertEqual(len(self.calls), 2)
        for method, endpoint, query, form in self.calls:
            self.assertEqual((method, endpoint, form), ("GET", til.ABUSEIPDB_CHECK, None))
            self.assertEqual(sorted(p.split("=")[0] for p in query.split("&")),
                             ["ipAddress", "maxAgeInDays", "verbose"])
        saved = json.loads(self.out.read_text())["first_reporter"]
        self.assertEqual(saved[A]["first"], "us")
        self.assertEqual(saved[B]["first"], "someone else")
        self.assertEqual(stat.S_IMODE(os.stat(self.out).st_mode), 0o600)
        self.assertIsNone(FULL_IPV4.search(shown), shown)
        self.assertNotIn("\x1b", shown)
        self.assertNotIn("test-key-never-shown", shown)
        self.assertIn("1 of 2", shown)

    def test_ips_already_checked_after_our_report_are_not_checked_again(self):
        answers = {A: check_data([our_report()]), B: check_data([our_report()])}
        self.run_main("--send", "--yes", answers=answers)
        self.calls.clear()
        shown = self.run_main("--send", "--yes", answers=answers)
        self.assertEqual(self.calls, [])
        self.assertIn("Nothing new to look up", shown)

    def test_the_other_lookups_are_untouched(self):
        answers = {A: check_data([our_report()]), B: check_data([our_report()])}
        self.out.parent.mkdir(parents=True)
        til.save_results(self.out, {"format": 1, "urlhaus": {}, "abuseipdb": {
            A: {"checked_at": (REPORTED_AT + timedelta(days=1)).isoformat(), "score": 15}}})
        self.run_main("--send", "--yes", answers=answers)
        saved = json.loads(self.out.read_text())
        self.assertEqual(saved["abuseipdb"][A]["score"], 15)


NOW = REPORTED_AT + timedelta(days=3)
FIRST_SEEN = NOW - timedelta(days=2, hours=12)  # the window goes back 3 days, then 1 more
YEAR_CHECKED = NOW - timedelta(hours=20)


def year_record(total, before=0, first_seen=FIRST_SEEN, checked=YEAR_CHECKED):
    return {"checked_at": checked.isoformat(), "first_seen_here": first_seen.isoformat(), "score": 100,
            "total_reports": total, "reports_before_us": before}


def empty_results():
    return {"format": 1, "urlhaus": {}, "abuseipdb": {}, "first_reporter": {},
            "abuseipdb_older": {}, "first_reporter_older": {}}


class OlderReportsTests(unittest.TestCase):
    """A second, cheaper check for IPs whose 100 listed reports all came after the honeypot saw them."""

    def test_the_window_reaches_a_day_further_back_than_the_moment(self):
        self.assertEqual(til.days_back(NOW - timedelta(days=2, hours=12), NOW), 4)
        self.assertEqual(til.days_back(NOW - timedelta(minutes=10), NOW), 2)
        self.assertEqual(til.days_back(NOW - timedelta(days=400), NOW), 365)

    def test_more_reports_in_the_year_than_in_the_window_means_some_came_before(self):
        got = til.count_older(year_total=3000, recent_total=120, days=4)
        self.assertTrue(got["older"])
        self.assertEqual(got["older_at_least"], 2880)

    def test_no_more_in_the_year_than_in_the_window_is_still_unknown(self):
        self.assertFalse(til.count_older(year_total=150, recent_total=150, days=4)["older"])
        newer_since = til.count_older(year_total=150, recent_total=170, days=4)  # reports kept coming
        self.assertFalse(newer_since["older"])
        self.assertEqual(newer_since["older_at_least"], 0)

    def test_a_window_as_long_as_the_year_proves_nothing(self):
        self.assertFalse(til.count_older(year_total=3000, recent_total=120, days=365)["older"])

    def test_only_cut_off_lists_with_nothing_listed_before_us_are_checked(self):
        results = empty_results()
        results["abuseipdb"] = {"1.1.1.1": year_record(150), "1.0.0.1": year_record(80),
                                "8.8.8.8": year_record(150, before=3)}
        todo = til.older_todo(results, {})
        self.assertEqual(list(todo), [("abuseipdb_older", "1.1.1.1")])
        self.assertEqual(todo[("abuseipdb_older", "1.1.1.1")], (FIRST_SEEN, 150, YEAR_CHECKED.isoformat()))

    def test_an_ip_is_checked_again_only_after_a_newer_year_check(self):
        results = empty_results()
        results["abuseipdb"] = {A: year_record(150)}
        results["abuseipdb_older"] = {A: {"checked_at": NOW.isoformat(), "year_checked_at": YEAR_CHECKED.isoformat()}}
        self.assertEqual(til.older_todo(results, {}), {})
        results["abuseipdb"][A] = year_record(150, checked=NOW)
        self.assertEqual(list(til.older_todo(results, {})), [("abuseipdb_older", A)])

    def test_reported_ips_nobody_could_tell_about_count_back_from_our_earliest_date(self):
        results = empty_results()
        results["first_reporter"] = {
            A: {"checked_at": YEAR_CHECKED.isoformat(), "first": "can't tell", "listed": 100, "total_reports": 1500,
                "our_report_at": REPORTED_AT.isoformat()},
            B: {"checked_at": YEAR_CHECKED.isoformat(), "first": "can't tell", "listed": 0, "total_reports": 0,
                "our_report_at": REPORTED_AT.isoformat()},
            "1.0.0.1": {"checked_at": YEAR_CHECKED.isoformat(), "first": "someone else", "listed": 100,
                        "total_reports": 900, "our_report_at": REPORTED_AT.isoformat()}}
        todo = til.older_todo(results, {A: ours(), B: ours(), "1.0.0.1": ours()})
        # AbuseIPDB may date our report at the attack time we sent, which came first.
        self.assertEqual(todo, {("first_reporter_older", A): (ATTACK_TIME, 1500, YEAR_CHECKED.isoformat())})


class OlderReportsMainTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.logs = Path(self.tmp.name) / "honeypot-logs"
        self.out = self.logs / "intel" / "lookups.json"
        self.logs.mkdir(parents=True)
        visits = [{"source_ip": ip, "time": FIRST_SEEN.timestamp(), "password": "admin"} for ip in (A, B)]
        (self.logs / "visits-2026-11-08.jsonl").write_text("".join(json.dumps(v) + "\n" for v in visits))
        results = empty_results()
        results["abuseipdb"] = {A: year_record(3000), B: year_record(80)}
        results["urlhaus"] = {"x": {"checked_at": YEAR_CHECKED.isoformat(), "kind": "host"}}
        til.save_results(self.out, results)
        self.calls = []

    def tearDown(self):
        self.tmp.cleanup()

    def fake_call(self, totals, stop_after=None):
        def call(method, endpoint, headers, query=None, form=None):
            if stop_after is not None and len(self.calls) >= stop_after:
                raise urllib.error.HTTPError(endpoint, 429, "Too Many Requests", {}, None)
            self.calls.append((method, endpoint, query, form))
            ip = urllib.parse.parse_qs(query)["ipAddress"][0]
            return {"data": {"totalReports": totals[ip], "abuseConfidenceScore": 100}}, {"X-RateLimit-Remaining": "900"}
        return call

    def run_main(self, *args, totals=None, stop_after=None):
        stdout = io.StringIO()
        with (mock.patch.object(til, "call", self.fake_call(totals or {}, stop_after)),
              mock.patch.object(til, "now", lambda: NOW),
              mock.patch.object(til.time, "sleep", lambda s: None),
              mock.patch.dict(os.environ, {"ABUSEIPDB_KEY": "test-key-never-shown"}),
              contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stdout)):
            til.main(["--older-reports", "--logs", str(self.logs), "--out", str(self.out), *args])
        return stdout.getvalue()

    def test_without_send_it_shows_the_exact_count_and_sends_nothing(self):
        shown = self.run_main()
        self.assertEqual(self.calls, [])
        self.assertIn("AbuseIPDB: 1 check", shown)
        self.assertIn("Nothing was sent", shown)
        self.assertIsNone(FULL_IPV4.search(shown), shown)

    def test_it_asks_only_for_a_count_over_the_days_since_and_saves_privately(self):
        shown = self.run_main("--send", "--yes", totals={A: 120})
        self.assertEqual(len(self.calls), 1)
        method, endpoint, query, form = self.calls[0]
        self.assertEqual((method, endpoint, form), ("GET", til.ABUSEIPDB_CHECK, None))
        self.assertEqual(urllib.parse.parse_qs(query, keep_blank_values=True),
                         {"ipAddress": [A], "maxAgeInDays": ["4"]})  # no verbose: no report details
        saved = json.loads(self.out.read_text())
        self.assertTrue(saved["abuseipdb_older"][A]["older"])
        self.assertEqual(saved["abuseipdb_older"][A]["older_at_least"], 2880)
        self.assertEqual(saved["abuseipdb_older"][A]["year_checked_at"], YEAR_CHECKED.isoformat())
        self.assertEqual(saved["abuseipdb"][A]["total_reports"], 3000)  # the year check is left alone
        self.assertIn("x", saved["urlhaus"])
        self.assertEqual(stat.S_IMODE(os.stat(self.out).st_mode), 0o600)
        self.assertIsNone(FULL_IPV4.search(shown), shown)
        self.assertNotIn("test-key-never-shown", shown)
        self.assertIn("1 of 1", shown)

    def test_a_second_run_checks_nothing_again(self):
        self.run_main("--send", "--yes", totals={A: 120})
        self.calls.clear()
        shown = self.run_main("--send", "--yes", totals={A: 120})
        self.assertEqual(self.calls, [])
        self.assertIn("Nothing new to look up", shown)

    def test_it_warns_when_some_ips_have_no_year_check_yet(self):
        results = json.loads(self.out.read_text())
        del results["abuseipdb"][B]
        til.save_results(self.out, results)
        shown = self.run_main()
        self.assertIn("1 IP in the logs has no year check yet", shown)

    def test_the_daily_limit_stops_it_and_keeps_what_it_has(self):
        results = json.loads(self.out.read_text())
        results["abuseipdb"][B] = year_record(500)
        til.save_results(self.out, results)
        shown = self.run_main("--send", "--yes", totals={A: 120, B: 120}, stop_after=1)
        self.assertIn("daily limit", shown)
        self.assertEqual(len(json.loads(self.out.read_text())["abuseipdb_older"]), 1)


if __name__ == "__main__":
    unittest.main()
