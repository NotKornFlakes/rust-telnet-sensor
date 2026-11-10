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
        # AbuseIPDB lists at most 10,000 reports, so older ones can be missing from the list.
        got = verdict([our_report(), report(REPORTED_AT + timedelta(hours=1), 7)], total=12000)
        self.assertEqual(got["first"], "can't tell")
        self.assertIn("10,000", got["why"])
        self.assertEqual(got["listed"], 2)
        self.assertEqual(got["total_reports"], 12000)

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


if __name__ == "__main__":
    unittest.main()
