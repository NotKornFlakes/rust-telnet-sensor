//! # Stage 3: Protecting the logs
//!
//! Your logs hold IP addresses and passwords, so they need looking after. In this
//! stage the honeypot learns to:
//! - refuse to write to a log that other users can read
//! - start a new file each day, named by the date
//! - delete files older than `KEEP_DAYS`
//! - hide passwords and most of the IP address on screen
//!
//! The log files still hold the full details, because that's what your research needs.
//!
//! Do the exercises in order, replacing each `todo!()`. Run one exercise's tests with
//! `cargo test log_files::tests::ex1`. Run all of Stage 3 with `cargo test log_files`.
//!
//! `cargo run` crashes with "not yet implemented" until you've finished this stage,
//! because `main.rs` now uses this file.

// While the exercises are full of `todo!()`, some arguments, imports and other code
// aren't used, and the compiler warns about it. This line silences those warnings.
// Delete this comment and the line below once you've finished the stage.
#![allow(dead_code, unused_variables, unused_imports)]

use std::ffi::OsStr;
use std::fs::{self, DirBuilder, File, OpenOptions};
use std::io::{self, Write};
use std::net::IpAddr;
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::time::SystemTime;

// `chrono` is a crate for dates. It was added with its optional extras turned off:
// `cargo add chrono --no-default-features --features std`. Every extra package is more
// code you have to trust, and this program talks to attackers.
use chrono::{DateTime, NaiveDate};

use crate::visit::{Visit, unix_seconds};

/// How many days to keep a log file before deleting it. Change this to suit your
/// research, and remember that logs you no longer need are a risk.
pub const KEEP_DAYS: i64 = 30;

// Log files are named like `visits-2026-10-31.jsonl`.
const LOG_PREFIX: &str = "visits-";
const LOG_SUFFIX: &str = ".jsonl";
const DATE_FORMAT: &str = "%Y-%m-%d";

// ---------------------------------------------------------------------------
// Who can read the logs
// ---------------------------------------------------------------------------

/// EXERCISE 1: check whether a file's permissions keep everyone else out.
///
/// `mode` is the number behind `chmod`. In `0o640`, the digits are for you, your group
/// and everyone else. A file is private if the last two digits are both 0.
///
/// The new idea is a bit mask. `mode & 0o077` keeps only those last two digits, and
/// blanks out everything else. `&` works the same way in JS and Python.
pub fn is_private(mode: u32) -> bool {
    mode & 0o077 == 0
}

/// EXERCISE 2: return an error if other users can get at this file or folder.
///
/// The new idea is making your own error, like `throw new Error("...")` in JS or
/// `raise` in Python:
///
/// ```text
/// return Err(io::Error::new(io::ErrorKind::PermissionDenied, "your message"));
/// ```
///
/// Hints:
/// - `fs::metadata(path)?.permissions().mode()` gets the mode number.
/// - Put the path in your message, so you can tell which file to fix. Use `format!`,
///   and `path.display()` to make a `Path` printable.
/// - If all is well, return `Ok(())`.
pub fn check_private(path: &Path) -> io::Result<()> {
    if is_private(fs::metadata(path)?.permissions().mode()) {
        Ok(())
    } else {
        Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!("File is not private: {}", path.display()),
        ))
    }
}

// ---------------------------------------------------------------------------
// Dates and file names
// ---------------------------------------------------------------------------

/// EXERCISE 3: work out the date from seconds since 1970.
///
/// The date is in UTC, like the `time` in your log lines, so a new day doesn't depend
/// on where the computer is or on daylight saving.
///
/// The new idea is converting between number types with `as`. JS has one number type,
/// but Rust has many and never converts them silently. You have a `u64`, and chrono
/// wants an `i64`, so write `seconds as i64`.
///
/// Hints:
/// - `DateTime::from_timestamp(seconds, 0)` returns an `Option`, which is `None` if
///   the number is too big to be a date. The `0` is for extra nanoseconds.
/// - `.unwrap_or_default()` gives you the value inside `Some`, or 1970 if it's `None`.
/// - `.date_naive()` then keeps just the date. "Naive" means no time zone is attached.
pub fn date_from_seconds(seconds: u64) -> NaiveDate {
    DateTime::from_timestamp(seconds as i64, 0)
        .unwrap_or_default()
        .date_naive()
}

/// Today's date, in UTC.
pub fn today() -> NaiveDate {
    date_from_seconds(unix_seconds(SystemTime::now()))
}

// Dates already know how to print themselves as `2026-10-31`.
fn log_file_name(date: NaiveDate) -> String {
    format!("{LOG_PREFIX}{date}{LOG_SUFFIX}")
}

/// EXERCISE 4: read the date back out of a log file's name.
///
/// `visits-2026-10-31.jsonl` gives that date. Anything else gives `None`.
///
/// The new idea is that `?` also works on an `Option`: if it's `None`, the whole
/// function returns `None` right away. It's a lot like `?.` in JS.
///
/// Hints:
/// - `name.strip_prefix(LOG_PREFIX)` returns an `Option`, because the text might not
///   start that way. `.strip_suffix(LOG_SUFFIX)` works the same way.
/// - `NaiveDate::parse_from_str(text, DATE_FORMAT)` returns a `Result`. `.ok()` turns
///   that into an `Option`, which can be your last line.
pub fn date_from_file_name(name: &str) -> Option<NaiveDate> {
    let name = name.strip_prefix(LOG_PREFIX)?;
    let name = name.strip_suffix(LOG_SUFFIX)?;
    NaiveDate::parse_from_str(name, DATE_FORMAT).ok()
}

// ---------------------------------------------------------------------------
// Deleting old logs
// ---------------------------------------------------------------------------

/// EXERCISE 5: decide whether a log from this date is old enough to delete.
///
/// A log exactly `KEEP_DAYS` old is kept. Anything older is expired.
///
/// The new idea is that a type can define what `-` means, as Python's `datetime` does.
/// `today - date` gives you a length of time rather than a number.
///
/// Hint: `.num_days()` turns that length of time into an `i64`.
pub fn is_expired(date: NaiveDate, today: NaiveDate) -> bool {
    (today - date).num_days() > KEEP_DAYS
}

// This is a worked example, not an exercise. It finds the files that are safe to
// consider deleting. It's strict on purpose, because deleting can't be undone:
//
// - `file_type` doesn't follow links, so folders and links are skipped.
// - `parse_from_str` is forgiving and accepts `2026-1-5`. The name must be exactly what
//   `log_file_name` would write, so the only files that match are ones we made.
pub fn dated_log_files(dir: &Path) -> io::Result<Vec<(PathBuf, NaiveDate)>> {
    let mut found = Vec::new();
    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        if !entry.file_type()?.is_file() {
            continue;
        }
        if let Some(date) = date_of_exact_name(&entry.file_name()) {
            found.push((entry.path(), date));
        }
    }
    Ok(found)
}

fn date_of_exact_name(name: &OsStr) -> Option<NaiveDate> {
    // File names on Linux don't have to be valid text, so this gives an `Option`.
    let name = name.to_str()?;
    let date = date_from_file_name(name)?;
    if log_file_name(date) == name {
        Some(date)
    } else {
        None
    }
}

/// EXERCISE 6: delete the expired log files, and return how many you deleted.
///
/// The new idea is unpacking in a `for` loop. `dated_log_files` gives you a list of
/// pairs, and you can unpack each one as you go:
///
/// ```text
/// for (path, date) in dated_log_files(dir)? {
/// ```
///
/// That's `for path, date in files:` in Python.
///
/// Hints:
/// - `fs::remove_file(path)?` deletes a file for good. There's no trash to get it back.
/// - Count with `let mut deleted = 0;`, as you would in any language.
pub fn delete_expired_logs(dir: &Path, today: NaiveDate) -> io::Result<usize> {
    let mut deleted = 0;
    for (path, date) in dated_log_files(dir)? {
        if is_expired(date, today) {
            fs::remove_file(path)?;
            deleted += 1;
        }
    }
    Ok(deleted)
}

// ---------------------------------------------------------------------------
// A new file each day
// ---------------------------------------------------------------------------

// This is a worked example, not an exercise. It opens the file for a day, and it's where
// the permission checks happen. `mode` only applies to a file when it's first created,
// so an older file could have looser permissions. That's why we check afterwards too.
//
// A new day is a good time to clean up. If that fails, we say so and carry on, because
// recording visits matters more.
fn start_day(dir: &Path, date: NaiveDate) -> io::Result<File> {
    DirBuilder::new().recursive(true).mode(0o700).create(dir)?;
    check_private(dir)?;

    let path = dir.join(log_file_name(date));
    let file = OpenOptions::new()
        .create(true)
        .append(true)
        .mode(0o600)
        .open(&path)?;
    check_private(&path)?;

    match delete_expired_logs(dir, date) {
        Ok(0) => {}
        Ok(deleted) => println!("Deleted {deleted} log file(s) older than {KEEP_DAYS} days."),
        Err(error) => eprintln!("could not delete old logs: {error}"),
    }
    Ok(file)
}

/// The log, which moves to a new file each day.
pub struct DailyLog {
    dir: PathBuf,
    date: NaiveDate,
    file: File,
}

impl DailyLog {
    /// Opens today's file, creating the folder and file if they don't exist yet.
    pub fn open(dir: &Path, today: NaiveDate) -> io::Result<DailyLog> {
        let file = start_day(dir, today)?;
        Ok(DailyLog {
            dir: dir.to_path_buf(),
            date: today,
            file,
        })
    }

    /// How many bytes are in the file for the current day.
    pub fn size(&self) -> io::Result<u64> {
        Ok(self.file.metadata()?.len())
    }

    /// EXERCISE 7: add a line to the log, starting a new file if the day has changed.
    ///
    /// The new idea is how files get closed. In JS you call `.close()`, and in Python
    /// you use `with`. In Rust, `self.file = ...` replaces the old `File`, and Rust
    /// closes it for you, because nothing owns it any more.
    ///
    /// Do these in order:
    /// 1. If `today` isn't `self.date`, set `self.file` using `start_day` and
    ///    `self.date` to `today`.
    /// 2. Write the line with `self.file.write_all(...)`.
    ///
    /// Hint: `self.dir` is a `PathBuf`, and `start_day` wants a `&Path`. Writing
    /// `&self.dir` converts it for you.
    pub fn append(&mut self, today: NaiveDate, line: &[u8]) -> io::Result<()> {
        if today != self.date {
            self.file = start_day(&self.dir, today)?;
            self.date = today;
        }
        self.file.write_all(line)
    }
}

// ---------------------------------------------------------------------------
// What shows on screen
// ---------------------------------------------------------------------------

/// EXERCISE 8: hide most of an IP address, for showing on screen.
///
/// - An IPv4 address keeps its first two numbers: `203.0.113.7` becomes `203.0.x.x`.
/// - An IPv6 address is hidden completely: `(ipv6)`.
///
/// The new idea is an enum that holds data. `IpAddr` is either a `V4` holding an IPv4
/// address, or a `V6` holding an IPv6 one, a bit like a TypeScript tagged union. `match`
/// hands you the data inside:
///
/// ```text
/// match ip {
///     IpAddr::V4(address) => ...,
///     IpAddr::V6(_) => ...,
/// }
/// ```
///
/// Hint: `address.octets()` gives you an array of the four numbers.
pub fn mask_ip(ip: IpAddr) -> String {
    match ip {
        IpAddr::V4(address) => {
            let octets = address.octets();
            format!("{}.{}.x.x", octets[0], octets[1])
        }
        IpAddr::V6(_) => "(ipv6)".to_string(),
    }
}

/// EXERCISE 9: describe a visit on one line, for showing on screen.
///
/// ```text
/// 2026-10-31 Attempted from 203.0.x.x user=admin password=(hidden)
/// 2026-10-31 Left from 203.0.x.x user=(none) password=(none)
/// ```
///
/// The new idea is showing whether a secret exists without showing the secret. Print
/// `(hidden)` if there's a password and `(none)` if there isn't, and never the password
/// itself. Screens get seen and recorded, so this is what safety rule 4 needs.
///
/// Hints:
/// - `date_from_seconds` and `mask_ip` give you the first and third pieces.
/// - `{:?}` prints an `Outcome` by its name.
/// - `visit.username.as_deref()` gives an `Option<&str>`, and `.unwrap_or("(none)")`
///   gets you text either way.
/// - `.is_some()` tells you whether there's a password.
pub fn screen_line(visit: &Visit) -> String {
    let date = date_from_seconds(visit.time);
    let outcome = &visit.outcome;
    let ip = mask_ip(visit.source_ip);
    let username = visit.username.as_deref().unwrap_or("(none)");
    let password = if visit.password.is_some() {
        "(hidden)"
    } else {
        "(none)"
    };
    let line = format!("{date} {outcome:?} from {ip} user={username} password={password}");
    // Stage 7: a session only ever shows as counts, never what was typed.
    let mut line = match &visit.shell {
        Some(session) => format!("{line} {}", session.screen_summary()),
        None => line,
    };
    // Stages 8 and 10: which service it was, the method and path of a web request, and only the
    // size of what an SSH client sent.
    if let Some(service) = visit.service {
        line.push_str(&format!(" service={service}"));
    }
    if let Some(request) = &visit.http {
        line.push_str(&format!(" {}", request.screen_summary()));
    }
    if let Some(banner) = &visit.client_banner {
        line.push_str(&format!(" banner_bytes={}", banner.len()));
    }
    line
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------
//
// You don't need to change anything below, but do read the tests: they show exactly
// how your code is going to be used.
//
// These tests only ever touch throwaway folders full of made-up data, never your real
// `logs` folder.

#[cfg(test)]
mod tests {
    use super::*;
    use crate::visit::Outcome;
    use chrono::TimeDelta;
    use std::env;
    use std::fs::Permissions;
    use std::net::{Ipv4Addr, Ipv6Addr};
    use std::os::unix::fs::symlink;

    // A folder that belongs to one test. Rust calls `drop` when a value goes away, even
    // if the test fails, so the folder always gets cleaned up.
    struct TestDir {
        path: PathBuf,
    }

    impl TestDir {
        fn new(test_name: &str) -> TestDir {
            let name = format!("honeypot-test-{}-{test_name}", std::process::id());
            let path = env::temp_dir().join(name);
            let _ = fs::remove_dir_all(&path);
            DirBuilder::new().mode(0o700).create(&path).unwrap();
            TestDir { path }
        }

        fn file(&self, name: &str) -> PathBuf {
            self.path.join(name)
        }

        fn exists(&self, name: &str) -> bool {
            self.file(name).symlink_metadata().is_ok()
        }
    }

    impl Drop for TestDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.path);
        }
    }

    fn date(year: i32, month: u32, day: u32) -> NaiveDate {
        NaiveDate::from_ymd_opt(year, month, day).unwrap()
    }

    fn days_before(today: NaiveDate, days: i64) -> NaiveDate {
        today - TimeDelta::days(days)
    }

    fn set_mode(path: &Path, mode: u32) {
        fs::set_permissions(path, Permissions::from_mode(mode)).unwrap();
    }

    fn mode_of(path: &Path) -> u32 {
        fs::metadata(path).unwrap().permissions().mode() & 0o777
    }

    fn sample_visit(ip: IpAddr) -> Visit {
        Visit {
            time: 86_400,
            source_ip: ip,
            outcome: Outcome::Attempted,
            username: Some("admin".to_string()),
            password: Some("hunter2".to_string()),
            telnet: None,
            shell: None,
            service: None,
            http: None,
            client_banner: None,
        }
    }

    // A documentation address. It's reserved, and it doesn't belong to anyone.
    const SAMPLE_IP: IpAddr = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 7));

    #[test]
    fn ex1_only_you_having_access_is_private() {
        for mode in [0o600, 0o700, 0o400] {
            assert!(is_private(mode), "{mode:o} should be private");
        }
    }

    #[test]
    fn ex1_anyone_else_having_access_is_not_private() {
        for mode in [0o640, 0o620, 0o604, 0o602, 0o644, 0o777] {
            assert!(!is_private(mode), "{mode:o} should not be private");
        }
    }

    #[test]
    fn ex1_ignores_the_digits_for_the_file_type() {
        assert!(is_private(0o100600));
        assert!(!is_private(0o100644));
    }

    #[test]
    fn ex2_accepts_a_private_file() {
        let dir = TestDir::new("ex2-accepts");
        let path = dir.file("private.txt");
        fs::write(&path, "made up").unwrap();
        set_mode(&path, 0o600);
        assert!(check_private(&path).is_ok());
    }

    #[test]
    fn ex2_refuses_a_file_others_can_read() {
        let dir = TestDir::new("ex2-refuses");
        let path = dir.file("open.txt");
        fs::write(&path, "made up").unwrap();
        set_mode(&path, 0o644);

        let error = check_private(&path).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
        assert!(error.to_string().contains("open.txt"));
    }

    #[test]
    fn ex2_a_missing_file_is_an_error() {
        let dir = TestDir::new("ex2-missing");
        assert!(check_private(&dir.file("not-there.txt")).is_err());
    }

    #[test]
    fn ex2_the_log_refuses_a_folder_others_can_read() {
        let dir = TestDir::new("ex2-open-folder");
        set_mode(&dir.path, 0o755);
        assert!(DailyLog::open(&dir.path, date(2026, 10, 31)).is_err());
    }

    #[test]
    fn ex2_the_log_refuses_an_old_file_others_can_read() {
        let dir = TestDir::new("ex2-open-file");
        let path = dir.file("visits-2026-10-31.jsonl");
        fs::write(&path, "made up\n").unwrap();
        set_mode(&path, 0o644);
        assert!(DailyLog::open(&dir.path, date(2026, 10, 31)).is_err());
    }

    #[test]
    fn ex3_finds_the_date() {
        assert_eq!(date_from_seconds(0), date(1970, 1, 1));
    }

    #[test]
    fn ex3_a_new_day_starts_at_midnight() {
        assert_eq!(date_from_seconds(86_399), date(1970, 1, 1));
        assert_eq!(date_from_seconds(86_400), date(1970, 1, 2));
    }

    #[test]
    fn ex3_a_number_too_big_to_be_a_date_gives_1970() {
        assert_eq!(date_from_seconds(i64::MAX as u64), date(1970, 1, 1));
    }

    #[test]
    fn ex4_reads_the_date() {
        let name = "visits-2026-10-31.jsonl";
        assert_eq!(date_from_file_name(name), Some(date(2026, 10, 31)));
    }

    #[test]
    fn ex4_anything_else_gives_none() {
        for name in [
            "login.log",
            "visits.jsonl",
            "visits-.jsonl",
            "visits-notadate.jsonl",
            "visits-2026-13-45.jsonl",
            "visits-2026-10-31.jsonl.bak",
            "old-visits-2026-10-31.jsonl",
        ] {
            assert_eq!(date_from_file_name(name), None, "{name}");
        }
    }

    #[test]
    fn ex5_today_is_not_expired() {
        let today = date(2026, 10, 31);
        assert!(!is_expired(today, today));
    }

    #[test]
    fn ex5_exactly_keep_days_old_is_kept() {
        let today = date(2026, 10, 31);
        assert!(!is_expired(days_before(today, KEEP_DAYS), today));
    }

    #[test]
    fn ex5_one_day_older_is_expired() {
        let today = date(2026, 10, 31);
        assert!(is_expired(days_before(today, KEEP_DAYS + 1), today));
    }

    #[test]
    fn ex5_a_future_date_is_not_expired() {
        let today = date(2026, 10, 31);
        assert!(!is_expired(days_before(today, -5), today));
    }

    #[test]
    fn ex6_deletes_expired_logs_and_counts_them() {
        let dir = TestDir::new("ex6-deletes");
        let today = date(2026, 10, 31);
        let old = log_file_name(days_before(today, KEEP_DAYS + 1));
        let older = log_file_name(days_before(today, KEEP_DAYS + 100));
        let recent = log_file_name(days_before(today, KEEP_DAYS));
        for name in [&old, &older, &recent] {
            fs::write(dir.file(name), "made up\n").unwrap();
        }

        assert_eq!(delete_expired_logs(&dir.path, today).unwrap(), 2);

        assert!(!dir.exists(&old));
        assert!(!dir.exists(&older));
        assert!(dir.exists(&recent));
    }

    #[test]
    fn ex6_leaves_everything_else_alone() {
        let dir = TestDir::new("ex6-leaves");
        let today = date(2026, 10, 31);

        // Old enough to delete if they counted as logs, but none of them do.
        let lookalikes = [
            "login.log",
            "visits.jsonl",
            "notes.txt",
            "visits-2020-1-1.jsonl",
            "visits-2020-01-01.jsonl.bak",
        ];
        for name in lookalikes {
            fs::write(dir.file(name), "made up\n").unwrap();
        }
        let folder = "visits-2020-01-02.jsonl";
        fs::create_dir(dir.file(folder)).unwrap();
        let link = "visits-2020-01-03.jsonl";
        symlink(dir.file("notes.txt"), dir.file(link)).unwrap();

        assert_eq!(delete_expired_logs(&dir.path, today).unwrap(), 0);

        for name in lookalikes {
            assert!(dir.exists(name), "{name} should still be there");
        }
        assert!(dir.exists(folder));
        assert!(dir.exists(link));
    }

    #[test]
    fn ex7_writes_to_the_file_for_today() {
        let dir = TestDir::new("ex7-writes");
        let today = date(2026, 10, 31);
        let mut log = DailyLog::open(&dir.path, today).unwrap();

        log.append(today, b"first\n").unwrap();
        log.append(today, b"second\n").unwrap();

        let written = fs::read_to_string(dir.file("visits-2026-10-31.jsonl")).unwrap();
        assert_eq!(written, "first\nsecond\n");
    }

    #[test]
    fn ex7_a_new_day_starts_a_new_file() {
        let dir = TestDir::new("ex7-new-day");
        let mut log = DailyLog::open(&dir.path, date(2026, 10, 31)).unwrap();

        log.append(date(2026, 10, 31), b"october\n").unwrap();
        log.append(date(2026, 11, 1), b"november\n").unwrap();
        log.append(date(2026, 11, 1), b"still november\n").unwrap();

        let october = fs::read_to_string(dir.file("visits-2026-10-31.jsonl")).unwrap();
        let november = fs::read_to_string(dir.file("visits-2026-11-01.jsonl")).unwrap();
        assert_eq!(october, "october\n");
        assert_eq!(november, "november\nstill november\n");
    }

    #[test]
    fn ex7_keeps_adding_to_a_file_that_already_exists() {
        let dir = TestDir::new("ex7-restart");
        let today = date(2026, 10, 31);

        let mut log = DailyLog::open(&dir.path, today).unwrap();
        log.append(today, b"before restart\n").unwrap();
        drop(log);

        let mut log = DailyLog::open(&dir.path, today).unwrap();
        log.append(today, b"after restart\n").unwrap();

        let written = fs::read_to_string(dir.file("visits-2026-10-31.jsonl")).unwrap();
        assert_eq!(written, "before restart\nafter restart\n");
    }

    #[test]
    fn ex7_new_files_are_private() {
        let dir = TestDir::new("ex7-private");
        let mut log = DailyLog::open(&dir.path, date(2026, 10, 31)).unwrap();
        log.append(date(2026, 11, 1), b"made up\n").unwrap();

        assert_eq!(mode_of(&dir.file("visits-2026-10-31.jsonl")), 0o600);
        assert_eq!(mode_of(&dir.file("visits-2026-11-01.jsonl")), 0o600);
    }

    #[test]
    fn ex7_a_new_day_deletes_expired_logs() {
        let dir = TestDir::new("ex7-cleanup");
        let today = date(2026, 10, 31);
        let tomorrow = date(2026, 11, 1);
        let mut log = DailyLog::open(&dir.path, today).unwrap();

        // Exactly old enough to expire tomorrow, but not today.
        let name = log_file_name(days_before(today, KEEP_DAYS));
        fs::write(dir.file(&name), "made up\n").unwrap();

        log.append(today, b"made up\n").unwrap();
        assert!(dir.exists(&name));

        log.append(tomorrow, b"made up\n").unwrap();
        assert!(!dir.exists(&name));
    }

    #[test]
    fn ex8_keeps_the_first_two_numbers_of_an_ipv4_address() {
        assert_eq!(mask_ip(SAMPLE_IP), "203.0.x.x");
    }

    #[test]
    fn ex8_hides_an_ipv6_address_completely() {
        let ip = IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1));
        assert_eq!(mask_ip(ip), "(ipv6)");
    }

    #[test]
    fn ex9_describes_an_attempt() {
        assert_eq!(
            screen_line(&sample_visit(SAMPLE_IP)),
            "1970-01-02 Attempted from 203.0.x.x user=admin password=(hidden)"
        );
    }

    #[test]
    fn ex9_says_when_nobody_answered() {
        let mut visit = sample_visit(SAMPLE_IP);
        visit.outcome = Outcome::Left;
        visit.username = None;
        visit.password = None;
        assert_eq!(
            screen_line(&visit),
            "1970-01-02 Left from 203.0.x.x user=(none) password=(none)"
        );
    }

    #[test]
    fn ex9_never_shows_the_password_or_the_full_ip() {
        let line = screen_line(&sample_visit(SAMPLE_IP));
        assert!(!line.contains("hunter2"));
        assert!(!line.contains("203.0.113.7"));
    }
}
