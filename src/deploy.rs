//! # Stage 5: Ready to deploy
//!
//! This is the last code you need before going live. So far the program can only ever
//! listen on localhost. In this stage it learns to:
//! - take a listen address, with localhost as the default and a deliberate flag needed
//!   for anything else
//! - refuse to run as root
//! - limit visits from one address each minute, so one source can't use up the day's log
//!   budget
//! - fail its tests if the code ever starts a program or connects out
//!
//! Do the exercises in order, replacing each `todo!()`. Run one exercise's tests with
//! `cargo test deploy::tests::ex1`. Run all of Stage 5 with `cargo test deploy`.
//!
//! `cargo run` crashes with "not yet implemented" until you've finished this stage,
//! because `main.rs` now uses this file.

// While the exercises are full of `todo!()`, some arguments, imports and other code
// aren't used, and the compiler warns about it. This line silences those warnings.
// Delete this comment and the line below once you've finished the stage.
#![allow(dead_code, unused_variables, unused_imports)]

use std::collections::HashMap;
use std::fs;
use std::io;
use std::net::{IpAddr, SocketAddr, TcpListener};
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::time::SystemTime;

use crate::visit::unix_seconds;

/// Where the program listens unless you say otherwise: this computer only.
pub const DEFAULT_LISTEN: &str = "127.0.0.1:2323";

/// The most visits one address can make each minute. At this rate, one address can add
/// at most about 8 MB a day to the log.
pub const MAX_VISITS_PER_MINUTE: u32 = 60;

/// The most addresses to keep track of in one minute, so that memory use stays limited.
pub const MAX_TRACKED_ADDRESSES: usize = 100_000;

// Each test module starts with this line. It has real newlines on both sides, so text
// that only mentions it, like this comment, doesn't count.
const TEST_MARKER: &str = "\n#[cfg(test)]\n";

fn setting_error(message: String) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message)
}

// ---------------------------------------------------------------------------
// Choosing where to listen
// ---------------------------------------------------------------------------

/// EXERCISE 1: turn text like `127.0.0.1:2323` into a real address.
///
/// The new idea is `.parse()`, which turns text into other types, a bit like `Number()`
/// in JS or `int()` in Python. Parsing into a `SocketAddr` never looks up a name like
/// `localhost`, because that would mean connecting out to a DNS server.
///
/// Hints:
/// - `text.parse::<SocketAddr>()` returns a `Result`. The `::<SocketAddr>` part says
///   what to parse the text into.
/// - Its error is a different type from `io::Error`. `.map_err(|error| ...)` converts it.
///   Inside, use `setting_error(format!(...))`, and put `text` in the message.
pub fn parse_listen_address(text: &str) -> io::Result<SocketAddr> {
    text.parse::<SocketAddr>()
        .map_err(|error| setting_error(format!("bad listen address {text:?}: {error}")))
}

/// EXERCISE 2: decide whether the program may listen on this address.
///
/// - IPv6 is always refused for now. One attacker can have huge numbers of IPv6
///   addresses, so the cap per IP wouldn't hold them back.
/// - A loopback address is fine, because only this computer can reach it.
/// - Anything else needs `checklist_done`, which means you've finished the whole Stage 6
///   checklist.
///
/// The new idea is writing a safety rule down as code. Checking in this order, with an
/// early `return Err(...)` for each refusal, keeps the rule easy to read.
///
/// Hints:
/// - `address.is_ipv6()` and `address.ip().is_loopback()` answer the first two questions.
/// - Use `setting_error` for the errors, and say what to do about it in the message.
pub fn check_address(address: SocketAddr, checklist_done: bool) -> io::Result<()> {
    if address.is_ipv6() {
        return Err(setting_error(format!(
            "IPv6 address {address} is not allowed"
        )));
    }
    if address.ip().is_loopback() {
        return Ok(());
    }
    if checklist_done {
        return Ok(());
    }
    Err(setting_error(format!("address {address} is not allowed")))
}
/// The settings the program runs with.
///
/// The field has no `pub`, and the only way to make `Settings` is through `checked`. So
/// the program can't listen anywhere that `check_address` hasn't approved.
///
/// `credentials` is the file of logins for the fake shell from Stage 7. With no file, the shell
/// stays off and every login is rejected.
///
/// `web_listen` is where the fake web service from Stage 8 listens, and `ftp_listen` and
/// `ssh_listen` are for the services from Stage 10. With no address, each one is off. They go
/// through `check_address` too, so they follow the same rule as the telnet port.
#[derive(Debug)]
pub struct Settings {
    listen: SocketAddr,
    credentials: Option<PathBuf>,
    web_listen: Option<SocketAddr>,
    ftp_listen: Option<SocketAddr>,
    ssh_listen: Option<SocketAddr>,
}

// The addresses for the services that are off unless you ask, as they came from the command line.
#[derive(Debug, Default)]
struct ExtraAddresses<'a> {
    web: Option<&'a str>,
    ftp: Option<&'a str>,
    ssh: Option<&'a str>,
}

impl Settings {
    fn checked(
        listen: &str,
        checklist_done: bool,
        credentials: Option<PathBuf>,
        extra: ExtraAddresses,
    ) -> io::Result<Settings> {
        let listen = parse_listen_address(listen)?;
        check_address(listen, checklist_done)?;
        Ok(Settings {
            listen,
            credentials,
            web_listen: checked_extra(extra.web, checklist_done)?,
            ftp_listen: checked_extra(extra.ftp, checklist_done)?,
            ssh_listen: checked_extra(extra.ssh, checklist_done)?,
        })
    }

    /// The file of logins for the fake shell, if there is one.
    pub fn credentials(&self) -> Option<&Path> {
        self.credentials.as_deref()
    }

    /// Where the fake web service listens, if it's on.
    pub fn web_listen(&self) -> Option<SocketAddr> {
        self.web_listen
    }

    /// Where the fake FTP service listens, if it's on.
    pub fn ftp_listen(&self) -> Option<SocketAddr> {
        self.ftp_listen
    }

    /// Where the fake SSH service listens, if it's on.
    pub fn ssh_listen(&self) -> Option<SocketAddr> {
        self.ssh_listen
    }

    /// EXERCISE 3: read the settings from the command line.
    ///
    /// `args` is what came after the program's name, like `sys.argv[1:]` in Python:
    ///
    /// ```text
    /// --listen 0.0.0.0:2323 --checklist-done
    /// ```
    ///
    /// The new idea is `while let`, which keeps looping for as long as a pattern matches.
    /// You need it instead of `for` because `--listen` takes the next argument too:
    ///
    /// ```text
    /// let mut args = args.iter();
    /// while let Some(arg) = args.next() {
    /// ```
    ///
    /// Do these in order:
    /// 1. Start with `DEFAULT_LISTEN` for the address, and `false` for `checklist_done`.
    /// 2. In the loop, `match arg.as_str()`:
    ///    - `"--listen"` takes its address from `args.next()`. If that's `None`, return an
    ///      error, because the address is missing.
    ///    - `"--checklist-done"` sets `checklist_done` to `true`.
    ///    - Anything else is an error. A typo must never be quietly ignored.
    /// 3. Finish with `Settings::checked`.
    pub fn from_args(args: &[String]) -> io::Result<Settings> {
        let mut listen = DEFAULT_LISTEN.to_string();
        let mut checklist_done = false;
        let mut credentials = None;
        let mut extra = ExtraAddresses::default();
        let mut args_iter = args.iter();

        while let Some(arg) = args_iter.next() {
            match arg.as_str() {
                "--listen" => {
                    if let Some(addr) = args_iter.next() {
                        listen = addr.clone();
                    } else {
                        return Err(setting_error("missing address after --listen".to_string()));
                    }
                }
                "--checklist-done" => {
                    checklist_done = true;
                }
                // Stage 7 adds this one. It takes the next argument, like `--listen`.
                "--credentials" => {
                    if let Some(path) = args_iter.next() {
                        credentials = Some(PathBuf::from(path));
                    } else {
                        return Err(setting_error(
                            "missing file after --credentials".to_string(),
                        ));
                    }
                }
                // Stages 8 and 10 add these. Each takes an address, like `--listen`.
                "--web-listen" => extra.web = Some(next_value(&mut args_iter, arg)?),
                "--ftp-listen" => extra.ftp = Some(next_value(&mut args_iter, arg)?),
                "--ssh-listen" => extra.ssh = Some(next_value(&mut args_iter, arg)?),
                _ => {
                    return Err(setting_error(format!("unknown argument: {arg}")));
                }
            }
        }

        Settings::checked(&listen, checklist_done, credentials, extra)
    }

    /// Starts listening at the address these settings allow.
    pub fn open_listener(&self) -> io::Result<TcpListener> {
        TcpListener::bind(self.listen)
    }
}

// This is a worked example from Stage 8. It's what `--listen` does with the argument after it, for
// flags added later.
fn next_value<'a>(args: &mut std::slice::Iter<'a, String>, flag: &str) -> io::Result<&'a str> {
    match args.next() {
        Some(value) => Ok(value),
        None => Err(setting_error(format!("missing address after {flag}"))),
    }
}

// An address for a service that's off unless you ask, checked by the same rule as `--listen`.
fn checked_extra(text: Option<&str>, checklist_done: bool) -> io::Result<Option<SocketAddr>> {
    match text {
        Some(text) => {
            let address = parse_listen_address(text)?;
            check_address(address, checklist_done)?;
            Ok(Some(address))
        }
        None => Ok(None),
    }
}

// ---------------------------------------------------------------------------
// Refusing to run as root
// ---------------------------------------------------------------------------

/// The ID of the user running this program. `/proc/self` is a special folder that always
/// belongs to whoever is asking.
pub fn current_uid() -> io::Result<u32> {
    Ok(fs::metadata("/proc/self")?.uid())
}

/// EXERCISE 4: return an error if this user is root.
///
/// Root can change anything on the computer. If an attacker ever found a way to take
/// over this program, it should have as little power as possible. Root's user ID is
/// always 0.
///
/// The new idea is building a safety check out of plain values. Taking `uid` as an
/// argument means the tests can try being root, without needing to be root.
///
/// Hint: use `io::ErrorKind::PermissionDenied`, as you did in Stage 3.
pub fn refuse_root(uid: u32) -> io::Result<()> {
    if uid == 0 {
        Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "refusing to run as root",
        ))
    } else {
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Limiting visits per minute
// ---------------------------------------------------------------------------

/// How many visits each address has made this minute.
#[derive(Debug)]
pub struct RateLimit {
    max_per_minute: u32,
    max_tracked: usize,
    minute: u64,
    counts: HashMap<IpAddr, u32>,
}

/// The number of whole minutes since 1970, which goes up by 1 each minute.
pub fn current_minute() -> u64 {
    unix_seconds(SystemTime::now()) / 60
}

impl RateLimit {
    pub fn new(max_per_minute: u32, max_tracked: usize) -> RateLimit {
        RateLimit {
            max_per_minute,
            max_tracked,
            minute: 0,
            counts: HashMap::new(),
        }
    }

    /// EXERCISE 5: when a new minute starts, forget the counts from the last one.
    ///
    /// If `minute` isn't `self.minute`, clear the counts and store the new minute.
    ///
    /// The new idea is `.clear()`, which empties a `HashMap` all at once, like `map.clear()`
    /// in JS or `counts.clear()` in Python.
    pub fn start_minute(&mut self, minute: u64) {
        if minute != self.minute {
            self.counts.clear();
            self.minute = minute;
        }
    }

    /// EXERCISE 6: count a visit, and return whether it's allowed.
    ///
    /// Your caps in Stage 4 limit how many connections are open at once. A visit that
    /// connects and leaves right away slips past those, however fast it repeats. This
    /// limits how many start each minute.
    ///
    /// Do these in order:
    /// 1. Call `self.start_minute(minute)`.
    /// 2. Look up this address's count, as you did in `count_for`.
    /// 3. Return `false` if the count has reached `self.max_per_minute`.
    /// 4. Return `false` if the count is 0 and `self.counts.len()` has reached
    ///    `self.max_tracked`. That's a new address with no room left to track it.
    /// 5. Otherwise, store the count plus 1 and return `true`.
    ///
    /// The new idea is the kind of limit. This is a *fixed window*: the count starts again
    /// each minute. It's simple, and it's good enough here, because someone can get at
    /// most two minutes' worth through around the moment the minute changes.
    pub fn allow(&mut self, ip: IpAddr, minute: u64) -> bool {
        self.start_minute(minute);
        let count = self.counts.get(&ip).cloned().unwrap_or(0);
        if count >= self.max_per_minute {
            return false;
        }
        if count == 0 && self.counts.len() >= self.max_tracked {
            return false;
        }
        self.counts.insert(ip, count + 1);
        true
    }
}

// ---------------------------------------------------------------------------
// Checking the code itself
// ---------------------------------------------------------------------------

/// EXERCISE 7: cut the test code off the end of a source file.
///
/// Tests are allowed to connect to localhost, because they play the visitor. Only the
/// real program has to follow the rule against connecting out.
///
/// Return everything before `TEST_MARKER`, or the whole file if it doesn't contain one.
///
/// The new idea is slicing text. `source.find(TEST_MARKER)` gives you an `Option` holding
/// a position, where JS's `indexOf` gives you `-1`. Then `&source[..position]` is like
/// `source[:position]` in Python, and no text gets copied.
pub fn code_only(source: &str) -> &str {
    if let Some(position) = source.find(TEST_MARKER) {
        &source[..position]
    } else {
        source
    }
}

/// EXERCISE 8: list the lines of code that use anything in the `forbidden` list.
///
/// Skip comment lines, which are allowed to talk about anything. Trim each line you
/// return, and return a line only once, even if it matches two entries.
///
/// The new idea is `.any(...)`, which is `list.some(...)` in JS or `any(...)` in Python:
///
/// ```text
/// forbidden.iter().any(|word| line.contains(word))
/// ```
///
/// Hints:
/// - `for line in code.lines()` goes through the text a line at a time.
/// - `line.trim_start().starts_with("//")` spots a comment line, and `continue` skips it.
/// - Build the list with `Vec::new()` and `.push(...)`, as `dated_log_files` does.
pub fn forbidden_uses(code: &str, forbidden: &[&str]) -> Vec<String> {
    let mut violations = Vec::new();
    for line in code.lines() {
        let trimmed_line = line.trim();
        if trimmed_line.starts_with("//") {
            continue;
        }
        if forbidden.iter().any(|word| trimmed_line.contains(word)) {
            violations.push(trimmed_line.to_string());
        }
    }
    violations
}

/// EXERCISE 9: check every file in a folder, and list everything that breaks the rules.
///
/// This is what makes the safety rules run on every `cargo test`. It catches accidents,
/// not someone determined to hide something, and it can't see inside your crates. That's
/// why Stage 6 also has `cargo audit`.
///
/// The new idea is adding a whole list to another with `.extend(...)`, like `push(...list)`
/// in JS or `extend` in Python.
///
/// Hints:
/// - `fs::read_dir(dir)?` loops over the folder, as in `dated_log_files`. Each entry is a
///   `Result`, so write `let entry = entry?;`.
/// - `fs::read_to_string(entry.path())?` reads a file. If someone adds a subfolder, this
///   fails, and the test failing is the right result. It means this check needs updating.
/// - Use your `code_only` and `forbidden_uses`.
pub fn violations_in_folder(dir: &Path, forbidden: &[&str]) -> io::Result<Vec<String>> {
    let mut violations = Vec::new();
    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        if path.is_file() {
            let code = fs::read_to_string(&path)?;
            let code_without_tests = code_only(&code);
            let file_violations = forbidden_uses(code_without_tests, forbidden);
            violations.extend(file_violations);
        }
    }
    Ok(violations)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------
//
// You don't need to change anything below, but do read the tests: they show exactly
// how your code is going to be used.
//
// These tests only check whether an address would be allowed. The only place they ever
// listen is on localhost, and logs are made up and go in throwaway folders.

#[cfg(test)]
mod tests {
    use super::*;
    use crate::log_files::{DailyLog, today};
    use crate::server::{Limits, Shared, serve_next};
    use std::env;
    use std::fs::DirBuilder;
    use std::io::{Read, Write};
    use std::net::{Ipv4Addr, TcpStream};
    use std::os::unix::fs::DirBuilderExt;
    use std::path::PathBuf;
    use std::time::Duration;

    // What the real program must never use. `unsafe` isn't here, because
    // `#![forbid(unsafe_code)]` makes the compiler itself refuse it. Stage 7 added the name
    // lookups and web clients, because a fake shell full of URLs mustn't get anywhere near one.
    const FORBIDDEN: &[&str] = &[
        "std::process",
        "process::Command",
        "TcpStream::connect",
        ".connect(",
        "UdpSocket",
        "extern \"C\"",
        "ToSocketAddrs",
        "to_socket_addrs",
        "reqwest::",
        "ureq::",
        "hyper::",
        "curl::",
    ];

    // Documentation addresses. They're reserved, and they don't belong to anyone.
    const IP_A: IpAddr = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 1));
    const IP_B: IpAddr = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 2));
    const REPLY: &str = "login: Password: Login incorrect\r\n";

    // A folder that belongs to one test, deleted when the test ends, as in Stage 3.
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

        fn write(&self, name: &str, text: &str) {
            fs::write(self.path.join(name), text).unwrap();
        }
    }

    impl Drop for TestDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.path);
        }
    }

    fn address(text: &str) -> SocketAddr {
        text.parse().unwrap()
    }

    fn args(text: &str) -> Vec<String> {
        text.split_whitespace().map(|arg| arg.to_string()).collect()
    }

    fn shared_with_rate_limit(dir: &TestDir, per_minute: u32) -> Shared {
        let log = DailyLog::open(&dir.path, today()).unwrap();
        let limits = Limits::new(10, 10);
        Shared::new(log, limits, 1_000_000, Duration::from_secs(5))
            .unwrap()
            .with_rate_limit(RateLimit::new(per_minute, 100))
    }

    // Connects to the listener as a visitor, types a login, and returns the reply.
    fn visit_and_get_reply(listener: &TcpListener, shared: &Shared) -> String {
        let mut visitor = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        visitor
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        visitor.write_all(b"admin\n1234\n").unwrap();
        serve_next(listener, shared).unwrap();

        let mut reply = Vec::new();
        let _ = visitor.read_to_end(&mut reply);
        String::from_utf8_lossy(&reply).to_string()
    }

    fn log_contents(dir: &TestDir) -> String {
        let name = format!("visits-{}.jsonl", today());
        fs::read_to_string(dir.path.join(name)).unwrap()
    }

    #[test]
    fn ex1_reads_an_address() {
        let parsed = parse_listen_address("127.0.0.1:2323").unwrap();
        assert_eq!(parsed, address("127.0.0.1:2323"));
    }

    #[test]
    fn ex1_bad_text_is_an_error_that_names_it() {
        for text in ["", "2323", "127.0.0.1", "not an address", "127.0.0.1:99999"] {
            let error = parse_listen_address(text).unwrap_err();
            assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
            assert!(error.to_string().contains(text), "{text}");
        }
    }

    #[test]
    fn ex1_never_looks_up_a_name() {
        assert!(parse_listen_address("localhost:2323").is_err());
        assert!(parse_listen_address("example.com:2323").is_err());
    }

    #[test]
    fn ex2_loopback_needs_no_flag() {
        assert!(check_address(address("127.0.0.1:2323"), false).is_ok());
        assert!(check_address(address("127.0.0.2:2323"), false).is_ok());
    }

    #[test]
    fn ex2_anything_public_needs_the_flag() {
        for text in ["0.0.0.0:2323", "203.0.113.1:2323", "192.168.1.5:2323"] {
            assert!(check_address(address(text), false).is_err(), "{text}");
        }
    }

    #[test]
    fn ex2_the_flag_allows_a_public_address() {
        assert!(check_address(address("0.0.0.0:2323"), true).is_ok());
    }

    #[test]
    fn ex2_ipv6_is_always_refused() {
        for text in ["[::1]:2323", "[::]:2323", "[2001:db8::1]:2323"] {
            assert!(check_address(address(text), true).is_err(), "{text}");
        }
    }

    #[test]
    fn ex3_no_settings_means_localhost() {
        let settings = Settings::from_args(&args("")).unwrap();
        assert_eq!(settings.listen, address(DEFAULT_LISTEN));
        assert!(settings.listen.ip().is_loopback());
    }

    #[test]
    fn ex3_reads_the_listen_address() {
        let settings = Settings::from_args(&args("--listen 127.0.0.1:9999")).unwrap();
        assert_eq!(settings.listen, address("127.0.0.1:9999"));
    }

    #[test]
    fn ex3_a_public_address_needs_the_flag() {
        assert!(Settings::from_args(&args("--listen 0.0.0.0:2323")).is_err());
    }

    #[test]
    fn ex3_the_flag_can_go_before_or_after_the_address() {
        for text in [
            "--listen 0.0.0.0:2323 --checklist-done",
            "--checklist-done --listen 0.0.0.0:2323",
        ] {
            let settings = Settings::from_args(&args(text)).unwrap();
            assert_eq!(settings.listen, address("0.0.0.0:2323"));
        }
    }

    #[test]
    fn ex3_a_missing_address_is_an_error() {
        assert!(Settings::from_args(&args("--listen")).is_err());
    }

    #[test]
    fn ex3_a_typo_is_an_error() {
        let error = Settings::from_args(&args("--lisen 127.0.0.1:2323")).unwrap_err();
        assert!(error.to_string().contains("--lisen"));
        assert!(Settings::from_args(&args("--checklist-don")).is_err());
    }

    #[test]
    fn ex3_the_listener_only_opens_where_the_settings_say() {
        let settings = Settings::from_args(&args("--listen 127.0.0.1:0")).unwrap();
        let listener = settings.open_listener().unwrap();
        assert!(listener.local_addr().unwrap().ip().is_loopback());
    }

    // Stage 7 added these two. They already pass, and they should never stop passing.
    #[test]
    fn guard_the_fake_shell_is_off_unless_you_ask() {
        for text in ["", "--listen 0.0.0.0:2323 --checklist-done"] {
            assert_eq!(
                Settings::from_args(&args(text)).unwrap().credentials(),
                None
            );
        }
    }

    #[test]
    fn guard_reads_the_file_of_logins() {
        let settings = Settings::from_args(&args("--credentials some/file.txt")).unwrap();
        assert_eq!(settings.credentials(), Some(Path::new("some/file.txt")));
        assert!(Settings::from_args(&args("--credentials")).is_err());
    }

    #[test]
    fn ex4_refuses_root() {
        let error = refuse_root(0).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
    }

    #[test]
    fn ex4_allows_anyone_else() {
        assert!(refuse_root(1000).is_ok());
    }

    #[test]
    fn ex5_keeps_the_counts_in_the_same_minute() {
        let mut limit = RateLimit::new(5, 100);
        limit.minute = 7;
        limit.counts.insert(IP_A, 3);
        limit.start_minute(7);
        assert_eq!(limit.counts.get(&IP_A), Some(&3));
    }

    #[test]
    fn ex5_forgets_the_counts_in_a_new_minute() {
        let mut limit = RateLimit::new(5, 100);
        limit.minute = 7;
        limit.counts.insert(IP_A, 3);
        limit.start_minute(8);
        assert!(limit.counts.is_empty());
        assert_eq!(limit.minute, 8);
    }

    #[test]
    fn ex6_allows_visits_up_to_the_limit_and_no_more() {
        let mut limit = RateLimit::new(2, 100);
        assert!(limit.allow(IP_A, 1));
        assert!(limit.allow(IP_A, 1));
        assert!(!limit.allow(IP_A, 1));
        assert!(!limit.allow(IP_A, 1));
    }

    #[test]
    fn ex6_counts_each_address_separately() {
        let mut limit = RateLimit::new(1, 100);
        assert!(limit.allow(IP_A, 1));
        assert!(!limit.allow(IP_A, 1));
        assert!(limit.allow(IP_B, 1));
    }

    #[test]
    fn ex6_a_new_minute_starts_again() {
        let mut limit = RateLimit::new(1, 100);
        assert!(limit.allow(IP_A, 1));
        assert!(!limit.allow(IP_A, 1));
        assert!(limit.allow(IP_A, 2));
    }

    #[test]
    fn ex6_memory_use_has_a_limit() {
        let mut limit = RateLimit::new(5, 1);
        assert!(limit.allow(IP_A, 1));
        assert!(!limit.allow(IP_B, 1));
        assert_eq!(limit.counts.len(), 1);
    }

    #[test]
    fn ex6_an_address_already_tracked_still_gets_in_when_memory_is_full() {
        let mut limit = RateLimit::new(5, 1);
        assert!(limit.allow(IP_A, 1));
        assert!(limit.allow(IP_A, 1));
    }

    #[test]
    fn ex6_the_server_serves_a_visit_under_the_limit() {
        // This checks the limit on its own first, so a mistake shows up here.
        assert!(RateLimit::new(1, 100).allow(IP_A, 1));

        let dir = TestDir::new("ex6-under");
        let shared = shared_with_rate_limit(&dir, 100);
        let listener = Settings::from_args(&args("--listen 127.0.0.1:0"))
            .unwrap()
            .open_listener()
            .unwrap();

        assert_eq!(visit_and_get_reply(&listener, &shared), REPLY);
        assert_eq!(log_contents(&dir).lines().count(), 1);
    }

    #[test]
    fn ex6_the_server_turns_away_a_visit_over_the_limit() {
        assert!(!RateLimit::new(0, 100).allow(IP_A, 1));

        let dir = TestDir::new("ex6-over");
        let shared = shared_with_rate_limit(&dir, 0);
        let listener = Settings::from_args(&args("--listen 127.0.0.1:0"))
            .unwrap()
            .open_listener()
            .unwrap();

        assert_eq!(visit_and_get_reply(&listener, &shared), "");
        assert_eq!(log_contents(&dir), "");
    }

    #[test]
    fn ex7_cuts_off_the_test_code() {
        let source = "real code\n\n#[cfg(test)]\nmod tests {}\n";
        assert_eq!(code_only(source), "real code\n");
    }

    #[test]
    fn ex7_keeps_a_file_with_no_tests() {
        assert_eq!(code_only("real code\n"), "real code\n");
    }

    #[test]
    fn ex7_a_mention_of_the_marker_does_not_count() {
        let source = "// #[cfg(test)] means a test module\nreal code\n";
        assert_eq!(code_only(source), source);
    }

    #[test]
    fn ex8_finds_a_forbidden_line_and_trims_it() {
        let code = "fine\n    let s = TcpStream::connect(a);\nfine too\n";
        assert_eq!(
            forbidden_uses(code, FORBIDDEN),
            ["let s = TcpStream::connect(a);"]
        );
    }

    #[test]
    fn ex8_returns_nothing_for_clean_code() {
        assert!(forbidden_uses("fine\nfine too\n", FORBIDDEN).is_empty());
    }

    #[test]
    fn ex8_comments_may_mention_anything() {
        let code = "// never use UdpSocket\n    /// or std::process\nfine\n";
        assert!(forbidden_uses(code, FORBIDDEN).is_empty());
    }

    #[test]
    fn ex8_returns_a_line_only_once() {
        let code = "use std::process; let x = TcpStream::connect(a);\n";
        assert_eq!(forbidden_uses(code, FORBIDDEN).len(), 1);
    }

    #[test]
    fn ex9_checks_every_file_in_the_folder() {
        let dir = TestDir::new("ex9-every-file");
        dir.write("one.rs", "use std::process;\n");
        dir.write("two.rs", "let socket = UdpSocket::bind(a);\n");
        dir.write("three.rs", "fine\n");
        let found = violations_in_folder(&dir.path, FORBIDDEN).unwrap();
        assert_eq!(found.len(), 2);
    }

    #[test]
    fn ex9_ignores_test_code() {
        let dir = TestDir::new("ex9-tests");
        dir.write(
            "one.rs",
            "fine\n\n#[cfg(test)]\nmod tests { let s = TcpStream::connect(a); }\n",
        );
        assert!(
            violations_in_folder(&dir.path, FORBIDDEN)
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn ex9_a_missing_folder_is_an_error() {
        let dir = TestDir::new("ex9-missing");
        let missing = dir.path.join("not-there");
        assert!(violations_in_folder(&missing, FORBIDDEN).is_err());
    }

    // This one is the point of the stage. From now on it runs on every `cargo test`.
    #[test]
    fn ex9_the_real_program_follows_the_safety_rules() {
        let found = violations_in_folder(Path::new("src"), FORBIDDEN).unwrap();
        assert!(found.is_empty(), "these lines break the rules: {found:#?}");

        for file in ["src/lib.rs", "src/main.rs"] {
            let source = fs::read_to_string(file).unwrap();
            assert!(source.contains("#![forbid(unsafe_code)]"), "{file}");
        }
    }
}
