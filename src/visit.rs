//! # Stage 2: Structured logs
//!
//! In Stage 1 you logged plain text, and only when a login finished. Here you build
//! a `Visit`: one line of JSON for every connection, whatever happened. That includes
//! visitors who connect and leave without typing, which Stage 1 missed.
//!
//! A log line looks like this, with `time` in seconds since 1970:
//!
//! ```text
//! {"time":1761935000,"source_ip":"127.0.0.1","outcome":"left","username":null,"password":null}
//! ```
//!
//! Do the exercises in order, replacing each `todo!()`. Stage 1 also has tests named
//! `ex1`, `ex2` and so on, so add `visit::tests::` to run just this stage's test:
//! `cargo test visit::tests::ex1`. Run all of Stage 2 with `cargo test visit`.
//!
//! `cargo run` crashes with "not yet implemented" until you've finished this stage,
//! because `main.rs` now uses this file.

// While the exercises are full of `todo!()`, the function arguments and some imports
// aren't used, and the compiler warns about it. This line silences those warnings.
// Delete this comment and the line below once you've finished the stage.
#![allow(unused_variables, unused_imports)]

use std::io::{self, BufRead, BufReader, Write};
use std::net::{IpAddr, TcpListener, TcpStream};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

// `serde` and `serde_json` are your first crates, which are packages from crates.io.
// They were added with `cargo add serde --features derive` and `cargo add serde_json`,
// which is like `npm install` or `pip install`. You can see them in Cargo.toml.
use serde::Serialize;

use crate::fake_shell::ShellSession;
use crate::fake_web::HttpRequest;
use crate::login::{
    LOGIN_PROMPT, PASSWORD_PROMPT, REJECTION, ask, escape_for_log, strip_line_ending,
};

// ---------------------------------------------------------------------------
// Outcome and Visit
// ---------------------------------------------------------------------------

/// How a visit ended.
///
/// `Serialize` in the derive line comes from `serde`. JS and Python can look inside
/// any object while the program runs to build JSON. Rust can't, so `derive` writes
/// that code when you compile.
///
/// `rename_all` makes `TimedOut` appear as `"timed_out"` in the JSON.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Outcome {
    /// They answered both prompts.
    Attempted,
    /// They disconnected before answering both prompts.
    Left,
    /// They stayed connected but went quiet until the timeout.
    TimedOut,
    /// They typed a login from the list and got the fake shell from Stage 7. How the session
    /// ended is in the visit's `shell`.
    LoggedIn,
    /// They sent a whole request to one of the other fake services: a web request from Stage 8,
    /// or an SSH version line from Stage 10. What they sent is in `http` or `client_banner`.
    Requested,
}

/// One connection to the honeypot, and what we learned from it.
///
/// `username` and `password` are `Option`s because someone might never answer. In
/// JSON, `None` becomes `null`, so "never answered" looks different from "pressed
/// Enter", which is an empty string.
///
/// `source_ip` is an `IpAddr` rather than a `String`, so it can only ever hold a real
/// IP address. `serde` writes it to JSON as text like `"127.0.0.1"`.
///
/// `pub(crate)` means other files in this library can use these fields, but `main.rs`
/// can't. Stage 3 needs them to decide what's safe to show on screen.
///
/// `telnet` and `shell` come from Stage 7. `telnet` is any negotiation the visitor sent, as hex, on
/// a server with the fake shell on, and `shell` is only there for visits that got in.
/// `skip_serializing_if` leaves them out of the JSON otherwise, so those lines look as they always
/// did.
///
/// `service`, `http` and `client_banner` come from Stages 8 and 10. `service` names the fake
/// service a visit came to, like `"http"` or `"ftp"`, and it's left out for the telnet login, so
/// those lines still look as they always did. `http` is the web request from Stage 8, and
/// `client_banner` is the first line an SSH client sent in Stage 10.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Visit {
    pub(crate) time: u64,
    pub(crate) source_ip: IpAddr,
    pub(crate) outcome: Outcome,
    pub(crate) username: Option<String>,
    pub(crate) password: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) telnet: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) shell: Option<ShellSession>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) service: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) http: Option<HttpRequest>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) client_banner: Option<String>,
}

// ---------------------------------------------------------------------------
// The pieces of a visit
// ---------------------------------------------------------------------------

/// EXERCISE 1: turn a point in time into seconds since 1970.
///
/// This is the same number as `Date.now() / 1000` in JS or `time.time()` in Python.
///
/// The new idea is handling a `Result` yourself instead of passing it on with `?`.
/// `time.duration_since(UNIX_EPOCH)` gives an `Err` if the time is before 1970. That
/// only happens if the clock is badly wrong, and a wrong clock shouldn't stop the
/// honeypot, so use 0 in that case.
///
/// Hints:
/// - `match` works on a `Result` like it does on an `Option`. The arms are `Ok(value)`
///   and `Err(_)`.
/// - `.as_secs()` turns the `Duration` inside the `Ok` into a `u64`.
pub fn unix_seconds(time: SystemTime) -> u64 {
    match time.duration_since(UNIX_EPOCH) {
        Ok(duration) => duration.as_secs(),
        Err(_) => 0,
    }
}

/// EXERCISE 2: turn what `ask` returned into an answer, or no answer.
///
/// The new idea is telling two kinds of "empty" apart:
/// - `""` has no bytes at all, which means the connection closed. That's no answer,
///   so return `None`.
/// - `"\n"` means they pressed Enter. That's an answer that happens to be empty, so
///   return `Some` holding an empty string.
///
/// Clean up any answer the same way as in Stage 1.
///
/// Hints:
/// - `.is_empty()` checks for `""`.
/// - `strip_line_ending` and `escape_for_log` are already imported from Stage 1.
pub fn clean_answer(raw: &str) -> Option<String> {
    if raw.is_empty() {
        None
    } else {
        Some(escape_for_log(strip_line_ending(raw)))
    }
}

impl Visit {
    /// EXERCISE 3: start a new visit, at the moment someone connects.
    ///
    /// The new idea is storing what you don't know yet. Nobody has answered, so both
    /// answers start as `None`. It's like starting a JS object with `null` fields.
    /// The outcome starts as `Outcome::Left`, and we assume they left until we learn
    /// otherwise.
    ///
    /// Hint: use `unix_seconds` for the time.
    pub fn new(now: SystemTime, source_ip: IpAddr) -> Visit {
        Visit {
            time: unix_seconds(now),
            source_ip,
            username: None,
            password: None,
            outcome: Outcome::Left,
            telnet: None,
            shell: None,
            service: None,
            http: None,
            client_banner: None,
        }
    }

    /// EXERCISE 4: turn a visit into one line of JSON.
    ///
    /// This is `JSON.stringify(visit)` in JS or `json.dumps(visit)` in Python. The new
    /// idea is calling a crate: here it's `serde_json::to_string(...)`.
    ///
    /// JSON escapes quotes and newlines, which keeps the file format safe. We keep
    /// Stage 1's escaping as well, because `jq -r` undoes JSON's escaping and would
    /// otherwise print real escape codes to your terminal.
    ///
    /// Hint: `self` is already a reference, which is what `to_string` wants. It also
    /// returns the right type, so it can be the whole function body.
    pub fn to_json_line(&self) -> serde_json::Result<String> {
        serde_json::to_string(self)
    }
}

/// EXERCISE 5: write a visit to the log, as one line.
///
/// The new idea is that `?` can convert errors. `to_json_line` fails with a
/// `serde_json::Error`, but this function returns an `io::Result`. `?` converts one
/// into the other, because `serde_json` tells Rust how.
///
/// One JSON object per line is called JSON Lines. You can add to the end of the file
/// without rewriting it, and one damaged line can't ruin the rest.
///
/// Hint: this is nearly the same as `append_to_log` from Stage 1.
pub fn append_visit(log: &mut impl Write, visit: &Visit) -> io::Result<()> {
    writeln!(log, "{}", visit.to_json_line()?)
}

/// EXERCISE 6: work out what a connection error means.
///
/// - A timeout means they stayed connected but went quiet: `Outcome::TimedOut`.
/// - Any other error means the connection broke, so they've gone: `Outcome::Left`.
///
/// The new idea is matching several values in one arm, like `except (A, B):` in
/// Python. A timeout shows up as `io::ErrorKind::WouldBlock` on Linux and
/// `io::ErrorKind::TimedOut` on some other systems, so treat both as timeouts.
///
/// Hints:
/// - `error.kind()` gives you something to `match` on.
/// - Join values with `|`, as in `A | B => ...`.
pub fn outcome_of_error(error: &io::Error) -> Outcome {
    match error.kind() {
        io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut => Outcome::TimedOut,
        _ => Outcome::Left,
    }
}

// ---------------------------------------------------------------------------
// Running a visit
// ---------------------------------------------------------------------------

impl Visit {
    /// EXERCISE 7: run the fake login, saving each answer as soon as you have it.
    ///
    /// The new idea is that `&mut self` keeps your progress. Stage 1's `fake_login`
    /// only returned a result if everything worked, so if the password step failed,
    /// `?` threw the username away. Here each answer goes straight into `self`, so
    /// it's still there after `?` leaves early.
    ///
    /// Do these in order:
    /// 1. `ask` with `LOGIN_PROMPT`, and store the `clean_answer` in `self.username`.
    /// 2. `ask` with `PASSWORD_PROMPT`, and store the `clean_answer` in `self.password`.
    /// 3. Send `REJECTION` and flush, as `ask` does with its prompt.
    ///
    /// Hint: `ask` returns a `String`, and `clean_answer` wants a `&str`, so put `&` in
    /// front of the call to `ask`.
    pub fn ask_for_answers(
        &mut self,
        reader: &mut impl BufRead,
        writer: &mut impl Write,
    ) -> io::Result<()> {
        let username = ask(LOGIN_PROMPT, reader, writer)?;
        self.username = clean_answer(&username);

        let password = ask(PASSWORD_PROMPT, reader, writer)?;
        self.password = clean_answer(&password);

        writer.write_all(REJECTION.as_bytes())?;
        writer.flush()?;

        Ok(())
    }

    /// EXERCISE 8: run the fake login and work out how the visit ended.
    ///
    /// This returns nothing, on purpose: whatever goes wrong, you still have a `Visit`
    /// to log.
    ///
    /// The new idea is `if let`, a shortcut for a `match` when you only care about one
    /// case:
    ///
    /// ```text
    /// if let Err(error) = something_that_can_fail() {
    ///     // it failed, and you can use `error` here
    /// }
    /// ```
    ///
    /// Do these in order:
    /// 1. Call `ask_for_answers` that way. If it failed, set `self.outcome` using
    ///    `outcome_of_error`.
    /// 2. Then, if `self.password.is_some()`, set the outcome to `Outcome::Attempted`.
    ///    Check this last, because someone who hangs up before seeing the rejection
    ///    still made an attempt.
    pub fn run_fake_login(&mut self, reader: &mut impl BufRead, writer: &mut impl Write) {
        if let Err(error) = self.ask_for_answers(reader, writer) {
            self.outcome = outcome_of_error(&error);
        }
        if self.password.is_some() {
            self.outcome = Outcome::Attempted;
        }
    }
}

// This is a worked example, not an exercise. It connects a visit to a real connection,
// like `login_over_connection` did in Stage 1. If the timeouts can't be set, a silent
// visitor could block the program forever, so we stop right there and still have a
// visit to log.
pub fn run_over_connection(visit: &mut Visit, stream: &TcpStream, timeout: Duration) {
    if let Err(error) = set_timeouts(stream, timeout) {
        visit.outcome = outcome_of_error(&error);
        return;
    }
    let mut reader = BufReader::new(stream);
    let mut writer = stream;
    visit.run_fake_login(&mut reader, &mut writer);
}

fn set_timeouts(stream: &TcpStream, timeout: Duration) -> io::Result<()> {
    stream.set_read_timeout(Some(timeout))?;
    stream.set_write_timeout(Some(timeout))
}

/// EXERCISE 9: wait for one connection and record the visit, whatever happens.
///
/// This is the fix for visitors who leave without typing. Stage 1's `serve_one` used
/// `?` on the login, so a failed login skipped the log. The new idea is that once a
/// connection is accepted, nothing between it and the log can leave early.
///
/// Do these in order:
/// 1. `listener.accept()`, with `?`. This time you need the address, so call it `peer`.
/// 2. Make a `Visit` using `SystemTime::now()` and `peer.ip()`.
/// 3. Call `run_over_connection`.
/// 4. Call `append_visit`, with `?`, and return the visit.
pub fn serve_and_record(
    listener: &TcpListener,
    log: &mut impl Write,
    timeout: Duration,
) -> io::Result<Visit> {
    let (stream, peer) = listener.accept()?;
    let mut visit = Visit::new(SystemTime::now(), peer.ip());
    run_over_connection(&mut visit, &stream, timeout);
    append_visit(log, &visit)?;
    Ok(visit)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------
//
// You don't need to change anything below, but do read the tests: they show exactly
// how your code is going to be used. This module is inside this file, so it's allowed
// to look at private fields like `visit.outcome`.

#[cfg(test)]
mod tests {
    use super::*;
    use crate::login::listen_on_localhost;
    use std::io::Read;
    use std::net::{Ipv4Addr, Shutdown};

    const LOCALHOST: IpAddr = IpAddr::V4(Ipv4Addr::LOCALHOST);

    // Long enough to work on a busy computer, and short enough not to slow the tests.
    const SHORT_TIMEOUT: Duration = Duration::from_millis(100);

    fn blank_visit() -> Visit {
        Visit {
            time: 1000,
            source_ip: LOCALHOST,
            outcome: Outcome::Left,
            username: None,
            password: None,
            telnet: None,
            shell: None,
            service: None,
            http: None,
            client_banner: None,
        }
    }

    fn answer(text: &str) -> Option<String> {
        Some(text.to_string())
    }

    // Turns the bytes the program wrote into text, so they're easy to compare.
    fn as_text(bytes: &[u8]) -> String {
        String::from_utf8_lossy(bytes).to_string()
    }

    // Reads the one line in `log` as JSON, so tests can check its fields.
    fn parse_log_line(log: &[u8]) -> serde_json::Value {
        serde_json::from_str(&as_text(log)).unwrap()
    }

    // A pretend visitor who has gone quiet. Reading from them reports a timeout right
    // away, so the test doesn't have to wait for a real one.
    struct GoesQuiet;

    impl Read for GoesQuiet {
        fn read(&mut self, _buffer: &mut [u8]) -> io::Result<usize> {
            Err(io::ErrorKind::WouldBlock.into())
        }
    }

    // A pretend connection that accepts a few writes, then acts as if the visitor hung
    // up.
    struct HangsUpAfter {
        writes_left: u32,
    }

    impl Write for HangsUpAfter {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            if self.writes_left == 0 {
                return Err(io::ErrorKind::BrokenPipe.into());
            }
            self.writes_left -= 1;
            Ok(bytes.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    // A real connection to the listener, playing the visitor. The server hasn't
    // accepted it yet, but the computer holds it ready, and holds anything it sends.
    fn visitor_connected_to(listener: &TcpListener) -> TcpStream {
        let visitor = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        visitor
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        visitor
    }

    #[test]
    fn ex1_counts_seconds_since_1970() {
        let time = UNIX_EPOCH + Duration::from_secs(1000);
        assert_eq!(unix_seconds(time), 1000);
    }

    #[test]
    fn ex1_a_clock_before_1970_gives_zero() {
        let time = UNIX_EPOCH - Duration::from_secs(5);
        assert_eq!(unix_seconds(time), 0);
    }

    #[test]
    fn ex2_no_bytes_means_no_answer() {
        assert_eq!(clean_answer(""), None);
    }

    #[test]
    fn ex2_pressing_enter_is_an_empty_answer() {
        assert_eq!(clean_answer("\n"), answer(""));
    }

    #[test]
    fn ex2_strips_the_line_ending() {
        assert_eq!(clean_answer("admin\r\n"), answer("admin"));
    }

    #[test]
    fn ex2_escapes_hostile_text() {
        assert_eq!(clean_answer("\u{1b}[2J\n"), answer(r"\u{1b}[2J"));
    }

    #[test]
    fn ex3_a_new_visit_starts_with_no_answers() {
        let now = UNIX_EPOCH + Duration::from_secs(1000);
        assert_eq!(Visit::new(now, LOCALHOST), blank_visit());
    }

    #[test]
    fn ex4_writes_null_for_missing_answers() {
        let line = blank_visit().to_json_line().unwrap();
        assert_eq!(
            line,
            r#"{"time":1000,"source_ip":"127.0.0.1","outcome":"left","username":null,"password":null}"#
        );
    }

    #[test]
    fn ex4_writes_the_answers() {
        let mut visit = blank_visit();
        visit.outcome = Outcome::Attempted;
        visit.username = answer("admin");
        visit.password = answer("1234");
        assert_eq!(
            visit.to_json_line().unwrap(),
            r#"{"time":1000,"source_ip":"127.0.0.1","outcome":"attempted","username":"admin","password":"1234"}"#
        );
    }

    #[test]
    fn ex4_a_quote_cannot_break_out_of_a_field() {
        let hostile = r#"x","outcome":"attempted"#;
        let mut visit = blank_visit();
        visit.username = answer(hostile);
        let parsed = parse_log_line(visit.to_json_line().unwrap().as_bytes());
        assert_eq!(parsed["outcome"], "left");
        assert_eq!(parsed["username"], hostile);
    }

    #[test]
    fn ex5_writes_one_line() {
        let mut log = Vec::new();
        append_visit(&mut log, &blank_visit()).unwrap();
        assert_eq!(
            as_text(&log),
            "{\"time\":1000,\"source_ip\":\"127.0.0.1\",\"outcome\":\"left\",\"username\":null,\"password\":null}\n"
        );
    }

    #[test]
    fn ex5_keeps_earlier_lines() {
        let mut log = Vec::new();
        append_visit(&mut log, &blank_visit()).unwrap();
        append_visit(&mut log, &blank_visit()).unwrap();
        assert_eq!(as_text(&log).lines().count(), 2);
    }

    #[test]
    fn ex5_hostile_text_stays_on_one_line() {
        let mut visit = blank_visit();
        visit.username = clean_answer("root\nfake line\u{1b}[2J\n");
        let mut log = Vec::new();
        append_visit(&mut log, &visit).unwrap();
        assert_eq!(as_text(&log).lines().count(), 1);
        assert!(!as_text(&log).contains('\u{1b}'));
    }

    #[test]
    fn ex6_a_timeout_means_timed_out() {
        for kind in [io::ErrorKind::WouldBlock, io::ErrorKind::TimedOut] {
            assert_eq!(outcome_of_error(&kind.into()), Outcome::TimedOut);
        }
    }

    #[test]
    fn ex6_anything_else_means_they_left() {
        for kind in [io::ErrorKind::ConnectionReset, io::ErrorKind::BrokenPipe] {
            assert_eq!(outcome_of_error(&kind.into()), Outcome::Left);
        }
    }

    #[test]
    fn ex7_saves_both_answers() {
        let mut visit = blank_visit();
        let mut typed = "admin\n1234\n".as_bytes();
        let mut sent = Vec::new();
        visit.ask_for_answers(&mut typed, &mut sent).unwrap();
        assert_eq!(visit.username, answer("admin"));
        assert_eq!(visit.password, answer("1234"));
        assert_eq!(as_text(&sent), "login: Password: Login incorrect\r\n");
    }

    #[test]
    fn ex7_keeps_the_username_if_the_password_step_fails() {
        let mut visit = blank_visit();
        let mut typed = BufReader::new("admin\n".as_bytes().chain(GoesQuiet));
        let mut sent = Vec::new();
        assert!(visit.ask_for_answers(&mut typed, &mut sent).is_err());
        assert_eq!(visit.username, answer("admin"));
        assert_eq!(visit.password, None);
    }

    #[test]
    fn ex8_answering_both_prompts_is_an_attempt() {
        let mut visit = blank_visit();
        let mut typed = "admin\n1234\n".as_bytes();
        visit.run_fake_login(&mut typed, &mut Vec::new());
        assert_eq!(visit.outcome, Outcome::Attempted);
    }

    #[test]
    fn ex8_leaving_without_typing_is_left() {
        let mut visit = blank_visit();
        let mut typed = "".as_bytes();
        visit.run_fake_login(&mut typed, &mut Vec::new());
        assert_eq!(visit.outcome, Outcome::Left);
        assert_eq!(visit.username, None);
        assert_eq!(visit.password, None);
    }

    #[test]
    fn ex8_answering_only_the_username_is_left() {
        let mut visit = blank_visit();
        let mut typed = "admin\n".as_bytes();
        visit.run_fake_login(&mut typed, &mut Vec::new());
        assert_eq!(visit.outcome, Outcome::Left);
        assert_eq!(visit.username, answer("admin"));
    }

    #[test]
    fn ex8_going_quiet_is_timed_out() {
        let mut visit = blank_visit();
        let mut typed = BufReader::new("admin\n".as_bytes().chain(GoesQuiet));
        visit.run_fake_login(&mut typed, &mut Vec::new());
        assert_eq!(visit.outcome, Outcome::TimedOut);
        assert_eq!(visit.username, answer("admin"));
    }

    #[test]
    fn ex8_hanging_up_before_the_rejection_is_still_an_attempt() {
        let mut visit = blank_visit();
        let mut typed = "admin\n1234\n".as_bytes();
        let mut connection = HangsUpAfter { writes_left: 2 };
        visit.run_fake_login(&mut typed, &mut connection);
        assert_eq!(visit.outcome, Outcome::Attempted);
    }

    #[test]
    fn ex9_logs_someone_who_connects_and_leaves() {
        let listener = listen_on_localhost(0).unwrap();
        drop(visitor_connected_to(&listener));

        let mut log = Vec::new();
        let visit = serve_and_record(&listener, &mut log, SHORT_TIMEOUT).unwrap();

        assert_eq!(visit.outcome, Outcome::Left);
        assert!(visit.time > 0);
        let line = parse_log_line(&log);
        assert_eq!(line["outcome"], "left");
        assert_eq!(line["source_ip"], "127.0.0.1");
        assert!(line["username"].is_null());
        assert!(line["password"].is_null());
    }

    #[test]
    fn ex9_logs_someone_who_stays_silent() {
        let listener = listen_on_localhost(0).unwrap();
        let _visitor = visitor_connected_to(&listener);

        let mut log = Vec::new();
        let visit = serve_and_record(&listener, &mut log, SHORT_TIMEOUT).unwrap();

        assert_eq!(visit.outcome, Outcome::TimedOut);
        assert_eq!(parse_log_line(&log)["outcome"], "timed_out");
    }

    #[test]
    fn ex9_logs_the_username_if_they_leave_before_the_password() {
        let listener = listen_on_localhost(0).unwrap();
        let mut visitor = visitor_connected_to(&listener);
        visitor.write_all(b"admin\n").unwrap();
        // This says "I've finished sending", which is how the server sees them leave.
        visitor.shutdown(Shutdown::Write).unwrap();

        let mut log = Vec::new();
        serve_and_record(&listener, &mut log, SHORT_TIMEOUT).unwrap();

        let line = parse_log_line(&log);
        assert_eq!(line["outcome"], "left");
        assert_eq!(line["username"], "admin");
        assert!(line["password"].is_null());
    }

    #[test]
    fn ex9_logs_a_login_attempt_and_rejects_it() {
        let listener = listen_on_localhost(0).unwrap();
        let mut visitor = visitor_connected_to(&listener);
        visitor.write_all(b"admin\n1234\n").unwrap();

        let mut log = Vec::new();
        serve_and_record(&listener, &mut log, SHORT_TIMEOUT).unwrap();

        let line = parse_log_line(&log);
        assert_eq!(line["outcome"], "attempted");
        assert_eq!(line["username"], "admin");
        assert_eq!(line["password"], "1234");

        let mut reply = String::new();
        visitor.read_to_string(&mut reply).unwrap();
        assert_eq!(reply, "login: Password: Login incorrect\r\n");
    }
}
