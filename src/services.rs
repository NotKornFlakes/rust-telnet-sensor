//! # Stage 10: More fake services
//!
//! Bots don't only knock on telnet and the web. In this stage the honeypot answers two more:
//! - FTP, with a fake login that always says no, like the telnet login before Stage 7
//! - SSH, with only the version banner, which is enough to record what software each client says
//!   it is. There's no key exchange and no login, so nobody gets any further
//!
//! Every service so far has its own code in `src/server.rs`. That doesn't grow well, so here you
//! write a trait, `FakeService`, which says what any fake service has to be able to do. Then one
//! piece of code in `src/server.rs` can run any of them, with the same caps on connections, the
//! same time limit and the same log as the telnet login.
//!
//! The rules haven't changed. Every reply is fixed text built into the program, nothing a visitor
//! sends is ever run, and this file can't read files, start programs or connect to anything. The
//! banners are generic, with no real product's name, which is safety rule 5.
//!
//! Log lines look like this:
//!
//! ```text
//! {"time":1761935000,"source_ip":"203.0.113.7","outcome":"attempted","username":"anonymous","password":"guest","service":"ftp"}
//! {"time":1761935000,"source_ip":"203.0.113.8","outcome":"requested","username":null,"password":null,"service":"ssh","client_banner":"SSH-2.0-Go"}
//! ```
//!
//! Do the exercises in order, replacing each `todo!()`. Run one exercise's tests with
//! `cargo test services::tests::ex1_`. Run all of Stage 10 with `cargo test services`.
//!
//! The tests named `guard_` already pass, and they should never stop passing.
//!
//! `cargo run` still works as it did, because both services stay off unless you pass
//! `--ftp-listen` or `--ssh-listen`. With either flag, it crashes with "not yet implemented" until
//! you've finished this stage.

// While the exercises are full of `todo!()`, some arguments, imports and other code aren't used,
// and the compiler warns about it. This line silences those warnings.
// Delete this comment and the line below once you've finished the stage.
#![allow(dead_code, unused_variables, unused_imports)]

use std::io::{self, BufRead, Write};
use std::net::SocketAddr;
use std::sync::Arc;

use crate::deploy::Settings;
use crate::login::{escape_for_log, read_answer, strip_line_ending};
use crate::visit::{Outcome, Visit, outcome_of_error};

/// The most lines one FTP visitor can send before the connection is closed. A login takes two.
pub const MAX_FTP_COMMANDS: usize = 10;

// ---------------------------------------------------------------------------
// What the services say
// ---------------------------------------------------------------------------

// As in Stages 7 and 8, every word is on this page, and `&'static str` means the compiler won't let
// a visitor's text in. The numbers at the front are FTP's reply codes, which is what clients read.
// A real server would often repeat the username, like `331 Password required for root`. These
// don't, for the same reason the shell doesn't.

/// What FTP says when someone connects.
pub const FTP_BANNER: &str = "220 Service ready.\r\n";
/// The reply to `USER`.
pub const FTP_PASSWORD_PLEASE: &str = "331 Password required.\r\n";
/// The reply to `PASS`. It's always this, so nobody ever logs in.
pub const FTP_LOGIN_INCORRECT: &str = "530 Login incorrect.\r\n";
/// The reply to anything else, since nobody is ever logged in.
pub const FTP_NOT_LOGGED_IN: &str = "530 Please log in with USER and PASS.\r\n";
/// The reply to `QUIT`.
pub const FTP_GOODBYE: &str = "221 Goodbye.\r\n";

/// What SSH says when someone connects, and the only thing it ever says. Real servers put their
/// software's name and version after `SSH-2.0-`, which is how scanners decide what to try.
pub const SSH_BANNER: &str = "SSH-2.0-Server\r\n";

// This is a worked example, not an exercise. It's the only way the FTP service sends anything, and
// like `ShellSession::send` in Stage 7 it only takes text built into the program.
fn reply(writer: &mut dyn Write, text: &'static str) -> io::Result<()> {
    writer.write_all(text.as_bytes())?;
    writer.flush()
}

// This is a worked example too. It's `read_answer` from Stage 1 for a `dyn` reader. `read_answer`
// takes `&mut impl BufRead`, and a `dyn BufRead` on its own has no fixed size, which `impl` needs.
// A *reference* to one does have a size, and it has `BufRead` too, so this hands over a reference
// to the reference.
pub fn read_line(reader: &mut dyn BufRead) -> io::Result<String> {
    let mut reader = reader;
    read_answer(&mut reader)
}

// ---------------------------------------------------------------------------
// The trait
// ---------------------------------------------------------------------------

/// What every fake service can do.
///
/// A trait is a list of methods a type promises to have, like an `interface` in TypeScript or a
/// `Protocol` in Python. You've used plenty already: `Read`, `Write` and `Drop`. This one is yours.
///
/// `Send + Sync` after the name means every fake service can be shared between threads, which the
/// server needs, because each visitor gets their own thread.
///
/// The reader and writer are `&mut dyn BufRead` and `&mut dyn Write`. `dyn` means "some type that
/// has this trait, decided while the program runs". So far you've written `impl BufRead`, where the
/// compiler decides. `dyn` is what lets one list hold different services, in Exercise 6.
pub trait FakeService: Send + Sync {
    /// The name that goes in the log line's `service`, like `"ftp"`.
    fn name(&self) -> &'static str;

    /// What to send as soon as someone connects.
    ///
    /// This one has a body, so a type that implements the trait gets it for free, and can write its
    /// own if it wants something else. A service that waits for the visitor to speak first, like
    /// the web, would leave this as it is.
    fn banner(&self) -> &'static str {
        ""
    }

    /// Talk to one visitor, after the banner. Store what they send in `visit` as soon as you have
    /// it, and set `visit.outcome` once you know it.
    fn converse(
        &self,
        visit: &mut Visit,
        reader: &mut dyn BufRead,
        writer: &mut dyn Write,
    ) -> io::Result<()>;

    /// EXERCISE 5: run one whole visit: the name, the banner and the conversation.
    ///
    /// This is a method with a body, like `banner`, so every service gets it without writing it.
    /// It's `run_fake_login` from Stage 2 again: whatever goes wrong, there's still a visit to log.
    ///
    /// Do these in order:
    /// 1. Set `visit.service` to `Some(self.name())`.
    /// 2. If the banner isn't empty, write it and flush.
    /// 3. Call `self.converse(visit, reader, writer)`.
    /// 4. If step 2 or 3 gave an error, and `visit.outcome` is still `Outcome::Left`, set it with
    ///    `outcome_of_error`. If `converse` already set an outcome, keep it: someone who sent a
    ///    password and then hung up still made an attempt.
    ///
    /// The new idea is calling the trait's other methods through `self`. You don't know which
    /// service this is, and you don't need to. `self.banner()` gives whichever banner it has.
    ///
    /// Hint: putting steps 2 and 3 in a closure that returns `io::Result<()>` lets you use `?`
    /// inside it, then check its result once: `let result = (|| { ...; Ok(()) })();`. A small
    /// private function would work just as well.
    fn run(&self, visit: &mut Visit, reader: &mut dyn BufRead, writer: &mut dyn Write) {
        todo!()
    }
}

// ---------------------------------------------------------------------------
// FTP
// ---------------------------------------------------------------------------

/// One line an FTP client sent.
///
/// This is an enum that holds data, like `IpAddr` in Stage 3, except it's yours. `User` and `Pass`
/// carry what came after the command, and the others carry nothing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FtpRequest {
    User(String),
    Pass(String),
    Quit,
    Other,
}

impl FtpRequest {
    /// EXERCISE 1: work out which request a line is.
    ///
    /// An FTP command is a word, then a space, then whatever it's about:
    ///
    /// ```text
    /// USER anonymous\r\n   →  FtpRequest::User("anonymous")
    /// pass hunter2\r\n     →  FtpRequest::Pass("hunter2")
    /// QUIT\r\n             →  FtpRequest::Quit
    /// SYST\r\n             →  FtpRequest::Other
    /// ```
    ///
    /// The command word doesn't care about case. Strip the line ending with `strip_line_ending`,
    /// and clean what comes after the word with `escape_for_log`, because it's going in the log.
    /// Keep any spaces in it, because a space can be part of a password. `USER` with nothing after
    /// it is a user with an empty name.
    ///
    /// The new idea is building an enum variant that holds data: `FtpRequest::User(name)`.
    ///
    /// Hints:
    /// - `split_once(' ')` gives the word and the rest, or `None` if there's no space. Then the
    ///   whole line is the word, and the rest is empty.
    /// - `word.to_ascii_uppercase()` gives a `String`, and `match word.as_str()` on it lets you
    ///   match `"USER"`, `"PASS"` and `"QUIT"`.
    pub fn parse(line: &str) -> FtpRequest {
        todo!()
    }
}

/// The fake FTP service. It has no fields, because every visit starts the same way. A struct with
/// nothing in it takes no memory, and it's still a type you can implement a trait for.
#[derive(Debug, Clone, Copy, Default)]
pub struct FakeFtp;

/// EXERCISE 2 and EXERCISE 3: make `FakeFtp` a fake service.
///
/// The new idea is `impl FakeService for FakeFtp`, which keeps the trait's promise for this type.
/// The compiler checks that every method without a body is here, and won't build until they are.
impl FakeService for FakeFtp {
    /// EXERCISE 2: give the service its name and banner.
    ///
    /// The name is `"ftp"`, and the banner is `FTP_BANNER`. Writing `banner` here replaces the
    /// trait's empty one. Run these tests with `cargo test services::tests::ex2_`.
    fn name(&self) -> &'static str {
        todo!()
    }

    fn banner(&self) -> &'static str {
        todo!()
    }

    /// EXERCISE 3: run the FTP login, which always says no.
    ///
    /// Read up to `MAX_FTP_COMMANDS` lines with `read_line`, which is `read_answer` from Stage 1.
    /// For each one:
    /// - An empty line means the connection closed, so return `Ok(())`.
    /// - `User(name)`: store it in `visit.username` and reply `FTP_PASSWORD_PLEASE`.
    /// - `Pass(password)`: store it in `visit.password`, set `visit.outcome` to
    ///   `Outcome::Attempted`, reply `FTP_LOGIN_INCORRECT`, and return. One try is all anyone gets,
    ///   like the telnet login.
    /// - `Quit`: reply `FTP_GOODBYE` and return.
    /// - `Other`: reply `FTP_NOT_LOGGED_IN`.
    ///
    /// After the last line you allow, just return, which closes the connection.
    ///
    /// The new idea is matching on your own enum and taking the data out of it:
    ///
    /// ```text
    /// match FtpRequest::parse(&line) {
    ///     FtpRequest::User(name) => ...,
    ///     ...
    /// }
    /// ```
    ///
    /// Hint: `for _ in 0..MAX_FTP_COMMANDS` repeats that many times. `_` says you don't need the
    /// count.
    fn converse(
        &self,
        visit: &mut Visit,
        reader: &mut dyn BufRead,
        writer: &mut dyn Write,
    ) -> io::Result<()> {
        todo!()
    }
}

// ---------------------------------------------------------------------------
// SSH
// ---------------------------------------------------------------------------

/// The fake SSH service. It sends its banner, writes down the client's, and closes.
#[derive(Debug, Clone, Copy, Default)]
pub struct FakeSsh;

impl FakeService for FakeSsh {
    /// EXERCISE 4: make `FakeSsh` a fake service too.
    ///
    /// This is all of Exercises 2 and 3 again, for a simpler service:
    /// - The name is `"ssh"`, and the banner is `SSH_BANNER`.
    /// - `converse` reads one line with `read_line`. If it's empty, return `Ok(())`. Otherwise
    ///   store it in `visit.client_banner`, cleaned as in Stage 1 with
    ///   `escape_for_log(strip_line_ending(...))`, and set `visit.outcome` to `Outcome::Requested`.
    ///
    /// It sends nothing else. After the banners, a real SSH connection goes on to binary messages
    /// that set up encryption, and the honeypot doesn't speak those, so the client gives up there.
    /// That's on purpose: there's nothing past the banner to get into.
    fn name(&self) -> &'static str {
        todo!()
    }

    fn banner(&self) -> &'static str {
        todo!()
    }

    fn converse(
        &self,
        visit: &mut Visit,
        reader: &mut dyn BufRead,
        writer: &mut dyn Write,
    ) -> io::Result<()> {
        todo!()
    }
}

// ---------------------------------------------------------------------------
// Which services are on
// ---------------------------------------------------------------------------

/// EXERCISE 6: list the services the settings turn on, with where each one listens.
///
/// Each service is off unless its address is in the settings: `settings.ftp_listen()` for
/// `FakeFtp` and `settings.ssh_listen()` for `FakeSsh`. Return them in that order. With neither,
/// the list is empty, and the honeypot runs exactly as it did before this stage.
///
/// The new idea is a list of trait objects. A `Vec` holds values of one type, and `FakeFtp` and
/// `FakeSsh` are different types. `Arc<dyn FakeService>` is one type that can hold either, so they
/// fit in one list, and `main.rs` can start them all with the same code. `Arc` rather than `Box`,
/// because every visitor's thread needs a handle on the same service.
///
/// ```text
/// let ftp: Arc<dyn FakeService> = Arc::new(FakeFtp);
/// ```
///
/// Hint: `if let Some(address) = settings.ftp_listen() { services.push((address, Arc::new(FakeFtp))) }`.
/// The `Vec`'s type says what goes in it, so Rust turns the `Arc<FakeFtp>` into an
/// `Arc<dyn FakeService>` for you.
pub fn services_from(settings: &Settings) -> Vec<(SocketAddr, Arc<dyn FakeService>)> {
    todo!()
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------
//
// You don't need to change anything below, but do read the tests: they show exactly how your code
// is going to be used.
//
// Connections in these tests only ever use localhost, and the logs are made up and go in
// throwaway folders, never your real `logs` folder.

#[cfg(test)]
mod tests {
    use super::*;
    use crate::deploy::{code_only, forbidden_uses};
    use crate::log_files::{DailyLog, dated_log_files, screen_line, today};
    use crate::login::listen_on_localhost;
    use crate::server::{Limits, Shared, handle_service_visit, serve_next_with};
    use std::env;
    use std::fs::{self, DirBuilder};
    use std::io::Read;
    use std::net::{IpAddr, Ipv4Addr, TcpStream};
    use std::os::unix::fs::DirBuilderExt;
    use std::path::PathBuf;
    use std::time::{Duration, UNIX_EPOCH};

    const LOCALHOST: IpAddr = IpAddr::V4(Ipv4Addr::LOCALHOST);
    const LONG_LIMIT: Duration = Duration::from_secs(20);
    const SHORT_LIMIT: Duration = Duration::from_millis(200);

    // Words that must never come back. This is what a visitor's own text looks like.
    const MARKER: &str = "XYZZY";

    // A folder that belongs to one test, deleted when the test ends, as in Stage 3.
    struct TestDir {
        path: PathBuf,
    }

    impl TestDir {
        fn new(test_name: &str) -> TestDir {
            let name = format!("honeypot-services-test-{}-{test_name}", std::process::id());
            let path = env::temp_dir().join(name);
            let _ = fs::remove_dir_all(&path);
            DirBuilder::new().mode(0o700).create(&path).unwrap();
            TestDir { path }
        }
    }

    impl Drop for TestDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.path);
        }
    }

    // A pretend visitor who has gone quiet, as in Stage 2.
    struct GoesQuiet;

    impl Read for GoesQuiet {
        fn read(&mut self, _buffer: &mut [u8]) -> io::Result<usize> {
            Err(io::ErrorKind::WouldBlock.into())
        }
    }

    // A pretend connection that accepts a few writes, then acts as if the visitor hung up.
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

    // A made-up service, so the trait's own methods can be tested before FTP and SSH exist.
    struct Echoless;

    impl FakeService for Echoless {
        fn name(&self) -> &'static str {
            "test"
        }

        fn converse(
            &self,
            visit: &mut Visit,
            reader: &mut dyn BufRead,
            _writer: &mut dyn Write,
        ) -> io::Result<()> {
            let line = read_line(reader)?;
            if !line.is_empty() {
                visit.outcome = Outcome::Requested;
            }
            Ok(())
        }
    }

    struct WithBanner;

    impl FakeService for WithBanner {
        fn name(&self) -> &'static str {
            "banner"
        }

        fn banner(&self) -> &'static str {
            "hello\r\n"
        }

        fn converse(
            &self,
            _visit: &mut Visit,
            _reader: &mut dyn BufRead,
            _writer: &mut dyn Write,
        ) -> io::Result<()> {
            Err(io::ErrorKind::BrokenPipe.into())
        }
    }

    fn blank_visit() -> Visit {
        Visit::new(UNIX_EPOCH + Duration::from_secs(1000), LOCALHOST)
    }

    fn as_text(bytes: &[u8]) -> String {
        String::from_utf8_lossy(bytes).to_string()
    }

    // Runs a whole visit to one service. Gives back the visit and what was sent.
    fn visit_to(service: &dyn FakeService, typed: &str) -> (Visit, String) {
        let mut visit = blank_visit();
        let mut sent = Vec::new();
        let mut reader = typed.as_bytes();
        service.run(&mut visit, &mut reader, &mut sent);
        (visit, as_text(&sent))
    }

    fn args(text: &str) -> Vec<String> {
        text.split_whitespace().map(String::from).collect()
    }

    fn settings(text: &str) -> Settings {
        Settings::from_args(&args(text)).unwrap()
    }

    fn server(dir: &TestDir, time_limit: Duration) -> Shared {
        let log = DailyLog::open(&dir.path, today()).unwrap();
        Shared::new(log, Limits::new(10, 10), 1_000_000, time_limit).unwrap()
    }

    fn logged_visits(dir: &TestDir) -> Vec<serde_json::Value> {
        let mut visits = Vec::new();
        for (path, _) in dated_log_files(&dir.path).unwrap() {
            for line in fs::read_to_string(path).unwrap().lines() {
                visits.push(serde_json::from_str(line).unwrap());
            }
        }
        visits
    }

    // Visits a service over a real connection on localhost, and gives back what it sent.
    fn visit_for_real(shared: &Shared, service: Arc<dyn FakeService>, typed: &[u8]) -> String {
        let listener = listen_on_localhost(0).unwrap();
        let mut visitor = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        visitor
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        visitor.write_all(typed).unwrap();
        serve_next_with(&listener, shared, move |stream, ip, shared| {
            handle_service_visit(stream, ip, shared, &*service)
        })
        .unwrap();
        let mut reply = Vec::new();
        let _ = visitor.read_to_end(&mut reply);
        as_text(&reply)
    }

    // The server handles visitors on their own threads, so a missing piece would only show up there
    // as a strange failure. This tries each piece on the test's own thread first.
    fn check_the_pieces_first() {
        visit_to(&FakeFtp, "USER a\r\nPASS b\r\n");
        visit_to(&FakeSsh, "SSH-2.0-x\r\n");
    }

    // -----------------------------------------------------------------------
    // Guards: these already pass, and they should never stop passing.
    // -----------------------------------------------------------------------

    #[test]
    fn guard_this_file_cannot_touch_the_system() {
        let source = fs::read_to_string("src/services.rs").unwrap();
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
            "File::",
            "OpenOptions",
            "include_",
        ];
        let found = forbidden_uses(code_only(&source), &never_here);
        assert!(found.is_empty(), "these lines break the rules: {found:#?}");
    }

    const ALL_REPLIES: [&str; 6] = [
        FTP_BANNER,
        FTP_PASSWORD_PLEASE,
        FTP_LOGIN_INCORRECT,
        FTP_NOT_LOGGED_IN,
        FTP_GOODBYE,
        SSH_BANNER,
    ];

    #[test]
    fn guard_every_reply_finishes_its_line() {
        for reply in ALL_REPLIES {
            assert!(reply.ends_with("\r\n"), "{reply:?}");
            assert_eq!(reply.matches('\n').count(), 1, "{reply:?}");
        }
    }

    // FTP's code for "you're logged in" is 230. No reply may ever start with it.
    #[test]
    fn guard_ftp_never_lets_anyone_in() {
        for reply in ALL_REPLIES {
            assert!(!reply.starts_with("230"), "{reply:?}");
            assert!(
                !reply.starts_with("2") || reply.starts_with("22"),
                "{reply:?}"
            );
        }
    }

    // Safety rule 5: no real product's name in a banner.
    #[test]
    fn guard_the_banners_are_generic() {
        let products = [
            "openssh",
            "dropbear",
            "libssh",
            "vsftpd",
            "proftpd",
            "pure-ftpd",
            "filezilla",
            "microsoft",
            "windows",
            "ubuntu",
            "debian",
            "cisco",
        ];
        for reply in ALL_REPLIES {
            let lower = reply.to_ascii_lowercase();
            for product in products {
                assert!(!lower.contains(product), "{product} in {reply:?}");
            }
        }
        assert!(SSH_BANNER.starts_with("SSH-2.0-"));
    }

    // A visitor's text only lasts as long as their connection. If a reply could ever borrow from
    // it, this stops compiling.
    #[test]
    fn guard_replies_are_always_text_built_into_the_program() {
        let replies: [&'static str; 6] = ALL_REPLIES;
        assert!(!replies.is_empty());
    }

    #[test]
    fn guard_the_trait_starts_with_no_banner() {
        assert_eq!(Echoless.banner(), "");
    }

    #[test]
    fn guard_without_the_flags_there_are_no_more_services() {
        let live = settings("--listen 0.0.0.0:2323 --checklist-done");
        assert_eq!(live.ftp_listen(), None);
        assert_eq!(live.ssh_listen(), None);
    }

    // Both ports follow the same rule as the telnet one: localhost, unless the checklist is done.
    #[test]
    fn guard_the_addresses_are_checked_too() {
        for flag in ["--ftp-listen", "--ssh-listen"] {
            for bad in [
                format!("{flag} 0.0.0.0:2121"),
                format!("{flag} [::1]:2121"),
                flag.to_string(),
            ] {
                assert!(Settings::from_args(&args(&bad)).is_err(), "{bad}");
            }
            let ok = format!("{flag} 0.0.0.0:2121 --checklist-done");
            assert!(Settings::from_args(&args(&ok)).is_ok(), "{ok}");
        }
        let local = settings("--ftp-listen 127.0.0.1:2121 --ssh-listen 127.0.0.1:2222");
        assert_eq!(local.ftp_listen(), Some("127.0.0.1:2121".parse().unwrap()));
        assert_eq!(local.ssh_listen(), Some("127.0.0.1:2222".parse().unwrap()));
    }

    // -----------------------------------------------------------------------
    // The exercises
    // -----------------------------------------------------------------------

    #[test]
    fn ex1_reads_each_command() {
        assert_eq!(
            FtpRequest::parse("USER anonymous\r\n"),
            FtpRequest::User("anonymous".to_string())
        );
        assert_eq!(
            FtpRequest::parse("PASS hunter2\r\n"),
            FtpRequest::Pass("hunter2".to_string())
        );
        assert_eq!(FtpRequest::parse("QUIT\r\n"), FtpRequest::Quit);
        assert_eq!(FtpRequest::parse("SYST\r\n"), FtpRequest::Other);
    }

    #[test]
    fn ex1_the_command_ignores_case() {
        assert_eq!(
            FtpRequest::parse("user root\n"),
            FtpRequest::User("root".to_string())
        );
        assert_eq!(FtpRequest::parse("Quit"), FtpRequest::Quit);
    }

    #[test]
    fn ex1_keeps_spaces_in_what_follows() {
        assert_eq!(
            FtpRequest::parse("PASS my pass \r\n"),
            FtpRequest::Pass("my pass ".to_string())
        );
    }

    #[test]
    fn ex1_nothing_after_user_is_an_empty_name() {
        assert_eq!(
            FtpRequest::parse("USER\r\n"),
            FtpRequest::User(String::new())
        );
        assert_eq!(
            FtpRequest::parse("USER \r\n"),
            FtpRequest::User(String::new())
        );
    }

    #[test]
    fn ex1_cleans_what_follows() {
        assert_eq!(
            FtpRequest::parse("USER a\u{1b}[2J\r\n"),
            FtpRequest::User("a\\u{1b}[2J".to_string())
        );
    }

    #[test]
    fn ex1_anything_else_is_other() {
        for line in ["", "\r\n", "USERNAME root", "LIST", "\u{1b}", "é"] {
            assert_eq!(FtpRequest::parse(line), FtpRequest::Other, "{line:?}");
        }
    }

    #[test]
    fn ex2_has_a_name_and_a_banner() {
        assert_eq!(FakeFtp.name(), "ftp");
        assert_eq!(FakeFtp.banner(), FTP_BANNER);
    }

    #[test]
    fn ex3_a_login_is_rejected() {
        let (visit, sent) = visit_to(&FakeFtp, "USER anonymous\r\nPASS guest\r\n");
        assert_eq!(
            sent,
            format!("{FTP_BANNER}{FTP_PASSWORD_PLEASE}{FTP_LOGIN_INCORRECT}")
        );
        assert_eq!(visit.username.as_deref(), Some("anonymous"));
        assert_eq!(visit.password.as_deref(), Some("guest"));
        assert_eq!(visit.outcome, Outcome::Attempted);
        assert_eq!(visit.service, Some("ftp"));
    }

    #[test]
    fn ex3_one_try_is_all_anyone_gets() {
        let (visit, sent) = visit_to(&FakeFtp, "USER a\r\nPASS b\r\nUSER c\r\nPASS d\r\n");
        assert_eq!(visit.password.as_deref(), Some("b"));
        assert_eq!(sent.matches("530").count(), 1);
    }

    #[test]
    fn ex3_anything_else_needs_a_login_first() {
        let (visit, sent) = visit_to(&FakeFtp, "SYST\r\nLIST\r\n");
        assert_eq!(
            sent,
            format!("{FTP_BANNER}{FTP_NOT_LOGGED_IN}{FTP_NOT_LOGGED_IN}")
        );
        assert_eq!(visit.outcome, Outcome::Left);
    }

    #[test]
    fn ex3_quit_says_goodbye() {
        let (visit, sent) = visit_to(&FakeFtp, "USER a\r\nQUIT\r\nPASS b\r\n");
        assert!(sent.ends_with(FTP_GOODBYE));
        assert_eq!(visit.username.as_deref(), Some("a"));
        assert_eq!(visit.password, None);
    }

    #[test]
    fn ex3_stops_after_the_limit() {
        let typed = "NOOP\r\n".repeat(MAX_FTP_COMMANDS + 5);
        let (_, sent) = visit_to(&FakeFtp, &typed);
        assert_eq!(sent.matches(FTP_NOT_LOGGED_IN).count(), MAX_FTP_COMMANDS);
    }

    #[test]
    fn ex3_hanging_up_keeps_the_username() {
        let (visit, _) = visit_to(&FakeFtp, "USER root\r\n");
        assert_eq!(visit.username.as_deref(), Some("root"));
        assert_eq!(visit.outcome, Outcome::Left);
    }

    #[test]
    fn ex3_a_password_without_a_user_still_counts() {
        let (visit, _) = visit_to(&FakeFtp, "PASS 1234\r\n");
        assert_eq!(visit.username, None);
        assert_eq!(visit.password.as_deref(), Some("1234"));
        assert_eq!(visit.outcome, Outcome::Attempted);
    }

    #[test]
    fn ex3_never_sends_back_anything_that_was_typed() {
        let typed = format!("USER {MARKER}\r\nPASS {MARKER}\r\n");
        let (_, sent) = visit_to(&FakeFtp, &typed);
        assert!(!sent.contains(MARKER));
    }

    #[test]
    fn ex4_has_a_name_and_a_banner() {
        assert_eq!(FakeSsh.name(), "ssh");
        assert_eq!(FakeSsh.banner(), SSH_BANNER);
    }

    #[test]
    fn ex4_writes_down_the_client() {
        let (visit, sent) = visit_to(&FakeSsh, "SSH-2.0-Go\r\n\x00\x00\x01\x14binary");
        assert_eq!(sent, SSH_BANNER);
        assert_eq!(visit.client_banner.as_deref(), Some("SSH-2.0-Go"));
        assert_eq!(visit.outcome, Outcome::Requested);
        assert_eq!(visit.service, Some("ssh"));
    }

    #[test]
    fn ex4_cleans_the_client_banner() {
        let (visit, _) = visit_to(&FakeSsh, "SSH-2.0-\u{1b}[31m\r\n");
        assert_eq!(visit.client_banner.as_deref(), Some("SSH-2.0-\\u{1b}[31m"));
    }

    #[test]
    fn ex4_sending_nothing_is_left() {
        let (visit, sent) = visit_to(&FakeSsh, "");
        assert_eq!(sent, SSH_BANNER);
        assert_eq!(visit.client_banner, None);
        assert_eq!(visit.outcome, Outcome::Left);
    }

    #[test]
    fn ex4_never_sends_anything_but_its_banner() {
        let typed = format!("SSH-2.0-{MARKER}\r\nmore\r\nand more\r\n");
        let (_, sent) = visit_to(&FakeSsh, &typed);
        assert_eq!(sent, SSH_BANNER);
    }

    #[test]
    fn ex5_sets_the_service() {
        let (visit, _) = visit_to(&Echoless, "hi\n");
        assert_eq!(visit.service, Some("test"));
        assert_eq!(visit.outcome, Outcome::Requested);
    }

    #[test]
    fn ex5_an_empty_banner_sends_nothing() {
        let (_, sent) = visit_to(&Echoless, "hi\n");
        assert_eq!(sent, "");
    }

    #[test]
    fn ex5_sends_the_banner_first() {
        let mut visit = blank_visit();
        let mut sent = Vec::new();
        WithBanner.run(&mut visit, &mut "".as_bytes(), &mut sent);
        assert_eq!(as_text(&sent), "hello\r\n");
    }

    #[test]
    fn ex5_an_error_sets_the_outcome() {
        let mut visit = blank_visit();
        let mut reader = io::BufReader::new(GoesQuiet);
        Echoless.run(&mut visit, &mut reader, &mut Vec::new());
        assert_eq!(visit.outcome, Outcome::TimedOut);
    }

    #[test]
    fn ex5_an_error_after_an_outcome_keeps_it() {
        let mut visit = blank_visit();
        let mut reader = "USER a\r\nPASS b\r\n".as_bytes();
        // The banner and the 331 go out, and then the visitor hangs up before the 530.
        let mut writer = HangsUpAfter { writes_left: 2 };
        FakeFtp.run(&mut visit, &mut reader, &mut writer);
        assert_eq!(visit.outcome, Outcome::Attempted);
        assert_eq!(visit.password.as_deref(), Some("b"));
    }

    #[test]
    fn ex5_hanging_up_during_the_banner_is_left() {
        let mut visit = blank_visit();
        let mut writer = HangsUpAfter { writes_left: 0 };
        WithBanner.run(&mut visit, &mut "".as_bytes(), &mut writer);
        assert_eq!(visit.outcome, Outcome::Left);
        assert_eq!(visit.service, Some("banner"));
    }

    #[test]
    fn ex6_no_flags_no_services() {
        assert!(services_from(&settings("")).is_empty());
    }

    #[test]
    fn ex6_lists_each_service_that_is_on() {
        let both = services_from(&settings(
            "--ssh-listen 127.0.0.1:2222 --ftp-listen 127.0.0.1:2121",
        ));
        let names: Vec<(String, &str)> = both
            .iter()
            .map(|(address, service)| (address.to_string(), service.name()))
            .collect();
        assert_eq!(
            names,
            [
                ("127.0.0.1:2121".to_string(), "ftp"),
                ("127.0.0.1:2222".to_string(), "ssh"),
            ]
        );

        let one = services_from(&settings("--ssh-listen 127.0.0.1:2222"));
        assert_eq!(one.len(), 1);
        assert_eq!(one[0].1.name(), "ssh");
    }

    // These run each service over a real connection on localhost, through the worked examples in
    // `src/server.rs`, so they share the same limits and log as the telnet login.

    #[test]
    fn ex6_an_ftp_visit_goes_in_the_log() {
        check_the_pieces_first();
        let dir = TestDir::new("ex6-ftp");
        let shared = server(&dir, LONG_LIMIT);

        let sent = visit_for_real(&shared, Arc::new(FakeFtp), b"USER root\r\nPASS root\r\n");

        assert_eq!(
            sent,
            format!("{FTP_BANNER}{FTP_PASSWORD_PLEASE}{FTP_LOGIN_INCORRECT}")
        );
        let visits = logged_visits(&dir);
        assert_eq!(visits.len(), 1);
        assert_eq!(visits[0]["service"], "ftp");
        assert_eq!(visits[0]["outcome"], "attempted");
        assert_eq!(visits[0]["username"], "root");
    }

    #[test]
    fn ex6_an_ssh_visit_goes_in_the_log() {
        check_the_pieces_first();
        let dir = TestDir::new("ex6-ssh");
        let shared = server(&dir, LONG_LIMIT);

        let sent = visit_for_real(&shared, Arc::new(FakeSsh), b"SSH-2.0-scanner\r\n");

        assert_eq!(sent, SSH_BANNER);
        let visits = logged_visits(&dir);
        assert_eq!(visits[0]["service"], "ssh");
        assert_eq!(visits[0]["client_banner"], "SSH-2.0-scanner");
        assert!(visits[0].get("http").is_none());
    }

    #[test]
    fn ex6_a_silent_visitor_is_timed_out() {
        check_the_pieces_first();
        let dir = TestDir::new("ex6-silent");
        let shared = server(&dir, SHORT_LIMIT);

        let sent = visit_for_real(&shared, Arc::new(FakeSsh), b"");

        assert_eq!(sent, SSH_BANNER);
        assert_eq!(logged_visits(&dir)[0]["outcome"], "timed_out");
    }

    #[test]
    fn ex6_the_screen_shows_the_service() {
        let (mut visit, _) = visit_to(&FakeFtp, "USER root\r\nPASS hunter2\r\n");
        visit.time = 0;
        let line = screen_line(&visit);
        assert_eq!(
            line,
            "1970-01-01 Attempted from 127.0.x.x user=root password=(hidden) service=ftp"
        );
        let (mut visit, _) = visit_to(&FakeSsh, "SSH-2.0-Go\r\n");
        visit.time = 0;
        assert_eq!(
            screen_line(&visit),
            "1970-01-01 Requested from 127.0.x.x user=(none) password=(none) service=ssh banner_bytes=10"
        );
    }
}
