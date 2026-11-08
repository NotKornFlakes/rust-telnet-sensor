//! # Stage 1: A fake login on localhost
//!
//! You'll build a fake login prompt. It asks for a username and password, always
//! says no, and writes down what was typed. Nothing real sits behind it.
//!
//! Do the exercises in order, replacing each `todo!()`. Run one exercise's tests
//! with `cargo test ex1`, `cargo test ex2`, and so on. Run everything with
//! `cargo test`. Once they all pass, the README shows how to try it for real.

// While the exercises are full of `todo!()`, the function arguments are never
// used and the compiler warns about it. This line silences those warnings.
// Delete this comment and the line below once you've finished the stage.
#![allow(unused_variables)]

use std::fmt;
use std::io::{self, BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::time::Duration;

/// What the fake login sends. These are the only things it ever says.
pub const LOGIN_PROMPT: &str = "login: ";
pub const PASSWORD_PROMPT: &str = "Password: ";
pub const REJECTION: &str = "Login incorrect\r\n";

/// The most we'll read for one answer, so nobody can fill up your memory.
pub const MAX_ANSWER_BYTES: u64 = 256;

/// How long to wait for someone before giving up on them.
pub const TIMEOUT: Duration = Duration::from_secs(30);

// ---------------------------------------------------------------------------
// Cleaning up what people type
// ---------------------------------------------------------------------------

/// EXERCISE 1: remove the line ending from what someone typed.
///
/// Text from a connection arrives with its line ending still on it, either `\n`
/// or `\r\n`. Remove those and nothing else. Keep any spaces, because a space in
/// a password is part of what they typed.
///
/// The new idea is the return type. A `&str` is a view into some text, so you can
/// return a smaller view of `line` without copying anything. JS and Python would
/// make a new string here.
///
/// Hint: `.trim()` would remove spaces too, so use `.trim_end_matches(...)`. You
/// can give it a list of characters, like `['x', 'y']`.
pub fn strip_line_ending(line: &str) -> &str {
    line.trim_end_matches(['\n', '\r'])
}

/// EXERCISE 2: make text safe to log and to print.
///
/// Anything an attacker types is hostile, even when you read it later:
/// - A newline in a username could fake a whole extra line in your log.
/// - Escape codes could change what your terminal shows you.
///
/// So turn invisible characters into visible text. A real newline becomes the two
/// characters `\n`. Python's `repr()` does the same thing, and so does
/// `JSON.stringify()` in JS.
///
/// Hint: `&str` has an `.escape_debug()` method. It doesn't return a `String`, so
/// finish with `.to_string()`.
pub fn escape_for_log(text: &str) -> String {
    text.escape_debug().to_string()
}

// ---------------------------------------------------------------------------
// LoginAttempt
// ---------------------------------------------------------------------------

/// One try at logging in.
///
/// These fields have no `pub`, so the only way to make a `LoginAttempt` from
/// outside this file is to call `LoginAttempt::new`.
#[derive(Debug, Clone, PartialEq)]
pub struct LoginAttempt {
    username: String,
    password: String,
}

impl LoginAttempt {
    /// EXERCISE 3: build an attempt from the raw text someone typed.
    ///
    /// The new idea is cleaning input as soon as it arrives. Since this is the
    /// only way to make a `LoginAttempt`, no uncleaned text can ever get into one,
    /// and the rest of the program doesn't have to remember to clean it.
    ///
    /// Hint: use your two functions on both fields. Strip the line ending first.
    /// If you escape first, the newline has already become visible text and
    /// stripping won't find it.
    pub fn new(username: &str, password: &str) -> LoginAttempt {
        LoginAttempt {
            username: escape_for_log(strip_line_ending(username)),
            password: escape_for_log(strip_line_ending(password)),
        }
    }
}

/// EXERCISE 4: decide how an attempt looks in the log.
///
/// ```text
/// username="admin" password="1234"
/// ```
///
/// This works just like `Display for Task` in your to-do app. The quotes are safe
/// because `.escape_debug()` also escapes any `"` in the text, so nobody can type
/// a quote to break out of a field.
///
/// Hint: to put a `"` inside a Rust string, write `\"`.
impl fmt::Display for LoginAttempt {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "username=\"{}\" password=\"{}\"",
            self.username, self.password
        )
    }
}

// ---------------------------------------------------------------------------
// Talking to a connection
// ---------------------------------------------------------------------------

// This is a worked example, not an exercise. Read it before Exercise 5, because it
// shows three new things:
//
// - `impl BufRead` means "anything you can read lines from". The real program
//   passes a network connection, and the tests pass plain bytes. It's like duck
//   typing in JS or Python, except the compiler checks it.
// - `io::Result<String>` means this can fail. You get either `Ok(text)` or
//   `Err(error)`. Rust has no exceptions, so failure is part of the type.
// - `?` means "if this failed, return the error from this function right now".
//   It's like letting an exception bubble up, except you can see where it happens.
pub fn read_answer(reader: &mut impl BufRead) -> io::Result<String> {
    let mut bytes = Vec::new();
    // `take` stops at the limit, so endless text with no newline can't fill memory.
    reader
        .take(MAX_ANSWER_BYTES)
        .read_until(b'\n', &mut bytes)?;
    // Scanners often send bytes that aren't valid text. `from_utf8_lossy` swaps
    // those for a placeholder character instead of failing.
    Ok(String::from_utf8_lossy(&bytes).to_string())
}

/// EXERCISE 5: send a prompt, then read the answer.
///
/// The new idea is using `?` yourself, as `read_answer` does above. Put it after
/// each call that can fail.
///
/// Hints:
/// - `writer.write_all(...)` sends bytes, not text. `.as_bytes()` converts a `&str`.
/// - `writer.flush()` makes the prompt leave right away instead of waiting in a
///   buffer.
/// - `read_answer` already returns the right type, so it can be your last line.
pub fn ask(prompt: &str, reader: &mut impl BufRead, writer: &mut impl Write) -> io::Result<String> {
    writer.write_all(prompt.as_bytes())?;
    writer.flush()?;
    read_answer(reader)
}

/// EXERCISE 6: run the whole fake login.
///
/// Ask with `LOGIN_PROMPT`, ask with `PASSWORD_PROMPT`, send `REJECTION`, and
/// return the `LoginAttempt`.
///
/// The new idea is `Ok(...)`: when a function returns a `Result`, wrap the value
/// in `Ok(...)` to say it worked.
///
/// This login always says no, because there's nothing real to log in to. Stage 7 adds
/// logins that succeed, in its own code and only into a shell that's entirely fake.
/// That's safety rule 1 in the README.
pub fn fake_login(reader: &mut impl BufRead, writer: &mut impl Write) -> io::Result<LoginAttempt> {
    let username = ask(LOGIN_PROMPT, reader, writer)?;
    let password = ask(PASSWORD_PROMPT, reader, writer)?;
    writer.write_all(REJECTION.as_bytes())?;
    Ok(LoginAttempt::new(&username, &password))
}

/// EXERCISE 7: write an attempt to the log, on its own line.
///
/// The new idea is `io::Result<()>`. `()` means "nothing", like a JS function that
/// returns nothing. Writing can still fail, for example if the disk is full, so
/// success is `Ok(())` and failure is an `Err`.
///
/// Hint: `writeln!` works like the `write!` you know, and adds a newline. It
/// already returns the right type, so it can be the whole function body.
pub fn append_to_log(log: &mut impl Write, attempt: &LoginAttempt) -> io::Result<()> {
    writeln!(log, "{}", attempt)
}

// ---------------------------------------------------------------------------
// Listening on the network
// ---------------------------------------------------------------------------

/// EXERCISE 8: start listening, on this computer only.
///
/// The new idea is using a function's signature as a safety rule. It only takes a
/// port, so no caller can ask it to listen on a different address.
///
/// `127.0.0.1` is localhost: only programs on this computer can connect. `0.0.0.0`
/// would open it up to every network the computer is on, which safety rule 3
/// forbids.
///
/// Hint: `TcpListener::bind(...)` takes the address and port as a pair, just like
/// `sock.bind((host, port))` in Python. It already returns the right type.
pub fn listen_on_localhost(port: u16) -> io::Result<TcpListener> {
    TcpListener::bind(("127.0.0.1", port))
}

// This is a worked example too. It connects the fake login to a real connection.
//
// This program handles one connection at a time, so someone who connects and stays
// silent would block everyone else. The timeouts make them fail with an `Err`
// instead. `BufReader` adds the ability to read line by line.
pub fn login_over_connection(stream: &TcpStream) -> io::Result<LoginAttempt> {
    stream.set_read_timeout(Some(TIMEOUT))?;
    stream.set_write_timeout(Some(TIMEOUT))?;
    let mut reader = BufReader::new(stream);
    let mut writer = stream;
    fake_login(&mut reader, &mut writer)
}

/// EXERCISE 9: wait for one connection, run the fake login, and log the result.
///
/// The new idea is unpacking a pair. `listener.accept()` gives you the connection
/// and the address of whoever connected. Unpack them with `let (a, b) = ...`, like
/// `a, b = ...` in Python or `const [a, b] = ...` in JS.
///
/// Hints:
/// - You won't use the address until Stage 2. Start its name with `_`, like
///   `_peer`, to tell Rust that's on purpose.
/// - Then call `login_over_connection` and `append_to_log`, using `?` on each.
/// - Finish by returning the attempt.
pub fn serve_one(listener: &TcpListener, log: &mut impl Write) -> io::Result<LoginAttempt> {
    let (stream, _peer) = listener.accept()?;
    let attempt = login_over_connection(&stream)?;
    writeln!(log, "{}", attempt)?;
    Ok(attempt)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------
//
// You don't need to change anything below, but do read the tests: they show
// exactly how your code is going to be used.
//
// Most tests don't touch the network. Plain bytes stand in for what someone typed,
// and a `Vec<u8>` collects what the program sends back. An `r"..."` string is a raw
// string: a backslash in it is just a backslash.

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::SocketAddr;
    use std::thread;

    // Turns the bytes the program wrote into text, so they're easy to compare.
    fn as_text(bytes: &[u8]) -> String {
        String::from_utf8_lossy(bytes).to_string()
    }

    // Plays the attacker: connects, types `typed`, and returns the reply. It runs
    // on its own thread so it can talk to the server at the same time.
    fn pretend_attacker(address: SocketAddr, typed: &'static str) -> thread::JoinHandle<String> {
        thread::spawn(move || {
            let mut reply = String::new();
            if let Ok(mut stream) = TcpStream::connect(address) {
                let _ = stream.set_read_timeout(Some(Duration::from_secs(5)));
                let _ = stream.write_all(typed.as_bytes());
                let _ = stream.read_to_string(&mut reply);
            }
            reply
        })
    }

    #[test]
    fn ex1_removes_a_newline() {
        assert_eq!(strip_line_ending("admin\n"), "admin");
    }

    #[test]
    fn ex1_removes_a_windows_line_ending() {
        assert_eq!(strip_line_ending("admin\r\n"), "admin");
    }

    #[test]
    fn ex1_keeps_spaces() {
        assert_eq!(strip_line_ending("  my pass  \n"), "  my pass  ");
    }

    #[test]
    fn ex2_leaves_normal_text_alone() {
        assert_eq!(escape_for_log("admin"), "admin");
    }

    #[test]
    fn ex2_makes_newlines_visible() {
        assert_eq!(escape_for_log("a\nb"), r"a\nb");
    }

    #[test]
    fn ex2_makes_terminal_codes_visible() {
        // "\u{1b}" is the invisible Escape character that starts a terminal code.
        assert_eq!(escape_for_log("\u{1b}[2J"), r"\u{1b}[2J");
    }

    #[test]
    fn ex3_strips_line_endings() {
        let attempt = LoginAttempt::new("admin\r\n", "1234\n");
        assert_eq!(attempt.username, "admin");
        assert_eq!(attempt.password, "1234");
    }

    #[test]
    fn ex3_escapes_hostile_text() {
        let attempt = LoginAttempt::new("root\nfake line\n", "\u{1b}[2J\n");
        assert_eq!(attempt.username, r"root\nfake line");
        assert_eq!(attempt.password, r"\u{1b}[2J");
    }

    #[test]
    fn ex4_log_format() {
        let attempt = LoginAttempt::new("admin\n", "1234\n");
        assert_eq!(attempt.to_string(), r#"username="admin" password="1234""#);
    }

    #[test]
    fn ex4_quotes_cannot_break_out_of_a_field() {
        let attempt = LoginAttempt::new("a\" b=\"c\n", "x\n");
        assert_eq!(attempt.to_string(), r#"username="a\" b=\"c" password="x""#);
    }

    #[test]
    fn ex5_sends_the_prompt_and_returns_the_answer() {
        let mut typed = "admin\n".as_bytes();
        let mut sent = Vec::new();
        let answer = ask("login: ", &mut typed, &mut sent).unwrap();
        assert_eq!(answer, "admin\n");
        assert_eq!(as_text(&sent), "login: ");
    }

    #[test]
    fn ex5_stops_reading_at_the_limit() {
        let huge = "a".repeat(1000);
        let mut typed = huge.as_bytes();
        let mut sent = Vec::new();
        let answer = ask("login: ", &mut typed, &mut sent).unwrap();
        assert_eq!(answer.len() as u64, MAX_ANSWER_BYTES);
    }

    #[test]
    fn ex5_survives_bytes_that_are_not_text() {
        let mut typed: &[u8] = &[0xff, 0xfe, b'\n'];
        let mut sent = Vec::new();
        assert!(ask("login: ", &mut typed, &mut sent).is_ok());
    }

    #[test]
    fn ex6_asks_twice_then_rejects() {
        let mut typed = "admin\n1234\n".as_bytes();
        let mut sent = Vec::new();
        fake_login(&mut typed, &mut sent).unwrap();
        assert_eq!(as_text(&sent), "login: Password: Login incorrect\r\n");
    }

    #[test]
    fn ex6_returns_what_was_typed() {
        let mut typed = "admin\n1234\n".as_bytes();
        let mut sent = Vec::new();
        let attempt = fake_login(&mut typed, &mut sent).unwrap();
        assert_eq!(attempt, LoginAttempt::new("admin", "1234"));
    }

    #[test]
    fn ex6_rejects_everything() {
        for typed in ["admin\nadmin\n", "root\ntoor\n", "\n\n", ""] {
            let mut typed = typed.as_bytes();
            let mut sent = Vec::new();
            fake_login(&mut typed, &mut sent).unwrap();
            assert!(as_text(&sent).ends_with(REJECTION));
        }
    }

    #[test]
    fn ex7_writes_one_line() {
        let mut log = Vec::new();
        append_to_log(&mut log, &LoginAttempt::new("admin", "1234")).unwrap();
        assert_eq!(as_text(&log), "username=\"admin\" password=\"1234\"\n");
    }

    #[test]
    fn ex7_keeps_earlier_lines() {
        let mut log = Vec::new();
        append_to_log(&mut log, &LoginAttempt::new("admin", "1234")).unwrap();
        append_to_log(&mut log, &LoginAttempt::new("root", "toor")).unwrap();
        assert_eq!(as_text(&log).lines().count(), 2);
    }

    #[test]
    fn ex7_a_fake_line_stays_on_one_line() {
        let hostile = LoginAttempt::new("root\nusername=\"fake\" password=\"fake\"", "x");
        let mut log = Vec::new();
        append_to_log(&mut log, &hostile).unwrap();
        assert_eq!(as_text(&log).lines().count(), 1);
    }

    // Port 0 asks the operating system to pick any free port, so tests can't clash.
    #[test]
    fn ex8_listens_only_on_localhost() {
        let listener = listen_on_localhost(0).unwrap();
        assert!(listener.local_addr().unwrap().ip().is_loopback());
    }

    #[test]
    fn ex8_uses_the_port_you_asked_for() {
        let free_port = listen_on_localhost(0).unwrap().local_addr().unwrap().port();
        let listener = listen_on_localhost(free_port).unwrap();
        assert_eq!(listener.local_addr().unwrap().port(), free_port);
    }

    #[test]
    fn ex9_handles_a_real_connection_on_localhost() {
        let listener = listen_on_localhost(0).unwrap();
        let attacker = pretend_attacker(listener.local_addr().unwrap(), "admin\n1234\n");

        let mut log = Vec::new();
        let attempt = serve_one(&listener, &mut log).unwrap();

        assert_eq!(attempt, LoginAttempt::new("admin", "1234"));
        assert_eq!(as_text(&log), "username=\"admin\" password=\"1234\"\n");
        assert_eq!(
            attacker.join().unwrap(),
            "login: Password: Login incorrect\r\n"
        );
    }
}
