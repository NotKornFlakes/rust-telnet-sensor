//! # Stage 4: Many connections at once
//!
//! So far the honeypot has handled one visitor at a time, so one silent visitor holds
//! up everyone else. In this stage each visitor gets their own thread, and you add the
//! limits that stop anyone from overwhelming it once it's on the internet:
//! - one time limit for a whole visit, even for someone sending a letter at a time
//! - a cap on connections, both overall and for each IP address
//! - a daily budget for the log, so nobody can fill up the disk
//!
//! You'll also fix a gap from Stage 2: text sent without a newline is now kept when
//! someone goes quiet.
//!
//! Do the exercises in order, replacing each `todo!()`. Run one exercise's tests with
//! `cargo test server::tests::ex1`. Run all of Stage 4 with `cargo test server`.
//!
//! `cargo run` crashes with "not yet implemented" until you've finished this stage,
//! because `main.rs` now uses this file.

// While the exercises are full of `todo!()`, some arguments, imports and other code
// aren't used, and the compiler warns about it. This line silences those warnings.
// Delete this comment and the line below once you've finished the stage.
#![allow(dead_code, unused_variables, unused_imports)]

use std::collections::HashMap;
use std::io::{self, BufReader, Read, Write};
use std::net::{IpAddr, TcpListener, TcpStream};
use std::sync::mpsc::{SyncSender, sync_channel};
use std::sync::{Arc, Mutex, MutexGuard};
use std::thread;
use std::time::{Duration, Instant, SystemTime};

use chrono::NaiveDate;

use crate::deploy::{RateLimit, current_minute};
use crate::fake_shell::{Credentials, SessionEnd, ShellBudget, TELNET_OPENING, TelnetFilter};
use crate::fake_web::WEB_SERVICE;
use crate::log_files::{DailyLog, screen_line, today};
use crate::services::FakeService;
use crate::visit::{Outcome, Visit, append_visit, outcome_of_error};

/// The most visitors handled at once. Each one gets a thread.
pub const MAX_CONNECTIONS: usize = 64;

/// The most connections one IP address can have at once, so that one source can't take
/// every place.
pub const MAX_PER_IP: usize = 4;

/// The most the log can grow each day: 100 MB. With `KEEP_DAYS` at 30, that's at most
/// 3 GB of logs on disk.
pub const MAX_LOG_BYTES_PER_DAY: u64 = 100 * 1024 * 1024;

/// How many lines can wait to be shown on screen before new ones are left out.
const SCREEN_QUEUE_LINES: usize = 1000;

// ---------------------------------------------------------------------------
// One time limit for the whole visit
// ---------------------------------------------------------------------------

/// EXERCISE 1: work out how much time is left before a deadline.
///
/// Return the time left, or `None` if the deadline has arrived or passed.
///
/// The timeouts so far only count silence, so someone sending one letter every 29
/// seconds would never trip them. They could hold a place for hours. That's why each
/// visit now gets a single deadline.
///
/// The new idea is `Instant`, a clock for measuring how long things take. It never
/// goes backwards, even if someone changes the computer's clock. It's like
/// `performance.now()` in JS or `time.monotonic()` in Python.
///
/// Hint: you can compare two `Instant`s with `<`, and `deadline - now` gives you a
/// `Duration`.
pub fn time_left(deadline: Instant, now: Instant) -> Option<Duration> {
    if now < deadline {
        Some(deadline - now)
    } else {
        None
    }
}

/// A connection you can read from until a deadline.
///
/// `'a` is a *lifetime*. It says this struct borrows the `TcpStream`, so the stream has
/// to outlive it. You don't need to write any here, just recognise them.
pub struct TimeLimited<'a> {
    stream: &'a TcpStream,
    deadline: Instant,
    timed_out: bool,
}

impl<'a> TimeLimited<'a> {
    pub fn new(stream: &'a TcpStream, time_limit: Duration) -> TimeLimited<'a> {
        TimeLimited {
            stream,
            deadline: Instant::now() + time_limit,
            timed_out: false,
        }
    }

    /// EXERCISE 2: decide what the result of a read means.
    ///
    /// This is the fix for text sent without a newline. An error during a read used
    /// to throw away the text read so far. If you report "end of input" instead, by
    /// returning `Ok(0)`, then `read_answer` keeps that text.
    ///
    /// - `Ok(count)` worked, so pass it on.
    /// - `io::ErrorKind::Interrupted` means "try again", so it stays an error.
    /// - A timeout ends the input. Set `self.timed_out` to `true`, and return `Ok(0)`.
    /// - Any other error means the connection broke, which also ends the input.
    ///
    /// The new idea is an `if` on a `match` arm, which only matches when the `if` is true:
    ///
    /// ```text
    /// Err(error) if error.kind() == io::ErrorKind::Interrupted => ...,
    /// ```
    ///
    /// Hint: `outcome_of_error` from Stage 2 already knows what a timeout looks like.
    pub fn finish_read(&mut self, result: io::Result<usize>) -> io::Result<usize> {
        match result {
            Ok(count) => Ok(count),
            Err(error) if error.kind() == io::ErrorKind::Interrupted => Err(error),
            Err(error) if outcome_of_error(&error) == Outcome::TimedOut => {
                self.timed_out = true;
                Ok(0)
            }
            Err(_) => Ok(0),
        }
    }

    fn read_with_limit(&mut self, buffer: &mut [u8], left: Duration) -> io::Result<usize> {
        self.stream.set_read_timeout(Some(left))?;
        self.stream.read(buffer)
    }
}

// This is a worked example, not an exercise. Implementing `Read` lets `BufReader` and
// your code from earlier stages use this type without changing. It's like giving a
// Python object a `.read()` method so it works as a file, except the compiler checks it.
impl Read for TimeLimited<'_> {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        let result = match time_left(self.deadline, Instant::now()) {
            Some(left) => self.read_with_limit(buffer, left),
            None => Err(io::ErrorKind::TimedOut.into()),
        };
        self.finish_read(result)
    }
}

// This is a worked example too. It runs your fake login from Stage 2 with one time limit
// for the whole visit. Replies are tiny and fit in the computer's own buffers, so
// writing can't be used to hold a place open for long.
pub fn run_visit(visit: &mut Visit, stream: &TcpStream, time_limit: Duration) {
    if let Err(error) = stream.set_write_timeout(Some(time_limit)) {
        visit.outcome = outcome_of_error(&error);
        return;
    }
    let mut reader = BufReader::new(TimeLimited::new(stream, time_limit));
    let mut writer = stream;
    visit.run_fake_login(&mut reader, &mut writer);
    if reader.get_ref().timed_out {
        visit.outcome = Outcome::TimedOut;
    }
}

// ---------------------------------------------------------------------------
// Stage 7: the same time limit for writing
// ---------------------------------------------------------------------------

/// A connection you can write to until a deadline.
///
/// The comment on `run_visit` says replies are tiny, so writing can't hold a place open for
/// long. The fake shell sends much more than that, so here the deadline covers writing as well.
pub struct WriteLimited<'a> {
    stream: &'a TcpStream,
    deadline: Instant,
}

impl<'a> WriteLimited<'a> {
    pub fn new(stream: &'a TcpStream, deadline: Instant) -> WriteLimited<'a> {
        WriteLimited { stream, deadline }
    }
}

/// STAGE 7, EXERCISE 9: write only until the deadline. The tests are in `src/fake_shell.rs`, so
/// run them with `cargo test fake_shell::tests::ex9`.
///
/// A socket's write timeout is measured from the start of each write. Someone who reads one
/// byte at a time, just often enough, could keep `write_all` going for a very long time. So
/// each write gets only the time that's left, the same way `Read for TimeLimited` does above.
///
/// The new idea is implementing a trait from the standard library that has a method you don't
/// write. `Write` provides `write_all` for free, as long as you provide `write` and `flush`.
///
/// Do these in order:
/// 1. `match` on `time_left(self.deadline, Instant::now())`.
/// 2. If that's `None`, return `Err(io::ErrorKind::TimedOut.into())`, and send nothing.
/// 3. If there's time `left`, call `self.stream.set_write_timeout(Some(left))?`, and then write
///    the bytes.
///
/// Hint: writing needs a `mut` handle, even though it only changes the connection and not the
/// reference. So write `let mut stream = self.stream;` and then `stream.write(bytes)`, as
/// `let mut writer = stream;` does in `run_visit`.
impl Write for WriteLimited<'_> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        match time_left(self.deadline, Instant::now()) {
            None => Err(io::ErrorKind::TimedOut.into()),
            Some(left) => {
                self.stream.set_write_timeout(Some(left))?;
                let mut stream = self.stream;
                stream.write(bytes)
            }
        }
    }

    // Nothing is held back in this type, so there's nothing to flush.
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

// This is a worked example for Stage 7. It's `run_visit` with the fake shell behind the login.
// The reader and the writer share a single deadline, which starts when the visit does, so
// getting past the login doesn't start the clock again. It speaks telnet first, as a real device
// does, and `TelnetFilter` keeps the answers out of what the visitor typed. `run_visit` above does
// neither, so a server without the shell behaves exactly as it did before Stage 7.
pub fn run_shell_visit(
    visit: &mut Visit,
    stream: &TcpStream,
    time_limit: Duration,
    credentials: &Credentials,
) {
    let limited = TimeLimited::new(stream, time_limit);
    let mut writer = WriteLimited::new(stream, limited.deadline);
    let mut reader = BufReader::new(TelnetFilter::new(limited));
    match writer.write_all(TELNET_OPENING) {
        Ok(()) => visit.run_login_or_shell(&mut reader, &mut writer, credentials),
        Err(error) => visit.outcome = outcome_of_error(&error),
    }
    visit.telnet = Some(reader.get_ref().negotiation_as_hex());
    if reader.get_ref().inner().timed_out {
        match &mut visit.shell {
            Some(session) => session.ended = SessionEnd::TimedOut,
            None => visit.outcome = Outcome::TimedOut,
        }
    }
}

// This is a worked example for Stage 8. It's `run_visit` for the fake web service. The reader and
// the writer share one deadline, as in `run_shell_visit`, so a request that drips in slowly, or a
// visitor who reads the page slowly, still can't hold a place for longer than a login can.
pub fn run_web_visit(visit: &mut Visit, stream: &TcpStream, time_limit: Duration) {
    let mut reader = TimeLimited::new(stream, time_limit);
    let mut writer = WriteLimited::new(stream, reader.deadline);
    visit.run_web_request(&mut reader, &mut writer);
    if reader.timed_out && visit.http.is_none() {
        visit.outcome = Outcome::TimedOut;
    }
}

// This is a worked example for Stage 10. It runs any `FakeService` with the same deadline for
// reading and writing as the others. It doesn't know or care which service it's running.
pub fn run_service_visit(
    visit: &mut Visit,
    stream: &TcpStream,
    time_limit: Duration,
    service: &dyn FakeService,
) {
    let limited = TimeLimited::new(stream, time_limit);
    let mut writer = WriteLimited::new(stream, limited.deadline);
    let mut reader = BufReader::new(limited);
    service.run(visit, &mut reader, &mut writer);
    if reader.get_ref().timed_out && visit.outcome == Outcome::Left {
        visit.outcome = Outcome::TimedOut;
    }
}

// ---------------------------------------------------------------------------
// Caps on connections
// ---------------------------------------------------------------------------

/// How many visitors are connected right now, overall and for each IP address.
///
/// `HashMap` is Rust's `Map` in JS or `dict` in Python, with the types of its keys and
/// values fixed.
#[derive(Debug)]
pub struct Limits {
    max_total: usize,
    max_per_ip: usize,
    total: usize,
    per_ip: HashMap<IpAddr, usize>,
    refused: u64,
}

impl Limits {
    pub fn new(max_total: usize, max_per_ip: usize) -> Limits {
        Limits {
            max_total,
            max_per_ip,
            total: 0,
            per_ip: HashMap::new(),
            refused: 0,
        }
    }

    /// EXERCISE 3: look up how many connections an IP address has.
    ///
    /// An address that isn't in the map has 0.
    ///
    /// The new idea is reading from a `HashMap`. `self.per_ip.get(&ip)` is like
    /// `map.get(ip)` in JS, except it gives you an `Option` instead of `undefined`.
    ///
    /// Hints:
    /// - `.get` gives you an `Option<&usize>`. `.copied()` turns it into an
    ///   `Option<usize>`.
    /// - `.unwrap_or(0)` gets you a number either way.
    pub fn count_for(&self, ip: IpAddr) -> usize {
        self.per_ip.get(&ip).copied().unwrap_or(0)
    }

    /// EXERCISE 4: let a visitor in if there's room, and return whether you did.
    ///
    /// There's room if `total` is under `max_total` and this address is under
    /// `max_per_ip`. If there's no room, change nothing and return `false`.
    ///
    /// The new idea is writing to a `HashMap`. `self.per_ip.insert(ip, count)` is like
    /// `counts[ip] = count` in Python, and it replaces any earlier value.
    ///
    /// Hint: don't forget to add 1 to `self.total` as well.
    pub fn admit(&mut self, ip: IpAddr) -> bool {
        let count = self.count_for(ip);
        if self.total < self.max_total && count < self.max_per_ip {
            self.total += 1;
            self.per_ip.insert(ip, count + 1);
            true
        } else {
            false
        }
    }

    /// EXERCISE 5: give a place back when a visitor leaves.
    ///
    /// Lower `total` and this address's count by 1. If this address has no connections
    /// to begin with, change nothing.
    ///
    /// The new idea is removing entries so a map can't grow forever. If you only ever
    /// stored 0, every address that ever visited would use up memory for good, and
    /// attackers come from a lot of addresses. So when the count reaches 0, use
    /// `self.per_ip.remove(&ip)`.
    pub fn release(&mut self, ip: IpAddr) {
        let count = self.count_for(ip);
        if count > 0 {
            self.total -= 1;
            if count == 1 {
                self.per_ip.remove(&ip);
            } else {
                self.per_ip.insert(ip, count - 1);
            }
        }
    }
}

// This is a worked example, not an exercise. A `Mutex` makes threads take turns with a
// value, and `lock` waits for your turn. The turn ends when the value `lock` returned
// goes away. In Rust, sharing a value between threads without something like this
// doesn't compile, so a whole family of bugs can't happen.
//
// If a thread crashes during its turn, Rust marks the `Mutex` as "poisoned" as a warning.
// A honeypot should keep recording rather than stop, so we carry on anyway.
pub fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// A visitor's place in the limits. While a `Slot` exists, the place is taken.
///
/// `Arc` lets several owners share one value, which goes away when the last owner does.
/// `Arc<Mutex<Limits>>` is the usual way to share something between threads: `Arc` for
/// the sharing, and `Mutex` for the taking turns.
pub struct Slot {
    limits: Arc<Mutex<Limits>>,
    ip: IpAddr,
}

/// EXERCISE 6: give the place back when a `Slot` goes away.
///
/// The new idea is `Drop`, which is code that runs when a value goes away. It's like
/// Python's `with` or a `finally` block, except nobody has to remember to use it. It
/// runs even if the thread crashes, so a place can never be lost.
///
/// Hint: `lock(&self.limits)` gives you the `Limits`, so you can call `release` on it.
impl Drop for Slot {
    fn drop(&mut self) {
        lock(&self.limits).release(self.ip);
    }
}

impl Slot {
    /// EXERCISE 7: take a place for this visitor, or return `None` if there's no room.
    ///
    /// The new idea is `Arc::clone(limits)`. It doesn't copy the `Limits`. It makes
    /// another owner of the same one, and adds 1 to a count of owners. Every object in
    /// Python is shared this way, without you having to ask.
    ///
    /// Hints:
    /// - Call `admit` using `lock(limits)`.
    /// - If it says yes, build a `Slot` with its own `Arc::clone(limits)`.
    pub fn try_take(limits: &Arc<Mutex<Limits>>, ip: IpAddr) -> Option<Slot> {
        if lock(limits).admit(ip) {
            Some(Slot {
                limits: Arc::clone(limits),
                ip,
            })
        } else {
            None
        }
    }
}

// ---------------------------------------------------------------------------
// A daily budget for the log
// ---------------------------------------------------------------------------

/// The log, with a limit on how much it can grow each day.
pub struct CappedLog {
    log: DailyLog,
    date: NaiveDate,
    bytes_today: u64,
    max_bytes: u64,
    warned_on: Option<NaiveDate>,
}

impl CappedLog {
    /// Starts counting from today's file size, so restarting can't reset the budget.
    pub fn new(log: DailyLog, today: NaiveDate, max_bytes: u64) -> io::Result<CappedLog> {
        let bytes_today = log.size()?;
        Ok(CappedLog {
            log,
            date: today,
            bytes_today,
            max_bytes,
            warned_on: None,
        })
    }

    /// EXERCISE 8: add a line to the log if it fits in today's budget.
    ///
    /// Without a limit, anyone could fill the disk just by connecting over and over.
    ///
    /// The new idea is the return type. `io::Result<bool>` keeps two things apart:
    /// `Err` means something went wrong, `Ok(false)` means the line was left out on
    /// purpose, and `Ok(true)` means it was written.
    ///
    /// Do these in order:
    /// 1. If `today` isn't `self.date`, update `self.date` and set `self.bytes_today` to 0.
    /// 2. If `self.bytes_today` plus the line's length is over `self.max_bytes`, return
    ///    `Ok(false)`. Never write part of a line.
    /// 3. Otherwise call `self.log.append`, add to `self.bytes_today`, and return `Ok(true)`.
    ///
    /// Hint: `line.len()` is a `usize`, so convert it with `as u64`.
    pub fn append(&mut self, today: NaiveDate, line: &[u8]) -> io::Result<bool> {
        if today != self.date {
            self.date = today;
            self.bytes_today = 0;
        }
        if self.bytes_today + line.len() as u64 > self.max_bytes {
            Ok(false)
        } else {
            self.log.append(today, line)?;
            self.bytes_today += line.len() as u64;
            Ok(true)
        }
    }
}

// ---------------------------------------------------------------------------
// A thread for each visitor
// ---------------------------------------------------------------------------

/// Everything the threads share. Cloning this only clones the `Arc`s, so every thread
/// gets its own handle on the same limits and the same log.
#[derive(Clone)]
pub struct Shared {
    limits: Arc<Mutex<Limits>>,
    log: Arc<Mutex<CappedLog>>,
    screen: SyncSender<String>,
    time_limit: Duration,
    rate: Option<Arc<Mutex<RateLimit>>>,
    shell: Option<Arc<FakeShell>>,
    web: Option<Arc<Mutex<ShellBudget>>>,
}

/// What the threads share for the fake shell from Stage 7.
struct FakeShell {
    credentials: Credentials,
    budget: Mutex<ShellBudget>,
}

// This is a worked example, not an exercise. Printing can get stuck, for example if the
// terminal is paused or nothing is reading the output. If visitors' threads did their
// own printing they'd get stuck too, holding their places until nobody could get in.
//
// So one thread does all the printing, and the others hand it lines through a channel,
// which is a queue between threads. `Shared::show` uses `try_send`, which gives up at
// once if the queue is full. That line never reaches the screen, but the visit is still
// in the log.
fn start_screen_thread() -> io::Result<SyncSender<String>> {
    let (sender, receiver) = sync_channel::<String>(SCREEN_QUEUE_LINES);
    thread::Builder::new().spawn(move || {
        for line in receiver {
            println!("{line}");
        }
    })?;
    Ok(sender)
}

impl Shared {
    pub fn new(
        log: DailyLog,
        limits: Limits,
        max_log_bytes: u64,
        time_limit: Duration,
    ) -> io::Result<Shared> {
        let log = CappedLog::new(log, today(), max_log_bytes)?;
        Ok(Shared {
            limits: Arc::new(Mutex::new(limits)),
            log: Arc::new(Mutex::new(log)),
            screen: start_screen_thread()?,
            time_limit,
            rate: None,
            shell: None,
            web: None,
        })
    }

    /// Turns on the limit on visits per minute from Stage 5.
    pub fn with_rate_limit(mut self, rate: RateLimit) -> Shared {
        self.rate = Some(Arc::new(Mutex::new(rate)));
        self
    }

    /// Turns on the fake shell from Stage 7. Without this, every login is rejected.
    pub fn with_fake_shell(mut self, credentials: Credentials, budget: ShellBudget) -> Shared {
        self.shell = Some(Arc::new(FakeShell {
            credentials,
            budget: Mutex::new(budget),
        }));
        self
    }

    /// Turns on the fake web service from Stage 8, with its own daily budget. Without this,
    /// `handle_web_visit` closes every connection without reading it.
    pub fn with_fake_web(mut self, budget: ShellBudget) -> Shared {
        self.web = Some(Arc::new(Mutex::new(budget)));
        self
    }

    // Whether the web service is on and this address still has room in its budget.
    fn web_open_for(&self, ip: IpAddr) -> bool {
        match &self.web {
            Some(budget) => lock(budget).has_room(ip, today()),
            None => false,
        }
    }

    // A web visit costs what its log line takes up. The page going back is small and the same
    // every time, so the cap on visits per minute already keeps that cheap.
    fn charge_for_request(&self, visit: &Visit) {
        if let (Some(budget), Some(_)) = (&self.web, &visit.http) {
            let logged = visit.to_json_line().map_or(0, |line| line.len());
            lock(budget).spend(visit.source_ip, today(), logged as u64);
        }
    }

    // Gives back the list of logins if the shell is on and this address still has room.
    fn shell_open_for(&self, ip: IpAddr) -> Option<&Credentials> {
        let shell = self.shell.as_ref()?;
        if lock(&shell.budget).has_room(ip, today()) {
            Some(&shell.credentials)
        } else {
            None
        }
    }

    // A session costs what its log line takes up plus what it sent back.
    fn charge_for_session(&self, visit: &Visit) {
        if let (Some(shell), Some(session)) = (&self.shell, &visit.shell) {
            let logged = visit.to_json_line().map_or(0, |line| line.len());
            let cost = (logged + session.reply_bytes) as u64;
            lock(&shell.budget).spend(visit.source_ip, today(), cost);
        }
    }

    fn over_rate_limit(&self, ip: IpAddr) -> bool {
        match &self.rate {
            Some(rate) => !lock(rate).allow(ip, current_minute()),
            None => false,
        }
    }

    fn show(&self, line: String) {
        // Losing a line from the screen is fine, so the result doesn't matter.
        let _ = self.screen.try_send(line);
    }

    fn note_refused(&self) {
        lock(&self.limits).refused += 1;
    }

    fn take_refused_count(&self) -> u64 {
        let mut limits = lock(&self.limits);
        let refused = limits.refused;
        limits.refused = 0;
        refused
    }

    // Log problems could happen on every visit, so only mention them once a day.
    fn warn_once_a_day(&self, message: &str) {
        let date = today();
        let mut log = lock(&self.log);
        if log.warned_on != Some(date) {
            log.warned_on = Some(date);
            eprintln!("{message}");
        }
    }
}

fn write_to_log(visit: &Visit, shared: &Shared) -> io::Result<bool> {
    let mut line = Vec::new();
    append_visit(&mut line, visit)?;
    lock(&shared.log).append(today(), &line)
}

// This is a worked example, not an exercise. It's everything one thread does for one
// visitor. Refused connections are only counted, not logged one by one, so that they
// can't use up the day's budget and push out the visits you want to study. The rate limit
// from Stage 5 does the same for floods of quick visits.
pub fn handle_visit(stream: &TcpStream, ip: IpAddr, shared: &Shared) {
    if shared.over_rate_limit(ip) {
        shared.note_refused();
        return;
    }

    let mut visit = Visit::new(SystemTime::now(), ip);
    match shared.shell_open_for(ip) {
        Some(credentials) => run_shell_visit(&mut visit, stream, shared.time_limit, credentials),
        None => run_visit(&mut visit, stream, shared.time_limit),
    }
    shared.charge_for_session(&visit);
    record_and_show(&visit, shared);
}

// The end of every visit, whichever service it came to: the log, then the screen.
pub fn record_and_show(visit: &Visit, shared: &Shared) {
    match write_to_log(visit, shared) {
        Ok(true) => {}
        Ok(false) => {
            shared.warn_once_a_day("Today's log is full, so visits aren't being recorded.")
        }
        Err(error) => shared.warn_once_a_day(&format!("could not write to the log: {error}")),
    }

    let refused = shared.take_refused_count();
    if refused > 0 {
        shared.show(format!(
            "Refused {refused} connection(s) since the last visit."
        ));
    }
    shared.show(screen_line(visit));
}

// This is a worked example for Stage 8. It's `handle_visit` for the fake web service, with the same
// limits. A visit from an address that has used up its share of the day is closed without reading
// anything, and it's still logged, as a visit that sent nothing.
pub fn handle_web_visit(stream: &TcpStream, ip: IpAddr, shared: &Shared) {
    if shared.over_rate_limit(ip) {
        shared.note_refused();
        return;
    }

    let mut visit = Visit::new(SystemTime::now(), ip);
    if shared.web_open_for(ip) {
        run_web_visit(&mut visit, stream, shared.time_limit);
    } else {
        visit.service = Some(WEB_SERVICE);
    }
    shared.charge_for_request(&visit);
    record_and_show(&visit, shared);
}

/// EXERCISE 9: accept one connection and handle it on its own thread.
///
/// The new idea is starting a thread. It's like `threading.Thread(target=...)` in Python,
/// and JS has nothing quite like it. `move` hands the closure ownership of everything it
/// uses, because the thread might outlive this function:
///
/// ```text
/// thread::Builder::new().spawn(move || {
///     // this runs on the new thread
/// })?;
/// ```
///
/// Unlike plain `thread::spawn`, this gives you an error instead of crashing if the
/// computer can't start another thread.
///
/// Do these in order:
/// 1. `listener.accept()`, as in Stage 2, and get the address with `peer.ip()`.
/// 2. `match` on `Slot::try_take(&shared.limits, ip)`.
/// 3. If there's no slot, call `shared.note_refused()`. Rust closes the connection for
///    you, because `stream` goes away at the end of this function.
/// 4. If there is one, make `let shared = shared.clone();` for the thread, and start it.
/// 5. In the thread, write `let _slot = slot;` and call `handle_visit`.
/// 6. Finish with `Ok(())`.
///
/// Hint: `let _slot = slot;` looks pointless, but it moves the slot into the thread, so
/// the place stays taken until the visit ends. Don't shorten it to `_`, which wouldn't
/// move it.
pub fn serve_next(listener: &TcpListener, shared: &Shared) -> io::Result<()> {
    let (stream, addr) = listener.accept()?;
    let ip = addr.ip();
    match Slot::try_take(&shared.limits, ip) {
        None => shared.note_refused(),
        Some(slot) => {
            let shared = shared.clone();
            thread::Builder::new().spawn(move || {
                let _slot = slot;
                handle_visit(&stream, ip, &shared);
            })?;
        }
    }
    Ok(())
}

// This is a worked example for Stage 10. It's `handle_visit` for any `FakeService`. What these
// services store is small and has its own limits, so the cap on visits per minute and the log's
// daily budget are all they need.
pub fn handle_service_visit(
    stream: &TcpStream,
    ip: IpAddr,
    shared: &Shared,
    service: &dyn FakeService,
) {
    if shared.over_rate_limit(ip) {
        shared.note_refused();
        return;
    }
    let mut visit = Visit::new(SystemTime::now(), ip);
    run_service_visit(&mut visit, stream, shared.time_limit, service);
    record_and_show(&visit, shared);
}

// This is a worked example for Stages 8 and 10. It's your `serve_next` with the visit handed to
// whatever `handle` is, so every fake service shares the same caps on connections. `FnOnce` means
// any function or closure that can be called once, and `Send + 'static` means it can be moved onto
// the new thread, as everything in a `move` closure has to be.
pub fn serve_next_with<F>(listener: &TcpListener, shared: &Shared, handle: F) -> io::Result<()>
where
    F: FnOnce(&TcpStream, IpAddr, &Shared) + Send + 'static,
{
    let (stream, addr) = listener.accept()?;
    let ip = addr.ip();
    match Slot::try_take(&shared.limits, ip) {
        None => shared.note_refused(),
        Some(slot) => {
            let shared = shared.clone();
            thread::Builder::new().spawn(move || {
                let _slot = slot;
                handle(&stream, ip, &shared);
            })?;
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------
//
// You don't need to change anything below, but do read the tests: they show exactly
// how your code is going to be used.
//
// Connections in these tests only ever use localhost, and the logs are made up and go
// in throwaway folders, never your real `logs` folder.

#[cfg(test)]
mod tests {
    use super::*;
    use crate::log_files::dated_log_files;
    use crate::login::{listen_on_localhost, read_answer};
    use std::env;
    use std::fs::{self, DirBuilder};
    use std::io::Write;
    use std::net::Ipv4Addr;
    use std::os::unix::fs::DirBuilderExt;
    use std::path::PathBuf;

    // Documentation addresses. They're reserved, and they don't belong to anyone.
    const IP_A: IpAddr = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 1));
    const IP_B: IpAddr = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 2));
    const IP_C: IpAddr = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 3));
    const LOCALHOST: IpAddr = IpAddr::V4(Ipv4Addr::LOCALHOST);

    const SHORT_LIMIT: Duration = Duration::from_millis(200);
    const LONG_LIMIT: Duration = Duration::from_secs(20);
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

        fn read(&self, name: &str) -> String {
            fs::read_to_string(self.path.join(name)).unwrap()
        }
    }

    impl Drop for TestDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.path);
        }
    }

    // A real connection on localhost: the visitor's end, then the server's end.
    fn connected_pair() -> (TcpStream, TcpStream) {
        let listener = listen_on_localhost(0).unwrap();
        let visitor = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let (server, _) = listener.accept().unwrap();
        (visitor, server)
    }

    fn shared_limits(max_total: usize, max_per_ip: usize) -> Arc<Mutex<Limits>> {
        Arc::new(Mutex::new(Limits::new(max_total, max_per_ip)))
    }

    fn day_one() -> NaiveDate {
        NaiveDate::from_ymd_opt(2026, 10, 31).unwrap()
    }

    fn day_two() -> NaiveDate {
        NaiveDate::from_ymd_opt(2026, 11, 1).unwrap()
    }

    fn capped_log(dir: &TestDir, max_bytes: u64) -> CappedLog {
        let log = DailyLog::open(&dir.path, day_one()).unwrap();
        CappedLog::new(log, day_one(), max_bytes).unwrap()
    }

    fn shared_for(
        dir: &TestDir,
        max_total: usize,
        max_per_ip: usize,
        time_limit: Duration,
    ) -> Shared {
        let log = DailyLog::open(&dir.path, today()).unwrap();
        let limits = Limits::new(max_total, max_per_ip);
        Shared::new(log, limits, 1_000_000, time_limit).unwrap()
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
        String::from_utf8_lossy(&reply).to_string()
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

    // Threads finish in their own time, so some tests have to wait for them.
    fn wait_until(check: impl Fn() -> bool) -> bool {
        let deadline = Instant::now() + Duration::from_secs(5);
        while Instant::now() < deadline {
            if check() {
                return true;
            }
            thread::sleep(Duration::from_millis(5));
        }
        check()
    }

    #[test]
    fn ex1_gives_the_time_left() {
        let now = Instant::now();
        let deadline = now + Duration::from_secs(5);
        assert_eq!(time_left(deadline, now), Some(Duration::from_secs(5)));
    }

    #[test]
    fn ex1_nothing_is_left_at_the_deadline() {
        let now = Instant::now();
        assert_eq!(time_left(now, now), None);
    }

    #[test]
    fn ex1_nothing_is_left_after_the_deadline() {
        let deadline = Instant::now();
        let later = deadline + Duration::from_secs(1);
        assert_eq!(time_left(deadline, later), None);
    }

    #[test]
    fn ex2_passes_on_what_was_read() {
        let (_visitor, server) = connected_pair();
        let mut reader = TimeLimited::new(&server, LONG_LIMIT);
        assert_eq!(reader.finish_read(Ok(5)).unwrap(), 5);
        assert!(!reader.timed_out);
    }

    #[test]
    fn ex2_a_timeout_ends_the_input_and_is_remembered() {
        let (_visitor, server) = connected_pair();
        for kind in [io::ErrorKind::WouldBlock, io::ErrorKind::TimedOut] {
            let mut reader = TimeLimited::new(&server, LONG_LIMIT);
            assert_eq!(reader.finish_read(Err(kind.into())).unwrap(), 0);
            assert!(reader.timed_out);
        }
    }

    #[test]
    fn ex2_a_broken_connection_ends_the_input() {
        let (_visitor, server) = connected_pair();
        let mut reader = TimeLimited::new(&server, LONG_LIMIT);
        let error = io::ErrorKind::ConnectionReset.into();
        assert_eq!(reader.finish_read(Err(error)).unwrap(), 0);
        assert!(!reader.timed_out);
    }

    #[test]
    fn ex2_interrupted_stays_an_error() {
        let (_visitor, server) = connected_pair();
        let mut reader = TimeLimited::new(&server, LONG_LIMIT);
        let error = io::ErrorKind::Interrupted.into();
        assert!(reader.finish_read(Err(error)).is_err());
    }

    #[test]
    fn ex2_keeps_text_sent_without_a_newline() {
        let (mut visitor, server) = connected_pair();
        visitor.write_all(b"adm").unwrap();

        let mut reader = BufReader::new(TimeLimited::new(&server, SHORT_LIMIT));
        assert_eq!(read_answer(&mut reader).unwrap(), "adm");
        assert!(reader.get_ref().timed_out);
    }

    #[test]
    fn ex2_a_slow_drip_cannot_keep_a_visit_going() {
        let (mut visitor, server) = connected_pair();
        thread::spawn(move || {
            for _ in 0..1000 {
                if visitor.write_all(b"a").is_err() {
                    return;
                }
                thread::sleep(Duration::from_millis(10));
            }
        });

        let started = Instant::now();
        let mut reader = BufReader::new(TimeLimited::new(&server, SHORT_LIMIT));
        read_answer(&mut reader).unwrap();

        assert!(started.elapsed() < Duration::from_secs(1));
        assert!(reader.get_ref().timed_out);
    }

    #[test]
    fn ex3_an_unknown_address_has_no_connections() {
        assert_eq!(Limits::new(3, 2).count_for(IP_A), 0);
    }

    #[test]
    fn ex3_reads_the_count_for_that_address() {
        let mut limits = Limits::new(3, 2);
        limits.per_ip.insert(IP_A, 2);
        assert_eq!(limits.count_for(IP_A), 2);
        assert_eq!(limits.count_for(IP_B), 0);
    }

    #[test]
    fn ex4_counts_the_visitors_it_admits() {
        let mut limits = Limits::new(3, 2);
        assert!(limits.admit(IP_A));
        assert!(limits.admit(IP_B));
        assert_eq!(limits.count_for(IP_A), 1);
        assert_eq!(limits.total, 2);
    }

    #[test]
    fn ex4_stops_at_the_cap_for_one_address() {
        let mut limits = Limits::new(3, 2);
        assert!(limits.admit(IP_A));
        assert!(limits.admit(IP_A));
        assert!(!limits.admit(IP_A));
    }

    #[test]
    fn ex4_another_address_still_gets_in() {
        let mut limits = Limits::new(3, 2);
        limits.admit(IP_A);
        limits.admit(IP_A);
        assert!(limits.admit(IP_B));
    }

    #[test]
    fn ex4_stops_at_the_overall_cap() {
        let mut limits = Limits::new(3, 2);
        assert!(limits.admit(IP_A));
        assert!(limits.admit(IP_B));
        assert!(limits.admit(IP_C));
        assert!(!limits.admit(IP_B));
        let new_address = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 4));
        assert!(!limits.admit(new_address));
    }

    #[test]
    fn ex4_refusing_changes_nothing() {
        let mut limits = Limits::new(3, 1);
        limits.admit(IP_A);
        limits.admit(IP_A);
        assert_eq!(limits.count_for(IP_A), 1);
        assert_eq!(limits.total, 1);
    }

    #[test]
    fn ex5_lowers_the_counts() {
        let mut limits = Limits::new(3, 2);
        limits.admit(IP_A);
        limits.admit(IP_A);
        limits.release(IP_A);
        assert_eq!(limits.count_for(IP_A), 1);
        assert_eq!(limits.total, 1);
    }

    #[test]
    fn ex5_makes_room_again() {
        let mut limits = Limits::new(1, 1);
        limits.admit(IP_A);
        limits.release(IP_A);
        assert!(limits.admit(IP_B));
    }

    #[test]
    fn ex5_forgets_an_address_with_no_connections() {
        let mut limits = Limits::new(3, 2);
        limits.admit(IP_A);
        limits.release(IP_A);
        assert!(limits.per_ip.is_empty());
    }

    #[test]
    fn ex5_releasing_an_unknown_address_changes_nothing() {
        let mut limits = Limits::new(3, 2);
        limits.admit(IP_A);
        limits.release(IP_B);
        assert_eq!(limits.count_for(IP_A), 1);
        assert_eq!(limits.total, 1);
    }

    #[test]
    fn ex6_dropping_a_slot_gives_the_place_back() {
        let limits = shared_limits(1, 1);
        assert!(lock(&limits).admit(IP_A));

        drop(Slot {
            limits: Arc::clone(&limits),
            ip: IP_A,
        });

        assert_eq!(lock(&limits).count_for(IP_A), 0);
    }

    #[test]
    fn ex6_a_thread_that_crashes_still_gives_its_place_back() {
        let limits = shared_limits(1, 1);

        // This checks an ordinary drop first, because a crash during a crash would stop
        // every test at once.
        assert!(lock(&limits).admit(IP_A));
        drop(Slot {
            limits: Arc::clone(&limits),
            ip: IP_A,
        });

        assert!(lock(&limits).admit(IP_A));
        let slot = Slot {
            limits: Arc::clone(&limits),
            ip: IP_A,
        };
        let crashing = thread::spawn(move || {
            let _slot = slot;
            panic!("a made-up crash");
        });
        assert!(crashing.join().is_err());

        assert_eq!(lock(&limits).count_for(IP_A), 0);
    }

    #[test]
    fn ex6_works_after_a_crash_during_someone_elses_turn() {
        let limits = shared_limits(1, 1);
        assert!(lock(&limits).admit(IP_A));
        let slot = Slot {
            limits: Arc::clone(&limits),
            ip: IP_A,
        };

        let poisoner = Arc::clone(&limits);
        let crashing = thread::spawn(move || {
            let _turn = poisoner.lock().unwrap();
            panic!("a made-up crash");
        });
        assert!(crashing.join().is_err());

        drop(slot);
        assert_eq!(lock(&limits).count_for(IP_A), 0);
    }

    #[test]
    fn ex7_takes_a_place_when_there_is_room() {
        let limits = shared_limits(1, 1);
        let slot = Slot::try_take(&limits, IP_A);
        assert!(slot.is_some());
        assert_eq!(lock(&limits).count_for(IP_A), 1);
    }

    #[test]
    fn ex7_gives_none_when_there_is_no_room() {
        let limits = shared_limits(1, 1);
        let _first = Slot::try_take(&limits, IP_A);
        assert!(Slot::try_take(&limits, IP_A).is_none());
    }

    #[test]
    fn ex7_a_slot_shares_the_same_limits() {
        let limits = shared_limits(1, 1);
        let slot = Slot::try_take(&limits, IP_A);
        assert_eq!(Arc::strong_count(&limits), 2);
        drop(slot);
        assert_eq!(Arc::strong_count(&limits), 1);
    }

    #[test]
    fn ex7_the_place_comes_back_when_the_slot_goes_away() {
        let limits = shared_limits(1, 1);
        drop(Slot::try_take(&limits, IP_A));
        assert!(Slot::try_take(&limits, IP_B).is_some());
    }

    #[test]
    fn ex8_writes_lines_that_fit() {
        let dir = TestDir::new("ex8-fits");
        let mut log = capped_log(&dir, 100);
        assert!(log.append(day_one(), b"first\n").unwrap());
        assert!(log.append(day_one(), b"second\n").unwrap());
        assert_eq!(dir.read("visits-2026-10-31.jsonl"), "first\nsecond\n");
    }

    #[test]
    fn ex8_a_line_that_exactly_fits_is_written() {
        let dir = TestDir::new("ex8-exact");
        let mut log = capped_log(&dir, 6);
        assert!(log.append(day_one(), b"12345\n").unwrap());
    }

    #[test]
    fn ex8_leaves_out_a_whole_line_that_would_go_over() {
        let dir = TestDir::new("ex8-over");
        let mut log = capped_log(&dir, 10);
        assert!(log.append(day_one(), b"12345\n").unwrap());
        assert!(!log.append(day_one(), b"123456\n").unwrap());
        assert_eq!(dir.read("visits-2026-10-31.jsonl"), "12345\n");
    }

    #[test]
    fn ex8_a_shorter_line_can_still_fit_afterwards() {
        let dir = TestDir::new("ex8-shorter");
        let mut log = capped_log(&dir, 10);
        log.append(day_one(), b"12345\n").unwrap();
        log.append(day_one(), b"123456\n").unwrap();
        assert!(log.append(day_one(), b"123\n").unwrap());
    }

    #[test]
    fn ex8_a_new_day_gets_a_new_budget() {
        let dir = TestDir::new("ex8-new-day");
        let mut log = capped_log(&dir, 6);
        assert!(log.append(day_one(), b"12345\n").unwrap());
        assert!(!log.append(day_one(), b"12345\n").unwrap());
        assert!(log.append(day_two(), b"12345\n").unwrap());
        assert_eq!(dir.read("visits-2026-11-01.jsonl"), "12345\n");
    }

    #[test]
    fn ex8_restarting_does_not_reset_the_budget() {
        let dir = TestDir::new("ex8-restart");
        let mut log = capped_log(&dir, 10);
        log.append(day_one(), b"12345\n").unwrap();
        drop(log);

        let mut log = capped_log(&dir, 10);
        assert!(!log.append(day_one(), b"123456\n").unwrap());
    }

    #[test]
    fn ex9_a_silent_visitor_does_not_hold_up_the_next_one() {
        let dir = TestDir::new("ex9-silent");
        let shared = shared_for(&dir, 10, 10, LONG_LIMIT);
        let listener = listen_on_localhost(0).unwrap();
        let started = Instant::now();

        let _silent = visitor_of(&listener);
        serve_next(&listener, &shared).unwrap();

        let mut next = visitor_of(&listener);
        next.write_all(b"admin\n1234\n").unwrap();
        serve_next(&listener, &shared).unwrap();

        assert_eq!(reply_to(&mut next), REPLY);
        assert!(started.elapsed() < Duration::from_secs(5));
    }

    #[test]
    fn ex9_a_visit_holds_its_place_until_it_ends() {
        let dir = TestDir::new("ex9-holds");
        let shared = shared_for(&dir, 10, 10, LONG_LIMIT);
        let listener = listen_on_localhost(0).unwrap();

        let silent = visitor_of(&listener);
        serve_next(&listener, &shared).unwrap();
        assert_eq!(lock(&shared.limits).count_for(LOCALHOST), 1);

        drop(silent);
        assert!(wait_until(|| lock(&shared.limits).count_for(LOCALHOST) == 0));
    }

    #[test]
    fn ex9_refuses_a_visitor_over_the_limit() {
        let dir = TestDir::new("ex9-refuses");
        let shared = shared_for(&dir, 1, 1, LONG_LIMIT);
        let listener = listen_on_localhost(0).unwrap();

        let _first = visitor_of(&listener);
        serve_next(&listener, &shared).unwrap();

        let mut second = visitor_of(&listener);
        serve_next(&listener, &shared).unwrap();

        assert_eq!(reply_to(&mut second), "");
        assert_eq!(lock(&shared.limits).refused, 1);
    }

    #[test]
    fn ex9_logs_a_visit_and_gives_its_place_back() {
        let dir = TestDir::new("ex9-logs");
        let shared = shared_for(&dir, 10, 10, LONG_LIMIT);
        let listener = listen_on_localhost(0).unwrap();

        let mut visitor = visitor_of(&listener);
        visitor.write_all(b"admin\n1234\n").unwrap();
        serve_next(&listener, &shared).unwrap();
        assert_eq!(reply_to(&mut visitor), REPLY);

        let visits = logged_visits(&dir);
        assert_eq!(visits.len(), 1);
        assert_eq!(visits[0]["outcome"], "attempted");
        assert_eq!(visits[0]["username"], "admin");
        assert_eq!(visits[0]["password"], "1234");
        assert!(wait_until(|| lock(&shared.limits).count_for(LOCALHOST) == 0));
    }

    #[test]
    fn ex9_a_stuck_screen_cannot_hold_up_visits() {
        let dir = TestDir::new("ex9-stuck-screen");
        let mut shared = shared_for(&dir, 10, 10, LONG_LIMIT);
        let listener = listen_on_localhost(0).unwrap();

        // A queue with room for one line and nobody reading it, like a paused terminal.
        let (screen, _nobody_reading) = sync_channel(1);
        shared.screen = screen;

        for _ in 0..3 {
            let mut visitor = visitor_of(&listener);
            visitor.write_all(b"admin\n1234\n").unwrap();
            serve_next(&listener, &shared).unwrap();
            reply_to(&mut visitor);
        }

        assert_eq!(logged_visits(&dir).len(), 3);
        assert!(wait_until(|| lock(&shared.limits).count_for(LOCALHOST) == 0));
    }

    #[test]
    fn ex9_logs_someone_who_connects_and_leaves() {
        let dir = TestDir::new("ex9-leaves");
        let shared = shared_for(&dir, 10, 10, LONG_LIMIT);
        let listener = listen_on_localhost(0).unwrap();

        drop(visitor_of(&listener));
        serve_next(&listener, &shared).unwrap();

        assert!(wait_until(|| logged_visits(&dir).len() == 1));
        let visits = logged_visits(&dir);
        assert_eq!(visits[0]["outcome"], "left");
        assert!(visits[0]["username"].is_null());
    }

    #[test]
    fn ex9_keeps_text_sent_without_a_newline() {
        let dir = TestDir::new("ex9-partial");
        let shared = shared_for(&dir, 10, 10, SHORT_LIMIT);
        let listener = listen_on_localhost(0).unwrap();

        let mut visitor = visitor_of(&listener);
        visitor.write_all(b"adm").unwrap();
        serve_next(&listener, &shared).unwrap();
        reply_to(&mut visitor);

        let visits = logged_visits(&dir);
        assert_eq!(visits[0]["outcome"], "timed_out");
        assert_eq!(visits[0]["username"], "adm");
        assert!(visits[0]["password"].is_null());
    }

    #[test]
    fn ex9_a_half_typed_password_is_not_an_attempt() {
        let dir = TestDir::new("ex9-half-password");
        let shared = shared_for(&dir, 10, 10, SHORT_LIMIT);
        let listener = listen_on_localhost(0).unwrap();

        let mut visitor = visitor_of(&listener);
        visitor.write_all(b"admin\npw").unwrap();
        serve_next(&listener, &shared).unwrap();
        reply_to(&mut visitor);

        let visits = logged_visits(&dir);
        assert_eq!(visits[0]["outcome"], "timed_out");
        assert_eq!(visits[0]["username"], "admin");
        assert_eq!(visits[0]["password"], "pw");
    }
}
