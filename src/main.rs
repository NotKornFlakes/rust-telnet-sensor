// The honeypot program. It crashes with "not yet implemented" until you've done
// Stage 5. After that, the README shows how to try it.

// This makes the compiler refuse any `unsafe` code in this file.
#![forbid(unsafe_code)]

use std::env;
use std::fs;
use std::io;
use std::net::TcpListener;
use std::path::Path;
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use honeypot::deploy::{
    MAX_TRACKED_ADDRESSES, MAX_VISITS_PER_MINUTE, RateLimit, Settings, current_uid, refuse_root,
};
use honeypot::fake_shell::{
    Credentials, MAX_SHELL_BYTES_PER_DAY, MAX_SHELL_BYTES_PER_IP, ShellBudget,
};
use honeypot::fake_web::{MAX_WEB_BYTES_PER_DAY, MAX_WEB_BYTES_PER_IP};
use honeypot::log_files::{DailyLog, today};
use honeypot::login::TIMEOUT;
use honeypot::server::{
    Limits, MAX_CONNECTIONS, MAX_LOG_BYTES_PER_DAY, MAX_PER_IP, Shared, handle_service_visit,
    handle_web_visit, serve_next, serve_next_with,
};
use honeypot::services::services_from;

const LOG_DIR: &str = "logs";

fn main() -> io::Result<()> {
    refuse_root(current_uid()?)?;

    // `skip(1)` leaves out the program's own name, like `sys.argv[1:]` in Python.
    let args: Vec<String> = env::args().skip(1).collect();
    let settings = Settings::from_args(&args)?;
    let listener = settings.open_listener()?;

    // This refuses to start if other users could read the logs.
    let log = DailyLog::open(Path::new(LOG_DIR), today())?;
    let limits = Limits::new(MAX_CONNECTIONS, MAX_PER_IP);
    let rate = RateLimit::new(MAX_VISITS_PER_MINUTE, MAX_TRACKED_ADDRESSES);
    let mut shared =
        Shared::new(log, limits, MAX_LOG_BYTES_PER_DAY, TIMEOUT)?.with_rate_limit(rate);

    // The fake shell from Stage 7 stays off unless you ask for it. If the list can't be read or
    // has a mistake in it, the program refuses to start, so you find out straight away.
    if let Some(path) = settings.credentials() {
        let credentials = Credentials::parse(&fs::read_to_string(path)?)?;
        println!("Fake shell on, for {} login(s).", credentials.count());
        let budget = ShellBudget::new(
            MAX_SHELL_BYTES_PER_IP,
            MAX_SHELL_BYTES_PER_DAY,
            MAX_TRACKED_ADDRESSES,
        );
        shared = shared.with_fake_shell(credentials, budget);
    }

    // The fake web service from Stage 8 stays off unless you give it an address. It shares the
    // limits and the log with the login, and has its own daily budget, like the shell.
    if let Some(address) = settings.web_listen() {
        let budget = ShellBudget::new(
            MAX_WEB_BYTES_PER_IP,
            MAX_WEB_BYTES_PER_DAY,
            MAX_TRACKED_ADDRESSES,
        );
        shared = shared.with_fake_web(budget);
        let web_listener = TcpListener::bind(address)?;
        println!(
            "Fake web service listening on {}.",
            web_listener.local_addr()?
        );
        let web_shared = shared.clone();
        thread::Builder::new().spawn(move || {
            keep_serving(|| serve_next_with(&web_listener, &web_shared, handle_web_visit))
        })?;
    }

    // The fake FTP and SSH services from Stage 10 stay off unless you give them an address. Each
    // one gets its own thread, and the same code serves all of them. Without either flag this
    // never calls Stage 10's code, so `cargo run` works before you've written it.
    let wants_services = settings.ftp_listen().is_some() || settings.ssh_listen().is_some();
    let services = if wants_services {
        services_from(&settings)
    } else {
        Vec::new()
    };
    for (address, service) in services {
        let service_listener = TcpListener::bind(address)?;
        println!(
            "Fake {} service listening on {}.",
            service.name(),
            service_listener.local_addr()?
        );
        let service_shared = shared.clone();
        thread::Builder::new().spawn(move || {
            keep_serving(|| {
                let service = Arc::clone(&service);
                serve_next_with(
                    &service_listener,
                    &service_shared,
                    move |stream, ip, shared| handle_service_visit(stream, ip, shared, &*service),
                )
            })
        })?;
    }

    println!("Fake login listening on {}.", listener.local_addr()?);
    println!("Press Ctrl+C to stop.");

    keep_serving(|| serve_next(&listener, &shared))
}

// Serves one connection after another, for ever.
fn keep_serving(mut serve_one: impl FnMut() -> io::Result<()>) -> ! {
    loop {
        // An error here means a connection couldn't be accepted or a thread couldn't
        // start. If the computer has run out of something, this would fail again at once,
        // so wait a moment instead of using all the CPU reporting it.
        if let Err(error) = serve_one() {
            eprintln!("could not serve a connection: {error}");
            thread::sleep(Duration::from_millis(100));
        }
    }
}
