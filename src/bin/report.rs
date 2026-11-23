// The report tool from Stage 9. It reads logs you've downloaded, on your own computer, and prints a
// summary. It's never uploaded to the server, and it never connects to anything. `src/report.rs`
// does the work, and this is a worked example that hands it the files.
//
// ```text
// cargo run --bin report -- ~/honeypot-logs --rules deploy/rules.txt
// ```

// This makes the compiler refuse any `unsafe` code in this file.
#![forbid(unsafe_code)]

use std::env;
use std::fs;
use std::io;

use honeypot::log_files::{check_private, dated_log_files};
use honeypot::report::{Report, ReportOptions, Rule};

fn main() -> io::Result<()> {
    let args: Vec<String> = env::args().skip(1).collect();
    let options = ReportOptions::from_args(&args)?;

    // Safety rule 4 applies on your computer too. If anyone else could read the logs, stop and say
    // so, as the honeypot itself does, instead of quietly reading them.
    check_private(&options.folder)?;

    let rules = match &options.rules {
        Some(path) => Rule::parse_rules(&fs::read_to_string(path)?)?,
        None => Vec::new(),
    };
    let mut report = Report::new(rules);

    // Only files named exactly like `visits-2026-11-03.jsonl`, oldest first.
    let mut files = dated_log_files(&options.folder)?;
    files.sort_by_key(|(_, date)| *date);
    for (path, _) in files {
        check_private(&path)?;
        // `from_utf8_lossy`, because a damaged file shouldn't stop the report.
        let bytes = fs::read(&path)?;
        for line in String::from_utf8_lossy(&bytes).lines() {
            report.add_line(line);
        }
    }

    print!("{}", report.render(options.top, options.show_secrets));
    Ok(())
}
