# Security Policy

This is a research honeypot. It is *meant* to be attacked by bots on the internet, so
"someone logged in to the fake shell" is not a vulnerability. What matters is whether the
safety design holds: nothing a visitor sends is ever run, fetched or echoed back, and the
server never connects out.

## Supported versions

There are no numbered releases. Only the latest commit on `master` is supported, and fixes
land there.

| Version                  | Supported          |
| ------------------------ | ------------------ |
| Latest `master`          | :white_check_mark: |
| Older commits and forks  | :x:                |

## What counts as a vulnerability

Please report anything that breaks the safety design, for example:

- A way to make the fake shell run, fetch or download anything, or start an outbound connection
- A way to make the fake shell send back text a visitor typed (every reply is supposed to be fixed text built into the program)
- A way out of the fake shell into the real server, or past the systemd sandbox in `deploy/host/honeypot.service`
- A gap in `deploy/host/nftables.conf` or `deploy/gcp/main.tf` that lets the server connect out, or exposes the admin port (22) to the internet
- Log files readable by anyone other than the `honeypot` user, or visitor data kept longer than the retention period
- A crash or resource exhaustion that a visitor can trigger to take the program down or affect the server
- A vulnerable dependency (CI also runs `cargo audit` on every push)

## What doesn't

- **That bots or people can tell it's a honeypot.** A fixed-reply shell is easy to spot, and the report documents this. Ideas for making it more convincing are welcome as a normal issue.
- **The attacks the honeypot records.** Report the source IPs to [AbuseIPDB](https://www.abuseipdb.com/) or the network's abuse contact, not here.
- **Logging in with the default credentials.** That's the bait.

## Reporting a vulnerability

**Please don't open a public issue.** Report it privately through GitHub:
go to the **Security** tab of this repository and choose **Report a vulnerability**.

Include what you found, the steps to reproduce it, and what you think the impact is.

**Test against your own copy, not the live server.** The program listens on `127.0.0.1:2323`
by default, so you can run it locally with `cargo run` and test safely. The live deployment
holds real visitor logs.

## What to expect

This is a one-person project, so these are honest targets rather than guarantees:

- **Acknowledgement** within 7 days.
- **An update** at least every 14 days until it's resolved.
- **If it's accepted:** I'll fix it on `master`, and if the live server is affected, close its
  public port first with the kill switch in `deploy/README.md`. You'll be credited in the fix
  and in a GitHub security advisory, unless you'd rather stay anonymous.
- **If it's declined:** I'll explain why, usually because it falls under "What doesn't" above.

Good-faith research that follows this policy is welcome, and I won't pursue action against
anyone who reports a problem this way.

