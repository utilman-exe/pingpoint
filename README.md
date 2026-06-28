# pingpoint

**Smart, cross-platform network diagnostics in pure Python.**

When someone says *"I don't have internet,"* `pingpoint` tells you **why** — not just *that* something's broken, but *which layer* failed and how to fix it. It checks connectivity from the bottom up, stops at the first thing that's actually wrong, and explains it in plain language instead of dumping raw output. It can also **monitor continuously**, alert you when something breaks, watch **specific servers**, trace the **network path**, and measure real **speed**.

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
![Python 3](https://img.shields.io/badge/python-3.6%2B-blue.svg)
![Platform](https://img.shields.io/badge/platform-Linux%20%7C%20macOS%20%7C%20Windows-lightgrey.svg)
![Dependencies](https://img.shields.io/badge/dependencies-none-brightgreen.svg)

```
           _                         _       __
    ____  (_)___  ____ _____  ____  (_)___  / /_
   / __ \/ / __ \/ __ `/ __ \/ __ \/ / __ \/ __/
  / /_/ / / / / / /_/ / /_/ / /_/ / / / / / /_
 / .___/_/_/ /_/\__, / .___/\____/_/_/ /_/\__/
/_/            /____/_/
                         made by utilman
```

---

## Why

Most network tools either show you everything (`ifconfig`, `mtr`, `ping` — you interpret it) or nothing useful (the OS "troubleshooter" that spins and says "couldn't fix the problem"). `pingpoint` does the interpretation a network engineer would: ping the gateway, then an IP, then a name — and reason about *where* the chain breaks.

> Connectivity works by IP but names don't resolve → **it's DNS**, not your connection.
> Gateway is reachable but `1.1.1.1` isn't → **it's your ISP**, not your computer.

That single distinction answers most "the internet is down" complaints.

## Features

- **Layered, fail-fast diagnosis** — checks each layer in order and stops at the first real failure, so you get one clear answer instead of a wall of red.
- **Big, obvious verdict** — a one-line summary at the top plus bold `HEALTHY` / `PROBLEM` ASCII art, so you can read the result at a glance.
- **Plain-language diagnosis + fix** for every failure mode.
- **Connection quality** — latency, jitter and packet-loss sampling, so "it's not down, just bad" becomes a concrete number.
- **Automatic path trace** — an mtr-style traceroute runs on its own and shows where the path stops responding.
- **IPv6 posture** — flags the sneaky case where you have an IPv6 address but can't actually use it (apps that prefer v6 then hang).
- **System-clock check** — a wrong clock silently breaks HTTPS; pingpoint catches it.
- **Router/modem identification** — names the gateway's vendor from its MAC.
- **Speed test** — real download/upload throughput on demand.
- **Continuous monitoring** (`--watch`) — re-checks on an interval, logs problems compactly, and prints a summary when you stop.
- **Server watchlist** — confirm specific URLs/IPs are reachable; tells "that server is down" apart from "your network is down."
- **Alerts** — notify Microsoft Teams / Slack / Discord / Power Automate via `--webhook`, or send email via `--email-to`, on problem and recovery.
- **Catches the common "no internet" causes** other tools miss: captive portals, `169.254` self-assigned (APIPA) addresses, airplane mode / disabled adapters.
- **Auto-fix mode** (`--fix`) — offers to run the matching remedy (DHCP renew, DNS flush, re-enable adapter…) with per-step confirmation.
- **Copy / save / `--json`**; exit code `0` = healthy, `1` = problem found.
- **Zero dependencies.** One standard-library Python file. Nothing to `pip install`.

## What it detects

| Layer | Catches |
|-------|---------|
| Adapter / radio | Disabled adapter, airplane mode, Wi-Fi off |
| Address | DHCP failure, `169.254` self-assigned (APIPA) address |
| Routing | Missing default gateway, unreachable router |
| Upstream | ISP / modem outage (with an automatic path trace) |
| Quality | Packet loss, high jitter, high latency |
| Portal | Captive "sign-in" pages (hotel, airport, café) |
| DNS | Resolver down, misconfigured, or slow |
| IPv6 | Has an address but the IPv6 internet is unreachable |
| Clock | System time wrong enough to break HTTPS |
| HTTP | Firewall / proxy blocking, broken TLS |
| Path | MTU / fragmentation issues |
| Watchlist | A specific URL/IP/server being unreachable |

## Install & run

`pingpoint` is a single self-contained Python script — no installation, no dependencies.

```bash
git clone https://github.com/utilman-exe/pingpoint.git
cd pingpoint
python3 pingpoint.py
```

Or just download `pingpoint.py` on its own and run it.

> **Requirement:** Python 3. Linux and macOS ship it already. On Windows, install it from [python.org](https://www.python.org/downloads/) and tick *"Add Python to PATH"* during setup, then run `python pingpoint.py`.

## Usage

```bash
python3 pingpoint.py                 # full diagnosis (+ automatic path trace)
python3 pingpoint.py example.com     # also monitor a specific URL/IP
python3 pingpoint.py --fix           # offer to run the matching fix
python3 pingpoint.py --speedtest     # include a download/upload speed test
python3 pingpoint.py --traffic       # include live up/down throughput
python3 pingpoint.py --no-trace      # skip the path trace (faster)
python3 pingpoint.py --json          # machine-readable output
```

### Watching specific servers

Give any URL or IP — as a positional argument, `--target`, `--check` (repeatable), or `--targets` (comma-separated). URLs are checked over HTTP, `host:port` via a TCP connect, bare hosts/IPs via ping (falling back to TCP if ICMP is blocked):

```bash
python3 pingpoint.py https://api.myapp.com
python3 pingpoint.py --check https://api.myapp.com --check 10.0.0.5:5432
python3 pingpoint.py --targets "github.com,1.1.1.1,db.internal:5432"
```

If your network is healthy but a watched server is down, pingpoint says so explicitly — *the problem is on their side, not your connection.*

### Continuous mode

`--watch` re-checks on an interval (default 10s). It runs a fast, light cycle and **logs only when something breaks**, so you get a clean record of when it dropped. Any URL/IP you pass is monitored every cycle too.

```bash
python3 pingpoint.py --watch                         # monitor the local connection
python3 pingpoint.py --watch 1.1.1.1 --interval 5    # also monitor a server, every 5s
python3 pingpoint.py --watch --full                  # run the deep checks every cycle
python3 pingpoint.py --watch --log ~/net.log         # custom log path
```

Press **Ctrl-C** for a summary — duration, number of checks, problem count, a causes breakdown, first/last times, and the longest outage:

```
  ── watch summary ──
  ran 2h 14m · 803 checks
  4 problem cycle(s) detected.
  causes:        dns×3, isp×1
  first / last:  2026-06-27 14:05:22  ->  2026-06-27 18:41:09
  longest outage: ~40s (8 consecutive checks)
```

The log stays small on purpose: one compact line per problem cycle, one full report the first time each new cause appears, and it **auto-rotates at 2 MB** (keeping one `.1` backup).

### Alerts (Teams / Slack / Discord / email)

In continuous mode, get notified on the **onset** of a problem and on **recovery** (not every cycle — no spam):

```bash
# Microsoft Teams (or Slack / Discord / Power Automate) incoming webhook
python3 pingpoint.py --watch --webhook "https://...logic.azure.com/.../invoke?...&sig=..."

# Email (defaults to Office 365 / Outlook SMTP)
python3 pingpoint.py --watch --email-to you@company.com \
  --smtp-user you@company.com --smtp-pass APP_PASSWORD
```

The webhook payload is auto-formatted per provider (a Teams Message Card for Teams/Power Automate URLs, Slack/Discord formats otherwise). SMTP credentials can also come from the `PINGPOINT_SMTP_USER` / `PINGPOINT_SMTP_PASS` environment variables so they stay out of your shell history. (Outlook/Office 365 needs an **app password**; Gmail works with `--smtp-host smtp.gmail.com`.)

**Setting up Microsoft Teams:** the old "Incoming Webhook" connector is retired — use the built-in **Workflows** app instead (it's free and keeps data in your tenant; skip third-party webhook apps). Create a flow with the *"When a Teams webhook request is received"* trigger, set **Who can trigger the flow → Anyone**, add a *Post message* action whose message uses the expression `triggerBody()?['text']`, save, then copy the generated URL and pass it to `--webhook`.

## Sample output

```text
  >> HEALTHY — no issues found

  SYSTEM
    Host       thinkpad
    Interface  wlan0
    IPv4       192.168.1.50/24
    Gateway    192.168.1.1
    Router     Netgear  (28:c6:8e:aa:bb:cc)
    DNS        1.1.1.1, 8.8.8.8
    Wi-Fi SSID HomeNet_5G
    Signal     -47 dBm / 78%   (Excellent)
    Speed      down 234 Mbps   up 45 Mbps

  CHECKS  (11 run, 3.4s)
  [ OK ]  Local IP ... Default gateway ... Internet by IP ... Captive portal
  [ OK ]  Connection quality  -  12ms  0% loss  3ms jitter
  [ OK ]  IPv6 ... System clock ... DNS resolution  -  24ms via 1.1.1.1
  [ OK ]  Load site by name ... Path MTU

██╗  ██╗███████╗ █████╗ ██╗  ████████╗██╗  ██╗██╗   ██╗
██║  ██║██╔════╝██╔══██╗██║  ╚══██╔══╝██║  ██║╚██╗ ██╔╝
███████║█████╗  ███████║██║     ██║   ███████║ ╚████╔╝
██╔══██║██╔══╝  ██╔══██║██║     ██║   ██╔══██║  ╚██╔╝
██║  ██║███████╗██║  ██║███████╗██║   ██║  ██║   ██║
╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝╚══════╝╚═╝   ╚═╝  ╚═╝   ╚═╝

  DIAGNOSIS
  Network is fully healthy. No issues found.

  PATH TO 1.1.1.1
     1  192.168.1.1      1ms
     2  10.0.0.1         8ms
     3  1.1.1.1          11ms
```

When something fails you get the red `PROBLEM` art, the diagnosis, and the fix instead.

## How it works

Pure standard library throughout. DNS resolution and HTTP checks run in Python itself (`socket`, `urllib`), so they're identical on every OS — only ping, route discovery, traceroute, throughput, and Wi-Fi/MAC lookup need platform-specific commands (`ip`/`ifconfig`/`ipconfig`, `traceroute`/`tracert`, `iw`/`nmcli`/`netsh`, `/proc/net/dev`/`netstat`). Every external command has a timeout, so it never hangs. The deep checks (quality, IPv6, clock, DNS speed) run in parallel to keep a full run fast, and are skipped during continuous polling unless you pass `--full`.

`--fix` maps each diagnosis to a known remedy and runs it only after you confirm, auto-prefixing `sudo` when needed (or telling Windows users to run as Administrator). Failure modes with no safe automatic fix — captive portals, ISP outages — say so rather than guessing.

## Limitations

- The live code path is tested on **Linux**. The macOS and Windows command parsers are written and logic-tested but not yet run on those platforms — output mismatches are possible, and PRs/issues with sample output are very welcome.
- The router-vendor list is a curated subset of common OUIs; unknown ones show the raw MAC.
- The `HEALTHY` / `PROBLEM` art uses block characters; it renders on modern terminals (incl. mobile Termux, iTerm, Windows Terminal). Use `--no-color` on a terminal that can't display them.

## Contributing

Issues and pull requests are welcome — especially real-world output from macOS and Windows to harden the parsers. Keep it dependency-free (standard library only).

## License

[MIT](LICENSE) — do whatever you like, just keep the copyright notice.
