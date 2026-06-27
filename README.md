# pingpoint

**Smart, cross-platform network diagnostics in pure Python.**

When someone says *"I don't have internet,"* `pingpoint` tells you **why** — not just *that* something's broken, but *which layer* failed and how to fix it. It runs connectivity checks from the bottom up, stops at the first thing that's actually wrong, and explains it in plain language instead of dumping raw output. It can also **monitor continuously**, log only when something breaks, watch **specific servers**, and show **live throughput**.

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
- **Big, obvious verdict** — bold `HEALTHY` / `PROBLEM` ASCII art so you can read the result at a glance.
- **Plain-language diagnosis + fix** for every failure mode.
- **System summary** — interface, MAC, IPv4 + subnet, gateway, DNS servers, Wi-Fi SSID & signal strength, public IP, and live throughput.
- **Continuous monitoring** (`--watch`) — re-checks on an interval and logs the full report **only when something breaks**, perfect for catching intermittent drops.
- **Server watchlist** (`--check`) — confirm specific URLs/IPs are reachable; distinguishes "that server is down" from "your network is down."
- **Live throughput** (`--traffic`) — current up/down rate from the interface counters.
- **Catches the common "no internet" causes** other tools miss: captive portals, `169.254` self-assigned (APIPA) addresses, airplane mode / disabled adapters.
- **Auto-fix mode** (`--fix`) — offers to run the matching remedy (DHCP renew, DNS flush, re-enable adapter…) with per-step confirmation.
- **Copy / save** — after a run, optionally copy the report to your clipboard or save it as a `.txt` in Downloads.
- **`--json`** for scripting and monitoring; exit code `0` = healthy, `1` = problem found.
- **Zero dependencies.** One standard-library Python file. Nothing to `pip install`.

## What it detects

| Layer | Catches |
|-------|---------|
| Adapter / radio | Disabled adapter, airplane mode, Wi-Fi off |
| Address | DHCP failure, `169.254` self-assigned (APIPA) address |
| Routing | Missing default gateway, unreachable router |
| Upstream | ISP / modem outage |
| Portal | Captive "sign-in" pages (hotel, airport, café) |
| DNS | Resolver down or misconfigured |
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

Or just download `pingpoint.py` on its own and run it:

```bash
python3 pingpoint.py
```

> **Requirement:** Python 3. Linux and macOS ship it already. On Windows, install it from [python.org](https://www.python.org/downloads/) and tick *"Add Python to PATH"* during setup, then run `python pingpoint.py`.

## Usage

```bash
python3 pingpoint.py                       # run the diagnosis
python3 pingpoint.py --fix                 # offer to run the matching fix
python3 pingpoint.py --target SITE         # also test reaching one host
python3 pingpoint.py --traffic             # include up/down throughput
python3 pingpoint.py --json                # machine-readable output
python3 pingpoint.py --no-public           # skip the public-IP lookup
```

### Monitoring an intermittent issue

`--watch` re-checks on an interval (default 10s) and logs the **full report only when a problem is found**, so you end up with a clean timestamped record of when it dropped:

```bash
python3 pingpoint.py --watch                       # every 10s, log to Downloads
python3 pingpoint.py --watch --interval 5          # every 5s
python3 pingpoint.py --watch --log ~/net.log       # custom log path
```

The console shows a compact line each cycle; the log (`pingpoint_watch_YYYYMMDD.log`) gets the full report for problem cycles, plus a note when it recovers:

```
[2026-06-27 14:05:12] OK        net 11ms   down 1.2 MB/s up 84 KB/s
[2026-06-27 14:05:22] PROBLEM   DNS is failing — internet works but names don't resolve
[2026-06-27 14:05:32] OK        net 12ms   down 1.4 MB/s up 90 KB/s   <- recovered
```

The logged **category** of each failure (`dns`, `no_gateway`, `isp`, `captive`…) tells you whether it's the same cause each time or something flapping upstream, and the timestamps reveal the frequency and duration.

### Watching specific servers

Confirm one or more servers are reachable — URLs are checked over HTTP, `host:port` via a TCP connect, bare hosts/IPs via ping (falling back to TCP if ICMP is blocked):

```bash
python3 pingpoint.py --check https://api.myapp.com --check 10.0.0.5:5432
python3 pingpoint.py --targets "github.com,1.1.1.1,db.internal:5432"
```

If your network is healthy but a watched server is down, pingpoint says so explicitly — *"these servers are unreachable… the problem is on their side, not your connection."* Combine with `--watch` to log exactly when a server drops:

```bash
python3 pingpoint.py --watch --check https://api.myapp.com --check 8.8.8.8
```

## Sample output

A healthy network ends with the big green verdict:

```text
  SYSTEM
    Host       thinkpad
    Interface  wlan0
    IPv4       192.168.1.50/24
    Gateway    192.168.1.1
    DNS        1.1.1.1, 8.8.8.8
    Wi-Fi SSID HomeNet_5G
    Signal     -47 dBm / 78%   (Excellent)
    Traffic    down 1.2 MB/s   up 84.0 KB/s

  CHECKS  (8 run, 1.2s)
  [ OK ]  Local IP address ... Default gateway ... Internet by IP ...
  [ OK ]  Captive portal ... DNS resolution ... Load site by name ... Path MTU

██╗  ██╗███████╗ █████╗ ██╗  ████████╗██╗  ██╗██╗   ██╗
██║  ██║██╔════╝██╔══██╗██║  ╚══██╔══╝██║  ██║╚██╗ ██╔╝
███████║█████╗  ███████║██║     ██║   ███████║ ╚████╔╝
██╔══██║██╔══╝  ██╔══██║██║     ██║   ██╔══██║  ╚██╔╝
██║  ██║███████╗██║  ██║███████╗██║   ██║  ██║   ██║
╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝╚══════╝╚═╝   ╚═╝  ╚═╝   ╚═╝

  DIAGNOSIS
  Network is fully healthy. No issues found.
```

When something fails, you get the red `PROBLEM` art, the diagnosis, and the fix:

```text
  [FAIL]  Captive portal  -  login page intercepting traffic

██████╗ ██████╗  ██████╗ ██████╗ ██╗     ███████╗███╗   ███╗
██╔══██╗██╔══██╗██╔═══██╗██╔══██╗██║     ██╔════╝████╗ ████║
██████╔╝██████╔╝██║   ██║██████╔╝██║     █████╗  ██╔████╔██║
██╔═══╝ ██╔══██╗██║   ██║██╔══██╗██║     ██╔══╝  ██║╚██╔╝██║
██║     ██║  ██║╚██████╔╝██████╔╝███████╗███████╗██║ ╚═╝ ██║
╚═╝     ╚═╝  ╚═╝ ╚═════╝ ╚═════╝ ╚══════╝╚══════╝╚═╝     ╚═╝

  DIAGNOSIS
  You're behind a captive portal — the 'sign in to Wi-Fi' page you get on
  hotel, airport, or café networks. Raw connectivity works, but web requests
  are redirected to a login page until you sign in.

  SUGGESTED FIXES
    • Open any website in a browser to trigger the login page.
    • Accept the terms / enter the access code, then re-run this.
```

## How it works

Pure standard library throughout. DNS resolution and HTTP checks run in Python itself (`socket`, `urllib`), so they're identical on every OS — only ping, route discovery, throughput, and Wi-Fi/MAC lookup need platform-specific commands (`ip`/`ifconfig`/`ipconfig`, `iw`/`nmcli`/`airport`/`netsh`, `/proc/net/dev`/`netstat`). Every external command has a timeout, so it never hangs.

`--fix` maps each diagnosis to a known remedy and runs it only after you confirm, auto-prefixing `sudo` when needed (or telling Windows users to run as Administrator). Failure modes with no safe automatic fix — captive portals, ISP outages — say so rather than guessing.

## Limitations

- The live code path is tested on **Linux**. The macOS and Windows command parsers are written and logic-tested but not yet run on those platforms — output mismatches are possible, and PRs/issues with sample output are very welcome.
- IPv4 only for now (IPv6 checks are planned).
- The `HEALTHY` / `PROBLEM` art uses block characters; it renders on modern terminals (incl. mobile Termux, iTerm, Windows Terminal). Use `--no-color` on a terminal that can't display them.

## Contributing

Issues and pull requests are welcome — especially real-world output from macOS and Windows to harden the parsers. Keep it dependency-free (standard library only).

## License

[MIT](LICENSE) — do whatever you like, just keep the copyright notice.
