# pingpoint

**Smart, cross-platform network diagnostics in pure Python.**

When someone says *"I don't have internet,"* `pingpoint` tells you **why** — not just *that* something's broken, but *which layer* failed and how to fix it. It runs connectivity checks from the bottom up, stops at the first thing that's actually wrong, and explains it in plain language instead of dumping raw output.

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
![Python 3](https://img.shields.io/badge/python-3.6%2B-blue.svg)
![Platform](https://img.shields.io/badge/platform-Linux%20%7C%20macOS%20%7C%20Windows-lightgrey.svg)
![Dependencies](https://img.shields.io/badge/dependencies-none-brightgreen.svg)

---

## Why

Most network tools either show you everything (`ifconfig`, `mtr`, `ping` — you interpret it) or nothing useful (the OS "troubleshooter" that spins and says "couldn't fix the problem"). `pingpoint` does the interpretation a network engineer would: ping the gateway, then an IP, then a name — and reason about *where* the chain breaks.

> Connectivity works by IP but names don't resolve → **it's DNS**, not your connection.
> Gateway is reachable but `1.1.1.1` isn't → **it's your ISP**, not your computer.

That single distinction answers most "the internet is down" complaints.

## Features

- **Layered, fail-fast diagnosis** — checks each layer in order and stops at the first real failure, so you get one clear answer instead of a wall of red.
- **Plain-language diagnosis + fix** for every failure mode.
- **System summary** — interface, MAC, IPv4 + subnet, gateway, DNS servers, Wi-Fi SSID & signal strength, and public IP.
- **Catches the common "no internet" causes** other tools miss: captive portals, `169.254` self-assigned (APIPA) addresses, airplane mode / disabled adapters.
- **Auto-fix mode** (`--fix`) — offers to run the matching remedy (DHCP renew, DNS flush, re-enable adapter…) with per-step confirmation.
- **Copy / save** — after each run, optionally copy the report to your clipboard or save it as a `.txt` in Downloads.
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
python3 pingpoint.py                  # run the diagnosis
python3 pingpoint.py --fix            # offer to run the matching fix
python3 pingpoint.py --fix --yes      # run fixes without confirming (careful)
python3 pingpoint.py --target SITE    # also test reaching a specific host
python3 pingpoint.py --json           # machine-readable output
python3 pingpoint.py --no-public      # skip the public-IP lookup
```

## Sample output

Healthy network:

```text
  SYSTEM
    Host       thinkpad
    OS         Linux 6.8
    Interface  wlan0
    MAC        a4:c3:f0:11:22:33
    IPv4       192.168.1.50/24
    Subnet     192.168.1.0/24
    Gateway    192.168.1.1
    DNS        1.1.1.1, 8.8.8.8
    Wi-Fi SSID HomeNet_5G
    Signal     -47 dBm / 78%   (Excellent)
    Public IP  203.0.113.7   (what the internet sees)

  CHECKS  (8 run, 1.2s)
  ----------------------------------------------------
  [ OK ]  Local IP address  -  192.168.1.50/24
  [ OK ]  Default gateway  -  192.168.1.1
  [ OK ]  Reach gateway  -  192.168.1.1  2ms
  [ OK ]  Internet by IP  -  1.1.1.1  11ms
  [ OK ]  Captive portal  -  none
  [ OK ]  DNS resolution  -  names resolving
  [ OK ]  Load site by name  -  sites loading
  [ OK ]  Path MTU (1500)  -  1500-byte packets pass

  DIAGNOSIS
  Network is fully healthy. No issues found.
```

Behind an airport captive portal:

```text
  CHECKS  (5 run, 2.4s)
  ----------------------------------------------------
  [ OK ]  Local IP address  -  10.5.12.88/16
  [ OK ]  Default gateway  -  10.5.0.1
  [ OK ]  Reach gateway  -  10.5.0.1  3ms
  [ OK ]  Internet by IP  -  1.1.1.1  39ms
  [FAIL]  Captive portal  -  login page intercepting traffic

  DIAGNOSIS
  You're behind a captive portal — the 'sign in to Wi-Fi' page you get on
  hotel, airport, or café networks. Raw connectivity works, but web requests
  are redirected to a login page until you sign in.

  SUGGESTED FIXES
    • Open any website in a browser to trigger the login page.
    • Accept the terms / enter the access code, then re-run this.
```

## How it works

Pure standard library throughout. DNS resolution and HTTP checks run in Python itself (`socket`, `urllib`), so they're identical on every OS — only ping, route discovery, and Wi-Fi/MAC lookup need platform-specific commands (`ip`/`ifconfig`/`ipconfig`, `iw`/`nmcli`/`airport`/`netsh`). Every external command has a timeout, so it never hangs.

`--fix` maps each diagnosis to a known remedy and runs it only after you confirm, auto-prefixing `sudo` when needed (or telling Windows users to run as Administrator). Failure modes with no safe automatic fix — captive portals, ISP outages — say so rather than guessing.

## Limitations

- The live code path is tested on **Linux**. The macOS and Windows command parsers are written and logic-tested but not yet run on those platforms — output mismatches are possible, and PRs/issues with sample output are very welcome.
- IPv4 only for now (IPv6 checks are planned).

## Contributing

Issues and pull requests are welcome — especially real-world output from macOS and Windows to harden the parsers. Keep it dependency-free (standard library only).

## License

[MIT](LICENSE) — do whatever you like, just keep the copyright notice.
