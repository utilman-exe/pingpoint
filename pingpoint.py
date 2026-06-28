#!/usr/bin/env python3
"""
pingpoint - a smart, cross-platform network diagnostic tool.

Runs bottom-up connectivity checks, stops reasoning at the first broken
layer, and tells you in plain language what's wrong and how to fix it.
Prints a SYSTEM summary (IP/subnet/gateway/DNS/interface/public IP) first.

Pure standard library. No dependencies. Works on Linux, macOS, Windows.
Usage:
    python3 pingpoint.py            # run diagnosis
    python3 pingpoint.py --json     # machine-readable output
    python3 pingpoint.py --target example.com   # also test a specific host
    python3 pingpoint.py --no-public            # skip public-IP lookup
    python3 pingpoint.py --no-color
"""

import argparse
import concurrent.futures
import ipaddress
import json
import os
import platform
import re
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.request

OS = platform.system()  # 'Linux', 'Darwin', 'Windows'

PUBLIC_IPS = ["1.1.1.1", "8.8.8.8"]
PUBLIC_HOSTS = ["cloudflare.com", "google.com", "wikipedia.org"]
PUBLIC_IP_SERVICES = ["https://api.ipify.org", "https://icanhazip.com",
                      "http://ifconfig.me/ip"]


# --------------------------------------------------------------------------- #
# Output helpers
# --------------------------------------------------------------------------- #
class C:
    enabled = sys.stdout.isatty() and os.environ.get("TERM") != "dumb"

    @classmethod
    def disable(cls):
        cls.enabled = False

    @classmethod
    def w(cls, code, s):
        return f"\033[{code}m{s}\033[0m" if cls.enabled else s


def green(s):  return C.w("32", s)
def red(s):    return C.w("31", s)
def yellow(s): return C.w("33", s)
def cyan(s):   return C.w("36", s)
def bold(s):   return C.w("1", s)
def dim(s):    return C.w("2", s)


# --------------------------------------------------------------------------- #
# ASCII art
# --------------------------------------------------------------------------- #
LOGO = '           _                         _       __ \n    ____  (_)___  ____ _____  ____  (_)___  / /_\n   / __ \\/ / __ \\/ __ `/ __ \\/ __ \\/ / __ \\/ __/\n  / /_/ / / / / / /_/ / /_/ / /_/ / / / / / /_  \n / .___/_/_/ /_/\\__, / .___/\\____/_/_/ /_/\\__/  \n/_/            /____/_/                         '

ART_HEALTHY = '██╗  ██╗███████╗ █████╗ ██╗  ████████╗██╗  ██╗██╗   ██╗\n██║  ██║██╔════╝██╔══██╗██║  ╚══██╔══╝██║  ██║╚██╗ ██╔╝\n███████║█████╗  ███████║██║     ██║   ███████║ ╚████╔╝ \n██╔══██║██╔══╝  ██╔══██║██║     ██║   ██╔══██║  ╚██╔╝  \n██║  ██║███████╗██║  ██║███████╗██║   ██║  ██║   ██║   \n╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝╚══════╝╚═╝   ╚═╝  ╚═╝   ╚═╝   \n                                                       '

ART_PROBLEM = '██████╗ ██████╗  ██████╗ ██████╗ ██╗     ███████╗███╗   ███╗\n██╔══██╗██╔══██╗██╔═══██╗██╔══██╗██║     ██╔════╝████╗ ████║\n██████╔╝██████╔╝██║   ██║██████╔╝██║     █████╗  ██╔████╔██║\n██╔═══╝ ██╔══██╗██║   ██║██╔══██╗██║     ██╔══╝  ██║╚██╔╝██║\n██║     ██║  ██║╚██████╔╝██████╔╝███████╗███████╗██║ ╚═╝ ██║\n╚═╝     ╚═╝  ╚═╝ ╚═════╝ ╚═════╝ ╚══════╝╚══════╝╚═╝     ╚═╝\n                                                            '


def banner():
    """Logo shown immediately on launch, so you know it's working."""
    art = green(LOGO) if C.enabled else LOGO
    return art + "\n" + dim("                         made by utilman") + "\n"


def status_art(healthy):
    art = ART_HEALTHY if healthy else ART_PROBLEM
    return (green(art) if healthy else red(art)) if C.enabled else art


PASS, FAIL, WARN, INFO = "PASS", "FAIL", "WARN", "INFO"


def badge(status):
    return {
        PASS: green("[ OK ]"),
        FAIL: red("[FAIL]"),
        WARN: yellow("[WARN]"),
        INFO: cyan("[INFO]"),
    }[status]


# --------------------------------------------------------------------------- #
# Low-level helpers
# --------------------------------------------------------------------------- #
def run(cmd, timeout=6):
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return p.returncode, p.stdout, p.stderr
    except FileNotFoundError:
        return 127, "", "command not found"
    except subprocess.TimeoutExpired:
        return 124, "", "timeout"
    except Exception as e:  # pragma: no cover
        return 1, "", str(e)


def ping(host, count=2, timeout_s=2):
    if OS == "Windows":
        cmd = ["ping", "-n", str(count), "-w", str(timeout_s * 1000), host]
    else:
        flag = "-W" if OS == "Linux" else "-t"
        cmd = ["ping", "-c", str(count), flag, str(timeout_s), host]
    rc, out, _ = run(cmd, timeout=count * timeout_s + 4)
    m = re.search(r"=\s*[\d.]+/([\d.]+)/", out) or \
        re.search(r"Average\s*=\s*(\d+)ms", out)
    return rc == 0, (float(m.group(1)) if m else None)


def mtu_probe(host="1.1.1.1"):
    payload = 1472  # +28 header = 1500
    if OS == "Windows":
        cmd = ["ping", "-n", "1", "-f", "-l", str(payload), "-w", "2000", host]
    elif OS == "Linux":
        cmd = ["ping", "-c", "1", "-M", "do", "-s", str(payload), "-W", "2", host]
    else:
        cmd = ["ping", "-c", "1", "-D", "-s", str(payload), "-t", "2", host]
    rc, out, _ = run(cmd, timeout=6)
    if rc == 0:
        return "ok"
    if re.search(r"frag|too long|message too long|needs to be fragmented", out, re.I):
        return "mtu_issue"
    return "unknown"


def mask_to_cidr(mask):
    """Convert '255.255.255.0' or '0xffffff00' to a prefix length int."""
    try:
        if mask.lower().startswith("0x"):
            return bin(int(mask, 16)).count("1")
        return sum(bin(int(o)).count("1") for o in mask.split("."))
    except (ValueError, AttributeError):
        return None


# --------------------------------------------------------------------------- #
# OS-specific discovery
# --------------------------------------------------------------------------- #
def local_ipv4():
    """Return list of dicts: {'iface', 'ip', 'cidr'} for non-loopback IPv4."""
    out_list = []
    if OS == "Linux":
        rc, out, _ = run(["ip", "-4", "-o", "addr", "show"])
        for line in out.splitlines():
            m = re.search(r"\d+:\s+(\S+)\s+inet (\d+\.\d+\.\d+\.\d+)/(\d+)", line)
            if m and not m.group(2).startswith("127."):
                out_list.append({"iface": m.group(1), "ip": m.group(2),
                                 "cidr": int(m.group(3))})
    elif OS == "Darwin":
        rc, out, _ = run(["ifconfig"])
        cur = None
        for line in out.splitlines():
            h = re.match(r"^(\w+):", line)
            if h:
                cur = h.group(1)
            m = re.search(r"inet (\d+\.\d+\.\d+\.\d+) netmask (0x[0-9a-fA-F]+)", line)
            if m and not m.group(1).startswith("127."):
                out_list.append({"iface": cur, "ip": m.group(1),
                                 "cidr": mask_to_cidr(m.group(2))})
    elif OS == "Windows":
        rc, out, _ = run(["ipconfig"])
        ip = None
        for line in out.splitlines():
            mi = re.search(r"IPv4 Address[.\s]*:\s*(\d+\.\d+\.\d+\.\d+)", line)
            mm = re.search(r"Subnet Mask[.\s]*:\s*(\d+\.\d+\.\d+\.\d+)", line)
            if mi:
                ip = mi.group(1)
            elif mm and ip:
                out_list.append({"iface": None, "ip": ip, "cidr": mask_to_cidr(mm.group(1))})
                ip = None

    if not out_list:  # universal fallback (no subnet info available)
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("1.1.1.1", 80))
            out_list.append({"iface": None, "ip": s.getsockname()[0], "cidr": None})
            s.close()
        except OSError:
            pass
    return out_list


def default_route():
    """Return (gateway_ip or None, interface or None)."""
    if OS == "Linux":
        rc, out, _ = run(["ip", "route", "show", "default"])
        gw = re.search(r"default via (\d+\.\d+\.\d+\.\d+)", out)
        dev = re.search(r"dev (\S+)", out)
        return (gw.group(1) if gw else None, dev.group(1) if dev else None)
    if OS == "Darwin":
        rc, out, _ = run(["route", "-n", "get", "default"])
        gw = re.search(r"gateway:\s*(\d+\.\d+\.\d+\.\d+)", out)
        dev = re.search(r"interface:\s*(\S+)", out)
        return (gw.group(1) if gw else None, dev.group(1) if dev else None)
    if OS == "Windows":
        rc, out, _ = run(["ipconfig"])
        gw = re.search(r"Default Gateway[.\s]*:\s*(\d+\.\d+\.\d+\.\d+)", out)
        return (gw.group(1) if gw else None, None)
    return (None, None)


def dns_servers():
    """Return list of configured DNS server IPs (best-effort)."""
    servers = []
    if OS == "Linux":
        try:
            with open("/etc/resolv.conf") as f:
                servers = re.findall(r"nameserver\s+(\d+\.\d+\.\d+\.\d+)", f.read())
        except OSError:
            pass
        # systemd-resolved often shows only the 127.0.0.53 stub; ask resolvectl.
        if servers in ([], ["127.0.0.53"]):
            rc, out, _ = run(["resolvectl", "status"])
            real = re.findall(r"DNS Servers?:\s*([\d.\s]+)", out)
            for chunk in real:
                servers += re.findall(r"\d+\.\d+\.\d+\.\d+", chunk)
    elif OS == "Darwin":
        rc, out, _ = run(["scutil", "--dns"])
        servers = re.findall(r"nameserver\[\d+\]\s*:\s*(\d+\.\d+\.\d+\.\d+)", out)
    elif OS == "Windows":
        rc, out, _ = run(["ipconfig", "/all"])
        servers = re.findall(r"DNS Servers[.\s]*:\s*(\d+\.\d+\.\d+\.\d+)", out)
    # dedupe, preserve order
    seen, uniq = set(), []
    for s in servers:
        if s not in seen:
            seen.add(s); uniq.append(s)
    return uniq


def public_ip(timeout=4):
    for url in PUBLIC_IP_SERVICES:
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "pingpoint"})
            with urllib.request.urlopen(req, timeout=timeout) as r:
                ip = r.read().decode().strip()
                if re.match(r"^\d+\.\d+\.\d+\.\d+$", ip):
                    return ip
        except Exception:
            continue
    return None


def mac_address(iface, ip=None):
    """MAC of the active interface (best-effort)."""
    if OS == "Linux":
        if iface:
            try:
                with open(f"/sys/class/net/{iface}/address") as f:
                    mac = f.read().strip()
                    if mac and mac != "00:00:00:00:00:00":
                        return mac
            except OSError:
                pass
        rc, out, _ = run(["ip", "link", "show"] + ([iface] if iface else []))
        m = re.search(r"link/ether (\S+)", out)
        return m.group(1) if m else None
    if OS == "Darwin":
        rc, out, _ = run(["ifconfig"] + ([iface] if iface else []))
        m = re.search(r"\bether (\S+)", out)
        return m.group(1) if m else None
    if OS == "Windows":
        rc, out, _ = run(["ipconfig", "/all"])
        # Try to match the adapter block that owns our IP; else first MAC found.
        if ip:
            blocks = re.split(r"\n(?=[^\s].*:\s*\n)", out)
            for b in blocks:
                if ip in b:
                    m = re.search(r"Physical Address[.\s]*:\s*([0-9A-Fa-f-]{17})", b)
                    if m:
                        return m.group(1)
        m = re.search(r"Physical Address[.\s]*:\s*([0-9A-Fa-f-]{17})", out)
        return m.group(1) if m else None
    return None


def signal_quality(dbm=None, pct=None):
    if dbm is not None:
        return ("Excellent" if dbm >= -50 else "Good" if dbm >= -60
                else "Fair" if dbm >= -70 else "Weak")
    if pct is not None:
        return ("Excellent" if pct >= 75 else "Good" if pct >= 50
                else "Fair" if pct >= 25 else "Weak")
    return None


def wifi_info(iface):
    """Return {'ssid', 'signal_dbm', 'signal_pct'} or None if not on Wi-Fi."""
    res = {"ssid": None, "signal_dbm": None, "signal_pct": None}
    if OS == "Linux":
        # nmcli gives signal as a percentage; iw gives dBm. Use both if present.
        rc, out, _ = run(["nmcli", "-t", "-f", "ACTIVE,SSID,SIGNAL", "dev", "wifi"])
        if rc == 0:
            for line in out.splitlines():
                p = line.split(":")
                if len(p) >= 3 and p[0] == "yes":
                    res["ssid"] = p[1] or res["ssid"]
                    try:
                        res["signal_pct"] = int(p[2])
                    except ValueError:
                        pass
        if iface:
            rc, out, _ = run(["iw", "dev", iface, "link"])
            ms = re.search(r"SSID:\s*(.+)", out)
            md = re.search(r"signal:\s*(-?\d+)\s*dBm", out)
            if ms and not res["ssid"]:
                res["ssid"] = ms.group(1).strip()
            if md:
                res["signal_dbm"] = int(md.group(1))
    elif OS == "Darwin":
        airport = ("/System/Library/PrivateFrameworks/Apple80211.framework"
                   "/Versions/Current/Resources/airport")
        rc, out, _ = run([airport, "-I"])
        if rc == 0 and out.strip():
            ms = re.search(r"\bSSID:\s*(.+)", out)
            md = re.search(r"agrCtlRSSI:\s*(-?\d+)", out)
            if ms:
                res["ssid"] = ms.group(1).strip()
            if md:
                res["signal_dbm"] = int(md.group(1))
        else:  # airport removed on newer macOS; fall back to system_profiler
            rc, out, _ = run(["system_profiler", "SPAirPortDataType"], timeout=10)
            ms = re.search(r"Current Network Information:\s*\n\s*(.+?):", out)
            md = re.search(r"Signal\s*/\s*Noise:\s*(-?\d+)\s*dBm", out)
            if ms:
                res["ssid"] = ms.group(1).strip()
            if md:
                res["signal_dbm"] = int(md.group(1))
    elif OS == "Windows":
        rc, out, _ = run(["netsh", "wlan", "show", "interfaces"])
        ms = re.search(r"^\s*SSID\s*:\s*(.+)$", out, re.M)
        mp = re.search(r"Signal\s*:\s*(\d+)%", out)
        if ms:
            res["ssid"] = ms.group(1).strip()
        if mp:
            res["signal_pct"] = int(mp.group(1))
    return res if res["ssid"] else None


def is_apipa(ip):
    """169.254.x.x = self-assigned 'automatic private' address => DHCP failed."""
    return bool(ip) and ip.startswith("169.254.")


def link_status(iface):
    """Best-effort: is the adapter up and the radio enabled?
    Returns {'any_up': bool|None, 'radio_blocked': bool|None}."""
    st = {"any_up": None, "radio_blocked": None}
    if OS == "Linux":
        rc, out, _ = run(["ip", "link"])
        if rc == 0:
            ups = re.findall(r"\d+:\s+(\S+):\s+<([^>]*)>.*state (\S+)", out)
            non_lo_up = [n for n, flags, state in ups
                         if n != "lo" and ("UP" in state or "UP" in flags)]
            st["any_up"] = len(non_lo_up) > 0
        rc, out, _ = run(["rfkill", "list"])
        if rc == 0:
            st["radio_blocked"] = bool(
                re.search(r"(Soft|Hard) blocked:\s*yes", out))
    elif OS == "Darwin":
        rc, out, _ = run(["networksetup", "-listallhardwareports"])
        wifi_dev = None
        m = re.search(r"Wi-Fi\s*\n\s*Device:\s*(\S+)", out)
        if m:
            wifi_dev = m.group(1)
        if wifi_dev:
            rc, out, _ = run(["networksetup", "-getairportpower", wifi_dev])
            if rc == 0:
                st["radio_blocked"] = "Off" in out
    elif OS == "Windows":
        rc, out, _ = run(["netsh", "interface", "show", "interface"])
        if rc == 0:
            states = re.findall(r"^\s*(Enabled|Disabled)\s+(Connected|Disconnected)",
                                out, re.M)
            st["any_up"] = any(s[0] == "Enabled" and s[1] == "Connected"
                               for s in states)
    return st


def captive_portal():
    """Detect a hotel/airport-style login portal.
    Returns 'portal', 'clear', or 'unknown'."""

    class _NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, *a):
            return None  # turn redirects into HTTPError so we can see them

    opener = urllib.request.build_opener(_NoRedirect)
    # 1) generate_204 endpoints: a clean network returns 204 + empty body.
    for url in ("http://connectivitycheck.gstatic.com/generate_204",
                "http://www.gstatic.com/generate_204"):
        try:
            with opener.open(url, timeout=4) as resp:
                body = resp.read(64)
                if resp.status == 204 and not body:
                    return "clear"
                return "portal"  # 200 + content where 204 was expected
        except urllib.error.HTTPError as e:
            if 300 <= e.code < 400:
                return "portal"  # redirected to a login page
        except Exception:
            continue
    # 2) Apple's endpoint: a clean network returns the literal body "Success".
    try:
        with opener.open("http://captive.apple.com/hotspot-detect.html",
                         timeout=4) as resp:
            body = resp.read(200).decode(errors="ignore")
            return "clear" if "Success" in body else "portal"
    except urllib.error.HTTPError as e:
        if 300 <= e.code < 400:
            return "portal"
    except Exception:
        pass
    return "unknown"


# --------------------------------------------------------------------------- #
# Pure-Python checks
# --------------------------------------------------------------------------- #
def dns_resolves(host, timeout=3):
    socket.setdefaulttimeout(timeout)
    try:
        socket.getaddrinfo(host, 80)
        return True
    except (socket.gaierror, socket.timeout, OSError):
        return False
    finally:
        socket.setdefaulttimeout(None)


def http_ok(host, timeout=5):
    for scheme in ("https", "http"):
        try:
            req = urllib.request.Request(f"{scheme}://{host}",
                                         headers={"User-Agent": "pingpoint"})
            with urllib.request.urlopen(req, timeout=timeout) as r:
                if r.status < 500:
                    return True
        except Exception:
            continue
    return False


# --------------------------------------------------------------------------- #
# Diagnostic engine
# --------------------------------------------------------------------------- #
class Report:
    def __init__(self):
        self.info = {}
        self.checks = []
        self.diagnosis = None
        self.fixes = []
        self.category = "healthy"  # used by --fix to pick a remedy

    def add(self, name, status, detail=""):
        self.checks.append((name, status, detail))

    def diagnose(self, text, fixes, category=None):
        self.diagnosis = text
        self.fixes = fixes
        if category:
            self.category = category


def gather_info(want_public=True):
    addrs = local_ipv4()
    gw, dev = default_route()
    primary = addrs[0] if addrs else {}
    subnet = None
    if primary.get("ip") and primary.get("cidr") is not None:
        try:
            net = ipaddress.ip_network(f"{primary['ip']}/{primary['cidr']}", strict=False)
            subnet = str(net)
        except ValueError:
            pass
    iface = primary.get("iface") or dev
    gw_mac = gateway_mac(gw)
    return {
        "host": socket.gethostname(),
        "os": f"{OS} {platform.release()}",
        "interface": iface,
        "mac": mac_address(iface, primary.get("ip")),
        "addresses": addrs,
        "subnet": subnet,
        "gateway": gw,
        "gateway_mac": gw_mac,
        "router_vendor": router_vendor(gw_mac),
        "dns": dns_servers(),
        "wifi": wifi_info(iface),
        "public_ip": None,  # filled later only if connectivity is confirmed
        "_want_public": want_public,
    }


def _iface_bytes():
    """Cumulative (rx_bytes, tx_bytes) across active interfaces, or None."""
    try:
        if OS == "Linux":
            rx = tx = 0
            with open("/proc/net/dev") as f:
                for line in f.readlines()[2:]:
                    name, _, data = line.partition(":")
                    if name.strip() == "lo":
                        continue
                    cols = data.split()
                    if len(cols) >= 16:
                        rx += int(cols[0]); tx += int(cols[8])
            return rx, tx
        elif OS == "Darwin":
            _, out, _ = run(["netstat", "-ibn"])
            seen, rx, tx = set(), 0, 0
            for line in out.splitlines()[1:]:
                c = line.split()
                if len(c) >= 10 and c[0] != "lo0" and c[0] not in seen:
                    try:
                        rx += int(c[6]); tx += int(c[9]); seen.add(c[0])
                    except ValueError:
                        continue
            return rx, tx
        elif OS == "Windows":
            _, out, _ = run(["netstat", "-e"])
            nums = re.findall(r"Bytes\s+(\d+)\s+(\d+)", out)
            if nums:
                return int(nums[0][0]), int(nums[0][1])
    except Exception:
        pass
    return None


def throughput(interval=1.0):
    """Sample byte counters over `interval` seconds → (down_Bps, up_Bps)."""
    a = _iface_bytes()
    if a is None:
        return None
    time.sleep(interval)
    b = _iface_bytes()
    if b is None:
        return None
    return max(0, (b[0] - a[0]) / interval), max(0, (b[1] - a[1]) / interval)


def rate(bps):
    """Bytes/sec → human string."""
    if bps is None:
        return "?"
    for unit in ("B/s", "KB/s", "MB/s", "GB/s"):
        if bps < 1024:
            return f"{bps:.0f} {unit}" if unit == "B/s" else f"{bps:.1f} {unit}"
        bps /= 1024
    return f"{bps:.1f} TB/s"


def check_target(t, timeout=5):
    """Reachability of a URL, host:port, or bare host/IP. Returns a dict."""
    t = t.strip()
    start = time.time()
    ms = lambda: (time.time() - start) * 1000

    if t.startswith(("http://", "https://")):
        try:
            req = urllib.request.Request(t, headers={"User-Agent": "pingpoint"},
                                         method="HEAD")
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                return {"target": t, "kind": "http", "ok": resp.status < 500,
                        "ms": ms(), "detail": f"HTTP {resp.status}"}
        except urllib.error.HTTPError as e:
            return {"target": t, "kind": "http", "ok": e.code < 500,
                    "ms": ms(), "detail": f"HTTP {e.code}"}
        except Exception:
            return {"target": t, "kind": "http", "ok": False, "ms": None,
                    "detail": "unreachable"}

    # host:port ?
    host, port = None, None
    if t.count(":") == 1:
        h, p = t.rsplit(":", 1)
        if p.isdigit():
            host, port = h, int(p)
    if host:
        try:
            socket.create_connection((host, port), timeout=timeout).close()
            return {"target": t, "kind": "tcp", "ok": True, "ms": ms(),
                    "detail": f"port {port} open"}
        except Exception:
            return {"target": t, "kind": "tcp", "ok": False, "ms": None,
                    "detail": f"port {port} closed/unreachable"}

    # bare host or IP: ping, then fall back to TCP 443/80 (ICMP may be blocked)
    ok, lat = ping(t)
    if ok:
        return {"target": t, "kind": "ping", "ok": True,
                "ms": lat, "detail": "ping ok"}
    for p in (443, 80):
        try:
            socket.create_connection((t, p), timeout=timeout).close()
            return {"target": t, "kind": "tcp", "ok": True, "ms": ms(),
                    "detail": f"tcp/{p} ok (ICMP blocked)"}
        except Exception:
            continue
    return {"target": t, "kind": "ping", "ok": False, "ms": None,
            "detail": "unreachable"}


def check_targets(targets, timeout=5):
    if not targets:
        return []
    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as ex:
        return list(ex.map(lambda t: check_target(t, timeout), targets))


def ping_stats(host, count=10, interval=0.2, timeout=2):
    """Multi-packet ping → {loss, min, avg, max, jitter} (ms), or None."""
    if OS == "Windows":
        cmd = ["ping", "-n", str(count), "-w", str(int(timeout * 1000)), host]
    elif OS == "Linux":
        cmd = ["ping", "-c", str(count), "-i", str(interval), "-W", str(timeout), host]
    else:  # Darwin
        cmd = ["ping", "-c", str(count), "-i", str(interval), host]
    rc, out, _ = run(cmd, timeout=count * (interval + timeout) + 10)
    st = {"loss": None, "min": None, "avg": None, "max": None, "jitter": None}
    m = re.search(r"([\d.]+)%\s*packet loss", out) or re.search(r"\((\d+)% loss\)", out)
    if m:
        st["loss"] = float(m.group(1))
    m = re.search(r"=\s*([\d.]+)/([\d.]+)/([\d.]+)(?:/([\d.]+))?\s*ms", out)
    if m:
        st["min"], st["avg"], st["max"] = (float(m.group(i)) for i in (1, 2, 3))
        if m.group(4):
            st["jitter"] = float(m.group(4))
    else:
        mm = re.search(r"Minimum = (\d+)ms.*?Maximum = (\d+)ms.*?Average = (\d+)ms",
                       out, re.S)
        if mm:
            st["min"], st["max"], st["avg"] = (float(mm.group(i)) for i in (1, 2, 3))
    return st if (st["loss"] is not None or st["avg"] is not None) else None


def quality_verdict(st):
    """(status, note) from ping stats."""
    loss = st.get("loss") or 0
    jit = st.get("jitter")
    avg = st.get("avg")
    bits = []
    if avg is not None:
        bits.append(f"{avg:.0f}ms")
    if loss:
        bits.append(f"{loss:.0f}% loss")
    if jit is not None:
        bits.append(f"{jit:.0f}ms jitter")
    note = "  ".join(bits) or "ok"
    if loss >= 20:
        return FAIL, note + " — severe packet loss"
    if loss >= 5:
        return WARN, note + " — packet loss"
    if jit is not None and jit >= 50:
        return WARN, note + " — high jitter (calls/video will stutter)"
    if jit is not None and jit >= 30:
        return WARN, note + " — elevated jitter"
    return PASS, note


def check_ipv6():
    """{addr, reachable, aaaa} — IPv6 posture."""
    res = {"addr": None, "reachable": None, "aaaa": None}
    try:
        s = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
        s.connect(("2606:4700:4700::1111", 80))
        ip = s.getsockname()[0]
        s.close()
        if ip and not ip.startswith(("fe80", "::1")):
            res["addr"] = ip
    except OSError:
        pass
    if res["addr"]:
        if OS == "Windows":
            cmd = ["ping", "-n", "2", "-6", "-w", "2000", "2606:4700:4700::1111"]
        elif OS == "Linux":
            cmd = ["ping", "-6", "-c", "2", "-W", "2", "2606:4700:4700::1111"]
        else:
            cmd = ["ping6", "-c", "2", "2606:4700:4700::1111"]
        rc, _, _ = run(cmd, timeout=8)
        res["reachable"] = rc == 0
    try:
        socket.getaddrinfo("cloudflare.com", 80, socket.AF_INET6)
        res["aaaa"] = True
    except Exception:
        res["aaaa"] = False
    return res


def dns_speed(hosts=("cloudflare.com", "google.com", "wikipedia.org")):
    """Average resolution time in ms, or None."""
    times = []
    for h in hosts:
        t = time.time()
        try:
            socket.getaddrinfo(h, 80)
            times.append((time.time() - t) * 1000)
        except Exception:
            pass
    return sum(times) / len(times) if times else None


def clock_skew():
    """Compare system clock to an HTTP Date header (over http, so a bad clock
    can't break it). Returns skew in seconds (local - server), or None."""
    import email.utils
    for url in ("http://cloudflare.com", "http://www.google.com"):
        try:
            req = urllib.request.Request(url, method="HEAD",
                                         headers={"User-Agent": "pingpoint"})
            with urllib.request.urlopen(req, timeout=5) as r:
                d = r.headers.get("Date")
                if d:
                    server = email.utils.parsedate_to_datetime(d).timestamp()
                    return time.time() - server
        except Exception:
            continue
    return None


def traceroute(target="1.1.1.1", max_hops=15):
    """Run the OS traceroute. Returns list of {hop, ip, ms, timeout}."""
    if OS == "Windows":
        cmd = ["tracert", "-d", "-h", str(max_hops), "-w", "1000", target]
    else:
        cmd = ["traceroute", "-n", "-w", "1", "-q", "1", "-m", str(max_hops), target]
    rc, out, _ = run(cmd, timeout=max_hops * 2 + 12)
    hops = []
    for line in out.splitlines():
        m = re.match(r"\s*(\d+)\s+(.*)", line)
        if not m:
            continue
        rest = m.group(2)
        ipm = re.search(r"(\d+\.\d+\.\d+\.\d+)", rest)
        latm = re.search(r"([\d.]+)\s*ms", rest)
        hops.append({"hop": int(m.group(1)), "ip": ipm.group(1) if ipm else None,
                     "ms": float(latm.group(1)) if latm else None,
                     "timeout": ipm is None})
    return hops


ROUTER_OUI = {
    # Curated common router / modem / AP vendor OUIs (first 3 octets).
    "00095B": "Netgear", "001E2A": "Netgear", "001F33": "Netgear",
    "00223F": "Netgear", "0024B2": "Netgear", "0026F2": "Netgear",
    "08BD43": "Netgear", "204E7F": "Netgear", "28C68E": "Netgear",
    "44947F": "Netgear", "9C3DCF": "Netgear", "C03F0E": "Netgear",
    "E0469A": "Netgear", "E091F5": "Netgear",
    "14CC20": "TP-Link", "50C7BF": "TP-Link", "60E327": "TP-Link",
    "A42BB0": "TP-Link", "AC84C6": "TP-Link", "EC086B": "TP-Link",
    "F4F26D": "TP-Link", "30B5C2": "TP-Link", "98DAC4": "TP-Link",
    "001BFC": "ASUS", "002215": "ASUS", "04D4C4": "ASUS", "08606E": "ASUS",
    "1C872C": "ASUS", "2C56DC": "ASUS", "305A3A": "ASUS", "50465D": "ASUS",
    "AC9E17": "ASUS", "B06EBF": "ASUS", "D850E6": "ASUS", "F832E4": "ASUS",
    "000C41": "Linksys/Cisco", "001839": "Linksys", "001A70": "Linksys",
    "0021299": "Linksys", "48F8B3": "Linksys", "C0C1C0": "Cisco",
    "00055D": "D-Link", "001346": "D-Link", "001CF0": "D-Link",
    "1C7EE5": "D-Link", "28107B": "D-Link", "84C9B2": "D-Link",
    "B8A386": "D-Link", "C8BE19": "D-Link", "F07D68": "D-Link",
    "00156D": "Ubiquiti", "002722": "Ubiquiti", "0418D6": "Ubiquiti",
    "245A4C": "Ubiquiti", "44D9E7": "Ubiquiti", "788A20": "Ubiquiti",
    "B4FBE4": "Ubiquiti", "DC9FDB": "Ubiquiti", "FCECDA": "Ubiquiti",
    "0000CA": "Arris", "00159A": "Arris", "001DCD": "Arris", "14358B": "Arris",
    "3C754A": "Arris", "44E137": "Arris", "84E058": "Arris", "BC644B": "Arris",
    "00147F": "Technicolor", "1CC63C": "Technicolor", "289EFC": "Technicolor",
    "44 32C8": "Technicolor", "5C353B": "Technicolor", "88F7C7": "Technicolor",
    "001882": "Huawei", "001E10": "Huawei", "04C06F": "Huawei",
    "286ED4": "Huawei", "5C7D5E": "Huawei", "84A8E4": "Huawei", "ACE215": "Huawei",
    "0015EB": "ZTE", "0019C6": "ZTE", "4C09B4": "ZTE", "986CF5": "ZTE",
    "D0608C": "ZTE", "F46DE2": "ZTE",
    "001349": "Zyxel", "0023F8": "Zyxel", "5CE28C": "Zyxel", "B0B2DC": "Zyxel",
    "000C42": "MikroTik", "18FD74": "MikroTik", "488F5A": "MikroTik",
    "6C3B6B": "MikroTik", "CC2DE0": "MikroTik", "E48D8C": "MikroTik",
    "000B86": "Aruba", "186472": "Aruba", "6CF37F": "Aruba", "ACA31E": "Aruba",
    "000A95": "Apple", "001B63": "Apple", "28CFDA": "Apple", "3C0754": "Apple",
    "60334B": "Apple", "A8BBCF": "Apple",
    "001A11": "Google", "30FD38": "Google", "388B59": "Google",
    "6CADF8": "Google", "F4F5D8": "Google", "F4F5E8": "Google",
    "244B81": "eero", "84531C": "eero", "F0214A": "eero",
    "000FB3": "Actiontec", "001F90": "Actiontec", "00247B": "Actiontec",
    "A021B7": "Actiontec", "FC51A4": "Actiontec",
    "001A2B": "Sagemcom", "1499E2": "Sagemcom", "44E9DD": "Sagemcom",
    "98C691": "Sagemcom", "F88E85": "Sagemcom",
}


def gateway_mac(gw):
    """MAC of the gateway from the ARP/neighbour table. Returns MAC or None."""
    if not gw:
        return None
    out = ""
    if OS == "Linux":
        rc, out, _ = run(["ip", "neigh", "show", gw])
        if "lladdr" not in out:
            rc, out, _ = run(["arp", "-n", gw])
    elif OS == "Darwin":
        rc, out, _ = run(["arp", "-n", gw])
    elif OS == "Windows":
        rc, out, _ = run(["arp", "-a", gw])
    m = re.search(r"([0-9a-fA-F]{2}(?:[:-][0-9a-fA-F]{2}){5})", out)
    return m.group(1) if m else None


def router_vendor(mac):
    if not mac:
        return None
    oui = re.sub(r"[^0-9A-Fa-f]", "", mac)[:6].upper()
    return ROUTER_OUI.get(oui)


def _download_speed(seconds=5):
    url = "https://speed.cloudflare.com/__down?bytes=100000000"
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "pingpoint"})
        start = time.time()
        total = 0
        with urllib.request.urlopen(req, timeout=15) as r:
            while True:
                chunk = r.read(65536)
                if not chunk or time.time() - start >= seconds:
                    total += len(chunk)
                    break
                total += len(chunk)
        el = time.time() - start
        return (total * 8 / el / 1e6) if el > 0 else None
    except Exception:
        return None


def _upload_speed(seconds=4):
    url = "https://speed.cloudflare.com/__up"
    try:
        data = b"0" * (8 * 1024 * 1024)
        req = urllib.request.Request(url, data=data, method="POST",
                                     headers={"Content-Type": "application/octet-stream",
                                              "User-Agent": "pingpoint"})
        start = time.time()
        with urllib.request.urlopen(req, timeout=20) as r:
            r.read()
        el = time.time() - start
        return (len(data) * 8 / el / 1e6) if el > 0 else None
    except Exception:
        return None


def speed_test():
    """Returns {down_mbps, up_mbps} via Cloudflare's speed endpoint."""
    return {"down_mbps": _download_speed(), "up_mbps": _upload_speed()}


def notify_webhook(url, title, text):
    """POST a message to a webhook, formatted for the detected provider."""
    if "hooks.slack.com" in url:
        payload = {"text": f"*{title}*\n{text}"}
    elif "discord.com/api/webhooks" in url or "discordapp.com" in url:
        payload = {"content": f"**{title}**\n{text}"}
    elif any(d in url for d in ("office.com", "logic.azure.com",
                                "powerautomate", "teams.microsoft")):
        # Microsoft Teams Workflows / Power Automate. MessageCard is the
        # supported drop-in format and also carries plain title/text fields,
        # so custom flows that read 'text' still work.
        payload = {"@type": "MessageCard",
                   "@context": "http://schema.org/extensions",
                   "summary": title, "themeColor": "D7263D",
                   "title": title, "text": text.replace("\n", "  \n")}
    else:  # generic
        payload = {"title": title, "text": text, "message": f"{title}\n{text}"}
    try:
        req = urllib.request.Request(
            url, data=json.dumps(payload).encode(),
            headers={"Content-Type": "application/json", "User-Agent": "pingpoint"})
        urllib.request.urlopen(req, timeout=10).read()
        return True
    except Exception:
        return False


def send_email(cfg, subject, body):
    """Send an alert email via SMTP (defaults to Office 365)."""
    import smtplib
    from email.message import EmailMessage
    msg = EmailMessage()
    msg["From"] = cfg.get("user") or cfg["to"]
    msg["To"] = cfg["to"]
    msg["Subject"] = subject
    msg.set_content(body)
    try:
        with smtplib.SMTP(cfg["host"], cfg["port"], timeout=20) as s:
            s.starttls()
            if cfg.get("user") and cfg.get("password"):
                s.login(cfg["user"], cfg["password"])
            s.send_message(msg)
        return True
    except Exception:
        return False


def diagnose(info, target=None, watch_targets=None, light=False):
    r = Report()
    r.info = info
    addrs = info["addresses"]
    link = link_status(info["interface"])

    # Layer -1: is the adapter even up / the radio on?
    if not addrs:
        if link.get("radio_blocked"):
            r.add("Wireless radio", FAIL, "blocked (airplane mode / Wi-Fi off)")
            r.diagnose(
                "Your Wi-Fi radio is switched off — airplane mode is on, or "
                "Wi-Fi was disabled. Nothing else can work until it's back on.",
                ["Turn off airplane mode / switch Wi-Fi back on.",
                 "Linux:  sudo rfkill unblock all"],
                category="radio_off")
            return r
        if link.get("any_up") is False:
            r.add("Network adapter", FAIL, "no interface is up")
            r.diagnose(
                "Your network adapter is down or disabled — no interface is "
                "active, so the machine can't connect to anything.",
                ["Enable the adapter in network settings.",
                 "Linux:  sudo ip link set <iface> up   (e.g. eth0/wlan0)"],
                category="adapter_off")
            return r
        r.add("Local IP address", FAIL, "no non-loopback IPv4 found")
        r.diagnose(
            "Your machine has no usable network address. DHCP likely failed "
            "or the cable/Wi-Fi isn't actually connected.",
            ["Linux:   sudo dhclient -v   (or restart networking)",
             "Check the cable / Wi-Fi association and that the interface is up."],
            category="no_ip")
        return r

    # Layer -0.5: self-assigned 169.254 address = DHCP handed out nothing.
    if all(is_apipa(a["ip"]) for a in addrs):
        r.add("Local IP address", FAIL,
              f"{addrs[0]['ip']} (self-assigned / APIPA)")
        r.diagnose(
            "You have a self-assigned 169.254.x.x address, which means DHCP "
            "failed completely — the router never gave you a real address. "
            "You're physically connected but not on the network.",
            ["Renew the lease:  Linux  sudo dhclient -v   /   "
             "Windows  ipconfig /release && ipconfig /renew",
             "Reboot the router; check the cable or re-join the Wi-Fi."],
            category="apipa")
        return r

    ip_str = ", ".join(f"{a['ip']}/{a['cidr']}" if a['cidr'] is not None else a['ip']
                       for a in addrs)
    r.add("Local IP address", PASS, ip_str)

    gw = info["gateway"]
    if not gw:
        r.add("Default gateway", FAIL, "no default route")
        r.diagnose(
            "You have an IP but no default route, so nothing can leave your "
            "local network. The router didn't hand out a gateway, or the "
            "route was removed.",
            ["Linux:   sudo dhclient -v   to re-request DHCP",
             "Inspect routes with:  ip route   (Linux) / route print (Windows)"],
            category="no_gateway")
        return r
    r.add("Default gateway", PASS, gw)

    gw_ok, gw_lat = ping(gw)
    if not gw_ok:
        r.add("Reach gateway", FAIL, f"{gw} not responding")
        r.diagnose(
            "Your gateway (router) isn't responding. The problem is between "
            "you and the router: cable, Wi-Fi signal, or the router itself.",
            ["Reboot the router / check Wi-Fi signal strength.",
             "Confirm you're on the right network (not a guest/isolated VLAN)."],
            category="gateway_unreachable")
        return r
    r.add("Reach gateway", PASS, f"{gw}" + (f"  {gw_lat:.0f}ms" if gw_lat else ""))

    ip_reached = [(ip, lat) for ip in PUBLIC_IPS for ok, lat in [ping(ip)] if ok]
    if not ip_reached:
        # Could still be a captive portal that blocks ICMP — check before blaming ISP.
        if captive_portal() == "portal":
            r.add("Captive portal", FAIL, "login page intercepting traffic")
            r.diagnose(
                "You're behind a captive portal — the 'sign in to Wi-Fi' page "
                "you get on hotel, airport, or café networks. You're connected "
                "but every request is hijacked until you log in.",
                ["Open any website in a browser to trigger the login page.",
                 "Accept the terms / enter the access code, then re-run this."],
                category="captive")
            return r
        r.add("Internet by IP", FAIL, "1.1.1.1 and 8.8.8.8 unreachable")
        r.diagnose(
            "You can reach your router but not the wider internet. Traffic "
            "dies upstream — this is almost always your ISP or modem, not "
            "your computer.",
            ["Reboot the modem (not just the router) and wait ~2 minutes.",
             "Check the ISP for an outage; test a phone on cellular to confirm."],
            category="isp")
        return r
    best = min((l for _, l in ip_reached if l), default=None)
    r.add("Internet by IP", PASS,
          f"{ip_reached[0][0]}" + (f"  {best:.0f}ms" if best else ""))

    # Captive portals often allow ICMP but hijack HTTP — check explicitly.
    portal = captive_portal()
    if portal == "portal":
        r.add("Captive portal", FAIL, "login page intercepting traffic")
        r.diagnose(
            "You're behind a captive portal — the 'sign in to Wi-Fi' page you "
            "get on hotel, airport, or café networks. Raw connectivity works, "
            "but web requests are redirected to a login page until you sign in.",
            ["Open any website in a browser to trigger the login page.",
             "Accept the terms / enter the access code, then re-run this."],
            category="captive")
        return r
    elif portal == "clear":
        r.add("Captive portal", PASS, "none")

    # Connectivity confirmed — safe to look up public IP now.
    if info.get("_want_public"):
        info["public_ip"] = public_ip()

    # Deeper checks run in parallel (each is a few seconds on its own).
    # Skipped in light mode (continuous polling) to keep cycles fast.
    qual = v6 = dspeed = skew = None
    if not light:
        with concurrent.futures.ThreadPoolExecutor(max_workers=4) as ex:
            f_qual = ex.submit(ping_stats, "1.1.1.1")
            f_v6 = ex.submit(check_ipv6)
            f_dns = ex.submit(dns_speed)
            f_clock = ex.submit(clock_skew)
            qual = f_qual.result()
            v6 = f_v6.result()
            dspeed = f_dns.result()
            skew = f_clock.result()

    if qual:
        st, note = quality_verdict(qual)
        r.add("Connection quality", st, note)
        r.info["quality"] = qual

    # IPv6: only a problem if you HAVE a v6 address but can't use it (apps that
    # prefer v6 then hang). No v6 at all is fine — just informational.
    if v6 and v6["addr"]:
        if v6["reachable"]:
            r.add("IPv6", PASS, f"{v6['addr']} — reachable")
        else:
            r.add("IPv6", WARN, "have an IPv6 address but can't reach the IPv6 "
                                "internet — apps that prefer IPv6 may hang")
        r.info["ipv6"] = v6
    elif v6:
        r.add("IPv6", INFO, "not configured (IPv4-only — fine)")
        r.info["ipv6"] = v6

    if skew is not None and abs(skew) > 120:
        r.add("System clock", WARN,
              f"off by {abs(skew)/60:.0f} min — wrong clock breaks HTTPS "
              f"(cert errors, sites won't load)")
    elif skew is not None:
        r.add("System clock", PASS, f"accurate (±{abs(skew):.0f}s)")

    dns_fail = [h for h in PUBLIC_HOSTS if not dns_resolves(h)]
    if len(dns_fail) == len(PUBLIC_HOSTS):
        r.add("DNS resolution", FAIL, "no names resolve")
        r.diagnose(
            "Connectivity is fine but DNS is broken — you can reach the "
            "internet by IP but can't turn names into addresses. The classic "
            "'internet works but no websites load' case.",
            ["Switch DNS to Cloudflare 1.1.1.1 or Google 8.8.8.8.",
             "Linux:  echo 'nameserver 1.1.1.1' | sudo tee /etc/resolv.conf",
             "Then flush any cache and retry."],
            category="dns")
        return r
    elif dns_fail:
        r.add("DNS resolution", WARN, f"some names failed: {', '.join(dns_fail)}")
    else:
        resolver = (info.get("dns") or ["?"])[0]
        if dspeed is not None and dspeed > 200:
            r.add("DNS resolution", WARN,
                  f"resolving but slow ({dspeed:.0f}ms via {resolver}) — "
                  f"try 1.1.1.1 for faster lookups")
        else:
            spd = f"  {dspeed:.0f}ms via {resolver}" if dspeed is not None else ""
            r.add("DNS resolution", PASS, "names resolving" + spd)

    http_fail = [h for h in PUBLIC_HOSTS if not http_ok(h)]
    if len(http_fail) == len(PUBLIC_HOSTS):
        r.add("Load site by name", FAIL, "no HTTP(S) succeeded")
        r.diagnose(
            "DNS and raw connectivity work, but HTTP(S) requests all fail. "
            "Likely a firewall, proxy, or captive portal intercepting traffic.",
            ["If on public Wi-Fi, open a browser to trigger the login portal.",
             "Check for a proxy (HTTP_PROXY/HTTPS_PROXY) or firewall rule."],
            category="http_blocked")
        return r
    elif http_fail:
        r.add("Load site by name", WARN, f"some failed: {', '.join(http_fail)}")
    else:
        r.add("Load site by name", PASS, "sites loading")

    mtu = mtu_probe()
    if mtu == "mtu_issue":
        r.add("Path MTU (1500)", WARN, "large packets fragmented/blocked")
    elif mtu == "ok":
        r.add("Path MTU (1500)", PASS, "1500-byte packets pass")
    else:
        r.add("Path MTU (1500)", INFO, "inconclusive (ICMP may be filtered)")

    if target:
        t_dns = dns_resolves(target)
        t_ping, _ = ping(target)
        t_http = http_ok(target)
        detail = f"dns={'ok' if t_dns else 'fail'} " \
                 f"ping={'ok' if t_ping else 'fail'} " \
                 f"http={'ok' if t_http else 'fail'}"
        status = PASS if (t_dns and (t_http or t_ping)) else FAIL
        r.add(f"Target: {target}", status, detail)
        if status == FAIL and not r.diagnosis:
            if not t_dns:
                r.diagnose(
                    f"Your connection is healthy, but '{target}' doesn't "
                    f"resolve. The name is likely wrong or that domain's DNS "
                    f"is down — not your network.",
                    [f"Verify the hostname; try resolving it elsewhere."])
            else:
                r.diagnose(
                    f"Your connection is healthy and '{target}' resolves, but "
                    f"it won't respond. The issue is on that host's side.",
                    [f"Check if {target} is down for everyone, not just you."])

    # Watchlist: user-specified servers to confirm reachable.
    target_results = check_targets(watch_targets)
    unreachable = []
    for tr in target_results:
        lat = f"  {tr['ms']:.0f}ms" if tr.get("ms") else ""
        r.add(f"Reach {tr['target']}", PASS if tr["ok"] else FAIL,
              tr["detail"] + lat)
        if not tr["ok"]:
            unreachable.append(tr["target"])
    r.info["watchlist_unreachable"] = unreachable

    if r.diagnosis is None:
        if unreachable:
            r.diagnose(
                "Your network is healthy, but these servers are unreachable: "
                + ", ".join(unreachable) + ". The problem is on their side (or "
                "they're blocking you), not your connection.",
                ["Check if each server is down for everyone, not just you.",
                 "If it's your own service, check the host/firewall/DNS for it."])
            r.category = "target_unreachable"
        elif any(c[1] == WARN for c in r.checks):
            r.diagnose(
                "Core connectivity is healthy, but some checks flagged "
                "warnings (above) that could cause intermittent issues.",
                ["Review the WARN lines; they often explain 'some sites are slow'."])
        else:
            r.diagnose("Network is fully healthy. No issues found.", [])
    return r


# --------------------------------------------------------------------------- #
# Presentation
# --------------------------------------------------------------------------- #
def render_report(r, elapsed, color=True):
    """Build the full report as a string. color=False yields clean plain text."""
    old = C.enabled
    C.enabled = color
    try:
        # One-line verdict at the very top.
        has_fail = any(st == FAIL for _, st, _ in r.checks)
        has_warn = any(st == WARN for _, st, _ in r.checks)
        head = (r.diagnosis or "").split(".")[0]
        if has_fail:
            summary = red("  >> PROBLEM: ") + head
        elif has_warn:
            summary = yellow("  >> OK (with warnings): ") + head
        else:
            summary = green("  >> HEALTHY — no issues found")
        L = ["", summary, "", cyan("  SYSTEM")]
        info = r.info
        rows = [
            ("Host", info["host"]),
            ("OS", info["os"]),
            ("Interface", info["interface"] or dim("unknown")),
            ("MAC", info.get("mac") or dim("unknown")),
            ("IPv4", ", ".join(
                f"{a['ip']}/{a['cidr']}" if a["cidr"] is not None else a["ip"]
                for a in info["addresses"]) or dim("none")),
            ("Subnet", info["subnet"] or dim("unknown")),
            ("Gateway", info["gateway"] or dim("none")),
        ]
        if info.get("router_vendor") or info.get("gateway_mac"):
            vend = info.get("router_vendor") or "unknown vendor"
            mac = info.get("gateway_mac")
            rows.append(("Router", f"{vend}" + (dim(f"  ({mac})") if mac else "")))
        rows.append(("DNS", ", ".join(info["dns"]) or dim("unknown")))
        wifi = info.get("wifi")
        if wifi:
            rows.append(("Wi-Fi SSID", wifi["ssid"]))
            dbm, pct = wifi.get("signal_dbm"), wifi.get("signal_pct")
            if dbm is not None and pct is not None:
                txt = f"{dbm} dBm / {pct}%"
            elif dbm is not None:
                txt = f"{dbm} dBm"
            elif pct is not None:
                txt = f"{pct}%"
            else:
                txt = None
            if txt:
                q = signal_quality(dbm, pct)
                if q:
                    txt += dim(f"   ({q})")
                rows.append(("Signal", txt))
        if info.get("public_ip"):
            rows.append(("Public IP",
                         info["public_ip"] + dim("   (what the internet sees)")))
        tr = info.get("traffic")
        if tr:
            rows.append(("Traffic", f"↓ {rate(tr[0])}   ↑ {rate(tr[1])}"))
        sp = info.get("speed")
        if sp:
            d = f"{sp['down_mbps']:.0f} Mbps" if sp.get("down_mbps") else "?"
            u = f"{sp['up_mbps']:.0f} Mbps" if sp.get("up_mbps") else "?"
            rows.append(("Speed", f"↓ {d}   ↑ {u}"))
        for k, v in rows:
            L.append(f"    {k:<11}{v}")

        L += ["", bold("  CHECKS  ") + dim(f"({len(r.checks)} run, {elapsed:.1f}s)"),
              dim("  " + "-" * 52)]
        for name, status, detail in r.checks:
            line = f"  {badge(status)}  {name}"
            if detail:
                line += dim(f"  -  {detail}")
            L.append(line)

        # Big status art: PROBLEM if anything failed, else HEALTHY.
        has_fail = any(st == FAIL for _, st, _ in r.checks)
        is_healthy = not has_fail and r.diagnosis and "unreachable" not in r.diagnosis
        L += ["", status_art(is_healthy), ""]
        L += [(green if is_healthy else red)("  DIAGNOSIS"),
              "  " + r.diagnosis.replace("\n", "\n  ")]
        if r.fixes:
            L += ["", cyan("  SUGGESTED FIXES")]
            L += [f"    • {f}" for f in r.fixes]
        L.append("")
        return "\n".join(L)
    finally:
        C.enabled = old


# --------------------------------------------------------------------------- #
# Clipboard + file save
# --------------------------------------------------------------------------- #
def copy_to_clipboard(text):
    """Cross-platform clipboard copy, no dependencies. Returns (ok, tool)."""
    if OS == "Darwin":
        cmds = [["pbcopy"]]
    elif OS == "Windows":
        cmds = [["clip"]]
    else:  # Linux: try Wayland then X11 utilities
        cmds = [["wl-copy"], ["xclip", "-selection", "clipboard"],
                ["xsel", "--clipboard", "--input"]]
    for c in cmds:
        try:
            p = subprocess.run(c, input=text, text=True, timeout=5,
                               capture_output=True)
            if p.returncode == 0:
                return True, c[0]
        except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
            continue
    return False, None


def save_txt(text):
    """Write to ~/Downloads (falling back to home). Returns the path."""
    downloads = os.path.join(os.path.expanduser("~"), "Downloads")
    if not os.path.isdir(downloads):
        downloads = os.path.expanduser("~")
    path = os.path.join(downloads, time.strftime("pingpoint_%Y%m%d_%H%M%S.txt"))
    with open(path, "w", encoding="utf-8") as f:
        f.write(text)
    return path


def handle_output(content, do_copy, do_save):
    """Perform the chosen actions. Messages go to stderr to keep stdout clean."""
    if do_copy:
        ok, tool = copy_to_clipboard(content)
        if ok:
            sys.stderr.write(f"✓ Copied to clipboard ({tool}).\n")
        else:
            hint = ("install wl-clipboard, xclip, or xsel" if OS == "Linux"
                    else "clipboard tool unavailable")
            sys.stderr.write(f"✗ Clipboard copy failed — {hint}.\n")
    if do_save:
        try:
            path = save_txt(content)
            sys.stderr.write(f"✓ Saved: {path}\n")
        except OSError as e:
            sys.stderr.write(f"✗ Save failed: {e}\n")


def prompt_choice():
    """Ask the user what to do. Returns (do_copy, do_save). Prompt on stderr."""
    if not sys.stdin.isatty():
        return False, False  # can't prompt without an interactive terminal
    sys.stderr.write("\nSave the results? "
                     "[c]lipboard, [t]xt file, [b]oth, [n]either (default n): ")
    sys.stderr.flush()
    try:
        choice = sys.stdin.readline().strip().lower()
    except (EOFError, KeyboardInterrupt):
        return False, False
    return choice in ("c", "b"), choice in ("t", "b")


# --------------------------------------------------------------------------- #
# Auto-fix engine  (--fix)
# --------------------------------------------------------------------------- #
def is_admin():
    if OS == "Windows":
        try:
            import ctypes
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        except Exception:
            return False
    return os.geteuid() == 0


def remedies(category, info):
    """Return a list of {'desc', 'cmd' (list), 'admin' (bool)} for a problem.
    Empty list means there's no safe local fix to automate."""
    iface = info.get("interface") or ""
    R = []

    def dhcp_renew():
        if OS == "Linux":
            return ([("Release & renew DHCP lease",
                      ["dhclient", "-r"] + ([iface] if iface else []), True),
                     ("Request a new DHCP lease",
                      ["dhclient"] + ([iface] if iface else []), True)])
        if OS == "Darwin" and iface:
            return [("Renew DHCP lease",
                     ["ipconfig", "set", iface, "DHCP"], True)]
        if OS == "Windows":
            return [("Release IP", ["ipconfig", "/release"], True),
                    ("Renew IP", ["ipconfig", "/renew"], True)]
        return []

    def dns_flush():
        if OS == "Linux":
            return [("Flush DNS cache", ["resolvectl", "flush-caches"], True)]
        if OS == "Darwin":
            return [("Flush DNS cache", ["dscacheutil", "-flushcache"], True),
                    ("Restart mDNSResponder", ["killall", "-HUP", "mDNSResponder"], True)]
        if OS == "Windows":
            return [("Flush DNS cache", ["ipconfig", "/flushdns"], True)]
        return []

    def radio_on():
        if OS == "Linux":
            return [("Unblock all wireless radios", ["rfkill", "unblock", "all"], True)]
        return []

    def adapter_up():
        if OS == "Linux" and iface:
            return [("Bring the interface up", ["ip", "link", "set", iface, "up"], True)]
        return []

    if category in ("no_ip", "no_gateway", "apipa"):
        R += dhcp_renew()
    elif category == "dns":
        R += dns_flush()
    elif category == "radio_off":
        R += radio_on()
    elif category == "adapter_off":
        R += adapter_up()
    # captive / isp / gateway_unreachable / http_blocked: no safe automatable fix
    return R


def run_fixes(r, assume_yes=False):
    """Offer and run remedies for the detected problem. Interactive by default."""
    fixes = remedies(r.category, r.info)
    if not fixes:
        sys.stderr.write(
            "\nNo safe automatic fix for this one — follow the suggested "
            "fixes above.\n")
        return
    admin = is_admin()
    sys.stderr.write(f"\n{len(fixes)} fix step(s) available for "
                     f"'{r.category}':\n")
    for desc, cmd, needs_admin in fixes:
        full = cmd
        if needs_admin and not admin and OS != "Windows":
            full = ["sudo"] + cmd
        shown = " ".join(full)
        if needs_admin and not admin and OS == "Windows":
            sys.stderr.write(f"  • {desc}: {shown}  "
                             f"(run this terminal as Administrator)\n")
            continue
        if not assume_yes:
            if not sys.stdin.isatty():
                sys.stderr.write(f"  • would run: {shown}  (skipped, non-interactive)\n")
                continue
            sys.stderr.write(f"\n  {desc}\n    Run:  {shown}\n    Proceed? [y/N]: ")
            sys.stderr.flush()
            try:
                if sys.stdin.readline().strip().lower() not in ("y", "yes"):
                    sys.stderr.write("    skipped.\n")
                    continue
            except (EOFError, KeyboardInterrupt):
                return
        rc, out, err = run(full, timeout=30)
        if rc == 0:
            sys.stderr.write(f"    ✓ done.\n")
        else:
            sys.stderr.write(f"    ✗ failed (rc={rc}): {(err or out).strip()[:200]}\n")
    sys.stderr.write("\nRe-run pingpoint to confirm the fix worked.\n")


def _status_line(r):
    """One-line summary of a run for the watch console."""
    detail = {n: d for n, s, d in r.checks}
    net = detail.get("Internet by IP", "")
    lat = ""
    m = re.search(r"(\d+)ms", net)
    if m:
        lat = f"  net {m.group(1)}ms"
    head = (r.diagnosis or "").split(".")[0]
    return head + lat


MAX_LOG_BYTES = 2 * 1024 * 1024  # rotate the watch log past ~2 MB


def _rotate_log(path):
    """Keep the log small: if it exceeds the cap, roll to <path>.1 (one backup)."""
    try:
        if os.path.exists(path) and os.path.getsize(path) > MAX_LOG_BYTES:
            os.replace(path, path + ".1")
    except OSError:
        pass


def watch_loop(interval, log_path, targets=None, full=False, notify=None):
    """Continuous mode: re-check on an interval, log problems compactly, and
    print a summary of what happened when you press Ctrl-C."""
    extra = f" · watching {len(targets)} server(s)" if targets else ""
    depth = " · full checks" if full else ""
    sys.stderr.write(banner() + "\n")
    sys.stderr.write(
        f"pingpoint continuous — every {interval}s{extra}{depth}. "
        f"Problems logged to:\n  {log_path}\nPress Ctrl-C to stop and see a summary.\n\n")
    sys.stderr.flush()

    import collections
    started = time.time()
    cycles = problems = 0
    cats = collections.Counter()
    first_at = last_at = None
    streak = longest = 0          # consecutive problem cycles
    last_cat = None
    was_healthy = True
    prev_bytes, prev_t = _iface_bytes(), time.time()

    def log(text):
        _rotate_log(log_path)
        try:
            with open(log_path, "a", encoding="utf-8") as f:
                f.write(text)
        except OSError:
            pass

    def send_alert(subject, body):
        if not notify:
            return
        host = socket.gethostname()
        if notify.get("webhook"):
            notify_webhook(notify["webhook"], f"pingpoint @ {host}: {subject}", body)
        if notify.get("email"):
            send_email(notify["email"], f"pingpoint @ {host}: {subject}", body)

    try:
        while True:
            cycles += 1
            t0 = time.time()
            info = gather_info(want_public=False)
            cur = _iface_bytes()
            if prev_bytes and cur:
                dt = max(0.001, t0 - prev_t)
                info["traffic"] = ((cur[0] - prev_bytes[0]) / dt,
                                   (cur[1] - prev_bytes[1]) / dt)
            prev_bytes, prev_t = cur, t0
            r = diagnose(info, watch_targets=targets, light=not full)
            has_fail = any(st == FAIL for _, st, _ in r.checks)
            ts = time.strftime("%Y-%m-%d %H:%M:%S")
            traf = info.get("traffic")
            traf_s = (dim(f"  ↓{rate(traf[0])} ↑{rate(traf[1])}") if traf else "")

            if not has_fail:
                streak = 0
                line = green(f"[{ts}] OK") + dim(f"  {_status_line(r)}") + traf_s
                if not was_healthy:
                    line += cyan("   <- recovered")
                    log(f"[{ts}] RECOVERED — healthy again.\n")
                    send_alert("recovered", f"Network healthy again at {ts}.")
                last_cat = None
            else:
                problems += 1
                streak += 1
                longest = max(longest, streak)
                cats[r.category] += 1
                first_at = first_at or ts
                last_at = ts
                line = red(f"[{ts}] PROBLEM") + f"  {_status_line(r)}" + traf_s
                # Compact one-liner every problem cycle (keeps the log tiny)...
                log(f"[{ts}] {r.category:<18} {_status_line(r)}\n")
                # ...plus one full report the first time a NEW cause appears,
                # and an alert on the onset of a new problem type.
                if r.category != last_cat:
                    log("-" * 64 + f"\n[{ts}] detail for '{r.category}':\n")
                    log(render_report(r, time.time() - t0, color=False) + "\n")
                    send_alert(f"PROBLEM ({r.category})",
                               f"{ts}\n{_status_line(r)}\n\n"
                               + "\n".join(f"- {f}" for f in r.fixes))
                last_cat = r.category
            was_healthy = not has_fail
            print(line)
            sys.stdout.flush()
            time.sleep(max(0, interval - (time.time() - t0)))
    except KeyboardInterrupt:
        dur = time.time() - started
        h, rem = divmod(int(dur), 3600)
        mnt, sec = divmod(rem, 60)
        span = (f"{h}h {mnt}m" if h else f"{mnt}m {sec}s")
        sys.stderr.write("\n\n" + cyan("  ── watch summary ──") + "\n")
        sys.stderr.write(f"  ran {span} · {cycles} checks\n")
        if not problems:
            sys.stderr.write(green("  no issues detected — connection was stable.\n"))
        else:
            causes = ", ".join(f"{c}×{n}" for c, n in cats.most_common())
            sys.stderr.write(red(f"  {problems} problem cycle(s) detected.\n"))
            sys.stderr.write(f"  causes:        {causes}\n")
            sys.stderr.write(f"  first / last:  {first_at}  →  {last_at}\n")
            sys.stderr.write(f"  longest outage: ~{longest * interval}s "
                             f"({longest} consecutive checks)\n")
            sys.stderr.write(f"  full log:      {log_path}\n")
        sys.exit(1 if problems else 0)


def main():
    ap = argparse.ArgumentParser(description="Smart cross-platform network diagnostics.")
    ap.add_argument("host", nargs="?", metavar="URL|IP",
                    help="optional URL/IP to monitor (works with --watch too)")
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--no-color", action="store_true")
    ap.add_argument("--no-public", action="store_true", help="skip public-IP lookup")
    ap.add_argument("--target", help="also test reachability of a specific host")
    ap.add_argument("--copy", action="store_true", help="copy to clipboard, skip prompt")
    ap.add_argument("--save", action="store_true", help="save txt to Downloads, skip prompt")
    ap.add_argument("--no-prompt", action="store_true", help="never prompt (for scripts)")
    ap.add_argument("--fix", action="store_true", help="offer to run the matching remedy")
    ap.add_argument("--yes", action="store_true", help="auto-confirm --fix steps")
    ap.add_argument("--watch", action="store_true",
                    help="run continuously, logging only when a problem is found")
    ap.add_argument("--full", action="store_true",
                    help="run the deep checks (quality/IPv6/clock) every --watch cycle")
    ap.add_argument("--interval", type=int, default=10,
                    help="seconds between checks in --watch mode (default 10)")
    ap.add_argument("--log", help="log file path for --watch (default: Downloads)")
    ap.add_argument("--check", action="append", default=[], metavar="URL|HOST",
                    help="server to confirm reachable (repeatable)")
    ap.add_argument("--targets", help="comma-separated servers to confirm reachable")
    ap.add_argument("--traffic", action="store_true",
                    help="sample current up/down throughput")
    ap.add_argument("--trace", nargs="?", const="1.1.1.1", metavar="HOST",
                    help="path-trace destination (default 1.1.1.1; runs automatically)")
    ap.add_argument("--no-trace", action="store_true",
                    help="skip the automatic path trace (faster)")
    ap.add_argument("--speedtest", action="store_true",
                    help="measure download/upload speed (uses bandwidth)")
    ap.add_argument("--webhook", help="POST an alert to this webhook on problem "
                                      "(Teams/Slack/Discord/Power Automate)")
    ap.add_argument("--email-to", help="email address to alert on problem")
    ap.add_argument("--smtp-host", default="smtp.office365.com")
    ap.add_argument("--smtp-port", type=int, default=587)
    ap.add_argument("--smtp-user", default=os.environ.get("PINGPOINT_SMTP_USER"))
    ap.add_argument("--smtp-pass", default=os.environ.get("PINGPOINT_SMTP_PASS"))
    args = ap.parse_args()
    if args.no_color:
        C.disable()

    # Any URL/IP — positional, --target, --check, or --targets — is monitored,
    # in single runs and continuously in --watch.
    targets = list(args.check)
    if args.targets:
        targets += [t for t in args.targets.split(",") if t.strip()]
    if args.target:
        targets.append(args.target)
    if args.host:
        targets.append(args.host)

    # Show the logo immediately so the user knows it's working while it loads.
    if not args.json:
        print(banner())
        sys.stdout.flush()

    if args.watch:
        log_path = args.log
        if not log_path:
            base = os.path.join(os.path.expanduser("~"), "Downloads")
            if not os.path.isdir(base):
                base = os.path.expanduser("~")
            log_path = os.path.join(base, time.strftime("pingpoint_watch_%Y%m%d.log"))
        notify = None
        if args.webhook or args.email_to:
            notify = {"webhook": args.webhook, "email": (
                {"to": args.email_to, "host": args.smtp_host, "port": args.smtp_port,
                 "user": args.smtp_user, "password": args.smtp_pass}
                if args.email_to else None)}
        watch_loop(args.interval, log_path, targets, full=args.full, notify=notify)
        return

    start = time.time()
    if not args.json:
        sys.stdout.write(dim("  running diagnostics...\n"))
        sys.stdout.flush()
    info = gather_info(want_public=not args.no_public)
    if args.traffic:
        info["traffic"] = throughput(1.0)
    if args.speedtest:
        if not args.json:
            sys.stdout.write(dim("  running speed test...\n"))
            sys.stdout.flush()
        info["speed"] = speed_test()
    r = diagnose(info, watch_targets=targets)
    elapsed = time.time() - start

    if args.json:
        content = json.dumps({
            "system": {k: v for k, v in r.info.items() if not k.startswith("_")},
            "checks": [{"name": n, "status": s, "detail": d} for n, s, d in r.checks],
            "category": r.category,
            "diagnosis": r.diagnosis,
            "fixes": r.fixes,
            "elapsed_s": round(elapsed, 2),
        }, indent=2)
        print(content)
    else:
        print(render_report(r, elapsed, color=C.enabled))
        content = render_report(r, elapsed, color=False)  # always plain for copy/save

    healthy = r.diagnosis and "fully healthy" in r.diagnosis

    # Path tracing runs automatically (single runs only — too slow per watch
    # cycle). --no-trace skips it; --trace HOST changes the destination.
    if not args.no_trace and not args.json:
        tgt = args.trace if isinstance(args.trace, str) else "1.1.1.1"
        sys.stdout.write(dim(f"\n  tracing path to {tgt} ...\n"))
        sys.stdout.flush()
        hops = traceroute(tgt)
        print(cyan(f"\n  PATH TO {tgt}"))
        if not hops:
            print(dim("    (traceroute unavailable or no response)"))
        else:
            last = None
            for h in hops:
                if h["timeout"]:
                    print(f"    {h['hop']:>2}  " + dim("* * *  (no reply)"))
                else:
                    ms = f"{h['ms']:.0f}ms" if h["ms"] is not None else ""
                    print(f"    {h['hop']:>2}  {h['ip']:<16} {dim(ms)}")
                    last = h["hop"]
            if last and last < len(hops):
                print(yellow(f"    → path stops responding after hop {last} "
                             f"(the break is around there)"))
        print()

    # --fix: offer to run the matching remedy (only when there's a problem).
    if args.fix and not healthy:
        run_fixes(r, assume_yes=args.yes)

    # Decide copy/save: explicit flags override the prompt; else ask.
    if args.copy or args.save:
        do_copy, do_save = args.copy, args.save
    elif args.no_prompt:
        do_copy, do_save = False, False
    else:
        do_copy, do_save = prompt_choice()
    handle_output(content, do_copy, do_save)

    sys.exit(0 if healthy else 1)


if __name__ == "__main__":
    try:
        main()
    except BrokenPipeError:
        try:
            sys.stdout.close()
        except Exception:
            pass
        os._exit(0)
    except KeyboardInterrupt:
        sys.exit(130)
