#!/usr/bin/env python3
"""
proxy_tester — GUI tester for SOCKS4 / SOCKS5 / HTTP proxies from monosans/proxy-list.

Flow: load the live list → filter (search, protocol, country) → pick checks →
run with progress/cancel → export csv / txt / html / json.

Checks:
  ping  — https://www.google.com/generate_204
  geo   — https://api.ip.sb/geoip  (exit IP + country)

Chain mode routes every test through a local SOCKS5 hop first:
  tester → local socks5 → candidate proxy → site

CLI:  python proxy_tester.py --cli [--file f.json] [--chain host:port] ...
"""

import argparse
import base64
import csv
import json
import os
import queue
import ssl
import struct
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from urllib.parse import quote, urlparse
from urllib.request import urlopen

LIST_URL = "https://raw.githubusercontent.com/monosans/proxy-list/main/proxies.json"
PING_URL = "https://www.google.com/generate_204"
GEO_URL = "https://api.ip.sb/geoip"
DEFAULT_CHAIN = "127.0.0.1:10808"
SCHEMES = {"http": "http", "https": "http", "socks4": "socks4", "socks5": "socks5"}
CSV_FIELDS = ["protocol", "host", "port", "latency_ms", "ping_ms", "exit_ip", "country", "status", "error"]

THEMES = {
    "dark": {
        "bg": "#0D0F13", "surface": "#14171C", "raised": "#1A1E24",
        "text": "#E9EBEF", "muted": "#8E949E", "accent": "#6480FF",
        "line": "#24282F", "ok": "#3DBE7A", "fail": "#E5493A",
    },
    "light": {
        "bg": "#F2F3F5", "surface": "#FFFFFF", "raised": "#F8F9FA",
        "text": "#0C0E12", "muted": "#71767F", "accent": "#1B3BFF",
        "line": "#E3E5E9", "ok": "#1E8E5A", "fail": "#C42B1C",
    },
}


class ProxyProtoError(Exception):
    pass


# ---------------------------------------------------------------- load

def load_proxies(path=None):
    if path:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
    else:
        with urlopen(LIST_URL, timeout=30) as r:
            data = json.load(r)
    if not isinstance(data, list) or not data:
        raise RuntimeError("Proxy list is empty or invalid.")
    out = []
    for p in data:
        out.append({
            "protocol": p.get("protocol", "http"),
            "host": p.get("host", ""),
            "port": p.get("port", 0),
            "username": p.get("username"),
            "password": p.get("password"),
            "country": (p.get("geolocation") or {}).get("country", {}).get("names", {}).get("en", "Unknown"),
            "country_code": (p.get("geolocation") or {}).get("country", {}).get("iso_code", ""),
            "city": (p.get("geolocation") or {}).get("city", {}).get("names", {}).get("en", ""),
            "asn": (p.get("asn") or {}).get("autonomous_system_organization", ""),
        })
    return out


def apply_filters(proxies, query, protocols, countries):
    q = query.strip().lower()
    out = []
    for p in proxies:
        if protocols and p["protocol"] not in protocols:
            continue
        if countries and p["country"] not in countries:
            continue
        if q:
            hay = f"{p['host']} {p['port']} {p['country']} {p['country_code']} {p['city']} {p['asn']} {p['protocol']}"
            if q not in hay.lower():
                continue
        out.append(p)
    return out


# ---------------------------------------------------------------- chain transport
# tester → local socks5 → candidate → target

def _recv_exact(sock, n):
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ProxyProtoError("connection closed during handshake")
        buf += chunk
    return buf


def _recv_until(sock, delim=b"\r\n\r\n", limit=65536):
    buf = b""
    while delim not in buf:
        if len(buf) >= limit:
            raise ProxyProtoError("response header too large")
        chunk = sock.recv(4096)
        if not chunk:
            break
        buf += chunk
    return buf


def _is_ipv4(host):
    parts = host.split(".")
    return len(parts) == 4 and all(p.isdigit() and 0 <= int(p) <= 255 for p in parts)


def _socks5_inner(sock, host, port, username=None, password=None):
    if username:
        sock.sendall(b"\x05\x02\x00\x02")
    else:
        sock.sendall(b"\x05\x01\x00")
    ver, method = _recv_exact(sock, 2)
    if ver != 5:
        raise ProxyProtoError(f"SOCKS5 bad version {ver}")
    if method == 0xFF:
        raise ProxyProtoError("SOCKS5: no acceptable auth method")
    if method == 2:
        if not username:
            raise ProxyProtoError("SOCKS5: auth required")
        u = username.encode()
        pw = (password or "").encode()
        sock.sendall(b"\x01" + bytes([len(u)]) + u + bytes([len(pw)]) + pw)
        _, status = _recv_exact(sock, 2)
        if status != 0:
            raise ProxyProtoError("SOCKS5: auth failed")
    elif method != 0:
        raise ProxyProtoError(f"SOCKS5: unsupported auth method {method}")
    hb = host.encode()
    sock.sendall(b"\x05\x01\x00\x03" + bytes([len(hb)]) + hb + struct.pack(">H", port))
    ver, rep, _, atyp = _recv_exact(sock, 4)
    if rep != 0:
        raise ProxyProtoError(f"SOCKS5: connect refused (code {rep})")
    if atyp == 1:
        _recv_exact(sock, 4)
    elif atyp == 3:
        _recv_exact(sock, _recv_exact(sock, 1)[0])
    elif atyp == 4:
        _recv_exact(sock, 16)
    else:
        raise ProxyProtoError(f"SOCKS5: bad atyp {atyp}")
    _recv_exact(sock, 2)  # bind port


def _socks4_inner(sock, host, port, username=None):
    import socket as _socket
    userid = (username or "").encode()[:255]
    ip = host if _is_ipv4(host) else _socket.gethostbyname(host)
    addr = bytes(int(x) for x in ip.split("."))
    sock.sendall(b"\x04\x01" + struct.pack(">H", port) + addr + userid + b"\x00")
    resp = _recv_exact(sock, 8)
    if resp[1] != 0x5A:
        raise ProxyProtoError(f"SOCKS4: rejected (status 0x{resp[1]:02x})")


def _http_inner(sock, host, port, username=None, password=None):
    lines = [f"CONNECT {host}:{port} HTTP/1.1", f"Host: {host}:{port}"]
    if username:
        cred = base64.b64encode(f"{username}:{password or ''}".encode()).decode()
        lines.append(f"Proxy-Authorization: Basic {cred}")
    lines.append("")
    lines.append("")
    sock.sendall("\r\n".join(lines).encode())
    data = _recv_until(sock)
    head = data.split(b"\r\n", 1)[0].decode(errors="replace")
    parts = head.split()
    if len(parts) < 2 or not parts[1].startswith("2"):
        raise ProxyProtoError(f"HTTP CONNECT failed: {head or 'no response'}")


def _read_http_response(tls):
    head = _recv_until(tls, limit=1 << 16)
    if b"\r\n\r\n" not in head:
        raise ProxyProtoError("truncated HTTP response")
    header_blob, _, rest = head.partition(b"\r\n\r\n")
    lines = header_blob.decode(errors="replace").split("\r\n")
    status_parts = lines[0].split()
    if len(status_parts) < 2:
        raise ProxyProtoError(f"bad status line: {lines[0]}")
    status = int(status_parts[1])
    headers = {}
    for line in lines[1:]:
        if ":" in line:
            k, v = line.split(":", 1)
            headers[k.strip().lower()] = v.strip()
    body = rest
    if status in (204, 304):
        return status, "", headers
    if "content-length" in headers:
        need = int(headers["content-length"])
        while len(body) < need:
            chunk = tls.recv(min(8192, need - len(body)))
            if not chunk:
                break
            body += chunk
        return status, body[:need].decode(errors="replace"), headers
    if headers.get("transfer-encoding", "").lower() == "chunked":
        out = b""
        while True:
            while b"\r\n" not in body:
                body += tls.recv(4096)
            line, _, body = body.partition(b"\r\n")
            size = int(line.split(b";")[0], 16)
            if size == 0:
                break
            while len(body) < size + 2:
                body += tls.recv(4096)
            out += body[:size]
            body = body[size + 2:]
        return status, out.decode(errors="replace"), headers
    while True:
        chunk = tls.recv(8192)
        if not chunk:
            break
        body += chunk
    return status, body.decode(errors="replace"), headers


def chain_get(url, cand, chain_host, chain_port, timeout):
    """GET url via tester → local socks5 → candidate → target. Returns (status, body, ms)."""
    import socks
    u = urlparse(url)
    target_host, target_port = u.hostname, u.port or (443 if u.scheme == "https" else 80)
    path = u.path + ("?" + u.query if u.query else "")

    s = socks.socksocket()
    try:
        s.settimeout(timeout)
        s.setproxy(socks.SOCKS5, chain_host, port=chain_port, rdns=True)
        s.connect((cand["host"], int(cand["port"])))

        proto = cand["protocol"]
        if proto == "socks5":
            _socks5_inner(s, target_host, target_port, cand.get("username"), cand.get("password"))
        elif proto == "socks4":
            _socks4_inner(s, target_host, target_port, cand.get("username"))
        elif proto in ("http", "https"):
            _http_inner(s, target_host, target_port, cand.get("username"), cand.get("password"))
        else:
            raise ProxyProtoError(f"unknown protocol {proto}")

        start = time.perf_counter()
        if u.scheme == "https":
            ctx = ssl.create_default_context()
            tls = ctx.wrap_socket(s, server_hostname=target_host)
            try:
                req = (f"GET {path} HTTP/1.1\r\nHost: {target_host}\r\n"
                       f"User-Agent: proxy-tester/2\r\nAccept: */*\r\nConnection: close\r\n\r\n").encode()
                tls.sendall(req)
                status, body, _ = _read_http_response(tls)
            finally:
                tls.close()
        else:
            req = (f"GET {path} HTTP/1.1\r\nHost: {target_host}\r\n"
                   f"User-Agent: proxy-tester/2\r\nAccept: */*\r\nConnection: close\r\n\r\n").encode()
            s.sendall(req)
            status, body, _ = _read_http_response(s)
        return status, body, round((time.perf_counter() - start) * 1000)
    finally:
        try:
            s.close()
        except Exception:
            pass


def plain_get(url, cand, timeout):
    """GET url through the candidate only (requests handles both hops' protocols)."""
    import requests
    scheme = SCHEMES.get(cand["protocol"], "http")
    auth = ""
    if cand.get("username"):
        auth = f"{quote(cand['username'], safe='')}:{quote(cand.get('password') or '', safe='')}@"
    purl = f"{scheme}://{auth}{cand['host']}:{cand['port']}"
    start = time.perf_counter()
    r = requests.get(url, proxies={"http": purl, "https": purl}, timeout=timeout, allow_redirects=True)
    ms = round((time.perf_counter() - start) * 1000)
    return r.status_code, r.text, ms


def preflight_chain(chain_host, chain_port, timeout=3):
    import socks
    s = socks.socksocket()
    try:
        s.settimeout(timeout)
        s.setproxy(socks.SOCKS5, chain_host, port=chain_port, rdns=True)
        s.connect(("www.google.com", 443))
        return True, ""
    except Exception as e:
        return False, str(e)
    finally:
        try:
            s.close()
        except Exception:
            pass


# ---------------------------------------------------------------- test engine

def test_proxy(p, *, do_ping, do_geo, chain, timeout):
    res = {
        "protocol": p["protocol"], "host": p["host"], "port": p["port"],
        "latency_ms": None, "ping_ms": None, "exit_ip": "", "country": "",
        "status": "fail", "error": "",
    }
    get = (lambda url: chain_get(url, p, chain[0], chain[1], timeout)) if chain else (lambda url: plain_get(url, p, timeout))
    primary_err = ""
    geo_err = ""
    try:
        if do_ping:
            status, _, ms = get(PING_URL)
            if status == 204:
                res["ping_ms"] = ms
                res["latency_ms"] = ms
            else:
                primary_err = f"ping HTTP {status}"
        if do_geo:
            status, body, ms = get(GEO_URL)
            if status == 200:
                try:
                    data = json.loads(body)
                    res["exit_ip"] = data.get("ip", "")
                    res["country"] = data.get("country", "")
                except json.JSONDecodeError:
                    geo_err = "geo: bad JSON"
                if res["latency_ms"] is None:
                    res["latency_ms"] = ms
            else:
                geo_err = f"geo HTTP {status}"
        primary_ok = res["ping_ms"] is not None if do_ping else not geo_err
        res["status"] = "ok" if primary_ok else "fail"
        if not primary_ok:
            res["error"] = primary_err or geo_err or "check failed"
        elif geo_err:
            res["error"] = geo_err
    except Exception as e:
        res["status"] = "fail"
        res["error"] = _short_err(e)
    return res


def _short_err(e):
    name = type(e).__name__
    msg = str(e)
    if len(msg) > 80:
        msg = msg[:77] + "..."
    return f"{name}: {msg}" if msg else name


def run_batch(proxies, *, do_ping, do_geo, chain, timeout, workers, on_progress, cancel_event):
    results = []
    done = 0
    total = len(proxies)
    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = {
            pool.submit(test_proxy, p, do_ping=do_ping, do_geo=do_geo, chain=chain, timeout=timeout): p
            for p in proxies
        }
        for fut in as_completed(futures):
            if cancel_event.is_set():
                for f in futures:
                    f.cancel()
            try:
                res = fut.result()
            except Exception as e:
                p = futures[fut]
                res = {"protocol": p["protocol"], "host": p["host"], "port": p["port"],
                       "latency_ms": None, "ping_ms": None, "exit_ip": "", "country": "",
                       "status": "fail", "error": _short_err(e)}
            results.append(res)
            done += 1
            on_progress(done, total, res)
            if cancel_event.is_set():
                break
    return results


# ---------------------------------------------------------------- exporters

def export_csv(results, path):
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=CSV_FIELDS)
        w.writeheader()
        for r in results:
            w.writerow({k: ("" if r.get(k) is None else r.get(k, "")) for k in CSV_FIELDS})


def export_txt(results, path):
    working = [r for r in results if r["status"] == "ok"]
    with open(path, "w", encoding="utf-8") as f:
        for r in working:
            f.write(f"{r['host']}:{r['port']}\n")


def export_json(results, path, meta):
    with open(path, "w", encoding="utf-8") as f:
        json.dump({"generated_at": datetime.now().isoformat(timespec="seconds"), **meta, "results": results},
                  f, indent=2, ensure_ascii=False)


def export_html(results, path, meta):
    ok = sum(1 for r in results if r["status"] == "ok")
    rows = "".join(
        f"<tr class='{r['status']}'><td>{r['host']}:{r['port']}</td><td>{r['protocol']}</td>"
        f"<td class='n'>{r['ping_ms'] if r['ping_ms'] is not None else '—'}</td>"
        f"<td>{r['exit_ip'] or '—'}</td><td>{r['country'] or '—'}</td>"
        f"<td>{r['status']}{' · ' + r['error'] if r['error'] else ''}</td></tr>"
        for r in results
    )
    html = f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Proxy test results</title>
<style>
:root {{
  --bg:#F2F3F5; --surface:#FFFFFF; --ink:#0C0E12; --line:#E3E5E9;
  --muted:#71767F; --accent:#1B3BFF; --ok:#1E8E5A; --fail:#C42B1C;
}}
@media (prefers-color-scheme: dark) {{
  :root {{
    --bg:#0D0F13; --surface:#14171C; --ink:#E9EBEF; --line:#24282F;
    --muted:#8E949E; --accent:#6480FF; --ok:#3DBE7A; --fail:#E5493A;
  }}
}}
* {{ box-sizing:border-box; margin:0; }}
body {{ font-family:"Segoe UI",system-ui,sans-serif; background:var(--bg); color:var(--ink); padding:40px 24px; }}
.wrap {{ max-width:1000px; margin:0 auto; }}
h1 {{ font-size:28px; letter-spacing:-.03em; font-weight:600; }}
.meta {{ color:var(--muted); font-size:13px; margin-top:6px; }}
.meta b {{ color:var(--ink); font-weight:600; }}
table {{ width:100%; border-collapse:collapse; background:var(--surface); border:1px solid var(--line);
  border-radius:6px; overflow:hidden; margin-top:24px; font-size:13px; }}
th {{ text-align:left; padding:10px 14px; border-bottom:2px solid var(--ink); font-weight:500;
  color:var(--muted); font-size:12px; }}
td {{ padding:8px 14px; border-bottom:1px solid var(--line); font-family:Consolas,monospace; font-size:12.5px; }}
tr:last-child td {{ border-bottom:none; }}
tr.fail td {{ color:var(--muted); }}
td.n {{ color:var(--accent); }}
tr.ok td:nth-child(6) {{ color:var(--ok); }}
tr.fail td:nth-child(6) {{ color:var(--fail); }}
</style></head><body><div class="wrap">
<h1>Proxy test results</h1>
<p class="meta">{datetime.now().strftime('%Y-%m-%d %H:%M')} · <b>{ok}</b> working of <b>{len(results)}</b>
 · ping {meta.get('ping') and 'on' or 'off'} · geo {meta.get('geo') and 'on' or 'off'}
 · chain {meta.get('chain') or 'off'}</p>
<table><thead><tr><th>Address</th><th>Protocol</th><th>Ping ms</th><th>Exit IP</th><th>Country</th><th>Status</th></tr></thead>
<tbody>{rows}</tbody></table>
</div></body></html>"""
    with open(path, "w", encoding="utf-8") as f:
        f.write(html)


# ---------------------------------------------------------------- CLI

def cli(argv):
    ap = argparse.ArgumentParser(description="Test SOCKS4/SOCKS5/HTTP proxies")
    ap.add_argument("--cli", action="store_true", help=argparse.SUPPRESS)
    ap.add_argument("--file", help="local proxies.json instead of the live list")
    ap.add_argument("--workers", type=int, default=150)
    ap.add_argument("--timeout", type=float, default=8.0)
    ap.add_argument("--out", default="results.csv")
    ap.add_argument("--chain", default="", metavar="HOST:PORT", help="route tests via local socks5, e.g. 127.0.0.1:10808")
    ap.add_argument("--no-geo", action="store_true")
    ap.add_argument("--no-ping", action="store_true")
    args = ap.parse_args(argv)

    do_ping, do_geo = not args.no_ping, not args.no_geo
    if not do_ping and not do_geo:
        raise SystemExit("at least one of ping/geo must stay enabled")

    chain = None
    if args.chain:
        host, _, port = args.chain.partition(":")
        if not host or not port.isdigit():
            raise SystemExit(f"bad --chain address: {args.chain}")
        ok, err = preflight_chain(host, int(port))
        if not ok:
            raise SystemExit(f"local proxy unreachable at {args.chain}: {err}")
        chain = (host, int(port))

    print(f"Fetching {args.file or LIST_URL} ...")
    proxies = load_proxies(args.file)
    print(f"Testing {len(proxies)} proxies" + (f" via chain {args.chain}" if chain else "") + " ...")

    def progress(done, total, _res):
        print(f"\r  tested {done}/{total}", end="", flush=True)

    results = run_batch(proxies, do_ping=do_ping, do_geo=do_geo, chain=chain,
                        timeout=args.timeout, workers=args.workers,
                        on_progress=progress, cancel_event=threading.Event())
    print()

    results.sort(key=lambda r: (r["status"] != "ok", r["latency_ms"] is None, r["latency_ms"] or 0))
    export_csv(results, args.out)
    ok = sum(1 for r in results if r["status"] == "ok")
    print(f"{ok} working / {len(results)} tested  ->  {args.out}")
    fastest = [r for r in results if r["status"] == "ok"][:10]
    if fastest:
        print(f"\n{'ping':>8}  {'protocol':<8}  {'exit ip':<16}  address")
        for r in fastest:
            print(f"{str(r['ping_ms']) + ' ms':>8}  {r['protocol']:<8}  {r['exit_ip'] or '-':<16}  {r['host']}:{r['port']}")


# ---------------------------------------------------------------- GUI

def run_gui():
    import customtkinter as ctk
    from tkinter import ttk, filedialog, messagebox

    ctk.set_appearance_mode("dark")

    class App(ctk.CTk):
        def __init__(self):
            super().__init__()
            self.title("Proxy Tester")
            self.geometry("1020x740")
            self.minsize(860, 620)
            self.proxies = []
            self.results = []
            self.q = queue.Queue()
            self.cancel_event = threading.Event()
            self.running = False
            self.theme = "dark"
            self.protocols = set()
            self.countries = set()
            self._theme_regs = []
            self._sort_key = "latency_ms"
            self._sort_asc = True

            self._build()
            self.apply_theme()
            self.after(100, self._poll_queue)
            self.after(200, self.fetch_list)

            if os.environ.get("PROXY_TESTER_SELFTEST"):
                self.after(1500, self.destroy)

        # -- theme helpers
        def T(self, widget, kwarg, role):
            self._theme_regs.append((widget, kwarg, role))
            return widget

        def apply_theme(self):
            t = THEMES[self.theme]
            for widget, kwarg, role in self._theme_regs:
                try:
                    widget.configure(**{kwarg: t[role]})
                except Exception:
                    pass
            style = ttk.Style(self)
            style.theme_use("clam")
            style.configure("Treeview", background=t["surface"], fieldbackground=t["surface"],
                            foreground=t["text"], borderwidth=0, rowheight=30,
                            font=("Segoe UI", 11))
            style.configure("Treeview.Heading", background=t["bg"], foreground=t["muted"],
                            borderwidth=0, font=("Segoe UI", 10, "bold"))
            style.map("Treeview.Heading", background=[("active", t["raised"])])
            style.map("Treeview", background=[("selected", t["accent"])],
                      foreground=[("selected", t["surface"])])

        def toggle_theme(self):
            self.theme = "light" if self.theme == "dark" else "dark"
            ctk.set_appearance_mode(self.theme)
            self.apply_theme()

        # -- layout
        def _build(self):
            t = THEMES[self.theme]
            self.configure(fg_color=t["bg"])

            header = ctk.CTkFrame(self, fg_color="transparent", corner_radius=0)
            header.pack(fill="x", padx=20, pady=(16, 8))
            left = ctk.CTkFrame(header, fg_color="transparent")
            left.pack(side="left")
            self.dot = ctk.CTkLabel(left, text="●", text_color=t["accent"], font=("Segoe UI", 14))
            self.dot.pack(side="left", padx=(0, 8))
            ctk.CTkLabel(left, text="Proxy Tester", font=("Segoe UI", 20, "bold")).pack(side="left")
            self.status_lbl = ctk.CTkLabel(left, text="  fetching list…", text_color=t["muted"],
                                           font=("Segoe UI", 13))
            self.status_lbl.pack(side="left", padx=(10, 0))
            self.theme_btn = ctk.CTkButton(header, text="◐", width=36, height=36,
                                           fg_color=t["surface"], hover_color=t["raised"],
                                           text_color=t["text"], border_width=1,
                                           border_color=t["line"], command=self.toggle_theme)
            self.theme_btn.pack(side="right")
            self._theme_regs += [
                (self.dot, "text_color", "accent"),
                (self.theme_btn, "fg_color", "surface"), (self.theme_btn, "hover_color", "raised"),
                (self.theme_btn, "text_color", "text"), (self.theme_btn, "border_color", "line"),
            ]

            # filters
            filt = self.T(ctk.CTkFrame(self, fg_color=t["surface"], border_width=1,
                                       border_color=t["line"], corner_radius=8),
                          "fg_color", "surface")
            self._theme_regs.append((filt, "border_color", "line"))
            filt.pack(fill="x", padx=20, pady=(4, 6))

            row1 = ctk.CTkFrame(filt, fg_color="transparent")
            row1.pack(fill="x", padx=12, pady=(10, 4))
            self.search = ctk.CTkEntry(row1, placeholder_text="Search host, port, city, network…",
                                       height=34, fg_color=t["bg"], border_color=t["line"],
                                       text_color=t["text"], border_width=1)
            self.search.pack(side="left", fill="x", expand=True, padx=(0, 10))
            self.search.bind("<KeyRelease>", lambda e: self._update_preview())
            self._theme_regs += [
                (self.search, "fg_color", "bg"), (self.search, "border_color", "line"),
                (self.search, "text_color", "text"),
            ]
            self.proto_btns = {}
            for proto in ("http", "socks4", "socks5"):
                b = ctk.CTkButton(row1, text=proto, width=76, height=34,
                                  fg_color=t["bg"], hover_color=t["raised"],
                                  text_color=t["muted"], border_width=1, border_color=t["line"],
                                  font=("Consolas", 12),
                                  command=lambda p=proto: self.toggle_proto(p))
                b.pack(side="left", padx=(0, 6))
                self.proto_btns[proto] = b
                self._theme_regs += [
                    (b, "fg_color", "bg"), (b, "hover_color", "raised"),
                    (b, "border_color", "line"),
                ]
            self.countries_btn = ctk.CTkButton(row1, text="Countries · all", width=130, height=34,
                                               fg_color=t["bg"], hover_color=t["raised"],
                                               text_color=t["muted"], border_width=1,
                                               border_color=t["line"],
                                               command=self.open_countries)
            self.countries_btn.pack(side="left")
            self._theme_regs += [
                (self.countries_btn, "fg_color", "bg"), (self.countries_btn, "hover_color", "raised"),
                (self.countries_btn, "text_color", "muted"), (self.countries_btn, "border_color", "line"),
            ]

            row2 = ctk.CTkFrame(filt, fg_color="transparent")
            row2.pack(fill="x", padx=12, pady=(4, 4))
            self.chk_ping = ctk.CTkCheckBox(row2, text="Ping · google/generate_204",
                                            fg_color=t["accent"], border_color=t["line"],
                                            text_color=t["text"], hover_color=t["raised"])
            self.chk_ping.select()
            self.chk_ping.pack(side="left", padx=(0, 18))
            self.chk_geo = ctk.CTkCheckBox(row2, text="Exit IP + country · api.ip.sb/geoip",
                                           fg_color=t["accent"], border_color=t["line"],
                                           text_color=t["text"], hover_color=t["raised"])
            self.chk_geo.select()
            self.chk_geo.pack(side="left", padx=(0, 18))
            self._theme_regs += [
                (self.chk_ping, "fg_color", "accent"), (self.chk_ping, "text_color", "text"),
                (self.chk_ping, "border_color", "line"),
                (self.chk_geo, "fg_color", "accent"), (self.chk_geo, "text_color", "text"),
                (self.chk_geo, "border_color", "line"),
            ]

            row3 = ctk.CTkFrame(filt, fg_color="transparent")
            row3.pack(fill="x", padx=12, pady=(4, 10))
            self.chk_chain = ctk.CTkCheckBox(row3, text="Chain via local socks5",
                                             fg_color=t["accent"], border_color=t["line"],
                                             text_color=t["text"], hover_color=t["raised"],
                                             command=self._chain_toggled)
            self.chk_chain.pack(side="left", padx=(0, 8))
            self.chain_entry = ctk.CTkEntry(row3, width=170, height=30, fg_color=t["bg"],
                                            border_color=t["line"], text_color=t["muted"],
                                            border_width=1)
            self.chain_entry.insert(0, DEFAULT_CHAIN)
            self.chain_entry.pack(side="left", padx=(0, 20))
            ctk.CTkLabel(row3, text="Workers", text_color=t["muted"]).pack(side="left")
            self.workers_entry = ctk.CTkEntry(row3, width=60, height=30, fg_color=t["bg"],
                                              border_color=t["line"], text_color=t["text"],
                                              border_width=1, justify="center")
            self.workers_entry.insert(0, "150")
            self.workers_entry.pack(side="left", padx=(6, 14))
            ctk.CTkLabel(row3, text="Timeout s", text_color=t["muted"]).pack(side="left")
            self.timeout_entry = ctk.CTkEntry(row3, width=60, height=30, fg_color=t["bg"],
                                              border_color=t["line"], text_color=t["text"],
                                              border_width=1, justify="center")
            self.timeout_entry.insert(0, "8")
            self.timeout_entry.pack(side="left", padx=(6, 0))
            self._theme_regs += [
                (self.chk_chain, "fg_color", "accent"), (self.chk_chain, "text_color", "text"),
                (self.chk_chain, "border_color", "line"),
                (self.chain_entry, "fg_color", "bg"), (self.chain_entry, "border_color", "line"),
                (self.chain_entry, "text_color", "muted"),
                (self.workers_entry, "fg_color", "bg"), (self.workers_entry, "border_color", "line"),
                (self.workers_entry, "text_color", "text"),
                (self.timeout_entry, "fg_color", "bg"), (self.timeout_entry, "border_color", "line"),
                (self.timeout_entry, "text_color", "text"),
            ]

            # run row
            run_row = ctk.CTkFrame(self, fg_color="transparent")
            run_row.pack(fill="x", padx=20, pady=(4, 6))
            self.run_btn = ctk.CTkButton(run_row, text="Run test", height=38, width=130,
                                         fg_color=t["accent"], hover_color=t["accent"],
                                         text_color="#FFFFFF", font=("Segoe UI", 14, "bold"),
                                         command=self.start_run)
            self.run_btn.pack(side="left")
            self.cancel_btn = ctk.CTkButton(run_row, text="Cancel", height=38, width=90,
                                            fg_color=t["surface"], hover_color=t["raised"],
                                            text_color=t["muted"], border_width=1,
                                            border_color=t["line"], state="disabled",
                                            command=self.cancel_run)
            self.cancel_btn.pack(side="left", padx=(10, 0))
            self._theme_regs += [
                (self.run_btn, "fg_color", "accent"),
                (self.cancel_btn, "fg_color", "surface"), (self.cancel_btn, "hover_color", "raised"),
                (self.cancel_btn, "text_color", "muted"), (self.cancel_btn, "border_color", "line"),
            ]
            self.progress = ctk.CTkProgressBar(run_row, height=8, progress_color=t["accent"])
            self.progress.pack(side="left", fill="x", expand=True, padx=16)
            self.progress.set(0)
            self._theme_regs.append((self.progress, "progress_color", "accent"))
            self.count_lbl = ctk.CTkLabel(run_row, text="0 / 0", text_color=t["muted"],
                                          font=("Consolas", 12), width=90)
            self.count_lbl.pack(side="right")
            self._theme_regs.append((self.count_lbl, "text_color", "muted"))

            # results table
            table_frame = ctk.CTkFrame(self, fg_color=t["surface"], border_width=1,
                                       border_color=t["line"], corner_radius=8)
            self._theme_regs += [
                (table_frame, "fg_color", "surface"), (table_frame, "border_color", "line"),
            ]
            table_frame.pack(fill="both", expand=True, padx=20, pady=(2, 6))

            self.tree = ttk.Treeview(table_frame, columns=("addr", "proto", "ping", "ip", "country", "status"),
                                     show="headings", selectmode="extended")
            cols = [("addr", "Address", 180, "w"), ("proto", "Protocol", 80, "center"),
                    ("ping", "Ping ms", 80, "e"), ("ip", "Exit IP", 130, "w"),
                    ("country", "Country", 150, "w"), ("status", "Status", 260, "w")]
            for cid, title, width, anchor in cols:
                self.tree.heading(cid, text=title, command=lambda c=cid: self.sort_by(c))
                self.tree.column(cid, width=width, anchor=anchor, stretch=(cid in ("addr", "status")))
            vsb = ttk.Scrollbar(table_frame, orient="vertical", command=self.tree.yview)
            self.tree.configure(yscrollcommand=vsb.set)
            self.tree.pack(side="left", fill="both", expand=True, padx=(10, 0), pady=10)
            vsb.pack(side="right", fill="y", pady=10, padx=(0, 8))

            # export row
            exp = ctk.CTkFrame(self, fg_color="transparent")
            exp.pack(fill="x", padx=20, pady=(0, 4))
            self.fmt_vars = {}
            ctk.CTkLabel(exp, text="Export", text_color=t["muted"]).pack(side="left")
            for fmt in ("csv", "txt", "html", "json"):
                c = ctk.CTkCheckBox(exp, text=fmt, fg_color=t["accent"], border_color=t["line"],
                                    text_color=t["text"], hover_color=t["raised"])
                c.select()
                c.pack(side="left", padx=(10, 0))
                self.fmt_vars[fmt] = c
                self._theme_regs += [
                    (c, "fg_color", "accent"), (c, "text_color", "text"), (c, "border_color", "line"),
                ]
            self.export_btn = ctk.CTkButton(exp, text="Export results", height=34, width=130,
                                            fg_color=t["accent"], hover_color=t["accent"],
                                            text_color="#FFFFFF", command=self.export_results)
            self.export_btn.pack(side="right")
            self._theme_regs.append((self.export_btn, "fg_color", "accent"))
            self.foot_lbl = ctk.CTkLabel(exp, text="data: monosans/proxy-list",
                                         text_color=t["muted"], font=("Segoe UI", 11))
            self.foot_lbl.pack(side="right", padx=(0, 14))
            self._theme_regs.append((self.foot_lbl, "text_color", "muted"))

        # -- helpers
        def _chain_toggled(self):
            if self.chk_chain.get():
                self.chain_entry.configure(text_color=THEMES[self.theme]["text"])
            else:
                self.chain_entry.configure(text_color=THEMES[self.theme]["muted"])

        def toggle_proto(self, p):
            t = THEMES[self.theme]
            if p in self.protocols:
                self.protocols.discard(p)
                self.proto_btns[p].configure(fg_color=t["bg"], text_color=t["muted"])
            else:
                self.protocols.add(p)
                self.proto_btns[p].configure(fg_color=t["accent"], text_color="#FFFFFF")
            self._update_preview()

        def open_countries(self):
            if not self.proxies:
                return
            t = THEMES[self.theme]
            win = ctk.CTkToplevel(self)
            win.title("Filter countries")
            win.geometry("340x480")
            win.configure(fg_color=t["bg"])
            win.grab_set()
            counts = {}
            for p in self.proxies:
                counts[p["country"]] = counts.get(p["country"], 0) + 1

            def refresh(filter_text=""):
                for w in scroll.winfo_children():
                    w.destroy()
                for name in sorted(counts):
                    if filter_text and filter_text.lower() not in name.lower():
                        continue
                    var = ctk.CTkCheckBox(scroll, text=f"{name}  ({counts[name]})",
                                          fg_color=t["accent"], text_color=t["text"],
                                          border_color=t["line"], hover_color=t["raised"])
                    if name in self.countries:
                        var.select()
                    var.pack(anchor="w", padx=8, pady=3)
                    boxen[name] = var
                    self._theme_regs += [
                        (var, "fg_color", "accent"), (var, "text_color", "text"),
                        (var, "border_color", "line"),
                    ]

            boxen = {}
            se = ctk.CTkEntry(win, placeholder_text="Filter…", fg_color=t["surface"],
                              border_color=t["line"], text_color=t["text"])
            se.pack(fill="x", padx=12, pady=(12, 6))
            se.bind("<KeyRelease>", lambda e: refresh(se.get()))
            scroll = ctk.CTkScrollableFrame(win, fg_color="transparent")
            scroll.pack(fill="both", expand=True, padx=8, pady=4)
            refresh()

            btns = ctk.CTkFrame(win, fg_color="transparent")
            btns.pack(fill="x", padx=12, pady=(4, 12))

            def select_all():
                for b in boxen.values():
                    b.select()

            def clear():
                for b in boxen.values():
                    b.deselect()

            def apply_sel():
                self.countries = {n for n, b in boxen.items() if b.get()}
                label = "all" if not self.countries else f"{len(self.countries)} selected"
                t2 = THEMES[self.theme]
                self.countries_btn.configure(text=f"Countries · {label}",
                                             fg_color=t2["accent"] if self.countries else t2["bg"],
                                             text_color="#FFFFFF" if self.countries else t2["muted"])
                self._update_preview()
                win.destroy()

            ctk.CTkButton(btns, text="All", width=60, fg_color=t["surface"], hover_color=t["raised"],
                          text_color=t["text"], border_width=1, border_color=t["line"],
                          command=select_all).pack(side="left", padx=(0, 6))
            ctk.CTkButton(btns, text="Clear", width=70, fg_color=t["surface"], hover_color=t["raised"],
                          text_color=t["muted"], border_width=1, border_color=t["line"],
                          command=clear).pack(side="left", padx=(0, 6))
            ctk.CTkButton(btns, text="Apply", width=90, fg_color=t["accent"], hover_color=t["accent"],
                          text_color="#FFFFFF", command=apply_sel).pack(side="right")

        def _update_preview(self):
            n = len(self._filtered())
            t = THEMES[self.theme]
            self.status_lbl.configure(text=f"  {n} of {len(self.proxies)} selected")

        def _filtered(self):
            return apply_filters(self.proxies, self.search.get(), self.protocols, self.countries)

        # -- data
        def fetch_list(self):
            self.status_lbl.configure(text="  fetching list…")
            self.dot.configure(text_color=THEMES[self.theme]["muted"])

            def work():
                try:
                    data = load_proxies()
                    self.q.put(("list", data, ""))
                except Exception as e:
                    self.q.put(("list_err", None, str(e)))

            threading.Thread(target=work, daemon=True).start()

        # -- run
        def start_run(self):
            if self.running:
                return
            do_ping = bool(self.chk_ping.get())
            do_geo = bool(self.chk_geo.get())
            if not do_ping and not do_geo:
                messagebox.showerror("Pick a check", "Enable at least one check (ping or exit IP).")
                return
            selected = self._filtered()
            if not selected:
                messagebox.showerror("Nothing to test", "No proxies match the current filters.")
                return

            chain = None
            if self.chk_chain.get():
                raw = self.chain_entry.get().strip()
                host, _, port = raw.partition(":")
                if not host or not port.isdigit():
                    messagebox.showerror("Bad chain address", "Use host:port, e.g. 127.0.0.1:10808")
                    return
                self.status_lbl.configure(text="  checking local proxy…")
                self.update_idletasks()
                ok, err = preflight_chain(host, int(port))
                if not ok:
                    messagebox.showerror("Local proxy unreachable",
                                         f"Can't reach socks5 at {raw}:\n{err}\n\nStart it or fix the address.")
                    return
                chain = (host, int(port))

            try:
                workers = max(1, int(self.workers_entry.get()))
                timeout = max(1.0, float(self.timeout_entry.get()))
            except ValueError:
                messagebox.showerror("Bad numbers", "Workers must be an integer, timeout a number.")
                return

            self.results = []
            for i in self.tree.get_children():
                self.tree.delete(i)
            self.cancel_event = threading.Event()
            self.running = True
            self.run_btn.configure(state="disabled")
            self.cancel_btn.configure(state="normal")
            self.progress.set(0)
            self.count_lbl.configure(text=f"0 / {len(selected)}")
            self.status_lbl.configure(text="  running…" + (" (chain)" if chain else ""))
            self.dot.configure(text_color=THEMES[self.theme]["accent"])

            def progress(done, total, res):
                self.q.put(("progress", (done, total), res))

            def work():
                try:
                    results = run_batch(selected, do_ping=do_ping, do_geo=do_geo, chain=chain,
                                        timeout=timeout, workers=workers,
                                        on_progress=progress, cancel_event=self.cancel_event)
                    self.q.put(("done", results, ""))
                except Exception as e:
                    self.q.put(("run_err", None, str(e)))

            threading.Thread(target=work, daemon=True).start()

        def cancel_run(self):
            self.cancel_event.set()
            self.status_lbl.configure(text="  cancelling…")

        def _poll_queue(self):
            try:
                while True:
                    kind, data, extra = self.q.get_nowait()
                    if kind == "list":
                        self.proxies = data
                        self.dot.configure(text_color=THEMES[self.theme]["ok"])
                        self._update_preview()
                    elif kind == "list_err":
                        self.dot.configure(text_color=THEMES[self.theme]["fail"])
                        self.status_lbl.configure(text=f"  load failed: {extra[:60]}")
                    elif kind == "progress":
                        (done, total), res = data
                        self.progress.set(done / total if total else 0)
                        self.count_lbl.configure(text=f"{done} / {total}")
                        self.results.append(res)
                        self._insert_row(res)
                    elif kind == "done":
                        self.results = data
                        self._repopulate()
                        self._finish_run()
                    elif kind == "run_err":
                        messagebox.showerror("Run failed", extra)
                        self._finish_run()
            except queue.Empty:
                pass
            self.after(80, self._poll_queue)

        def _finish_run(self):
            self.running = False
            self.run_btn.configure(state="normal")
            self.cancel_btn.configure(state="disabled")
            ok = sum(1 for r in self.results if r["status"] == "ok")
            cancelled = self.cancel_event.is_set()
            self.status_lbl.configure(
                text=f"  {ok} working / {len(self.results)} tested" + (" (cancelled)" if cancelled else ""))
            self.dot.configure(text_color=THEMES[self.theme]["ok"] if ok else THEMES[self.theme]["fail"])

        # -- table
        def _row_values(self, r):
            return (
                f"{r['host']}:{r['port']}",
                r["protocol"],
                str(r["ping_ms"]) if r["ping_ms"] is not None else "—",
                r["exit_ip"] or "—",
                r["country"] or "—",
                r["status"] + (f" · {r['error']}" if r["error"] else ""),
            )

        def _insert_row(self, r):
            self.tree.insert("", "end", values=self._row_values(r),
                             tags=(r["status"],))

        def _repopulate(self):
            for i in self.tree.get_children():
                self.tree.delete(i)
            ordered = self._sorted_results()
            for r in ordered:
                self._insert_row(r)

        def _sorted_results(self):
            key, asc = self._sort_key, self._sort_asc

            def val(r):
                if key == "addr":
                    return (f"{r['host']}:{r['port']}",)
                v = r.get(key)
                if key in ("latency_ms", "ping_ms"):
                    return (v is None, v if v is not None else 0)
                return (str(v or "").lower(),)

            return sorted(self.results, key=val, reverse=not asc)

        def sort_by(self, col):
            mapping = {"addr": "addr", "proto": "protocol", "ping": "ping_ms",
                       "ip": "exit_ip", "country": "country", "status": "status"}
            key = mapping.get(col, "addr")
            if self._sort_key == key:
                self._sort_asc = not self._sort_asc
            else:
                self._sort_key = key
                self._sort_asc = True
            self._repopulate()

        # -- export
        def export_results(self):
            if not self.results:
                messagebox.showerror("Nothing to export", "Run a test first.")
                return
            chosen = [f for f, var in self.fmt_vars.items() if var.get()]
            if not chosen:
                messagebox.showerror("Pick a format", "Select at least one of csv, txt, html, json.")
                return
            folder = filedialog.askdirectory(title="Choose export folder")
            if not folder:
                return
            stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
            meta = {
                "ping": bool(self.chk_ping.get()),
                "geo": bool(self.chk_geo.get()),
                "chain": self.chain_entry.get().strip() if self.chk_chain.get() else "",
                "list_url": LIST_URL,
            }
            ordered = self._sorted_results()
            written = []
            for fmt in chosen:
                path = os.path.join(folder, f"proxy-results-{stamp}.{fmt}")
                if fmt == "csv":
                    export_csv(ordered, path)
                elif fmt == "txt":
                    export_txt(ordered, path)
                elif fmt == "json":
                    export_json(ordered, path, meta)
                elif fmt == "html":
                    export_html(ordered, path, meta)
                written.append(os.path.basename(path))
            self.status_lbl.configure(text="  wrote " + ", ".join(written))
            messagebox.showinfo("Exported", "Wrote:\n" + "\n".join(
                os.path.join(folder, w) for w in written))

    app = App()
    app.mainloop()


# ---------------------------------------------------------------- entry

def main():
    if "--cli" in sys.argv:
        argv = [a for a in sys.argv[1:] if a != "--cli"]
        cli(argv)
    else:
        run_gui()


if __name__ == "__main__":
    main()
