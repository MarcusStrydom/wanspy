"""
wanspy - a passive public-network reconnaissance and audit toolkit.

One Python file plus JSON detection data, modelled on webspy
(https://github.com/MarcusStrydom/webspy) but pointed at the network
you are currently associated with instead of a web domain. It answers
the questions a traveller, auditor or incident responder actually asks
about a coffee-shop, hotel, airport or conference Wi-Fi before trusting
it with traffic:

  - What am I actually connected to, and how is it secured at layer 2?
  - Is my DNS being hijacked or leaking to a resolver I didn't choose?
  - Is there a captive portal, and is it behaving the way a captive
    portal should?
  - Is something on this segment intercepting my TLS (a corporate proxy,
    a security appliance, or something worse)?
  - Is someone spoofing the gateway's ARP entry?
  - What is the gateway exposing to every other guest on this network?

"Passive" here means wanspy only does what any client is already doing
by joining the network: DHCP/ARP/mDNS observation, ordinary DNS lookups,
a handful of plain HTTP/HTTPS requests to the gateway and to well-known
connectivity-check endpoints, and read-only OS queries for the Wi-Fi
state. It never transmits deauthentication frames, attempts to crack or
guess Wi-Fi credentials, floods ARP, or probes devices other than the
default gateway. See "Responsible use" in the README.
"""

from __future__ import annotations

import argparse
import concurrent.futures
import ipaddress
import json
import os
import platform
import re
import socket
import ssl
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

__version__ = "0.1.0"

CONFIG_SECTIONS = (
    "settings",
    "port_services",
    "banner_signatures",
    "tls_checks",
    "profiles",
)

DEFAULT_CONFIG_DIR = Path(__file__).parent / "config"


class WanspyConfigError(ValueError):
    """Raised for bad config layers: unknown section/key or an invalid regex."""


class Config:
    """Holds the merged section dicts used by a NetAudit instance."""

    def __init__(self, sections):
        self._sections = sections

    def __getattr__(self, name):
        try:
            return self._sections[name]
        except KeyError:
            raise AttributeError(name)

    def get(self, section, key=None, default=None):
        s = self._sections.get(section, {})
        if key is None:
            return s
        return s.get(key, default)


def _load_json_dir(directory):
    sections = {}
    directory = Path(directory)
    if directory.is_file():
        name = directory.stem
        with open(directory, "r", encoding="utf-8") as f:
            sections[name] = json.load(f)
        return sections
    for name in CONFIG_SECTIONS:
        path = directory / f"{name}.json"
        if path.exists():
            with open(path, "r", encoding="utf-8") as f:
                sections[name] = json.load(f)
    return sections


def _deep_merge(base, overlay):
    """Merge overlay into base. A '+key' in overlay appends/updates base['key']."""
    for raw_key, value in overlay.items():
        append = raw_key.startswith("+")
        key = raw_key[1:] if append else raw_key
        if append:
            existing = base.get(key)
            if isinstance(existing, list) and isinstance(value, list):
                base[key] = existing + value
            elif isinstance(existing, dict) and isinstance(value, dict):
                merged = dict(existing)
                merged.update(value)
                base[key] = merged
            elif existing is None:
                base[key] = value
            else:
                raise WanspyConfigError(
                    f"cannot append ('+{key}') onto non-list/dict default {key!r}"
                )
        else:
            if isinstance(value, dict) and isinstance(base.get(key), dict):
                base[key] = _deep_merge(dict(base[key]), value)
            else:
                base[key] = value
    return base


def _validate_regex_fields(sections):
    """Walk known pattern-bearing lists and make sure every 'pattern' compiles."""
    pattern_lists = [
        ("banner_signatures", "signatures"),
    ]
    for section, key in pattern_lists:
        for entry in sections.get(section, {}).get(key, []) or []:
            pat = entry.get("pattern")
            if pat is None:
                continue
            try:
                re.compile(pat, re.IGNORECASE)
            except re.error as exc:
                raise WanspyConfigError(
                    f"bad regex in {section}.json[{key}]: {pat!r} ({exc})"
                )


SETTINGS_KEYS = {
    "timeout", "cache_ttl", "workers", "user_agent", "deep",
    "ping_count", "traceroute_max_hops", "top_ports",
    "full_scan_max_ports", "full_scan_hard_cap",
    "block_scan_max_hosts", "block_discovery_ports",
    "rdap_ip_base", "rdap_timeout", "geo_lookup_url", "geo_lookup_enabled",
}


def build_config(*layers, **options):
    sections = _load_json_dir(DEFAULT_CONFIG_DIR)
    sections = {k: json.loads(json.dumps(v)) for k, v in sections.items()}  # deep copy

    def apply_layer(layer):
        if isinstance(layer, Config):
            layer = layer._sections
        if isinstance(layer, (str, Path)):
            layer = _load_json_dir(layer)
        if not isinstance(layer, dict):
            raise WanspyConfigError(f"unsupported config layer: {layer!r}")
        for key, value in layer.items():
            if key in CONFIG_SECTIONS:
                if not isinstance(value, dict):
                    raise WanspyConfigError(f"section {key!r} must be a dict")
                sections.setdefault(key, {})
                sections[key] = _deep_merge(dict(sections[key]), value)
            elif key in SETTINGS_KEYS or key in ("target", "timeout_connect"):
                sections.setdefault("settings", {})
                sections["settings"][key] = value
            else:
                raise WanspyConfigError(
                    f"unknown config key {key!r} (not a section and not a recognised setting)"
                )

    for layer in layers:
        apply_layer(layer)
    if options:
        apply_layer(options)

    _validate_regex_fields(sections)
    return Config(sections)


def _run(cmd, timeout=5):
    """Run a read-only OS command, return stdout text or '' on any failure."""
    try:
        out = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout, check=False
        )
        return out.stdout or ""
    except Exception:
        return ""


def _now():
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def _probe_result(target, value=None, error=None, **extra):
    r = {"target": target, "time": _now(), "value": value}
    if error is not None:
        r["error"] = str(error)
    r.update(extra)
    return r


class NetAudit:
    """
    Passive-recon auditor for a public host or a CIDR block.

    NetAudit() uses the bundled JSON config. NetAudit(*confs, **options)
    layers overrides over it the same way webspy's Passive does: each
    positional argument is a dict, a path (folder of <section>.json files
    or a single file), or a Config; keyword arguments are one more dict
    layer. A leading '+' on a section key appends to / updates a list or
    dict default instead of replacing it. clone(**options) derives a new
    instance from an existing one.

    Every probe is a `get_*` method, returns a dict with at least
    `target`, `time`, `value` (or `error`), and never raises for an
    ordinary network failure (timeout, refused connection, NXDOMAIN) -
    failures are reported in `error` / `diagnostics` instead.
    """

    def __init__(self, *layers, **options):
        self.config = build_config(*layers, **options)
        self._cache = {}

    def clone(self, *layers, **options):
        new = NetAudit.__new__(NetAudit)
        new.config = build_config(self.config, *layers, **options)
        new._cache = {}
        return new

    def clear_cache(self):
        self._cache.clear()

    # -- settings shortcuts -------------------------------------------------
    def _setting(self, name, override=None):
        if override is not None:
            return override
        return self.config.get("settings", name)

    # -- target normalisation ------------------------------------------------
    @staticmethod
    def _is_cidr(target):
        return "/" in target

    def _resolve_target_ip(self, target):
        """Best-effort: hostname -> first A record, else assume it's already an IP."""
        try:
            ipaddress.ip_address(target)
            return target
        except ValueError:
            pass
        try:
            return socket.gethostbyname(target)
        except socket.gaierror:
            return None

    def _cached(self, key, fn):
        ttl = self.config.get("settings", "cache_ttl", 0)
        if ttl:
            hit = self._cache.get(key)
            if hit and (time.time() - hit[0]) < ttl:
                return hit[1]
        value = fn()
        if ttl:
            self._cache[key] = (time.time(), value)
        return value

    # -- identity -------------------------------------------------------------
    def get_dns_resolve(self, target, **kw):
        """Resolve a hostname to its A/AAAA addresses (no-op if target is already an IP)."""
        try:
            ipaddress.ip_address(target)
            return _probe_result(target, value={"is_ip": True, "addresses": [target]})
        except ValueError:
            pass
        try:
            infos = socket.getaddrinfo(target, None)
            addrs = sorted({i[4][0] for i in infos})
            return _probe_result(target, value={"is_ip": False, "addresses": addrs})
        except socket.gaierror as exc:
            return _probe_result(target, error=f"resolution failed: {exc}")

    def get_rdns(self, target, **kw):
        """Reverse-DNS (PTR) lookup for a single IP."""
        ip = self._resolve_target_ip(target)
        if not ip:
            return _probe_result(target, error="could not resolve target to an IP")
        try:
            host, _, _ = socket.gethostbyaddr(ip)
            return _probe_result(target, value={"ip": ip, "ptr": host})
        except (socket.herror, socket.gaierror):
            return _probe_result(target, value={"ip": ip, "ptr": None})

    def get_ping(self, target, count=None, timeout=None, **kw):
        """ICMP echo via the OS ping binary (read-only; no raw sockets / root needed)."""
        ip = self._resolve_target_ip(target)
        if not ip:
            return _probe_result(target, error="could not resolve target to an IP")
        count = self._setting("ping_count", count) or 3
        timeout = self._setting("timeout", timeout) or 3
        system = platform.system().lower()
        if system == "windows":
            cmd = ["ping", "-n", str(count), "-w", str(int(timeout * 1000)), ip]
        else:
            cmd = ["ping", "-c", str(count), "-W", str(int(timeout)), ip]
        out = _run(cmd, timeout=timeout * count + 3)
        if not out:
            return _probe_result(target, value={"ip": ip, "alive": False, "raw": None},
                                  error="ping produced no output (binary missing, or blocked)")
        alive = ("0% packet loss" in out or " 0.0% packet loss" in out
                  or re.search(r"\breceived\b.*\b([1-9]\d*)\b", out) is not None
                  or re.search(r"Reply from", out) is not None)
        loss_match = re.search(r"(\d+(?:\.\d+)?)\s*%\s*(?:packet\s*)?loss", out)
        rtt_match = re.search(
            r"(?:rtt|round-trip|Average)[^=]*=?\s*([\d.]+)/([\d.]+)/([\d.]+)", out
        )
        rtt_avg = re.search(r"Average = (\d+)ms", out)
        value = {
            "ip": ip,
            "alive": alive,
            "packet_loss_pct": float(loss_match.group(1)) if loss_match else None,
            "rtt_min_ms": float(rtt_match.group(1)) if rtt_match else None,
            "rtt_avg_ms": float(rtt_match.group(2)) if rtt_match else (
                float(rtt_avg.group(1)) if rtt_avg else None
            ),
            "rtt_max_ms": float(rtt_match.group(3)) if rtt_match else None,
        }
        return _probe_result(target, value=value)

    def get_traceroute(self, target, max_hops=None, timeout=None, **kw):
        """Hop-by-hop path via the OS traceroute/tracert binary."""
        ip = self._resolve_target_ip(target)
        if not ip:
            return _probe_result(target, error="could not resolve target to an IP")
        max_hops = self._setting("traceroute_max_hops", max_hops) or 30
        timeout = self._setting("timeout", timeout) or 3
        system = platform.system().lower()
        if system == "windows":
            cmd = ["tracert", "-d", "-h", str(max_hops), "-w", str(int(timeout * 1000)), ip]
        elif system == "darwin":
            cmd = ["traceroute", "-n", "-m", str(max_hops), "-w", str(int(timeout)), ip]
        else:
            cmd = ["traceroute", "-n", "-m", str(max_hops), "-w", str(int(timeout)), ip]
        out = _run(cmd, timeout=max_hops * timeout + 5)
        if not out:
            return _probe_result(target, value={"ip": ip, "hops": []},
                                  error="traceroute produced no output (binary missing, blocked, or needs privileges)")
        hops = []
        for line in out.splitlines():
            m = re.match(r"\s*(\d+)\s+(.*)", line)
            if not m:
                continue
            hop_no = int(m.group(1))
            rest = m.group(2)
            ips_found = re.findall(r"\d{1,3}(?:\.\d{1,3}){3}", rest)
            timed_out = "*" in rest and not ips_found
            hops.append({
                "hop": hop_no,
                "ip": ips_found[0] if ips_found else None,
                "timed_out": timed_out,
                "raw": rest.strip(),
            })
        reached = bool(hops) and hops[-1].get("ip") == ip
        return _probe_result(target, value={"ip": ip, "hops": hops, "reached_target": reached})

    # -- port scanning / service exposure -------------------------------------
    def _connect_scan_one(self, ip, port, timeout):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        try:
            result = s.connect_ex((ip, port))
            return port, (result == 0)
        except socket.error:
            return port, False
        finally:
            s.close()

    def _connect_scan_many(self, ip, ports, timeout, workers):
        open_ports = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as ex:
            futures = [ex.submit(self._connect_scan_one, ip, p, timeout) for p in ports]
            for fut in concurrent.futures.as_completed(futures):
                port, is_open = fut.result()
                if is_open:
                    open_ports.append(port)
        return sorted(open_ports)

    def get_port_scan(self, target, ports=None, timeout=None, workers=None, **kw):
        """TCP connect scan of the configured top_ports list (or an explicit `ports` list)."""
        ip = self._resolve_target_ip(target)
        if not ip:
            return _probe_result(target, error="could not resolve target to an IP")
        timeout = self._setting("timeout", timeout) or 3
        workers = self._setting("workers", workers) or 20
        port_list = ports or self.config.get("settings", "top_ports")
        open_ports = self._connect_scan_many(ip, port_list, timeout, workers)
        port_notes = self.config.get("port_services", "ports") or {}
        services = {
            str(p): port_notes.get(str(p), {"name": "unknown", "risk": "info",
                                             "note": "no signature for this port"})
            for p in open_ports
        }
        return _probe_result(target, value={
            "ip": ip, "scanned_ports": len(port_list),
            "open_ports": open_ports, "services": services,
        })

    def get_port_scan_full(self, target, timeout=None, workers=None, **kw):
        """Wider connect scan: 1..full_scan_max_ports, capped at full_scan_hard_cap."""
        max_ports = self.config.get("settings", "full_scan_max_ports", 1024)
        hard_cap = self.config.get("settings", "full_scan_hard_cap", 4096)
        max_ports = min(max_ports, hard_cap)
        ports = list(range(1, max_ports + 1))
        return self.get_port_scan(target, ports=ports, timeout=timeout, workers=workers, **kw)

    def get_service_banners(self, target, ports=None, timeout=None, **kw):
        """Connect to each open port found by get_port_scan and read/send a probe for a banner."""
        ip = self._resolve_target_ip(target)
        if not ip:
            return _probe_result(target, error="could not resolve target to an IP")
        timeout = self._setting("timeout", timeout) or 3
        if ports is None:
            scan = self._cached(f"portscan:{ip}", lambda: self.get_port_scan(target))
            ports = scan["value"]["open_ports"] if scan.get("value") else []
        sigs = self.config.get("banner_signatures", "signatures") or []
        results = {}
        for port in ports:
            banner = self._grab_banner(ip, port, timeout)
            match = self._match_banner(banner, sigs) if banner else None
            results[str(port)] = {"banner": banner, "identified": match}
        return _probe_result(target, value=results)

    def _grab_banner(self, ip, port, timeout):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(timeout)
            s.connect((ip, port))
            try:
                s.settimeout(timeout)
                data = s.recv(256)
            except socket.timeout:
                data = b""
            if not data and port in (80, 8080, 8000, 8888, 3000, 5000, 9090, 9000):
                try:
                    s.sendall(b"HEAD / HTTP/1.0\r\nHost: %b\r\n\r\n" % ip.encode())
                    s.settimeout(timeout)
                    data = s.recv(512)
                except socket.error:
                    pass
            s.close()
            if not data:
                return None
            return data.decode("utf-8", errors="replace").strip()
        except socket.error:
            return None

    @staticmethod
    def _match_banner(banner, sigs):
        if not banner:
            return None
        for sig in sigs:
            m = re.search(sig["pattern"], banner, re.IGNORECASE)
            if m:
                version = None
                grp = sig.get("version_group")
                if grp:
                    try:
                        version = m.group(grp)
                    except IndexError:
                        version = None
                return {"product": sig["product"], "version": version}
        return None

    # -- TLS / HTTP -------------------------------------------------------------
    def get_tls_cert_info(self, target, port=443, timeout=None, **kw):
        """Fetch and parse the target's own leaf certificate (expiry, issuer, self-signed, SANs)."""
        ip = self._resolve_target_ip(target)
        if not ip:
            return _probe_result(target, error="could not resolve target to an IP")
        timeout = self._setting("timeout", timeout) or 3
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        try:
            with socket.create_connection((ip, port), timeout=timeout) as raw_sock:
                with ctx.wrap_socket(raw_sock, server_hostname=target) as tls_sock:
                    der = tls_sock.getpeercert(binary_form=True)
                    cipher = tls_sock.cipher()
                    tls_version = tls_sock.version()
        except (socket.error, ssl.SSLError, OSError) as exc:
            return _probe_result(target, error=f"TLS connect failed on port {port}: {exc}")

        cert_text = ssl.DER_cert_to_PEM_cert(der)
        parsed = self._parse_cert_openssl(cert_text, timeout)
        value = {
            "ip": ip, "port": port, "tls_version": tls_version,
            "cipher": cipher[0] if cipher else None,
        }
        value.update(parsed)
        return _probe_result(target, value=value)

    def _parse_cert_openssl(self, cert_pem, timeout):
        """Use the `openssl` CLI to parse the cert (avoids a cryptography dependency)."""
        try:
            proc = subprocess.run(
                ["openssl", "x509", "-noout", "-subject", "-issuer", "-dates",
                 "-ext", "subjectAltName", "-fingerprint", "-sha256"],
                input=cert_pem, capture_output=True, text=True, timeout=timeout + 2, check=False,
            )
            out = proc.stdout
        except Exception:
            out = ""
        subject = self._extract_after(out, "subject=")
        issuer = self._extract_after(out, "issuer=")
        not_before = self._extract_after(out, "notBefore=")
        not_after = self._extract_after(out, "notAfter=")
        san_match = re.search(r"X509v3 Subject Alternative Name:\s*\n\s*(.*)", out)
        sans = [s.strip() for s in san_match.group(1).split(",")] if san_match else []
        fp_match = re.search(r"SHA256 Fingerprint=([0-9A-F:]+)", out)
        self_signed = bool(subject and issuer and subject == issuer)
        days_left = None
        if not_after:
            try:
                import email.utils as eut
                expiry_ts = eut.parsedate_to_datetime(not_after)
                days_left = (expiry_ts.replace(tzinfo=None) - __import__("datetime").datetime.utcnow()).days
            except Exception:
                days_left = None
        return {
            "subject": subject, "issuer": issuer,
            "not_before": not_before, "not_after": not_after,
            "days_until_expiry": days_left,
            "self_signed": self_signed,
            "subject_alt_names": sans,
            "sha256_fingerprint": fp_match.group(1) if fp_match else None,
            "parse_ok": bool(subject or issuer),
        }

    @staticmethod
    def _extract_after(text, marker):
        for line in text.splitlines():
            if line.startswith(marker):
                return line[len(marker):].strip()
        return None

    def get_http_info(self, target, port=None, timeout=None, **kw):
        """Plain HTTP(S) HEAD/GET: status, Server/X-Powered-By headers, redirect chain, <title>."""
        ip = self._resolve_target_ip(target)
        if not ip:
            return _probe_result(target, error="could not resolve target to an IP")
        timeout = self._setting("timeout", timeout) or 3
        ua = self.config.get("settings", "user_agent")
        schemes = [("https", 443)] if port == 443 else [("http", port or 80), ("https", port or 443)]
        results = {}
        for scheme, p in schemes:
            url = f"{scheme}://{target}:{p}/" if p not in (80, 443) else f"{scheme}://{target}/"
            req = urllib.request.Request(url, headers={"User-Agent": ua})
            ctx = ssl._create_unverified_context() if scheme == "https" else None
            try:
                with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
                    body = resp.read(4096).decode("utf-8", errors="replace")
                    title_m = re.search(r"<title[^>]*>(.*?)</title>", body, re.IGNORECASE | re.DOTALL)
                    results[scheme] = {
                        "status": resp.status,
                        "final_url": resp.geturl(),
                        "server": resp.headers.get("Server"),
                        "x_powered_by": resp.headers.get("X-Powered-By"),
                        "title": title_m.group(1).strip() if title_m else None,
                    }
            except urllib.error.HTTPError as exc:
                results[scheme] = {"status": exc.code, "server": exc.headers.get("Server") if exc.headers else None}
            except Exception as exc:
                results[scheme] = {"error": str(exc)}
        return _probe_result(target, value=results)

    # -- registration / geo -------------------------------------------------------
    def get_rdap(self, target, timeout=None, **kw):
        """RDAP lookup for the IP: registered network block, org/holder, country, abuse contact."""
        ip = self._resolve_target_ip(target)
        if not ip:
            return _probe_result(target, error="could not resolve target to an IP")
        timeout = self._setting("timeout", self.config.get("settings", "rdap_timeout", timeout)) or 6
        base = self.config.get("settings", "rdap_ip_base")
        url = base + ip
        try:
            req = urllib.request.Request(url, headers={"User-Agent": self.config.get("settings", "user_agent")})
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                data = json.loads(resp.read().decode("utf-8", errors="replace"))
        except Exception as exc:
            return _probe_result(target, error=f"RDAP lookup failed: {exc}")
        entities = []
        for ent in data.get("entities", []) or []:
            vcard = ent.get("vcardArray")
            name = None
            if vcard and len(vcard) > 1:
                for field in vcard[1]:
                    if field[0] == "fn":
                        name = field[3]
            entities.append({"roles": ent.get("roles"), "name": name})
        value = {
            "ip": ip,
            "handle": data.get("handle"),
            "name": data.get("name"),
            "cidr_blocks": [f"{c.get('v4prefix') or c.get('v6prefix')}/{c.get('length')}"
                             for c in data.get("cidr0_cidrs", [])] or None,
            "start_address": data.get("startAddress"),
            "end_address": data.get("endAddress"),
            "country": data.get("country"),
            "entities": entities,
        }
        return _probe_result(target, value=value)

    def get_geo_hint(self, target, timeout=None, **kw):
        """Coarse IP geolocation / ISP hint from a free public API. Treat as approximate."""
        if not self.config.get("settings", "geo_lookup_enabled", True):
            return _probe_result(target, value=None, error="geo lookup disabled in config")
        ip = self._resolve_target_ip(target)
        if not ip:
            return _probe_result(target, error="could not resolve target to an IP")
        timeout = self._setting("timeout", timeout) or 3
        url = self.config.get("settings", "geo_lookup_url").format(ip=ip)
        try:
            req = urllib.request.Request(url, headers={"User-Agent": self.config.get("settings", "user_agent")})
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                data = json.loads(resp.read().decode("utf-8", errors="replace"))
        except Exception as exc:
            return _probe_result(target, error=f"geo lookup failed: {exc}")
        if data.get("status") == "fail":
            return _probe_result(target, value=None, error=data.get("message", "lookup failed"))
        return _probe_result(target, value=data)

    # -- block discovery -------------------------------------------------------------
    def get_block_discovery(self, target, ports=None, timeout=None, workers=None, max_hosts=None, **kw):
        """
        For a CIDR target: probe every host for liveness via the configured
        block_discovery_ports (fast connect attempts), capped at block_scan_max_hosts.
        For a single host/IP target: returns that one address as a convenience.
        """
        timeout = self._setting("timeout", timeout) or 3
        workers = self._setting("workers", workers) or 20
        ports = ports or self.config.get("settings", "block_discovery_ports")
        cap = max_hosts or self.config.get("settings", "block_scan_max_hosts", 256)

        if self._is_cidr(target):
            try:
                network = ipaddress.ip_network(target, strict=False)
            except ValueError as exc:
                return _probe_result(target, error=f"invalid CIDR: {exc}")
            hosts = list(network.hosts())
            truncated = len(hosts) > cap
            hosts = hosts[:cap]
        else:
            ip = self._resolve_target_ip(target)
            if not ip:
                return _probe_result(target, error="could not resolve target to an IP")
            hosts = [ipaddress.ip_address(ip)]
            truncated = False

        def host_alive(ip_obj):
            ip_str = str(ip_obj)
            for p in ports:
                _, is_open = self._connect_scan_one(ip_str, p, timeout)
                if is_open:
                    return ip_str, True
            return ip_str, False

        live = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as ex:
            futures = [ex.submit(host_alive, h) for h in hosts]
            for fut in concurrent.futures.as_completed(futures):
                ip_str, alive = fut.result()
                if alive:
                    live.append(ip_str)

        return _probe_result(target, value={
            "hosts_probed": len(hosts),
            "hosts_truncated": truncated,
            "live_hosts": sorted(live, key=lambda s: ipaddress.ip_address(s)),
            "probe_ports": ports,
        })

    # -- probe registry -------------------------------------------------------------
    PROBE_DOCS = {
        "get_dns_resolve": "Resolve a hostname to its addresses (no-op for a bare IP)",
        "get_rdns": "Reverse-DNS (PTR) lookup for the target IP",
        "get_ping": "ICMP ping via the OS binary: alive, loss %, RTT",
        "get_traceroute": "Hop-by-hop path via the OS traceroute/tracert binary",
        "get_port_scan": "TCP connect scan of the configured top-ports list",
        "get_port_scan_full": "TCP connect scan of ports 1..full_scan_max_ports",
        "get_service_banners": "Grab a banner from each open port and identify product/version",
        "get_tls_cert_info": "Parse the target's own TLS certificate: expiry, issuer, self-signed, SANs",
        "get_http_info": "HTTP/HTTPS status, Server/X-Powered-By headers, page title",
        "get_rdap": "RDAP lookup: registered network block, holder org, country",
        "get_geo_hint": "Coarse IP geolocation / ISP hint from a public API (approximate)",
        "get_block_discovery": "Sweep a CIDR block for live hosts (or confirm a single host)",
    }

    def list_probes(self):
        return dict(self.PROBE_DOCS)

    def run_probe(self, name, target, **kw):
        fn = getattr(self, name, None)
        if fn is None or not name.startswith("get_"):
            raise WanspyConfigError(f"unknown probe: {name}")
        return fn(target, **kw)

    def run_audit(self, target, profile="standard", workers=None):
        probe_names = self.config.get("profiles", profile)
        if probe_names is None:
            raise WanspyConfigError(
                f"unknown profile {profile!r}; known profiles: "
                f"{', '.join(self.config.get('profiles').keys())}"
            )
        workers = self._setting("workers", workers) or 3
        results = {}
        with concurrent.futures.ThreadPoolExecutor(max_workers=min(workers, 3)) as ex:
            futures = {ex.submit(self.run_probe, name, target): name for name in probe_names}
            for fut in concurrent.futures.as_completed(futures):
                name = futures[fut]
                try:
                    results[name] = fut.result()
                except Exception as exc:
                    results[name] = _probe_result(target, error=f"probe crashed: {exc}")

        findings = self.derive_findings(target, results)
        severity_rank = self.config.get("settings", "severity_rank")
        counts = {k: 0 for k in severity_rank}
        for f in findings:
            counts[f["severity"]] = counts.get(f["severity"], 0) + 1

        return {
            "target": target,
            "profile": profile,
            "time": _now(),
            "wanspy_version": __version__,
            "probes": results,
            "findings": sorted(findings, key=lambda f: -severity_rank.get(f["severity"], 0)),
            "summary": {
                "severity_counts": counts,
                "probes_run": list(results.keys()),
                "probes_with_errors": [n for n, r in results.items() if r.get("error")],
            },
        }

    # -- findings engine -------------------------------------------------------------
    def derive_findings(self, target, probes):
        findings = []

        def add(severity, title, detail, probe, confidence="high"):
            findings.append({
                "severity": severity, "confidence": confidence,
                "title": title, "detail": detail, "probe": probe,
            })

        ping = probes.get("get_ping", {}).get("value")
        if ping and ping.get("alive") is False:
            add("info", "Host did not respond to ICMP",
                "No reply to ping; this is common for hosts that filter ICMP and does not "
                "by itself mean the host is down.", "get_ping", confidence="low")

        port_services = self.config.get("port_services", "ports") or {}
        scan = probes.get("get_port_scan", {}).get("value") or probes.get("get_port_scan_full", {}).get("value")
        banners = (probes.get("get_service_banners", {}).get("value") or {})
        if scan:
            for p in scan.get("open_ports", []):
                note = port_services.get(str(p), {"name": "unknown", "risk": "info", "note": ""})
                banner_info = banners.get(str(p), {})
                identified = banner_info.get("identified")
                detail = note["note"]
                if identified:
                    detail += f" Identified as {identified['product']}"
                    if identified.get("version"):
                        detail += f" {identified['version']}"
                    detail += "."
                add(note["risk"], f"Open port {p}/tcp ({note['name']})", detail, "get_port_scan")

        tls = probes.get("get_tls_cert_info", {}).get("value")
        if tls and not tls.get("error"):
            checks = self.config.get("tls_checks")
            if tls.get("self_signed") and checks.get("flag_self_signed"):
                add("medium", "Self-signed TLS certificate",
                    f"Subject and issuer are identical ({tls.get('subject')}). "
                    "Not inherently malicious but means no public CA vouches for this host.",
                    "get_tls_cert_info")
            days = tls.get("days_until_expiry")
            if days is not None:
                if days < 0:
                    add("high", "TLS certificate has expired",
                        f"Expired {abs(days)} day(s) ago ({tls.get('not_after')}).",
                        "get_tls_cert_info")
                elif days < checks.get("expiry_warning_days", 30):
                    add("low", "TLS certificate expiring soon",
                        f"Expires in {days} day(s) ({tls.get('not_after')}).",
                        "get_tls_cert_info")

        rdap = probes.get("get_rdap", {}).get("value")
        if rdap:
            add("info", "Network registration",
                f"{rdap.get('name') or rdap.get('handle') or 'unknown block'} "
                f"({', '.join(rdap.get('cidr_blocks') or []) or 'range not reported'}), "
                f"country {rdap.get('country') or 'unknown'}.",
                "get_rdap", confidence="high")

        block = probes.get("get_block_discovery", {}).get("value")
        if block and block.get("live_hosts") is not None:
            add("info", f"{len(block['live_hosts'])} live host(s) discovered",
                f"Out of {block['hosts_probed']} probed"
                + (" (block truncated to the configured cap)" if block.get("hosts_truncated") else "") + ".",
                "get_block_discovery", confidence="high")

        return findings

    # -- reports -------------------------------------------------------------
    @staticmethod
    def save_report(report, path):
        with open(path, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2, default=str)

    @staticmethod
    def report_to_markdown(report):
        lines = [
            f"# wanspy report: {report['target']}",
            "",
            f"- Profile: `{report['profile']}`",
            f"- Generated: {report['time']}",
            f"- Probes run: {len(report['summary']['probes_run'])} "
            f"({len(report['summary']['probes_with_errors'])} with errors)",
            "",
            "## Findings",
            "",
        ]
        sev_emoji = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🔵", "info": "⚪"}
        if not report["findings"]:
            lines.append("_No findings._")
        for f in report["findings"]:
            lines.append(
                f"- {sev_emoji.get(f['severity'], '')} **[{f['severity'].upper()}]** "
                f"{f['title']} — {f['detail']} _(probe: `{f['probe']}`, confidence: {f['confidence']})_"
            )
        lines += ["", "## Raw probe output", ""]
        for name, result in report["probes"].items():
            lines.append(f"### `{name}`")
            lines.append("```json")
            lines.append(json.dumps(result, indent=2, default=str))
            lines.append("```")
            lines.append("")
        return "\n".join(lines)


def _print_probe_list(audit):
    for name, doc in sorted(audit.list_probes().items()):
        print(f"{name:24s} {doc}")


def main(argv=None):
    parser = argparse.ArgumentParser(
        prog="wanspy",
        description="Passive recon/audit of a public host or CIDR block (nmap/whois-style, "
                     "not a web-page auditor). Only scan systems you own or are authorised to test.",
    )
    parser.add_argument("target", nargs="?", help="hostname, IP, or CIDR block, e.g. 203.0.113.4 or 203.0.113.0/28")
    parser.add_argument("--profile", default="standard", choices=["quick", "standard", "full"])
    parser.add_argument("--probe", action="append", dest="probes", default=[],
                         help="run one named probe instead of a profile (repeatable)")
    parser.add_argument("--json", metavar="PATH", help="write the JSON report here")
    parser.add_argument("--markdown", metavar="PATH", help="write the Markdown report here")
    parser.add_argument("--config", metavar="PATH", help="folder or file of config overrides")
    parser.add_argument("--timeout", type=float, default=None)
    parser.add_argument("--workers", type=int, default=None)
    parser.add_argument("--list-probes", action="store_true")
    parser.add_argument("--version", action="version", version=f"wanspy {__version__}")
    args = parser.parse_args(argv)

    layers = []
    if args.config:
        layers.append(args.config)
    options = {}
    if args.timeout is not None:
        options["timeout"] = args.timeout
    if args.workers is not None:
        options["workers"] = args.workers

    audit = NetAudit(*layers, **options)

    if args.list_probes:
        _print_probe_list(audit)
        return 0

    if not args.target:
        parser.error("a target (hostname, IP, or CIDR) is required unless using --list-probes")

    if args.probes:
        for name in args.probes:
            result = audit.run_probe(name, args.target)
            print(json.dumps(result, indent=2, default=str))
        return 0

    report = audit.run_audit(args.target, profile=args.profile)
    print(json.dumps(report["summary"], indent=2, default=str))

    if args.json:
        audit.save_report(report, args.json)
        print(f"\nJSON report written to {args.json}", file=sys.stderr)
    if args.markdown:
        with open(args.markdown, "w", encoding="utf-8") as f:
            f.write(audit.report_to_markdown(report))
        print(f"Markdown report written to {args.markdown}", file=sys.stderr)
    if not args.json and not args.markdown:
        print()
        print(audit.report_to_markdown(report))
    return 0


if __name__ == "__main__":
    sys.exit(main())
