# wanspy

[#wanspy](#wanspy)

A passive public-network reconnaissance and audit toolkit: one Python file plus
JSON detection data. Point it at a public IP, hostname, or CIDR block and it
answers the questions an auditor, pentester or incident responder actually asks:

- Is the host up, and how far away is it (ping, traceroute)?
- What is it exposing to the internet, and how risky is each thing (port scan,
  service/version fingerprinting)?
- Is its TLS certificate valid, self-signed, or expiring?
- Who registered this address space, and roughly where does it sit?
- On a whole block: which hosts in that range are even alive?

wanspy is the sibling of [webspy](https://github.com/MarcusStrydom/webspy)
(which audits a *web application*); wanspy audits the *network host or block*
underneath one — same architecture (single module, JSON-driven detection
data, probe catalogue, audit profiles, severity-ranked findings, JSON/Markdown
reports), different target. It intentionally does **not** do anything
LAN-side (Wi-Fi association, ARP, DHCP, captive portals) — that's a separate,
embedded-device-based project.

"Passive" means wanspy only does what any ordinary internet client already
does, just more systematically: TCP connect attempts, ICMP pings, the OS's
own traceroute, a handful of plain HTTP/HTTPS requests, a TLS handshake, and
public registries (RDAP). It never sends exploit payloads, brute-forces
credentials, or tries to log in. It **does** send traffic to the target at
some volume (especially `full` profile / block scans), so see
[Responsible use](#responsible-use) before pointing it at anything.

## Install

[#install](#install)

```
pip install -r requirements.txt   # standard library only; no required third-party deps
```

Python 3.9+. Copy `wanspy.py` and the `config/` folder into your project, or
install the package (`pip install -e .`) to get the `wanspy` console script.

## Quick start

[#quick-start](#quick-start)

### Command line

[#command-line](#command-line)

```
wanspy 203.0.113.4                                       # standard audit of a single host
wanspy example.com --profile full --json report.json --markdown report.md
wanspy 203.0.113.0/28 --profile full                      # sweep a block, then audit live hosts' context
wanspy 203.0.113.4 --probe get_port_scan --probe get_tls_cert_info
wanspy --list-probes
```

### Library

[#library](#library)

```python
from wanspy import NetAudit

audit = NetAudit()                                 # defaults from config/*.json
scan = audit.get_port_scan('203.0.113.4')
banners = audit.get_service_banners('203.0.113.4')
tls = audit.get_tls_cert_info('203.0.113.4')

report = audit.run_audit('203.0.113.4', profile='standard')
print(report['summary']['severity_counts'])
audit.save_report(report, 'report.json')
print(audit.report_to_markdown(report))
```

### Several configured instances

[#several-configured-instances](#several-configured-instances)

`NetAudit(*confs, **options)` builds a probe set from the config files plus
any overrides you give it, exactly like webspy's `Passive`:

```python
light = NetAudit(workers=5, timeout=2)
strict = NetAudit({'port_services': {'+ports': {
             '9999': {'name': 'Internal API', 'risk': 'high', 'note': 'should not be public'}}}},
           'my_config/',                 # a folder (or single <section>.json) of overrides
           timeout=3)
derived = strict.clone(workers=50)       # derive from an existing instance

light.get_port_scan('203.0.113.4')
```

Each argument is a layer applied over the defaults, in order: a **dict**, a
**path** (folder of `<section>.json` files, or one file) or a **Config**
object. Keyword arguments are one more dict layer. Inside a section a key
replaces the default value; prefix it with `+` (`'+ports'`) to append to a
list or update a dict instead. Settings (`timeout`, `workers`, `top_ports`,
etc.) are set directly as keyword/dict keys, not inside a section. Unknown
sections, keys and bad regexes raise immediately, naming the offender.
Arguments passed to a probe always win over the instance defaults.

Every probe returns `{'target', 'time', 'value', ...}`; any failure is
reported as an `error` field instead of raising.

## Audit profiles

[#audit-profiles](#audit-profiles)

| Profile    | Purpose                          | Probes                                                                                                   |
| ---------- | --------------------------------- | ---------------------------------------------------------------------------------------------------------- |
| `quick`    | Fast liveness/exposure check      | DNS resolve, rDNS, ping, top-port scan                                                                    |
| `standard` | Default host audit                | + traceroute, service banners, TLS cert check, HTTP info, RDAP, geo hint                                   |
| `full`     | Audit plus wider recon            | + full port range scan (1..`full_scan_max_ports`), CIDR block discovery (if target is a block)             |

`run_audit` runs the probes (3 in parallel by default), then `derive_findings`
converts the raw output into severity-ranked findings (`critical`, `high`,
`medium`, `low`, `info`).

## Probe catalogue

[#probe-catalogue](#probe-catalogue)

**Reachability** `get_dns_resolve` · `get_rdns` · `get_ping` · `get_traceroute`

**Exposure** `get_port_scan` · `get_port_scan_full` · `get_service_banners`

**Transport security** `get_tls_cert_info`

**Application layer** `get_http_info`

**Registration / attribution** `get_rdap` · `get_geo_hint`

**Block recon** `get_block_discovery` (CIDR sweep for live hosts; also accepts
a single host as a one-element convenience)

Run `wanspy --list-probes` for one-line descriptions of each.

## How exposure detection works

[#how-exposure-detection-works](#how-exposure-detection-works)

1. **Connect scan.** `get_port_scan` does a plain TCP connect (no raw sockets,
   no root needed) against the `top_ports` list from `config/settings.json`
   (common admin, database, file-sharing and remote-access ports).
   `get_port_scan_full` widens this to 1..`full_scan_max_ports`, hard-capped
   at `full_scan_hard_cap` so a typo in config can't turn into a 65535-port
   scan by accident.
2. **Risk context per port.** Every open port is looked up in
   `config/port_services.json`, which carries a baseline severity and why
   that service being internet-facing matters (e.g. Redis/Mongo/Elasticsearch
   with no default auth, RDP/VNC/Telnet as common ransomware/IoT entry
   points, TR-069 as a historically mass-exploited ISP management protocol).
3. **Banner / version fingerprinting.** `get_service_banners` connects to
   each open port, reads (or, for common web ports, sends a bare `HEAD /`
   and reads) the first response bytes, and matches it against the regexes
   in `config/banner_signatures.json` to name the product and version where
   possible — this is the same signal `nmap -sV` uses, just regex-driven and
   readable.
4. **TLS posture.** `get_tls_cert_info` fetches the target's own leaf
   certificate directly (certificate verification is intentionally disabled
   for this probe — the point is to see *what the host presents*, not to
   validate a trust chain) and reports subject, issuer, SANs, self-signed
   status and days until expiry.
5. **Registration context.** `get_rdap` resolves the IP to its registered
   network block and holder organisation via RDAP (same mechanism webspy
   uses for domains, here applied to the IP). `get_geo_hint` adds a coarse,
   best-effort geolocation/ISP hint from a free public API — treat it as a
   lead, not ground truth.

## Investigation / audit workflows

[#investigation--audit-workflows](#investigation--audit-workflows)

- **Is this box even reachable, and from where?** `get_ping` + `get_traceroute`
  — note that a host with `alive: false` may simply be filtering ICMP; cross-
  check against `get_port_scan` before concluding it's down.
- **What's internet-facing here that shouldn't be?** `get_port_scan` /
  `get_port_scan_full` + `get_service_banners`, read against
  `config/port_services.json`'s risk notes — databases, admin panels and
  remote-access services with no business being reachable from the public
  internet are the highest-value findings.
- **Is the certificate trustworthy and current?** `get_tls_cert_info` — flags
  self-signed certs and looming/expired certs via `config/tls_checks.json`
  thresholds.
- **Whose infrastructure is this, and where does it sit?** `get_rdap` +
  `get_geo_hint` together give registrant org, network block and a rough
  location, useful for attribution or for confirming a host actually belongs
  to the organisation you're auditing before you go further.
- **What else is alive on this block?** `get_block_discovery` against a CIDR
  sweeps for live hosts via fast connect attempts on
  `block_discovery_ports`, capped at `block_scan_max_hosts` so a `/16` typed
  by mistake doesn't turn into an hours-long scan.

## Extending

[#extending](#extending)

Detection data lives in JSON files under `config/`, not in the code. Add a
port signature by appending to `config/port_services.json`, or per instance:

```python
NetAudit({'port_services': {'+ports': {
    '4000': {'name': 'Internal Admin', 'risk': 'high', 'note': 'should not be public'}}}})
```

Add a banner signature to `config/banner_signatures.json` (or per instance
with `'+signatures'`):

```json
{ "pattern": "MyDatabase Server ([\\d.]+)", "product": "MyDatabase", "version_group": 1 }
```

Patterns are case-insensitive regexes matched against the raw banner bytes
(or, where noted, an HTTP header). Add new probes as
`def get_*(self, target, **kwargs)` on `NetAudit` (start by resolving the
target with `self._resolve_target_ip(target)`); they appear in
`--list-probes` and can be added to `config/profiles.json`. Add finding rules
in `derive_findings`.

| File                      | Contents                                                                 |
| ------------------------- | ------------------------------------------------------------------------- |
| `settings.json`           | defaults for every option (timeouts, workers, port lists, scan caps, RDAP/geo endpoints), severity and confidence ranking |
| `port_services.json`      | port -> service name, baseline risk, and why it matters                  |
| `banner_signatures.json`  | regexes for identifying product/version from a service banner            |
| `tls_checks.json`         | certificate expiry/self-signed thresholds                                |
| `profiles.json`           | audit profiles (name to probe list; add your own)                        |

The default config files are loaded once at import; overrides are compiled
when an instance is created. Regexes are validated on load, so a typo fails
immediately with the file and entry named. Set `WANSPY_CONFIG_DIR` to use a
different config directory system-wide, or pass `--config` / a path layer
per instance.

## Configuration

[#configuration](#configuration)

| Setting                                          | Option / argument     | Default |
| -------------------------------------------------- | ---------------------- | ------- |
| Response cache TTL (seconds, `0` disables)        | `cache_ttl`            | `30` (cache is per instance; `clear_cache()`) |
| Request/connect timeout (seconds)                 | `timeout`              | `3`     |
| Scan parallelism (port scan / block discovery)    | `workers`              | `20`    |
| Audit parallelism (probes run concurrently)       | n/a (fixed at 3)       | `3`     |
| Ping count                                        | `ping_count`           | `3`     |
| Traceroute max hops                               | `traceroute_max_hops`  | `30`    |
| Top-ports list scanned by `get_port_scan`         | `top_ports`            | ~45 common admin/db/remote-access ports |
| Max ports for `get_port_scan_full`                | `full_scan_max_ports`  | `1024`  |
| Hard cap for `get_port_scan_full`                 | `full_scan_hard_cap`   | `4096`  |
| Max hosts probed per CIDR in `get_block_discovery`| `block_scan_max_hosts` | `256`   |

All of these live in `config/settings.json`, can be set per instance, and can
be overridden per probe call (`audit.get_port_scan(target, timeout=1)`).

## Limitations

[#limitations](#limitations)

- Connect scans are accurate but not stealthy — a host or its firewall will
  see (and may log or block) the attempt. There is no SYN/half-open scanning
  here on purpose; it would need raw sockets and root, and connect scans are
  sufficient for an audit.
- A filtered port and a closed port both read as "not open" to a connect
  scan; wanspy does not distinguish `filtered` from `closed` the way a raw
  SYN scanner can.
- `get_ping` and `get_traceroute` shell out to the OS binaries; if they're
  missing, blocked by policy, or ICMP is filtered end-to-end, you'll see an
  `error` rather than a false "down" reading — always cross-check with
  `get_port_scan` before concluding a host is unreachable.
- Banner/version identification is signature-based and will go stale as
  software ships new versions; treat an unmatched banner as a lead to
  identify manually, not a dead end.
- `get_tls_cert_info` deliberately disables certificate verification (it's
  inspecting the cert, not validating a trust chain) and relies on the
  system `openssl` CLI to parse fields; without `openssl` on `PATH` you'll
  still get the raw handshake info (version, cipher) but not subject/issuer
  detail.
- RDAP coverage varies by registry; `get_geo_hint` uses a free third-party
  API with its own rate limits and should be treated as approximate.
- `get_block_discovery`'s liveness check is a fast connect probe on a small
  port set, not a full ping sweep — a host with everything in that set
  filtered will read as not-live even if it's up.
- `derive_findings` is a triage aid, not a substitute for manual review.

## Responsible use

[#responsible-use](#responsible-use)

Use wanspy only against hosts and address ranges you own or are explicitly
authorised to test. Port scanning and probing systems you don't control
without authorisation is illegal in most jurisdictions (e.g. the US
Computer Fraud and Abuse Act, UK Computer Misuse Act) regardless of intent.
`get_port_scan_full` and `get_block_discovery` generate meaningfully more
traffic than `quick`/`standard` and are more likely to trip an IDS/IPS or a
cloud provider's abuse detection — get written authorization before running
them against anything you don't personally own, and respect the target's
rate limits, acceptable-use policy and applicable law.

## Changelog

[#changelog](#changelog)

**0.1**

- Initial release: host/CIDR-focused `NetAudit`, config-driven probe
  catalogue (reachability, exposure, TLS, HTTP, RDAP/geo, block discovery),
  `quick`/`standard`/`full` profiles, `run_audit`/`derive_findings`,
  JSON/Markdown reports, CLI, response cache.
