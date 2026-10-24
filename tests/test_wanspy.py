import json
import socket
import threading
import time

import pytest

from wanspy import NetAudit, WanspyConfigError


@pytest.fixture
def audit():
    return NetAudit(timeout=1, workers=20)


def _serve_once(port, banner=b""):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("127.0.0.1", port))
    s.listen(5)

    def run():
        while True:
            conn, _ = s.accept()
            if banner:
                conn.sendall(banner)
            conn.close()

    t = threading.Thread(target=run, daemon=True)
    t.start()
    time.sleep(0.2)
    return s


def test_dns_resolve_ip_is_noop(audit):
    r = audit.get_dns_resolve("127.0.0.1")
    assert r["value"]["is_ip"] is True
    assert r["value"]["addresses"] == ["127.0.0.1"]


def test_rdns_loopback(audit):
    r = audit.get_rdns("127.0.0.1")
    assert r["value"]["ip"] == "127.0.0.1"


def test_port_scan_detects_open_and_closed(audit):
    _serve_once(23456)
    r = audit.get_port_scan("127.0.0.1", ports=[23456, 23457])
    assert r["value"]["open_ports"] == [23456]


def test_banner_identifies_openssh(audit):
    _serve_once(23458, banner=b"SSH-2.0-OpenSSH_9.6\r\n")
    r = audit.get_service_banners("127.0.0.1", ports=[23458])
    identified = r["value"]["23458"]["identified"]
    assert identified["product"] == "OpenSSH"
    assert identified["version"] == "9.6"


def test_block_discovery_single_host(audit):
    _serve_once(80)
    r = audit.get_block_discovery("127.0.0.1", ports=[80])
    assert r["value"]["live_hosts"] == ["127.0.0.1"]


def test_run_audit_quick_produces_findings(audit):
    _serve_once(21, banner=b"220 (vsftpd 3.0.5)\r\n")
    report = audit.run_audit("127.0.0.1", profile="quick")
    titles = [f["title"] for f in report["findings"]]
    assert any("21/tcp" in t for t in titles)
    assert "severity_counts" in report["summary"]


def test_unknown_probe_raises(audit):
    with pytest.raises(WanspyConfigError):
        audit.run_probe("get_nope", "127.0.0.1")


def test_bad_regex_override_raises():
    with pytest.raises(WanspyConfigError):
        NetAudit({"banner_signatures": {"+signatures": [{"pattern": "(unclosed", "product": "x"}]}})


def test_unknown_config_key_raises():
    with pytest.raises(WanspyConfigError):
        NetAudit(not_a_real_setting=1)


def test_clone_layers_over_parent():
    a = NetAudit(timeout=5)
    b = a.clone(timeout=2)
    assert a.config.get("settings", "timeout") == 5
    assert b.config.get("settings", "timeout") == 2


def test_report_round_trips_json(audit, tmp_path):
    _serve_once(8081)
    report = audit.run_audit("127.0.0.1", profile="quick")
    out = tmp_path / "report.json"
    audit.save_report(report, out)
    loaded = json.loads(out.read_text())
    assert loaded["target"] == "127.0.0.1"
