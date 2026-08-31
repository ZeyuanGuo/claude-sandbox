from pathlib import Path

import yaml


def test_mihomo_11450_template_has_one_fail_closed_exit() -> None:
    root = Path(__file__).resolve().parents[1]
    config = yaml.safe_load(
        (root / "examples" / "mihomo-11450.example.yaml").read_text(encoding="utf-8")
    )

    assert config["mixed-port"] == 11450
    assert config["allow-lan"] is True
    assert config["bind-address"] == "0.0.0.0"
    assert config["mode"] == "rule"
    assert config["rules"] == ["MATCH,sandbox-fixed-exit"]

    proxies = {proxy["name"]: proxy for proxy in config["proxies"]}
    final = proxies["fixed-la-exit"]
    assert final["type"] == "http"
    assert final["dialer-proxy"] == "commercial-first-hop"

    groups = {group["name"]: group for group in config["proxy-groups"]}
    assert groups["sandbox-fixed-exit"]["proxies"] == ["fixed-la-exit"]
    assert not {"DIRECT", "PASS", "COMPATIBLE"} & set(
        groups["sandbox-fixed-exit"]["proxies"]
    )


def test_mihomo_user_service_uses_persistent_user_paths() -> None:
    root = Path(__file__).resolve().parents[1]
    unit = (root / "examples" / "mihomo-11450.service").read_text(encoding="utf-8")

    assert (
        "ExecStartPre=/bin/sh -ec 'uid=$$(/usr/bin/id -u); "
        'exec /usr/bin/systemctl is-active --quiet '
        '"cdm-u$${uid}-main-parent-guard.service"\''
    ) in unit
    assert "ExecStart=%h/.local/share/claude-sandbox/mihomo/mihomo" in unit
    assert "-f %h/.config/claude-sandbox/mihomo-11450.yaml" in unit
    assert "Restart=always" in unit
    assert "WantedBy=default.target" in unit
    assert "DIRECT" not in unit
