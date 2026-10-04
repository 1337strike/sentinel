#!/usr/bin/env python3
"""Derive the offline seed fixtures from ground truth and the lab mockups.

Invoked by refresh_seed.sh. Keeping fixture generation in one script means the
offline replay cannot silently drift from the live testbed: change a target in
ground_truth.yaml or docker-compose.yml, re-run, and the fixtures follow.

Response metadata is kept in step with labs/docker/docker-compose.yml by hand
(SERVER, PRODUCT_PATHS, TLS below). That duplication is the one weak seam here;
the determinism experiment E4 is what would catch a divergence, by comparing a
live lab run against an offline replay of the same targets.
"""

from __future__ import annotations

import json
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[2]
SEED = ROOT / "labs" / "seed"

# Mirrors the `environment:` blocks in labs/docker/docker-compose.yml.
SERVER: dict[str, str | None] = {
    "redy": "REDY-Process/2.4.1 lighttpd/1.4.55",
    "niagara": None,
    "niagara-tls": None,
    "ignition": "Jetty(9.4.44.v20210927)",
    "wonderware": None,
    "factorytalk": "Microsoft-IIS/10.0 FactoryTalk/12.0",
    "citect": "CitectSCADA/8.10 Microsoft-IIS/8.5",
    "geifix": "Proficy-iFIX/6.1",
    "abb": None,
    "honeywell": "Honeywell-WEBvision/3.2",
    "corporate": "nginx/1.25.3",
    "intranet": "nginx/1.25.3",
}

# Product paths that answer 200, i.e. what fingerprinting layer L5 confirms.
PRODUCT_PATHS: dict[str, list[str]] = {
    "redy": ["/api/datapoints", "/process/overview", "/redy", "/cgi-bin/redy"],
    "niagara": ["/login", "/ord", "/prelogin"],
    "niagara-tls": ["/login", "/ord", "/prelogin"],
    "ignition": ["/main/web/status", "/main/web/config", "/system/gateway"],
    "geifix": ["/Webspace", "/iFIX", "/Proficy"],
    "abb": ["/webvisu.htm", "/plc/webvisu.htm"],
}

# Which HMI document each target serves (several targets share one).
SITE: dict[str, str] = {"niagara-tls": "niagara"}

PROTOCOL_SERVICES = {"modbus", "s7comm", "opcua", "niagara-fox"}


def slug(container: str) -> str:
    return container.replace("sentinel-control-", "").replace("sentinel-", "")


def site_dir(name: str) -> Path:
    doc = SITE.get(name, name)
    for base in ("labs/docker/hmi", "labs/docker/controls"):
        candidate = ROOT / base / doc / "index.html"
        if candidate.is_file():
            return candidate
    raise SystemExit(f"no mockup document found for target {name!r}")


def main() -> None:
    gt = yaml.safe_load((ROOT / "experiments" / "ground_truth.yaml").read_text())
    targets = gt["targets"]

    banners = SEED / "banners"
    banners.mkdir(parents=True, exist_ok=True)
    for stale in banners.glob("*.txt"):
        stale.unlink()

    for target in targets:
        name = slug(target["container"])
        ip, port = target["ip"], target["port"]
        out = banners / f"{ip}_{port}.txt"

        if target["service"] == "ssh":
            # Server-speaks-first: a raw banner, not an HTTP response.
            out.write_text("SSH-2.0-OpenSSH_9.6p1 Debian-4\r\n")
            continue

        if target["service"] in PROTOCOL_SERVICES:
            # Client-speaks-first: nothing is volunteered. An empty fixture is
            # the honest representation of what a listen-only probe observes,
            # and writing anything else here would inflate what the zero-payload
            # methodology can claim.
            out.write_text("")
            continue

        body = site_dir(name).read_text()

        # Status 200 throughout: the authentication boundary on these targets is
        # the password field in the document, which _detect_auth_wall finds.
        # The live containers serve 200 as well, so fixture and lab agree.
        headers = ["HTTP/1.1 200 OK"]
        if SERVER.get(name):
            headers.append(f"Server: {SERVER[name]}")
        headers.append("Content-Type: text/html; charset=utf-8")

        if target.get("tls_subject"):
            # parse_raw_http_fixture reads these pseudo-headers as the recorded
            # certificate, which is how layer L2 is replayed offline.
            subject = _rfc4514(target["tls_subject"])
            headers.append(f"X-Fixture-TLS-Subject: {subject}")
            headers.append(f"X-Fixture-TLS-Issuer: {subject}")

        if PRODUCT_PATHS.get(name):
            headers.append(f"X-Fixture-Paths: {','.join(PRODUCT_PATHS[name])}")

        out.write_text("\n".join(headers) + "\n\n" + body)

    print(f"[seed] {len(targets)} banner fixtures")

    # masscan -oJ fixture. The trailing comma before ']' reproduces masscan's
    # actual (invalid-JSON) output, so the tolerant parser is exercised by real
    # data rather than only by a unit test.
    records = [
        {
            "ip": t["ip"],
            "timestamp": "1767225600",
            "ports": [
                {
                    "port": t["port"],
                    "proto": "tcp",
                    "status": "open",
                    "reason": "syn-ack",
                    "ttl": 64,
                }
            ],
        }
        for t in targets
    ]
    (SEED / "masscan-lab.json").write_text(
        "[\n" + ",\n".join(json.dumps(r) for r in records) + ",\n]\n"
    )
    print("[seed] masscan-lab.json")

    _dataset_fixtures()
    print("[seed] dataset fixtures (RIPEstat, InternetDB, RIR, RDAP)")


def _rfc4514(openssl_subject: str) -> str:
    """Convert an OpenSSL '/CN=x/O=y' subject to the RFC 4514 form.

    cryptography's ``rfc4514_string()`` is what the live probe records, so the
    fixture must use the same spelling or an offline replay would match on a
    string the live path never produces.
    """
    parts = [p for p in openssl_subject.split("/") if p]
    return ",".join(reversed(parts))


def _dataset_fixtures() -> None:
    rs = SEED / "stat.ripe.net"
    rs.mkdir(parents=True, exist_ok=True)
    (rs / "announced-prefixes-AS64500.json").write_text(
        json.dumps(
            {
                "status": "ok",
                "status_code": 200,
                "data_call_name": "announced-prefixes",
                "data": {
                    "resource": "64500",
                    "prefixes": [
                        {"prefix": "192.0.2.0/24", "timelines": []},
                        {"prefix": "198.51.100.0/24", "timelines": []},
                    ],
                },
            },
            indent=2,
        )
        + "\n"
    )
    (rs / "as-overview-AS64500.json").write_text(
        json.dumps(
            {
                "status": "ok",
                "status_code": 200,
                "data_call_name": "as-overview",
                "data": {
                    "resource": "64500",
                    "holder": "EXAMPLE-DOCUMENTATION-AS",
                    "announced": True,
                    "type": "as",
                },
            },
            indent=2,
        )
        + "\n"
    )
    (rs / "network-info-192.0.2.10.json").write_text(
        json.dumps(
            {
                "status": "ok",
                "status_code": 200,
                "data_call_name": "network-info",
                "data": {"prefix": "192.0.2.0/24", "asns": ["64500"]},
            },
            indent=2,
        )
        + "\n"
    )

    idb = SEED / "internetdb.shodan.io"
    idb.mkdir(parents=True, exist_ok=True)
    samples = {
        "192.0.2.10": {
            "ports": [80, 443, 9000],
            "tags": ["ics"],
            "cpes": ["cpe:/a:example:bms_controller:2.4.1"],
            "vulns": [],
            "hostnames": ["bms-01.example.net"],
        },
        "192.0.2.11": {
            "ports": [80, 502],
            "tags": ["ics", "scada"],
            "cpes": [],
            "vulns": ["CVE-2021-22779"],
            "hostnames": [],
        },
        "192.0.2.12": {
            "ports": [22, 80],
            "tags": [],
            "cpes": [],
            "vulns": [],
            "hostnames": ["web.example.net"],
        },
    }
    for ip, payload in samples.items():
        (idb / f"{ip}.json").write_text(json.dumps({"ip": ip, **payload}, indent=2) + "\n")

    rir = SEED / "rir"
    rir.mkdir(parents=True, exist_ok=True)
    (rir / "delegated-ripencc-extended-latest").write_text(
        "\n".join(
            [
                "2|ripencc|1767225600|125000|19830705|20260101|+0100",
                "ripencc|*|ipv4|*|65536|summary",
                "ripencc|NL|ipv4|192.0.2.0|256|20260101|assigned|ff00000000000000|e-stats",
                "ripencc|DE|ipv4|198.51.100.0|256|20260101|allocated|ff00000000000001|e-stats",
                "ripencc|NL|ipv4|203.0.113.0|256|20260101|reserved|ff00000000000002|e-stats",
            ]
        )
        + "\n"
    )

    rdap = SEED / "rdap"
    rdap.mkdir(parents=True, exist_ok=True)
    (rdap / "ripencc-192.0.2.10.json").write_text(
        json.dumps(
            {
                "objectClassName": "ip network",
                "handle": "192.0.2.0 - 192.0.2.255",
                "name": "EXAMPLE-DOC-NET",
                "country": "NL",
                "entities": [
                    {
                        "objectClassName": "entity",
                        "handle": "ORG-EXAMPLE1-RIPE",
                        "roles": ["registrant"],
                        "vcardArray": [
                            "vcard",
                            [
                                ["version", {}, "text", "4.0"],
                                ["fn", {}, "text", "Example Documentation Org"],
                            ],
                        ],
                    }
                ],
            },
            indent=2,
        )
        + "\n"
    )


if __name__ == "__main__":
    main()
