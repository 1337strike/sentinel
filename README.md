# Sentinel

Defensive exposure monitoring for Internet-facing ICS/SCADA assets, using
passive fingerprinting and **no credentials of any kind**.

Research artifact for the paper *"Zero-Credential Passive Fingerprinting for
ICS/SCADA Exposure Monitoring: A Reproducible Lab-Validated Methodology."*

> **Blue-team research tool.** Active measurement is restricted to ranges you
> are authorized to test, and that restriction is enforced in code, not in
> documentation. Sentinel sends no exploit payloads, submits no credentials,
> and writes no protocol frames to industrial ports. Read `docs/ETHICS.md`
> before using `--active`.

---

## What it is

A pipeline that answers "which of our industrial assets are reachable from the
Internet, and did that change since yesterday?" — without a Shodan key, a
Censys account, or any paid tier.

```
discover → scan → fingerprint → enrich → risk → report → monitor (diff)
```

Three properties distinguish it from a scan script:

**1. Passive by default, and structurally so.** The default mode emits zero
packets to any target. Active scanning requires a validated scope file, and the
enforcement is a *type constraint*: the only function that emits packets takes an
`ActiveGrant` as its first parameter, and that class refuses construction unless
it came from `ActiveGrant.from_scope_file()`. "Active scan without
authorization" is therefore unrepresentable, not merely guarded by an `if`.

```console
$ sentinel scan --cidr-file lab.txt --active          # no --scope-file
Refused: --active requires --scope-file <path>.       # exit code 2
```

**2. Zero credentials, enforced at runtime.** `sentinel/credguard.py` replaces
`os.environ` with a guarded mapping that raises if Sentinel's own code reads a
variable matching `TOKEN|KEY|SECRET|PASSWORD`. Reads are attributed by caller
frame, because the stdlib `ssl` module legitimately reads `SSLKEYLOGFILE` on
every TLS handshake — the guard fires on *the reader*, not the variable name.
Variables merely *existing* is fine and is logged as ignored; a normal CI runner
exports plenty.

```console
$ sentinel credentials
Sentinel requires no credentials, no keys, and no accounts.
14 environment variable(s) in this shell match the credential policy and were ignored
Source scan clean: no credential-shaped identifiers.
```

**3. Rate limiting as a safety control.** Legacy PLCs and building controllers
fault under scan pressure. Ports are classified OT/web, a target set containing
*any* OT port is paced at the OT budget (100 pps default vs 1000 for web), and
`--rate` can only ever *lower* the effective rate — `min(requested, ceiling)`.

---

## Install (Arch Linux)

### 1. System packages

```bash
# Offline pipeline only — this is all you need to replay a full study
sudo pacman -S --needed git python base-devel

# Active scanning + enrichment (optional)
sudo pacman -S --needed masscan nmap whois

# Lab containers (optional)
sudo pacman -S --needed docker docker-compose
sudo systemctl enable --now docker
sudo usermod -aG docker "$USER"      # re-login for this to take effect

# KVM/QEMU testbed (optional)
sudo pacman -S --needed qemu-full libvirt virt-install dnsmasq iptables-nft
sudo systemctl enable --now libvirtd
sudo usermod -aG libvirt "$USER"
```

`masscan` (extra, 1.3.2), `pyenv` (extra), `libvirt` and `qemu-full` (extra) are
confirmed present in the official repositories. If `pacman` reports any other
name above as not found, locate it with `pacman -Ss <name>` rather than reaching
for the AUR — all of these are official packages.

### 2. Pin the interpreter — read this before using system Python

Arch currently ships **Python 3.14**. This project is verified on **3.11**; 3.12
and 3.13 are expected to work, and **3.14 is untested**. `aiohttp` and
`cryptography` are the realistic 3.14 risks (no wheel for the running
interpreter means a source build, which needs a Rust toolchain for
`cryptography`).

Arch is also a rolling release, so a system-Python venv silently inherits a new
minor version on any `pacman -Syu` and can break mid-study. For research you
want the interpreter pinned, which is what `.python-version` is for:

```bash
sudo pacman -S --needed pyenv
# pyenv build dependencies on Arch
sudo pacman -S --needed base-devel openssl zlib xz tk libffi bzip2 readline sqlite

# bash; use ~/.zshrc for zsh
echo 'eval "$(pyenv init -)"' >> ~/.bashrc && exec "$SHELL"

pyenv install 3.11.11
```

Use system Python only if you accept the untested-3.14 risk and the rolling
upgrade exposure.

### 3. Project

```bash
git clone https://github.com/1337strike/sentinel && cd sentinel
pyenv local 3.11.11          # skip if using system Python
python -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
```

Arch marks system Python as externally managed (PEP 668), so `pip install`
outside a venv is refused. That is the correct behaviour and the venv above is
the answer — do **not** reach for `--break-system-packages`.

### 4. Verify

```bash
sentinel credentials      # endpoint inventory; confirms the credential guard
sentinel --version
```

Then run the offline pipeline in the next section. If it produces
6 CRITICAL / 1 HIGH / 6 MEDIUM / 3 LOW over 16 targets, the install is good.

### 5. masscan without root

`masscan` needs raw sockets. Grant the capability instead of running the whole
scanner as root:

```bash
sudo setcap cap_net_raw,cap_net_admin+eip /usr/bin/masscan
masscan --version
```

Note that `setcap` is cleared by every `pacman` upgrade of the package, so
re-apply it after updates. Sentinel detects the missing privilege and says so
explicitly rather than failing opaquely.

### Other distributions

Nothing here is Arch-specific beyond package names — Debian/Ubuntu is
`apt install masscan nmap whois docker.io docker-compose qemu-kvm libvirt-daemon-system`.
`masscan` is an intentional external dependency and is never bundled. The full
offline pipeline needs none of the optional packages.

## Run it offline, right now

No network, no containers, no credentials — the committed fixtures in
`labs/seed/` replay a full study:

```bash
# Active lab scan (replayed from a recorded masscan result)
sentinel scan --cidr-file lab.example.txt --active --scope-file labs/lab-scope.yaml \
              --ports lab --dry-run --scan-fixture labs/seed/masscan-lab.json \
              -o out/scan.json

sentinel fingerprint -i out/scan.json --dry-run -o out/fp.json
sentinel enrich      -i out/fp.json   --dry-run --registries ripencc -o out/enriched.json
sentinel report      -i out/enriched.json --format markdown -o out/report.md
sentinel verify-audit
```

Result on the reference testbed (17 targets, 14 ICS + 3 non-ICS controls):

| Address | Risk | Conf. | Identified | Layers |
|---|---|---|---|---|
| `10.99.0.10:9000` | CRITICAL | 0.86 | REDY-Process | L1 L3 L4 L5 |
| `10.99.0.11:8080` | HIGH | 0.55 | Niagara/Tridium | L3 L4 L5 |
| `10.99.0.12:8088` | CRITICAL | 0.64 | Ignition | L1 L4 L5 |
| `10.99.0.13:8080` | MEDIUM | 0.27 | WonderWare/AVEVA | L3 |
| `10.99.0.16:8080` | CRITICAL | 0.86 | GE iFIX | L1 L3 L4 L5 |
| `10.99.0.17:8080` | CRITICAL | 0.55 | *CODESYS WebVisu* | L3 L4 L5 |
| `10.99.0.19:8443` | HIGH | 0.68 | Niagara/Tridium | **L2** L3 L4 L5 |
| `10.99.0.20:502` | MEDIUM | 0.00 | — (port only) | — |
| `10.99.0.30:80` | LOW | 0.00 | — | — |

The three rows worth reading are the *failures*, which are deliberate:

- **`.13`** presents only a page title, so it scores 0.27 — below the 0.45
  confirmation threshold. It is the threshold-sensitive case that makes the
  detection ROC curve non-degenerate.
- **`.17`** is an ABB AC500, which genuinely serves a CODESYS WebVisu
  application and exposes `/webvisu.htm`. The matcher reports CODESYS at
  CRITICAL: *confidently misattributed*, not uncertain. Confidence measures
  evidential agreement, not attribution correctness — so E1 reports ICS
  detection and vendor attribution as two separate rates.
- **`.30`** is the hard negative: a consultancy page saying "process control",
  "SCADA migration", "HMI usability", "building management", "IEC 62443". It
  scores **0.000**. A keyword matcher flags it; the layered matcher does not,
  because body text alone never satisfies a content layer.

`.19` is the **layer-L2 ablation control**: byte-identical content to `.11`
with the same suppressed `Server` header, differing only by HTTPS with a
self-signed certificate naming the product. The +0.137 confidence delta between
the pair *is* L2's contribution, measured rather than inferred — and it
independently confirms the weight arithmetic (0.15 / 1.10 = 0.136).

Lab targets are **hand-authored from product documentation, never generated
from `signatures.yaml`** — deriving targets from the detector's own patterns
would make detection measurement circular and guarantee a meaningless 100%
recall.

---

## Fingerprinting: five layers

| | Evidence | Why |
|---|---|---|
| L1 | `Server` header | Embedded HTTP stacks rarely disguise themselves |
| L2 | TLS certificate | ICS devices ship distinctive self-signed certs |
| L3 | Page title | Survives proxies that strip headers |
| L4 | JS globals | SPA-based HMIs expose product globals pre-auth |
| L5 | URL paths | Confirms what other layers only suggest |

Weighted sum → continuous score; the threshold is a *parameter*, which is what
makes a ROC sweep possible. Port affinity never identifies a product on its own.

**The zero-payload constraint.** Modbus, S7, OPC-UA and Fox are
client-speaks-first, and Sentinel never writes to an OT port. So for those the
honest result is "a service is listening", recorded as such — not inflated into
a vendor claim. This is a real methodological limit, declared in the output
rather than hidden.

## Risk model

Pure function of an evidence vector — no I/O, no clock — so the model is
replayable from a table and auditable without running the collector.

| Condition | Level |
|---|---|
| ICS confirmed, no auth boundary | CRITICAL |
| ICS confirmed, auth required | HIGH |
| Generic industrial vocabulary | MEDIUM |
| Non-ICS service reachable | LOW |
| No evidence | INFO |

One documented refinement: an open OT protocol port with no identified product
scores MEDIUM, not LOW — TCP/502 carries no general-purpose service, so grading
it as an ordinary open port understates exposure. It is switchable
(`ot_exposure_is_industrial`) so results can be reported under both the literal
model and the refined one.

## Audit trail

Append-only (`O_APPEND` + `fsync`), mode `0600`, and **hash-chained**: each
record carries its predecessor's digest, so deletion or in-place edit breaks the
chain and `verify-audit` names the first bad index. There is deliberately no
rotate or clear function.

---

## Verification status — read this before running experiments

**Executed and verified:**

- Offline pipeline end-to-end (`scan → fingerprint → enrich → report`), 17 targets
- **Live** async fingerprint against real sockets (aiohttp, `probe_http`,
  candidate path probing, auth-wall detection, **TLS layer L2 certificate
  extraction**) — scores identical to the offline replay (0.864 for `.10`,
  0.682 for the TLS target), which is what makes offline reproduction
  trustworthy
- `docker compose config` validated; all 17 static addresses confirmed
- `monitor` over two cycles: baseline, diff, alert file; 0 alerts on an
  identical cycle (determinism), 34 correctly-graded alerts on a changed pair
- Refusals: `--active` without scope → exit 2; direct `ActiveGrant(...)` →
  `ModeViolation`; denylist refusing documentation/private ranges
- Audit hash-chain; credential guard (14 matching env vars ignored); grep gate
  zero matches; ruff + black clean
- Threshold sweep → monotonic confirmed-host counts, controls at 0.000
  confidence at every operating point
- Isolated L2 ablation delta +0.137, matching the configured weight exactly

**Never executed — expect these to be where breakage lives:**

- `masscan` subprocess (binary not installed in the dev container; only the
  `--dry-run` fixture path has run). Argument construction, rate clamping and
  output parsing are unit-level sound but the real invocation is unproven.
- **Every script in `labs/kvm/`** — written and reviewed, never executed; the
  dev container has no KVM and no outbound network. Read them before `sudo`.
- `docker compose build`/`up` against real containers (no egress to pull images).
- Live dataset calls to `stat.ripe.net`, `internetdb.shodan.io`, RIR delegation
  downloads and RDAP — outbound HTTPS is blocked by the dev container's proxy,
  so only fixture replay has run.
- Reverse DNS (dnspython), live WHOIS/RDAP org attribution
- `verify_with_nmap` (nmap not installed)
- There is **no test suite yet**, so none of the above is protected against
  regression.

Six bugs so far were found by running the code rather than reading it, which is
why the list above matters. None of them crashed; each would have produced a
wrong number:

1. **L5 never fired live** — path probing used the alphabetically-first paths in
   the whole database, so a REDY device was asked for `/CitectSCADA`. Any
   layer-ablation result would have been an artifact.
2. **L2 never fired live** — the certificate was read via
   `response.connection`, which aiohttp returns as `None`. Offline replay
   "worked" because the fixture declares the subject, so the layer looked
   functional while collecting nothing.
3. **`dry_run: true` in `monitor.yaml` was ignored** for dataset lookups — the
   monitor hit the live network while reporting a dry run.
4. **Monitor discovered zero prefixes** — a denylist allowance existed only in
   the scan path, so an empty baseline looked like "nothing exposed".
5. **The `lab` port preset omitted 8088 and 8443**, so Ignition and the TLS
   target would never have been found by a real active scan.
6. **TLS context construction raised** under `-W error::DeprecationWarning`,
   which this project's own pytest config sets.

## Status

Complete and verified end-to-end offline:

- [x] `sentinel/` — CLI, discovery, scanner, fingerprint, enrich, risk, monitor,
      report, audit, scope, credguard, config loader
- [x] `signatures.yaml` — 11 vendors + CODESYS/OPC-UA + 5 generic classes
- [x] `config/sentinel.yaml`, `credential_policy.yaml`, `scope.example.yaml`
- [x] `labs/seed/` — offline fixtures; full pipeline replays with zero egress
- [x] `labs/docker/` — HMI mockups + HMI simulator server
- [x] `experiments/ground_truth.yaml` — 16 targets with per-target priors
- [x] ruff + black clean; credential grep gate passes with zero matches

Still to come (tracked, not started):

- [ ] `tests/` — pytest suite with socket-blocking conftest
- [ ] `experiments/` — E1–E6 harness, metrics, IEEE-style plotting
- [ ] `labs/docker/docker-compose.yml`, `labs/kvm/` provisioning scripts
- [ ] `paper/` — IEEEtran LaTeX skeleton, figure/table generators
- [ ] `docs/` — ARCHITECTURE, ETHICS, CREDENTIALS, THREAT_MODEL, REPRODUCE,
      PAPER_NOTES

## Every endpoint contacted

All anonymous, all keyless. Enumerated in `credential_policy.yaml` and checked
at call time; a host not on the list raises before the socket opens.

| Host | Purpose |
|---|---|
| `stat.ripe.net` | ASN → announced prefixes, AS holder |
| `internetdb.shodan.io` | Per-IP ports, tags, CPEs, CVE refs (free, keyless) |
| `ftp.{ripe,arin,apnic,lacnic,afrinic}.net` | RIR delegation → country |
| `rdap.{db.ripe,arin,apnic,lacnic,afrinic}.net` | RDAP → org name |
| system resolver | Reverse DNS PTR |
| `whois` binary | IP WHOIS org name (local, optional) |

Explicitly **not used**, at any tier: ipinfo.io, the Shodan REST API, Censys,
FOFA, ZoomEye, BinaryEdge, GreyNoise, VirusTotal, AbuseIPDB. Where a field
cannot be obtained anonymously it is left `null` and a `source_unavailable`
event is logged — quantifying that incompleteness is the point of the gap
analysis, so substituting a commercial API would destroy the result.

## Licence

MIT. The signature database's CVE lists are **triage pointers, not
version-matched vulnerability assertions** — Sentinel reads no firmware version
and never authenticates, so it cannot and does not claim a matched host is
affected. Verify against the vendor advisory and the CISA ICS advisory database
before citing.
