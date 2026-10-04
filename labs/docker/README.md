# Lab targets

17 simulated targets on an isolated bridge: 14 ICS, 3 non-ICS false-positive
controls. `../../experiments/ground_truth.yaml` is the authoritative statement
of what each one is; this file explains how they are built and why.

```bash
docker compose build     # ONCE, while the guest still has internet
docker compose up -d
docker compose ps
```

## Addresses

| Address | Port | Target | ICS | Layers present |
|---|---|---|---|---|
| 10.99.0.10 | 9000 | REDY-Process | ✓ | L1 L3 L4 L5 |
| 10.99.0.11 | 8080 | Niagara/Tridium | ✓ | L3 L4 L5 |
| 10.99.0.12 | 8088 | Ignition | ✓ | L1 L4 L5 |
| 10.99.0.13 | 8080 | WonderWare/AVEVA | ✓ | L3 only — *weak on purpose* |
| 10.99.0.14 | 8080 | FactoryTalk | ✓ | L1 L3 L4 |
| 10.99.0.15 | 8080 | Citect | ✓ | L1 L3 L4 |
| 10.99.0.16 | 8080 | GE iFIX | ✓ | L1 L3 L4 L5 |
| 10.99.0.17 | 8080 | ABB AC500 | ✓ | L3 L4 L5 — *ambiguous on purpose* |
| 10.99.0.18 | 8080 | Honeywell | ✓ | L1 L3 L4 — *ambiguous on purpose* |
| 10.99.0.19 | 8443 | Niagara over TLS | ✓ | L2 L3 L4 L5 — *L2 ablation control* |
| 10.99.0.20 | 502 | Modbus (pymodbus, real) | ✓ | port only |
| 10.99.0.21 | 102 | S7comm (**stub**) | ✓ | port only |
| 10.99.0.22 | 4840 | OPC-UA (asyncua, real) | ✓ | port only |
| 10.99.0.23 | 1911 | Niagara Fox (**stub**) | ✓ | port only |
| 10.99.0.30 | 80 | Consultancy page | ✗ | **the hard negative** |
| 10.99.0.31 | 22 | SSH banner | ✗ | — |
| 10.99.0.32 | 8080 | Intranet login | ✗ | — |

## Four design decisions worth understanding

**1. Mockups are hand-authored, never generated from `signatures.yaml`.**
Building targets from the detector's own patterns would make detection
measurement circular and guarantee a meaningless 100% recall. The pages were
written from public product documentation, and they expose *different subsets*
of the five layers so detection difficulty genuinely varies.

**2. Two targets are supposed to be hard.** `10.99.0.13` presents a page title
and nothing else, scoring ~0.27 against a 0.45 confirmation threshold — it is
what makes the ROC curve non-degenerate. `10.99.0.17` is an AC500 serving a
CODESYS WebVisu application, so it is *confidently misidentified as CODESYS*,
which is real product behaviour. Neither is a bug. Do not "fix" them.

**3. `10.99.0.19` exists to isolate layer L2.** It serves byte-identical content
to `10.99.0.11` with the same suppressed `Server` header; the only difference is
HTTPS with a self-signed certificate naming the product. The confidence delta
between the pair (+0.137) is L2's contribution, measured rather than inferred.
That figure also independently confirms the weight arithmetic: the configured
`tls_subject` weight is 0.15 and the weight sum is 1.10, so 0.15/1.10 = 0.136.

**4. The hard negative is the most informative target here.** `10.99.0.30` is a
consultancy marketing page saying "process control", "SCADA migration", "HMI
usability", "building management", "IEC 62443" — while being an ordinary web
server. A keyword matcher flags it. Sentinel scores it **0.000**, because body
text alone never satisfies a content layer. That single number is the core E2
result.

## Declared limitations

**S7 (102) and Fox (1911) are bare TCP listeners, not protocol stacks.** For a
listen-only detector this is behaviourally identical — Sentinel connects, writes
nothing, reads nothing, records "listening" — but it means **E1 must not claim
S7 or Fox protocol identification**, only port-level ICS classification. Ground
truth marks them `vendor_detectable: false`.

For genuine protocol fidelity, replace `s7` with a snap7-based server (needs
`libsnap7`) and `fox` with a licensed Niagara station, then re-record ground
truth. Nothing else in the pipeline changes.

**Modbus and OPC-UA are real servers,** and the OPC-UA one permits anonymous
sessions — a genuine misconfiguration that Sentinel will *not* report, because
confirming it requires a protocol handshake the methodology excludes. The gap
between what is true and what Sentinel can say is a limitations finding, not a
defect.

## Why a Python HTTP server instead of nginx

`Server` is fingerprinting layer L1 — the single most important signal under
test — and nginx cannot override its own `Server` header without the
third-party headers-more module. `targets/hmi_server.py` gives exact control
over it, including suppressing it entirely (which three targets need), plus
product-specific endpoints for L5 and an authentication boundary, with no build
step.

## Safety properties

- **No published ports.** Nothing in `docker-compose.yml` has a `ports:` key.
  These are intentionally insecure simulators; publishing one would put it on
  the host's external interface. That is the one mistake in that file that would
  actually matter.
- **`internal: true`** on the network: Docker installs no NAT or masquerade, so
  no container can reach the internet. This is the innermost of three isolation
  layers (see `docs/REPRODUCE.md`).
- **Hardened containers** around deliberately-insecure applications:
  `cap_drop: ALL`, `no-new-privileges`, `read_only`, non-root user.
- **No credentials anywhere.** The 401 responses are an authentication
  *boundary* for the detector to observe, not an authentication *system* — no
  credential is ever accepted or validated, so there is nothing to brute-force
  even in the lab.

## After changing anything here

Addresses, ports and response metadata are duplicated in the offline fixtures.
Regenerate them or the offline replay silently diverges from the live lab:

```bash
../seed/refresh_seed.sh
```

Then confirm live and offline still agree, per `docs/REPRODUCE.md` Part 3.
