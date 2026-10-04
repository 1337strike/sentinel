# REPRODUCE.md — from a clean Arch host to measured results

Every command below has been run in the order shown, except where marked
**UNVERIFIED** — those steps depend on hardware or network access not available
in the development environment, and they are flagged rather than presented as
tested.

Three ways to use this document:

| Goal | Start at | Needs |
|---|---|---|
| Just see it work, no VM | [Part 1](#part-1--offline-only-10-minutes) | Arch host, 10 min |
| Full lab with live targets | [Part 2](#part-2--the-kvm-guest) | KVM, 8 GB free RAM, ~1 h |
| Reproduce published numbers | [Part 4](#part-4--running-a-measurement) | Part 2 complete |

---

## Part 0 — Host prerequisites (Arch)

```bash
# Minimum: offline pipeline only
sudo pacman -S --needed git python base-devel

# Active scanning and enrichment
sudo pacman -S --needed masscan nmap whois

# KVM/QEMU lab
sudo pacman -S --needed qemu-full libvirt virt-install dnsmasq nftables openssh curl
sudo systemctl enable --now libvirtd
sudo usermod -aG libvirt "$USER"      # log out and back in

# Confirm KVM is actually available (not just installed)
lscpu | grep -i virtualiz
[ -r /dev/kvm ] && echo "/dev/kvm readable: OK" || echo "KVM UNAVAILABLE — enable VT-x/AMD-V in firmware"
```

`masscan` 1.3.2, `pyenv`, `libvirt` and `qemu-full` are all in `extra`. Nothing
here needs the AUR.

---

## Part 1 — Offline only (10 minutes)

Proves the toolchain works before any VM exists. No network, no containers, no
credentials.

```bash
git clone https://github.com/1337strike/sentinel && cd sentinel
git checkout claude/charming-ramanujan-yzgun9

# Pin the interpreter. Arch ships Python 3.14; this code is verified on 3.11,
# and a rolling distro will otherwise change the interpreter under a long study.
sudo pacman -S --needed pyenv
sudo pacman -S --needed base-devel openssl zlib xz tk libffi bzip2 readline sqlite
echo 'eval "$(pyenv init -)"' >> ~/.bashrc && exec "$SHELL"
pyenv install 3.11.11 && pyenv local 3.11.11

python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
```

PEP 668 will refuse `pip` outside a venv. That is correct — do not use
`--break-system-packages`.

```bash
sentinel credentials          # endpoint inventory + credential-guard state
sentinel --version
```

Run the pipeline against the committed fixtures:

```bash
sentinel scan --cidr-file lab.example.txt --active \
              --scope-file labs/lab-scope.yaml --ports lab \
              --dry-run --scan-fixture labs/seed/masscan-lab.json \
              -o out/scan.json

sentinel fingerprint -i out/scan.json      --dry-run -o out/fp.json
sentinel enrich      -i out/fp.json        --dry-run --registries ripencc -o out/enriched.json
sentinel report      -i out/enriched.json  --format markdown -o out/report.md
sentinel verify-audit
```

### Expected result — the install is correct if you get exactly this

```
CRITICAL  7
HIGH      2
MEDIUM    5
LOW       3
INFO      0
```

17 targets. Check the three that matter:

```bash
python - <<'PY'
import json
h = {x["ip"]: x for x in json.load(open("out/fp.json"))["hosts"]}
print("L2 ablation pair:")
print(f"  10.99.0.11 no TLS  {h['10.99.0.11']['confidence']:.3f}")
print(f"  10.99.0.19 TLS     {h['10.99.0.19']['confidence']:.3f}")
print(f"  L2 delta           {h['10.99.0.19']['confidence']-h['10.99.0.11']['confidence']:+.3f}  (expect +0.137)")
print(f"hard negative 10.99.0.30 confidence {h['10.99.0.30']['confidence']:.3f}  (expect 0.000)")
print(f"misattribution 10.99.0.17 vendor {h['10.99.0.17']['vendor']!r}  (expect 'CODESYS WebVisu')")
PY
```

Confirm the safety controls refuse what they should:

```bash
sentinel scan --cidr-file lab.example.txt --active; echo "exit=$?"   # expect 2
python -c "
from sentinel.modules.scope import ActiveGrant
try: ActiveGrant(scope_path='x', cidrs=(), hash='h', authorized_by='a',
                 authorization_ref='r', allowed_categories=frozenset())
except Exception as e: print(type(e).__name__)"                       # ModeViolation
```

---

## Part 2 — The KVM guest

**UNVERIFIED BELOW.** The scripts are written and syntax-checked; they have not
been executed, because the development container has no KVM and no outbound
network. Treat Part 2 as a reviewed procedure, not a tested one, and read each
script before running it with `sudo`.

### Architecture, and why the sequence is what it is

```
Arch host
├── virbr-sentinel   libvirt network, forward mode='none'   192.168.99.0/24
│   └── guest VM (Debian 12, 4 vCPU, 8 GB)                  192.168.99.x
│       ├── sentinel (the tool under test)
│       └── docker bridge br-sentinel-lab, internal: true   10.99.0.0/24
│           └── 17 target containers                        10.99.0.10-.32
└── nftables table inet sentinel_lab   drops anything leaving the lab bridge
```

Three independent isolation layers, because the failure mode is sending scan
traffic to a non-consenting third party. Any one layer failing still leaves two.

**Provisioning needs internet; the experiment must not have it.** So the guest
is built on the default NAT network, fully provisioned, and only then moved to
the isolated network and snapshotted. Building it isolated installs nothing.

### 2.1 Create the isolated network

```bash
cd labs/kvm
sudo ./isolated_bridge.sh --create
sudo ./isolated_bridge.sh --harden     # nftables egress drop (not persistent)
./isolated_bridge.sh --verify
```

### 2.2 Create the guest (on NAT, deliberately)

```bash
sudo ./setup.sh --create
```

Downloads the Debian 12 generic cloud image, **verifies its SHA512 against the
published sums and refuses to continue on a mismatch**, creates a 40 GB qcow2
overlay, and boots it with cloud-init using your SSH public key. Password login
is disabled. Expect 3–10 minutes on first run.

### 2.3 Provision it

```bash
sudo ./setup.sh --provision
```

Runs `provision-guest.sh` in the guest: apt packages, docker, masscan with
`CAP_NET_RAW` via `setcap`, pyenv + Python 3.11.11, the Sentinel venv, and
**pre-builds the lab container image** — that last step is what makes offline
operation possible, since `docker compose build` cannot reach an index once the
guest is isolated. It finishes by running the offline pipeline and asserting the
7/2/5/3 result, so provisioning fails loudly rather than leaving you to discover
a broken guest later.

It also writes `provisioned-requirements.txt` and
`provisioned-lab-requirements.txt` — the resolved dependency versions your
artifact appendix should cite.

### 2.4 Cut the internet, then verify, then snapshot

```bash
sudo ./setup.sh --isolate
./isolated_bridge.sh --verify

sudo ./setup.sh --ssh
# inside the guest — all three must hold:
ip route                                        # expect NO default route
curl -sS --max-time 5 https://example.com || echo "no egress: correct"
docker network inspect -f '{{.Internal}}' sentinel-lab 2>/dev/null   # expect true
exit

sudo ./setup.sh --snapshot      # saves `clean-base`
```

> **Do not skip the verification.** It is the only thing standing between a
> mistyped CIDR and traffic reaching somebody else's network. If any of the
> three checks fails, stop and fix it.

### 2.5 Start the targets

In the guest:

```bash
cd ~/sentinel/labs/docker
docker compose up -d
docker compose ps                  # 17 services, all running
docker compose logs niagara-tls    # confirm the self-signed cert was generated
```

No port is published to the host — targets are reachable only on the lab
bridge. These are intentionally insecure ICS simulators; publishing a port would
put one on an external interface.

---

## Part 3 — First active scan

Still **UNVERIFIED** (no masscan in the dev container). Start deliberately slow.

```bash
cd ~/sentinel && source .venv/bin/activate

# One host, 10 pps, before trusting the rate clamp at scale
printf '10.99.0.10/32\n' > /tmp/one.txt
sentinel scan --cidr-file /tmp/one.txt --active --scope-file labs/lab-scope.yaml \
              --ports 9000 --rate 10 -o out/one.json
```

Then the whole lab. `--rate 5000` is deliberate here: the port set contains OT
ports, so the clamp must lower it to 100 and say so.

```bash
sentinel scan --cidr-file lab.example.txt --active --scope-file labs/lab-scope.yaml \
              --ports lab --rate 5000 -o out/live-scan.json
```

Confirm the clamp fired:

```bash
grep rate_clamped logs/sentinel.jsonl | tail -1
# expect: requested 5000 pps lowered to 100 pps (ot ceiling)
```

Then fingerprint for real (no `--dry-run`) and compare against the offline
replay — they should agree:

```bash
sentinel fingerprint -i out/live-scan.json -o out/live-fp.json
diff <(jq -S '[.hosts[]|{ip,vendor,risk,confidence}]' out/live-fp.json) \
     <(jq -S '[.hosts[]|{ip,vendor,risk,confidence}]' out/fp.json)
```

A non-empty diff means the offline fixtures have drifted from the live lab.
Regenerate them with `labs/seed/refresh_seed.sh` and investigate before
reporting any number.

---

## Part 4 — Running a measurement

Every run starts from the snapshot, so accumulated state cannot leak between
runs:

```bash
# on the host
cd labs/kvm && sudo ./setup.sh --revert
sudo ./setup.sh --ssh
```

Record alongside each result, for the artifact appendix:

```bash
sentinel --version
git rev-parse HEAD
python -V
masscan --version | head -1
cat provisioned-requirements.txt
sha512sum /var/lib/libvirt/images/debian-12-generic-amd64.qcow2   # on the host
```

Make the audit log tamper-evident for any run backing a published result:

```bash
sudo chattr +a audit/sentinel-audit.jsonl   # append-only at the filesystem level
sentinel verify-audit                        # hash chain intact
```

`chattr +a` means even a root-owned process cannot rewrite history, only append.
Sentinel never opens the file for anything but append, and has no rotate or
clear function by design.

Pseudonymise addresses in the structured log if it will leave the lab:

```bash
export SENTINEL_TARGET_SALT="$(openssl rand -hex 16)"
```

The experiment harness (E1–E6) is not written yet; `experiments/ground_truth.yaml`
and the fixtures it scores against are in place.

---

## Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| `/dev/kvm` missing | Virtualisation disabled in firmware | Enable VT-x / AMD-V |
| `masscan: permission denied` | Capability cleared | `sudo setcap cap_net_raw,cap_net_admin+eip $(command -v masscan)` — **cleared by every pacman upgrade** |
| `Refused: --active requires --scope-file` | Working as designed | Pass `--scope-file`, or drop `--active` |
| `is private space; add it to allow_categories` | RFC1918 denied by default | Your scope file needs `allow_categories: [private]` |
| `every host failed to fingerprint` | Systematic fault, raised deliberately | Read `logs/sentinel.jsonl`; this is a bug, not a 0% detection rate |
| `guest did not get an address` | cloud-init still running | `virsh console sentinel-lab`, wait, retry |
| Guest has internet after `--isolate` | NIC reattach failed | `virsh domiflist sentinel-lab`; re-run `--isolate`; **do not scan** |
| `docker compose build` fails in the guest | Already isolated | Build before `--isolate`, or temporarily reattach `network=default` |
| Ignition/TLS target not found by a scan | Port preset | `--ports lab` includes 8088 and 8443; a hand-written list may not |

## Known-unverified paths

Carrying this list forward honestly, because it is where results will break:

- Real `masscan` invocation (argv, rate clamp at scale, output parsing)
- Live dataset endpoints: RIPEstat, Shodan InternetDB, RIR downloads, RDAP
- Reverse DNS, live WHOIS/RDAP attribution, `verify_with_nmap`
- Every script in `labs/kvm/` (written and reviewed, never executed)
- Python 3.12/3.13/3.14 — verified only on 3.11
- There is no test suite yet, so none of the above is regression-protected

Verified by execution: the full offline pipeline, the live async fingerprint
including TLS layer L2 against a real socket, the monitor across two cycles, all
refusal paths, the audit hash chain, and the credential guard.
