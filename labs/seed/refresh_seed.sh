#!/usr/bin/env bash
# Regenerate the offline seed fixtures from ground_truth.yaml and the lab
# mockups.
#
# Fixtures are DERIVED, not hand-maintained: when a target's address, port or
# content changes, the fixtures must follow or the offline replay silently
# diverges from the live lab. Run this after editing
# experiments/ground_truth.yaml or anything under labs/docker/.
#
# Produces, under labs/seed/:
#   banners/<ip>_<port>.txt                 recorded probe responses
#   masscan-lab.json                        masscan -oJ result for the lab
#   stat.ripe.net/*.json                    RIPEstat responses
#   internetdb.shodan.io/*.json             Shodan InternetDB responses
#   rir/delegated-*-extended-latest         RIR delegation extract
#   rdap/*.json                             RDAP responses
#
# Dataset fixtures use RFC 5398 documentation ASNs (AS64500) and RFC 5737
# documentation addresses (192.0.2.0/24, 198.51.100.0/24). No real ASN,
# organisation or address is recorded anywhere in this repository.
set -euo pipefail

cd "$(dirname "$0")/../.."
PY=${PYTHON:-python3}
[[ -x .venv/bin/python ]] && PY=.venv/bin/python

echo "[seed] regenerating fixtures with $PY"
"$PY" labs/seed/_generate.py
echo "[seed] done. Verify with:"
echo "  sentinel scan --cidr-file lab.example.txt --active \\"
echo "    --scope-file labs/lab-scope.yaml --ports lab --dry-run \\"
echo "    --scan-fixture labs/seed/masscan-lab.json -o out/scan.json"
echo "  sentinel fingerprint -i out/scan.json --dry-run -o out/fp.json"
