#!/usr/bin/env bash
# ===========================================================================
# Runs INSIDE the Sentinel guest VM. Invoked by setup.sh --provision.
# ===========================================================================
#
# Must run while the guest still has internet. Installs docker, pyenv, a pinned
# Python, the Sentinel package, and pre-builds the lab container image so that
# everything afterwards works with no egress at all.
#
# Pre-building the image here is the step that makes offline operation possible:
# once the guest is isolated, `docker compose build` cannot reach an index, so
# the image must already exist in the local store.
# ===========================================================================
set -euo pipefail

REPO_URL="${REPO_URL:-https://github.com/1337strike/sentinel}"
REPO_BRANCH="${REPO_BRANCH:-claude/charming-ramanujan-yzgun9}"
REPO_DIR="${REPO_DIR:-$HOME/sentinel}"
PYTHON_VERSION="${PYTHON_VERSION:-3.11.11}"
MASSCAN_RATE_TEST="${MASSCAN_RATE_TEST:-10}"

GRN=$'\033[32m'; YLW=$'\033[33m'; RST=$'\033[0m'
info() { printf '%s==>%s %s\n' "$GRN" "$RST" "$1"; }
warn() { printf '%s==>%s %s\n' "$YLW" "$RST" "$1"; }

info "checking internet (provisioning requires it)"
curl -fsS --max-time 10 https://deb.debian.org >/dev/null || {
  echo "No internet. Provision BEFORE moving the guest to the isolated network." >&2
  exit 1
}

info "installing system packages"
sudo apt-get update -qq
sudo DEBIAN_FRONTEND=noninteractive apt-get install -y -qq \
  git curl ca-certificates jq \
  build-essential libssl-dev zlib1g-dev libbz2-dev libreadline-dev \
  libsqlite3-dev libffi-dev liblzma-dev tk-dev uuid-dev \
  masscan nmap whois \
  nftables

info "installing docker from the Debian repositories"
sudo DEBIAN_FRONTEND=noninteractive apt-get install -y -qq \
  docker.io docker-compose-v2 || \
  sudo DEBIAN_FRONTEND=noninteractive apt-get install -y -qq docker.io docker-compose
sudo systemctl enable --now docker
sudo usermod -aG docker "$USER"

# masscan needs raw sockets. Grant the capability rather than running the whole
# scanner as root; Sentinel detects the missing privilege and reports it clearly
# if this step is skipped.
info "granting CAP_NET_RAW to masscan"
sudo setcap cap_net_raw,cap_net_admin+eip "$(command -v masscan)" || \
  warn "setcap failed; masscan will need sudo"

info "installing pyenv and Python ${PYTHON_VERSION}"
if [[ ! -d "$HOME/.pyenv" ]]; then
  git clone --depth 1 https://github.com/pyenv/pyenv.git "$HOME/.pyenv"
fi
export PYENV_ROOT="$HOME/.pyenv"
export PATH="$PYENV_ROOT/bin:$PATH"
eval "$(pyenv init -)"

if ! grep -q PYENV_ROOT "$HOME/.bashrc"; then
  cat >>"$HOME/.bashrc" <<'BASHRC'

# pyenv (Sentinel testbed)
export PYENV_ROOT="$HOME/.pyenv"
export PATH="$PYENV_ROOT/bin:$PATH"
eval "$(pyenv init -)"
BASHRC
fi

pyenv install -s "$PYTHON_VERSION"

info "cloning Sentinel"
if [[ -d $REPO_DIR/.git ]]; then
  git -C "$REPO_DIR" fetch origin "$REPO_BRANCH"
  git -C "$REPO_DIR" checkout "$REPO_BRANCH"
  git -C "$REPO_DIR" pull --ff-only origin "$REPO_BRANCH"
else
  git clone --branch "$REPO_BRANCH" "$REPO_URL" "$REPO_DIR"
fi

cd "$REPO_DIR"
pyenv local "$PYTHON_VERSION"

info "creating the project venv and installing"
python -m venv .venv
# shellcheck disable=SC1091
source .venv/bin/activate
pip install -q --upgrade pip
pip install -q -e ".[dev]"

info "pre-building the lab container image (REQUIRED before going offline)"
sudo docker compose -f labs/docker/docker-compose.yml build 2>/dev/null \
  || sudo docker-compose -f labs/docker/docker-compose.yml build

info "recording resolved dependency versions for the artifact appendix"
pip freeze --exclude-editable > provisioned-requirements.txt
sudo docker run --rm sentinel-lab-targets:latest pip freeze \
  > provisioned-lab-requirements.txt 2>/dev/null || true

info "smoke test: offline pipeline"
sentinel credentials >/dev/null
sentinel scan --cidr-file lab.example.txt --active --scope-file labs/lab-scope.yaml \
  --ports lab --dry-run --scan-fixture labs/seed/masscan-lab.json \
  -o out/smoke-scan.json --quiet
sentinel fingerprint -i out/smoke-scan.json --dry-run -o out/smoke-fp.json --quiet
python - <<'PY'
import json
hosts = json.load(open("out/smoke-fp.json"))["hosts"]
hist = {}
for h in hosts:
    hist[h["risk"]] = hist.get(h["risk"], 0) + 1
print(f"  hosts={len(hosts)} histogram={hist}")
expected = {"CRITICAL": 7, "HIGH": 2, "MEDIUM": 5, "LOW": 3}
if hist != expected:
    raise SystemExit(f"UNEXPECTED RESULT: got {hist}, expected {expected}")
print("  offline pipeline matches the reference result")
PY

echo
info "provisioning complete"
echo
warn "Log out and back in (or run 'newgrp docker') for docker group membership."
echo
echo "On the HOST, next:"
echo "  sudo ./setup.sh --isolate     # cut internet"
echo "  ./isolated_bridge.sh --verify # confirm no egress"
echo "  sudo ./setup.sh --snapshot    # save clean-base"
