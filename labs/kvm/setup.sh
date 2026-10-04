#!/usr/bin/env bash
# ===========================================================================
# Provision the Sentinel guest VM on an Arch host (KVM/QEMU + libvirt)
# ===========================================================================
#
# Creates a Debian 12 guest from the official generic cloud image with
# cloud-init, so the install is unattended and reproducible -- no interactive
# installer, no manual steps, same result every time.
#
# SEQUENCE MATTERS. The guest is built on the DEFAULT NAT NETWORK because
# provisioning needs internet (apt, pip, docker image builds). Only once it is
# fully provisioned is it moved to the isolated network and snapshotted. Build
# it isolated and nothing can install.
#
#   1. ./setup.sh --create       guest on NAT, cloud-init provisions it
#   2. ./setup.sh --provision    run provision-guest.sh inside the guest
#   3. ./setup.sh --isolate      move the NIC to the isolated network
#   4. ./setup.sh --snapshot     save as `clean-base`
#
# Then every experiment starts from:
#   ./setup.sh --revert          restore `clean-base`
#
# Reverting to a snapshot is what makes the determinism experiment (E4)
# meaningful: three runs from the same snapshot differ only in the code under
# test, not in accumulated system state.
# ===========================================================================
set -euo pipefail

VM_NAME="${VM_NAME:-sentinel-lab}"
VCPUS="${VCPUS:-4}"
RAM_MB="${RAM_MB:-8192}"
DISK_GB="${DISK_GB:-40}"
POOL_DIR="${POOL_DIR:-/var/lib/libvirt/images}"
ISOLATED_NET="${ISOLATED_NET:-sentinel-isolated}"
SNAPSHOT="${SNAPSHOT:-clean-base}"
GUEST_USER="${GUEST_USER:-sentinel}"

# Debian 12 generic cloud image. Pinned by checksum at run time -- see --create.
IMG_URL="${IMG_URL:-https://cloud.debian.org/images/cloud/bookworm/latest/debian-12-generic-amd64.qcow2}"
IMG_SHA_URL="${IMG_SHA_URL:-https://cloud.debian.org/images/cloud/bookworm/latest/SHA512SUMS}"
BASE_IMG="${POOL_DIR}/debian-12-generic-amd64.qcow2"
VM_DISK="${POOL_DIR}/${VM_NAME}.qcow2"

GRN=$'\033[32m'; YLW=$'\033[33m'; RED=$'\033[31m'; RST=$'\033[0m'
info() { printf '%s==>%s %s\n' "$GRN" "$RST" "$1"; }
warn() { printf '%s==>%s %s\n' "$YLW" "$RST" "$1"; }
die()  { printf '%s==>%s %s\n' "$RED" "$RST" "$1" >&2; exit 1; }

need_root() { [[ $EUID -eq 0 ]] || die "this action needs root (use sudo)"; }

require_tools() {
  local missing=()
  for tool in virsh virt-install qemu-img ssh-keygen curl; do
    command -v "$tool" >/dev/null || missing+=("$tool")
  done
  if ((${#missing[@]})); then
    die "missing: ${missing[*]}
Install on Arch:  sudo pacman -S --needed qemu-full libvirt virt-install openssh curl
Then:             sudo systemctl enable --now libvirtd"
  fi
}

ssh_key() {
  local key="$HOME/.ssh/id_ed25519.pub"
  [[ -f $key ]] || key="$HOME/.ssh/id_rsa.pub"
  [[ -f $key ]] || die "no SSH public key found. Generate one:  ssh-keygen -t ed25519"
  cat "$key"
}

guest_ip() {
  # Works on both the NAT and the isolated network: read the lease libvirt's
  # dnsmasq handed out for this domain's interface.
  virsh domifaddr "$VM_NAME" --source lease 2>/dev/null \
    | awk '/ipv4/ {split($4, a, "/"); print a[1]; exit}'
}

create() {
  need_root
  require_tools
  mkdir -p "$POOL_DIR"

  if virsh dominfo "$VM_NAME" >/dev/null 2>&1; then
    die "domain $VM_NAME already exists. Remove it with --destroy first."
  fi

  if [[ ! -f $BASE_IMG ]]; then
    info "downloading the Debian 12 generic cloud image"
    curl -fL --progress-bar -o "${BASE_IMG}.part" "$IMG_URL"

    # Verify against the published checksum. An unverified base image is an
    # unverified foundation for every measurement taken on it, and the paper's
    # artifact appendix should state the digest.
    info "verifying checksum"
    local sums expected actual
    sums="$(mktemp)"
    if curl -fsL -o "$sums" "$IMG_SHA_URL"; then
      expected="$(awk -v f="$(basename "$IMG_URL")" '$2 == f {print $1}' "$sums" | head -1)"
      if [[ -n $expected ]]; then
        actual="$(sha512sum "${BASE_IMG}.part" | awk '{print $1}')"
        if [[ $expected != "$actual" ]]; then
          rm -f "${BASE_IMG}.part" "$sums"
          die "CHECKSUM MISMATCH -- refusing to use this image
  expected $expected
  actual   $actual"
        fi
        info "checksum verified: ${actual:0:16}..."
        echo "$actual" > "${BASE_IMG}.sha512"
      else
        warn "image not listed in SHA512SUMS; cannot verify"
      fi
    else
      warn "could not fetch SHA512SUMS; cannot verify the image"
    fi
    rm -f "$sums"
    mv "${BASE_IMG}.part" "$BASE_IMG"
  else
    info "reusing cached base image $BASE_IMG"
  fi

  info "creating a ${DISK_GB}G overlay disk"
  rm -f "$VM_DISK"
  qemu-img create -f qcow2 -F qcow2 -b "$BASE_IMG" "$VM_DISK" "${DISK_GB}G" >/dev/null

  local userdata
  userdata="$(mktemp)"
  cat >"$userdata" <<CLOUDINIT
#cloud-config
hostname: ${VM_NAME}
users:
  - name: ${GUEST_USER}
    groups: [sudo, docker]
    shell: /bin/bash
    sudo: ["ALL=(ALL) NOPASSWD:ALL"]
    ssh_authorized_keys:
      - $(ssh_key)
# Password login stays disabled: key-only access. A lab VM with a known
# password is still a VM with a known password.
ssh_pwauth: false
package_update: true
packages: [git, curl, ca-certificates, python3, python3-venv, sudo]
CLOUDINIT

  info "creating the guest on the DEFAULT NAT network (provisioning needs internet)"
  virt-install \
    --name "$VM_NAME" \
    --memory "$RAM_MB" \
    --vcpus "$VCPUS" \
    --cpu host-passthrough \
    --disk "path=${VM_DISK},format=qcow2,bus=virtio" \
    --os-variant debian12 \
    --network network=default,model=virtio \
    --graphics none \
    --console pty,target_type=serial \
    --cloud-init "user-data=${userdata}" \
    --import \
    --noautoconsole
  rm -f "$userdata"

  info "waiting for the guest to take a DHCP lease"
  local ip=""
  for _ in $(seq 1 60); do
    ip="$(guest_ip || true)"
    [[ -n $ip ]] && break
    sleep 5
  done
  [[ -n $ip ]] || die "guest did not get an address. Inspect with: virsh console $VM_NAME"

  info "guest is up at $ip"
  echo
  echo "Next:  sudo ./setup.sh --provision"
}

provision() {
  require_tools
  local ip
  ip="$(guest_ip)" || die "cannot determine the guest address"
  [[ -n $ip ]] || die "cannot determine the guest address; is $VM_NAME running?"

  info "waiting for SSH on $ip"
  for _ in $(seq 1 40); do
    ssh -o StrictHostKeyChecking=accept-new -o ConnectTimeout=5 \
        "${GUEST_USER}@${ip}" true 2>/dev/null && break
    sleep 5
  done

  info "copying provision-guest.sh and running it (this installs docker, pyenv, deps)"
  scp -o StrictHostKeyChecking=accept-new \
      "$(dirname "$0")/provision-guest.sh" "${GUEST_USER}@${ip}:/tmp/"
  ssh "${GUEST_USER}@${ip}" "chmod +x /tmp/provision-guest.sh && /tmp/provision-guest.sh"

  info "provisioning complete"
  echo
  echo "Next:  sudo ./setup.sh --isolate     # cut internet, then snapshot"
}

isolate() {
  need_root
  virsh net-info "$ISOLATED_NET" >/dev/null 2>&1 \
    || die "network $ISOLATED_NET not defined. Run: sudo ./isolated_bridge.sh --create"

  info "shutting the guest down to reattach its NIC"
  virsh shutdown "$VM_NAME" 2>/dev/null || true
  for _ in $(seq 1 40); do
    [[ "$(virsh domstate "$VM_NAME" 2>/dev/null)" == "shut off" ]] && break
    sleep 3
  done
  [[ "$(virsh domstate "$VM_NAME")" == "shut off" ]] || virsh destroy "$VM_NAME"

  local mac
  mac="$(virsh dumpxml "$VM_NAME" | awk -F"'" '/mac address/ {print $2; exit}')"

  info "detaching the NAT interface"
  virsh detach-interface "$VM_NAME" network --mac "$mac" --config 2>/dev/null || true

  info "attaching $ISOLATED_NET"
  virsh attach-interface "$VM_NAME" network "$ISOLATED_NET" \
    --model virtio --config --persistent

  virsh start "$VM_NAME"
  info "guest moved to $ISOLATED_NET and restarted"
  echo
  warn "VERIFY ISOLATION BEFORE ANY ACTIVE SCAN:"
  echo "  ./isolated_bridge.sh --verify"
  echo "  ssh ${GUEST_USER}@\$(virsh domifaddr $VM_NAME --source lease | awk '/ipv4/{split(\$4,a,\"/\");print a[1]}')"
  echo "  # in the guest:  curl -sS --max-time 5 https://example.com || echo 'no egress: correct'"
  echo
  echo "Next:  sudo ./setup.sh --snapshot"
}

snapshot() {
  need_root
  info "creating snapshot '$SNAPSHOT' (guest will be paused briefly)"
  virsh snapshot-create-as "$VM_NAME" "$SNAPSHOT" \
    "Provisioned, isolated, pre-experiment baseline" --atomic
  virsh snapshot-list "$VM_NAME"
  info "snapshot '$SNAPSHOT' created"
  echo
  echo "Start every experiment from a clean state:  sudo ./setup.sh --revert"
}

revert() {
  need_root
  info "reverting to '$SNAPSHOT'"
  virsh snapshot-revert "$VM_NAME" "$SNAPSHOT" --running
  info "reverted. The guest is at the pre-experiment baseline."
}

status() {
  virsh dominfo "$VM_NAME" 2>/dev/null || { echo "domain $VM_NAME does not exist"; return 1; }
  echo
  echo "Interfaces:"; virsh domiflist "$VM_NAME"
  echo
  echo "Address:    $(guest_ip || echo '(no lease)')"
  echo "Snapshots:"; virsh snapshot-list "$VM_NAME" 2>/dev/null || echo "  none"
}

ssh_in() {
  local ip; ip="$(guest_ip)" || die "no guest address"
  exec ssh "${GUEST_USER}@${ip}"
}

destroy() {
  need_root
  warn "this removes the guest $VM_NAME and its disk (the cached base image is kept)"
  read -r -p "type the VM name to confirm: " confirm
  [[ $confirm == "$VM_NAME" ]] || die "aborted"
  virsh destroy "$VM_NAME" 2>/dev/null || true
  virsh snapshot-delete "$VM_NAME" --snapshotname "$SNAPSHOT" 2>/dev/null || true
  virsh undefine "$VM_NAME" --nvram --remove-all-storage 2>/dev/null \
    || virsh undefine "$VM_NAME" 2>/dev/null || true
  rm -f "$VM_DISK"
  info "removed $VM_NAME"
}

case "${1:---status}" in
  --create)    create ;;
  --provision) provision ;;
  --isolate)   isolate ;;
  --snapshot)  snapshot ;;
  --revert)    revert ;;
  --status)    status ;;
  --ssh)       ssh_in ;;
  --destroy)   destroy ;;
  *) sed -n '2,33p' "$0"; exit 1 ;;
esac
