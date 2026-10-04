#!/usr/bin/env bash
# ===========================================================================
# Isolated libvirt network for the Sentinel testbed
# ===========================================================================
#
# Defines a libvirt network with <forward mode='none'/>: no NAT, no masquerade,
# no route to the outside. The host reaches the guest over the bridge (so you
# can SSH in and copy results out), but the guest cannot reach anything else.
#
# This is isolation layer 2 of 3:
#   1. nftables egress drop on the host for the lab bridge (--harden below)
#   2. libvirt network with forwarding disabled        (this script)
#   3. Docker network with internal: true              (docker-compose.yml)
#
# Three layers because the consequence of getting it wrong is sending scan
# traffic to a non-consenting third party. Any one layer failing still leaves
# two, and `--verify` checks all three rather than trusting that `virsh
# net-define` did what it was told.
#
# Usage:
#   sudo ./isolated_bridge.sh --create     define and start the network
#   sudo ./isolated_bridge.sh --harden     add the nftables egress drop
#   ./isolated_bridge.sh --verify          check isolation (no root needed)
#   sudo ./isolated_bridge.sh --destroy    tear down
#
# Provisioning needs internet, so build the guest on the default NAT network
# FIRST and attach it here only once it is ready. See docs/REPRODUCE.md.
# ===========================================================================
set -euo pipefail

NET_NAME="${NET_NAME:-sentinel-isolated}"
BRIDGE="${BRIDGE:-virbr-sentinel}"
# Host<->guest management subnet. Deliberately NOT 10.99.0.0/24: that range
# belongs to the Docker lab network inside the guest, and overlapping the two
# produces routing behaviour that is very hard to reason about.
MGMT_SUBNET="${MGMT_SUBNET:-192.168.99.0/24}"
MGMT_HOST_IP="${MGMT_HOST_IP:-192.168.99.1}"
DHCP_START="${DHCP_START:-192.168.99.10}"
DHCP_END="${DHCP_END:-192.168.99.50}"
LAB_SUBNET="${LAB_SUBNET:-10.99.0.0/24}"

RED=$'\033[31m'; GRN=$'\033[32m'; YLW=$'\033[33m'; RST=$'\033[0m'
ok()   { printf '%s  OK  %s %s\n' "$GRN" "$RST" "$1"; }
bad()  { printf '%s FAIL %s %s\n' "$RED" "$RST" "$1"; }
warn() { printf '%s WARN %s %s\n' "$YLW" "$RST" "$1"; }

need_root() {
  [[ $EUID -eq 0 ]] || { echo "this action needs root (use sudo)" >&2; exit 1; }
}

create() {
  need_root
  command -v virsh >/dev/null || { echo "virsh not found: pacman -S libvirt" >&2; exit 1; }

  if virsh net-info "$NET_NAME" >/dev/null 2>&1; then
    warn "network $NET_NAME already exists; leaving it alone"
  else
    local xml
    xml="$(mktemp)"
    # forward mode='none' is the whole point: an isolated network. libvirt still
    # runs dnsmasq on the bridge for DHCP, so the guest gets an address and the
    # host can reach it, but there is no forwarding path outward.
    cat >"$xml" <<XML
<network>
  <name>${NET_NAME}</name>
  <bridge name='${BRIDGE}' stp='on' delay='0'/>
  <forward mode='none'/>
  <ip address='${MGMT_HOST_IP}' netmask='255.255.255.0'>
    <dhcp>
      <range start='${DHCP_START}' end='${DHCP_END}'/>
    </dhcp>
  </ip>
</network>
XML
    virsh net-define "$xml"
    rm -f "$xml"
    ok "defined $NET_NAME"
  fi

  virsh net-start "$NET_NAME" 2>/dev/null || true
  virsh net-autostart "$NET_NAME"
  ok "started $NET_NAME on $BRIDGE ($MGMT_SUBNET, no forwarding)"
  echo
  echo "Attach a guest with:  --network network=${NET_NAME},model=virtio"
  echo "Then verify:          ./isolated_bridge.sh --verify"
}

harden() {
  need_root
  command -v nft >/dev/null || { echo "nft not found: pacman -S nftables" >&2; exit 1; }

  # Belt-and-braces egress drop. libvirt's forward mode='none' should already
  # prevent this; the explicit rule means a future libvirt change, or someone
  # editing the network definition, cannot quietly re-enable forwarding.
  nft list table inet sentinel_lab >/dev/null 2>&1 && nft delete table inet sentinel_lab
  nft -f - <<NFT
table inet sentinel_lab {
  chain forward {
    type filter hook forward priority -10; policy accept;
    iifname "${BRIDGE}" counter drop comment "sentinel lab: no egress from lab bridge"
    oifname "${BRIDGE}" ct state new counter drop comment "sentinel lab: no inbound initiation"
    ip saddr ${LAB_SUBNET} counter drop comment "sentinel lab: lab subnet never forwarded"
    ip daddr ${LAB_SUBNET} counter drop comment "sentinel lab: lab subnet never routed to"
  }
}
NFT
  ok "nftables egress drop installed for $BRIDGE and $LAB_SUBNET"
  warn "this is NOT persistent across reboot; re-run --harden, or add it to"
  warn "/etc/nftables.conf if the testbed is long-lived"
}

verify() {
  local failures=0
  echo "=== Sentinel lab isolation check ==="
  echo

  echo "[1/5] libvirt network forwarding"
  if virsh net-dumpxml "$NET_NAME" 2>/dev/null | grep -q "<forward mode='none'"; then
    ok "$NET_NAME has forwarding disabled"
  elif virsh net-info "$NET_NAME" >/dev/null 2>&1; then
    bad "$NET_NAME EXISTS BUT FORWARDS TRAFFIC -- guest can reach the internet"
    virsh net-dumpxml "$NET_NAME" | grep -i forward || true
    failures=$((failures + 1))
  else
    bad "$NET_NAME is not defined (run --create)"
    failures=$((failures + 1))
  fi

  echo "[2/5] bridge present"
  if ip link show "$BRIDGE" >/dev/null 2>&1; then
    ok "$BRIDGE is up"
  else
    bad "$BRIDGE missing (network not started?)"
    failures=$((failures + 1))
  fi

  echo "[3/5] IP forwarding on the host"
  if [[ "$(sysctl -n net.ipv4.ip_forward 2>/dev/null || echo 0)" == "1" ]]; then
    warn "net.ipv4.ip_forward=1 on the host (normal with libvirt/docker)."
    warn "Isolation then rests on the libvirt network and the nftables rule --"
    warn "both checked here. Run --harden if step 4 fails."
  else
    ok "host IP forwarding disabled"
  fi

  echo "[4/5] nftables egress drop"
  if nft list table inet sentinel_lab >/dev/null 2>&1; then
    ok "sentinel_lab nftables table present"
  else
    warn "no sentinel_lab nftables table (run --harden for the third layer)"
  fi

  echo "[5/5] docker lab network internal"
  if command -v docker >/dev/null 2>&1 && docker network inspect sentinel-lab >/dev/null 2>&1; then
    if [[ "$(docker network inspect -f '{{.Internal}}' sentinel-lab)" == "true" ]]; then
      ok "docker network sentinel-lab is internal (no NAT)"
    else
      bad "docker network sentinel-lab is NOT internal -- containers can egress"
      failures=$((failures + 1))
    fi
  else
    warn "docker network sentinel-lab not found (run inside the guest, after compose up)"
  fi

  echo
  if [[ $failures -eq 0 ]]; then
    ok "isolation checks passed"
    echo
    echo "Confirm from inside the guest before any active scan:"
    echo "  ip route                      # expect NO default route"
    echo "  curl -sS --max-time 5 https://example.com || echo 'no egress: correct'"
    return 0
  fi
  bad "$failures check(s) FAILED -- do not run an active scan"
  return 1
}

destroy() {
  need_root
  virsh net-destroy "$NET_NAME" 2>/dev/null || true
  virsh net-undefine "$NET_NAME" 2>/dev/null || true
  nft delete table inet sentinel_lab 2>/dev/null || true
  ok "removed $NET_NAME and the nftables table"
}

case "${1:---verify}" in
  --create)  create ;;
  --harden)  harden ;;
  --verify)  verify ;;
  --destroy) destroy ;;
  *) sed -n '2,30p' "$0"; exit 1 ;;
esac
