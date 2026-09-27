#!/bin/bash
# create-privileged-lxc.sh — build a privileged Debian LXC container without
# the linked-clone trap.
#
# WHY THIS EXISTS: `unprivileged` is fixed at container creation and copied
# as-is by `pct clone` (linked or full) — there is no clone-time override.
# If your fleet's shared base template was created unprivileged (Proxmox's
# own "Create CT" wizard default), cloning it can never give you a
# privileged container, no matter what clone options you pick. See
# CLAUDE.md's "Cloning a container never changes privileged/unprivileged"
# for the full story, including why hand-editing the config file afterward
# doesn't work either.
#
# This script builds fresh from a base OS template archive (not a clone),
# with --unprivileged 0. It does NOT try to replicate any customization your
# shared template has beyond stock Debian — reapply that yourself (an
# Ansible role, ideally) after this script hands you a clean privileged
# container.
#
# Run this ON THE PROXMOX HOST.
#
# USAGE:
#   ./create-privileged-lxc.sh --vmid 511 --hostname zeek \
#       --template local:vztmpl/debian-12-standard_12.7-1_amd64.tar.zst \
#       --bridge defense --ip 10.0.10.3/24 --gw 10.0.10.1 \
#       --nameserver 10.0.10.1 --searchdomain example.lab \
#       --cores 1 --memory 4096 --swap 512 --rootfs-storage local-zfs --rootfs-size 16

set -euo pipefail

CORES=1
MEMORY=4096
SWAP=512
ROOTFS_STORAGE="local-zfs"
ROOTFS_SIZE=16
FEATURES="nesting=1"

usage() {
  cat <<'EOF'
Usage:
  create-privileged-lxc.sh --vmid <id> --hostname <name> --template <storage:vztmpl/file> \
      --bridge <vnet> --ip <ip/cidr> --gw <gateway> \
      [--nameserver <ip>] [--searchdomain <domain>] \
      [--cores N] [--memory MB] [--swap MB] \
      [--rootfs-storage <storage>] [--rootfs-size GB] [--tags <tag1;tag2>]

All the --cores/--memory/--swap/--rootfs-* options have sensible small
defaults (1 core, 4096MB memory, 512MB swap, 16GB root on local-zfs) —
override whichever ones matter for your case.
EOF
}

VMID="" HOSTNAME="" TEMPLATE="" BRIDGE="" IP="" GW="" NAMESERVER="" SEARCHDOMAIN="" TAGS=""

while [ $# -gt 0 ]; do
  case "$1" in
    --vmid) VMID="$2"; shift 2 ;;
    --hostname) HOSTNAME="$2"; shift 2 ;;
    --template) TEMPLATE="$2"; shift 2 ;;
    --bridge) BRIDGE="$2"; shift 2 ;;
    --ip) IP="$2"; shift 2 ;;
    --gw) GW="$2"; shift 2 ;;
    --nameserver) NAMESERVER="$2"; shift 2 ;;
    --searchdomain) SEARCHDOMAIN="$2"; shift 2 ;;
    --cores) CORES="$2"; shift 2 ;;
    --memory) MEMORY="$2"; shift 2 ;;
    --swap) SWAP="$2"; shift 2 ;;
    --rootfs-storage) ROOTFS_STORAGE="$2"; shift 2 ;;
    --rootfs-size) ROOTFS_SIZE="$2"; shift 2 ;;
    --tags) TAGS="$2"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "Unknown argument: $1" >&2; usage; exit 1 ;;
  esac
done

for required in VMID HOSTNAME TEMPLATE BRIDGE IP GW; do
  if [ -z "${!required}" ]; then
    echo "Error: --${required,,} is required." >&2
    usage
    exit 1
  fi
done

NET0="name=eth0,bridge=${BRIDGE},firewall=1,gw=${GW},ip=${IP},type=veth"

CMD=(pct create "$VMID" "$TEMPLATE"
  --hostname "$HOSTNAME"
  --cores "$CORES"
  --memory "$MEMORY"
  --swap "$SWAP"
  --rootfs "${ROOTFS_STORAGE}:${ROOTFS_SIZE}"
  --net0 "$NET0"
  --ostype debian
  --unprivileged 0
  --features "$FEATURES")

[ -n "$NAMESERVER" ] && CMD+=(--nameserver "$NAMESERVER")
[ -n "$SEARCHDOMAIN" ] && CMD+=(--searchdomain "$SEARCHDOMAIN")
[ -n "$TAGS" ] && CMD+=(--tags "$TAGS")

echo "Running: ${CMD[*]}"
"${CMD[@]}"

echo
echo "Created privileged container ${VMID} (${HOSTNAME})."
echo "Verify with: pct config ${VMID}   # no 'unprivileged:' line means privileged"
echo "Start it with: pct start ${VMID}"
echo
echo "Remember: this container has ONLY stock Debian on it. Reapply whatever"
echo "customization your shared template normally carries (ideally via an"
echo "Ansible role) before treating it as equivalent to a cloned container."
