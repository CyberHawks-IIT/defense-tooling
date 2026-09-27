#!/bin/bash
# setup-mirror.sh — mirror a router VM's interface(s) to a sensor's capture NIC.
#
# Run this ON THE PROXMOX HOST, not via Ansible — it operates on host-level
# tap/veth devices and Proxmox's own VM config, which Ansible has no clean
# way to reach from inside a guest.
#
# WHY THIS EXISTS: Proxmox's default ("simple zone") SDN networks are plain
# Linux bridges with no SPAN/port-mirror feature. A sensor attached to the
# same bridge as your router only ever sees broadcast traffic and frames
# addressed to its own MAC — not the router's traffic to/from other networks.
# This script uses `tc` to clone ingress traffic on the router's chosen
# interfaces and inject it directly onto the sensor's capture NIC.
#
# WHAT IT DOES:
#   1. Looks up which net<N> on the router VM corresponds to each vnet you
#      name, and resolves that to its host-side tap device (tap<vmid>i<N>).
#   2. Adds a `tc` ingress qdisc + mirred filter on each of those taps,
#      targeting the sensor's capture interface.
#   3. Installs a Proxmox hookscript on the router VM so the mirror is
#      reapplied every time it restarts (tap devices, and any tc config on
#      them, are recreated fresh on every VM start).
#
# WHAT IT ASSUMES:
#   - The router is a QEMU VM (this script reads `qm config`).
#   - The sensor's capture NIC is an LXC container NIC (host-side name
#     veth<ctid>i<N>) with firewall=0 and no IP — see CLAUDE.md's "Proxmox's
#     per-guest firewall silently drops mirrored traffic" for why firewall=0
#     specifically matters. If your sensor is a VM instead, host-side names
#     are tap<vmid>i<N> instead of veth<ctid>i<N> — adjust SENSOR_IFACE
#     accordingly (see --sensor-iface below).
#   - A snippets-capable storage already exists (see
#     docs/manual-prerequisites.md) — required for the hookscript.
#
# USAGE:
#   ./setup-mirror.sh --router-vmid 100 --router-vnets attacker,ad \
#       --sensor-ctid 511 --sensor-net-index 1 [--storage local]
#
# UNDO:
#   ./setup-mirror.sh --undo --router-vmid 100 --router-vnets attacker,ad

set -euo pipefail

STORAGE="local"
UNDO=0
SENSOR_IFACE=""

usage() {
  cat <<'EOF'
Usage:
  setup-mirror.sh --router-vmid <vmid> --router-vnets <vnet1,vnet2,...> \
                   --sensor-ctid <ctid> --sensor-net-index <N> \
                   [--storage <storage-name>]

  setup-mirror.sh --undo --router-vmid <vmid> --router-vnets <vnet1,vnet2,...>

Options:
  --router-vmid <vmid>        QEMU VMID of the router/firewall VM (e.g. pfSense)
  --router-vnets <list>       Comma-separated vnet names to mirror FROM
                               (must match a bridge= value in `qm config <vmid>`)
  --sensor-ctid <ctid>        LXC CTID of the sensor (e.g. the Zeek container)
  --sensor-net-index <N>      The sensor's netN that is its dedicated capture
                               NIC (firewall=0, no IP)
  --sensor-iface <name>       Override the computed sensor interface name
                               (auto-computed as veth<ctid>i<N> otherwise —
                               use this if your sensor is a VM, where the
                               host-side name is tap<vmid>i<N> instead)
  --storage <name>            Storage for the hookscript snippet (default: local)
  --undo                      Remove the tc mirror rules and the hookscript
  -h, --help                  This help
EOF
}

ROUTER_VMID=""
ROUTER_VNETS=""
SENSOR_CTID=""
SENSOR_NET_INDEX=""

while [ $# -gt 0 ]; do
  case "$1" in
    --router-vmid) ROUTER_VMID="$2"; shift 2 ;;
    --router-vnets) ROUTER_VNETS="$2"; shift 2 ;;
    --sensor-ctid) SENSOR_CTID="$2"; shift 2 ;;
    --sensor-net-index) SENSOR_NET_INDEX="$2"; shift 2 ;;
    --sensor-iface) SENSOR_IFACE="$2"; shift 2 ;;
    --storage) STORAGE="$2"; shift 2 ;;
    --undo) UNDO=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) echo "Unknown argument: $1" >&2; usage; exit 1 ;;
  esac
done

if [ -z "$ROUTER_VMID" ] || [ -z "$ROUTER_VNETS" ]; then
  echo "Error: --router-vmid and --router-vnets are required." >&2
  usage
  exit 1
fi

# Resolve each named vnet to its host-side tap device by reading the
# router's own config (net<N>: ...,bridge=<vnet>,...).
resolve_taps() {
  local vmid="$1" vnets="$2"
  local taps=()
  IFS=',' read -ra vnet_list <<< "$vnets"
  for vnet in "${vnet_list[@]}"; do
    local net_line index
    net_line=$(qm config "$vmid" | grep -E "^net[0-9]+: .*bridge=${vnet}(,|$)" || true)
    if [ -z "$net_line" ]; then
      echo "Error: no netN on VM $vmid has bridge=${vnet}" >&2
      exit 1
    fi
    index=$(echo "$net_line" | sed -E 's/^net([0-9]+):.*/\1/')
    taps+=("tap${vmid}i${index}")
  done
  echo "${taps[@]}"
}

if [ -z "$SENSOR_IFACE" ]; then
  if [ -z "$SENSOR_CTID" ] || [ -z "$SENSOR_NET_INDEX" ]; then
    echo "Error: provide --sensor-iface directly, or both --sensor-ctid and --sensor-net-index." >&2
    exit 1
  fi
  SENSOR_IFACE="veth${SENSOR_CTID}i${SENSOR_NET_INDEX}"
fi

TAPS=$(resolve_taps "$ROUTER_VMID" "$ROUTER_VNETS")

if [ "$UNDO" -eq 1 ]; then
  echo "Removing tc mirror rules..."
  for tap in $TAPS; do
    tc qdisc del dev "$tap" ingress 2>/dev/null && echo "  removed ingress qdisc on $tap" || echo "  (nothing to remove on $tap)"
  done
  echo "Removing hookscript from VM ${ROUTER_VMID}..."
  qm set "$ROUTER_VMID" --delete hookscript 2>/dev/null || true
  SNIPPET_PATH="/var/lib/vz/snippets/mirror-${ROUTER_VMID}.sh"
  rm -f "$SNIPPET_PATH"
  echo "Done. (If you also enabled the 'snippets' content type on ${STORAGE} just for this, that's still enabled — remove it yourself with 'pvesm set' if you want it fully reverted.)"
  exit 0
fi

echo "Mirroring taps [$TAPS] on VM ${ROUTER_VMID} -> ${SENSOR_IFACE}"

for tap in $TAPS; do
  if tc qdisc show dev "$tap" | grep -q ingress; then
    echo "  $tap already has an ingress qdisc, skipping (idempotent)"
  else
    tc qdisc add dev "$tap" ingress
    tc filter add dev "$tap" parent ffff: protocol all u32 match u32 0 0 action mirred egress mirror dev "$SENSOR_IFACE"
    echo "  mirroring $tap -> $SENSOR_IFACE"
  fi
done

# Persist across router VM restarts via a Proxmox hookscript.
SNIPPET_DIR="/var/lib/vz/snippets"
SNIPPET_PATH="${SNIPPET_DIR}/mirror-${ROUTER_VMID}.sh"
mkdir -p "$SNIPPET_DIR"

TAPS_ARRAY_LITERAL=$(printf '"%s" ' $TAPS)

cat > "$SNIPPET_PATH" <<EOF
#!/bin/bash
# Auto-generated by setup-mirror.sh — re-applies mirroring for VM ${ROUTER_VMID}
# on every post-start, since tap devices (and any tc config on them) are
# recreated fresh each time the VM starts.
VMID="\$1"
PHASE="\$2"
SENSOR_IFACE="${SENSOR_IFACE}"
TAPS=(${TAPS_ARRAY_LITERAL})

if [ "\$PHASE" != "post-start" ]; then
  exit 0
fi

for tap in "\${TAPS[@]}"; do
  if ! tc qdisc show dev "\$tap" | grep -q ingress; then
    tc qdisc add dev "\$tap" ingress
    tc filter add dev "\$tap" parent ffff: protocol all u32 match u32 0 0 action mirred egress mirror dev "\$SENSOR_IFACE"
  fi
done
EOF
chmod +x "$SNIPPET_PATH"

qm set "$ROUTER_VMID" --hookscript "${STORAGE}:snippets/$(basename "$SNIPPET_PATH")"

echo "Hookscript installed: ${STORAGE}:snippets/$(basename "$SNIPPET_PATH")"
echo "Done. To verify: tc filter show dev <tap> parent ffff:"
echo "To undo everything: $0 --undo --router-vmid ${ROUTER_VMID} --router-vnets ${ROUTER_VNETS}"
