#!/bin/bash
# setup-mirror.sh — mirror a router VM's interface(s) to a sensor's capture NIC.
#
# Run this ON THE PROXMOX HOST, not via Ansible — it operates on host-level
# tap/veth devices and Proxmox's own VM/CT config, which Ansible has no clean
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
#      targeting the sensor's capture interface. Always deletes and
#      recreates rather than checking first — see the gotcha below for why.
#   3. Installs a Proxmox hookscript on **both** the router VM and the
#      sensor CT, each re-running the same rebuild on its own post-start.
#      Both are needed — see "Two restart paths, not one" below.
#
# GOTCHA — WHY THIS ALWAYS DELETES AND RECREATES, NEVER JUST CHECKS:
#   An earlier version of this script skipped re-adding the mirror if a tap
#   already had an ingress qdisc. That's wrong: when the SENSOR container
#   restarts, its veth is destroyed and recreated with the same NAME but a
#   new kernel ifindex. The tc mirred action on the router's tap is bound to
#   the OLD ifindex — the qdisc/filter still exist (so a "does it exist"
#   check says yes) but silently point at a dead interface
#   (`tc filter show` prints "Egress Mirror to device *" instead of the
#   interface name). The sensor then sees nothing, with no error anywhere.
#   Deleting and recreating unconditionally, every time this runs, is cheap
#   and avoids this class of bug entirely — there's no meaningful cost to
#   "over-applying" a tc rule that's already correct.
#
# TWO RESTART PATHS, NOT ONE:
#   - Router (e.g. pfSense) restarts -> its taps are recreated fresh, along
#     with any tc config on them -> needs a hookscript ON THE ROUTER.
#   - Sensor restarts -> its own veth is recreated (see gotcha above) -> the
#     router's taps still exist but now mirror to a dead interface -> needs
#     a hookscript ON THE SENSOR.
#   Either one restarting independently breaks the mirror if only the other
#   side has a hookscript. This script installs both.
#
# WHAT IT ASSUMES:
#   - The router is a QEMU VM (this script reads `qm config`).
#   - The sensor's capture NIC is an LXC container NIC (host-side name
#     veth<ctid>i<N>) with firewall=0 and no IP — see CLAUDE.md's "Proxmox's
#     per-guest firewall silently drops mirrored traffic" for why firewall=0
#     specifically matters. If your sensor is a VM instead, host-side names
#     are tap<vmid>i<N> instead of veth<ctid>i<N> — pass --sensor-iface
#     directly in that case; this script won't install a sensor-side
#     hookscript for you (add one yourself, same pattern as the router's).
#   - A snippets-capable storage already exists (see
#     docs/manual-prerequisites.md) — required for the hookscripts.
#
# USAGE:
#   ./setup-mirror.sh --router-vmid 100 --router-vnets attacker,ad \
#       --sensor-ctid 511 --sensor-net-index 1 [--storage local]
#
# UNDO:
#   ./setup-mirror.sh --undo --router-vmid 100 --router-vnets attacker,ad --sensor-ctid 511

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

  setup-mirror.sh --undo --router-vmid <vmid> --router-vnets <vnet1,vnet2,...> \
                   [--sensor-ctid <ctid>]

Options:
  --router-vmid <vmid>        QEMU VMID of the router/firewall VM (e.g. pfSense)
  --router-vnets <list>       Comma-separated vnet names to mirror FROM
                               (must match a bridge= value in `qm config <vmid>`)
  --sensor-ctid <ctid>        LXC CTID of the sensor (e.g. the Zeek container).
                               Also used to install the sensor-side hookscript.
  --sensor-net-index <N>      The sensor's netN that is its dedicated capture
                               NIC (firewall=0, no IP)
  --sensor-iface <name>       Override the computed sensor interface name
                               (auto-computed as veth<ctid>i<N> otherwise —
                               use this if your sensor is a VM; no sensor-side
                               hookscript is installed in that case)
  --storage <name>            Storage for the hookscript snippets (default: local)
  --undo                      Remove the tc mirror rules and both hookscripts
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
SNIPPET_DIR="/var/lib/vz/snippets"
ROUTER_SNIPPET_PATH="${SNIPPET_DIR}/mirror-router-${ROUTER_VMID}.sh"
SENSOR_SNIPPET_PATH="${SNIPPET_DIR}/mirror-sensor-${SENSOR_CTID}.sh"

if [ "$UNDO" -eq 1 ]; then
  echo "Removing tc mirror rules..."
  for tap in $TAPS; do
    tc qdisc del dev "$tap" ingress 2>/dev/null && echo "  removed ingress qdisc on $tap" || echo "  (nothing to remove on $tap)"
  done
  echo "Removing hookscripts..."
  qm set "$ROUTER_VMID" --delete hookscript 2>/dev/null || true
  rm -f "$ROUTER_SNIPPET_PATH"
  if [ -n "$SENSOR_CTID" ]; then
    pct set "$SENSOR_CTID" --delete hookscript 2>/dev/null || true
    rm -f "$SENSOR_SNIPPET_PATH"
  fi
  echo "Done. (If you also enabled the 'snippets' content type on ${STORAGE} just for this, that's still enabled — remove it yourself with 'pvesm set' if you want it fully reverted.)"
  exit 0
fi

echo "Mirroring taps [$TAPS] on VM ${ROUTER_VMID} -> ${SENSOR_IFACE}"

for tap in $TAPS; do
  tc qdisc del dev "$tap" ingress 2>/dev/null || true
  tc qdisc add dev "$tap" ingress
  tc filter add dev "$tap" parent ffff: protocol all u32 match u32 0 0 action mirred egress mirror dev "$SENSOR_IFACE"
  echo "  mirroring $tap -> $SENSOR_IFACE"
done

mkdir -p "$SNIPPET_DIR"
TAPS_ARRAY_LITERAL=$(printf '"%s" ' $TAPS)

# Shared rebuild logic for both hookscripts. $1 = sensor iface name at
# generation time (baked in, since it doesn't change — only its underlying
# ifindex does). Skips cleanly (doesn't fail the boot) if the sensor
# interface doesn't exist yet, e.g. the router came up before the sensor.
write_hookscript() {
  local out_path="$1" comment="$2"
  cat > "$out_path" <<EOF
#!/bin/bash
# Auto-generated by setup-mirror.sh — ${comment}
VMID="\$1"
PHASE="\$2"
SENSOR_IFACE="${SENSOR_IFACE}"
TAPS=(${TAPS_ARRAY_LITERAL})

if [ "\$PHASE" != "post-start" ]; then
  exit 0
fi

if ! ip link show "\$SENSOR_IFACE" >/dev/null 2>&1; then
  # Sensor isn't up yet (or this ran on the sensor's own hook before its
  # interface finished attaching) -- nothing to bind to. Not an error.
  exit 0
fi

for tap in "\${TAPS[@]}"; do
  if ! ip link show "\$tap" >/dev/null 2>&1; then
    continue
  fi
  tc qdisc del dev "\$tap" ingress 2>/dev/null || true
  tc qdisc add dev "\$tap" ingress
  tc filter add dev "\$tap" parent ffff: protocol all u32 match u32 0 0 action mirred egress mirror dev "\$SENSOR_IFACE"
done
EOF
  chmod +x "$out_path"
}

write_hookscript "$ROUTER_SNIPPET_PATH" "re-applies mirroring when the router VM (${ROUTER_VMID}) restarts, since its taps are recreated fresh"
qm set "$ROUTER_VMID" --hookscript "${STORAGE}:snippets/$(basename "$ROUTER_SNIPPET_PATH")"
echo "Router-side hookscript installed on VM ${ROUTER_VMID}: ${STORAGE}:snippets/$(basename "$ROUTER_SNIPPET_PATH")"

if [ -n "$SENSOR_CTID" ]; then
  write_hookscript "$SENSOR_SNIPPET_PATH" "re-applies mirroring when the sensor CT (${SENSOR_CTID}) restarts, since its own capture interface is recreated with a new ifindex even though the name is unchanged"
  pct set "$SENSOR_CTID" --hookscript "${STORAGE}:snippets/$(basename "$SENSOR_SNIPPET_PATH")"
  echo "Sensor-side hookscript installed on CT ${SENSOR_CTID}: ${STORAGE}:snippets/$(basename "$SENSOR_SNIPPET_PATH")"
else
  echo "WARNING: no --sensor-ctid given, so no sensor-side hookscript was installed."
  echo "If your sensor ever restarts on its own, the mirror will silently break until this script is re-run. See the 'Two restart paths' note at the top of this script."
fi

echo "Done. To verify: tc filter show dev <tap> parent ffff:"
echo "To undo everything: $0 --undo --router-vmid ${ROUTER_VMID} --router-vnets ${ROUTER_VNETS} --sensor-ctid ${SENSOR_CTID}"
