#!/bin/bash
# mirror-vnet-guests.sh — mirror every guest's own NIC on a vnet to a
# sensor's capture NIC, not just a router's.
#
# Run this ON THE PROXMOX HOST, not via Ansible — same reasoning as
# setup-mirror.sh: it operates on host-level tap/veth devices and Proxmox's
# own VM/CT config.
#
# WHY THIS EXISTS, AND WHY IT'S SEPARATE FROM setup-mirror.sh:
#   setup-mirror.sh mirrors a ROUTER's own interface into a vnet, which
#   only ever sees traffic addressed to/from the router itself (plus
#   broadcast) — a Linux bridge is a real switch, so two OTHER hosts on the
#   same vnet talking directly to each other (or broadcasting) never reach
#   the router's port at all, and so never reach the sensor either.
#   Confirmed live 2026-09-27, two ways: (1) a coercion attack's resulting
#   outbound SMB connection from a DC to a same-vnet listener never showed
#   up in Zeek's conn.log, even though the DC's identical connection to a
#   listener on a DIFFERENT vnet (crossing the router) showed up fine; (2)
#   LLMNR/NBT-NS/mDNS poisoning traffic (inherently broadcast/multicast,
#   entirely within one vnet) was completely invisible to Zeek even though
#   the poisoning itself demonstrably worked (a real NTLMv2 hash was
#   captured). Mirroring the ROUTER's tap can never fix either case,
#   because the traffic never reaches the router's port in the first
#   place. The actual fix is mirroring EVERY guest's own tap on the vnet,
#   so each host's own outbound traffic (unicast to any destination, or
#   broadcast/multicast) gets copied to the sensor directly, regardless of
#   whether it ever transits the router.
#
# WHAT IT DOES:
#   1. Finds every QEMU VM and LXC container with a NIC on the named vnet
#      bridge (reads `qm config`/`pct config` for every guest on the host),
#      and resolves each to its host-side tap/veth device.
#   2. Adds a `tc` ingress qdisc + mirred filter on each of those
#      interfaces, targeting the sensor's capture interface — identical
#      mechanism to setup-mirror.sh, just applied to every guest instead of
#      one router.
#   3. Installs a Proxmox hookscript on **each guest** (re-mirroring its
#      own tap on its own post-start) and REPLACES the sensor's existing
#      hookscript with one covering every tap from both this script and
#      any prior setup-mirror.sh run, so a sensor restart fixes every
#      mirror source at once. If the sensor already has a hookscript from
#      setup-mirror.sh, pass --existing-sensor-taps to preserve those
#      alongside the new ones (see USAGE) — this script does not try to
#      read setup-mirror.sh's own state.
#   4. Installs a udev rule (+ /usr/local/sbin/cyberhawks-mirror-iface and
#      /etc/cyberhawks/mirror-<vnet>.conf) that re-applies the same mirror
#      whenever any of those interfaces, or the sensor's, is created. This is
#      what covers a reboot issued inside an LXC guest, which recreates its
#      veth without running the hookscripts from step 3.
#   5. A guest that already has an unrelated hookscript set will have it
#      REPLACED — check first (`qm config <vmid> | grep hookscript` /
#      `pct config <ctid> | grep hookscript`) if that guest might be
#      running something else's hookscript already; this script does not
#      attempt to merge with a pre-existing one.
#
# GOTCHA (same as setup-mirror.sh): always deletes and recreates the tc
# qdisc/filter rather than checking first, since a stale filter can point
# at a dead ifindex with no visible error if the sensor's own interface
# was recreated since the filter was added.
#
# USAGE:
#   ./mirror-vnet-guests.sh --vnet ad --sensor-ctid 511 --sensor-net-index 1 \
#       [--existing-sensor-taps tap100i3,tap100i6] [--storage local]
#
# UNDO:
#   ./mirror-vnet-guests.sh --undo --vnet ad
#
# WHAT IT ASSUMES: same as setup-mirror.sh (LXC sensor with a dedicated,
# firewall=0, no-IP capture NIC; a snippets-capable storage already set up).

set -euo pipefail

STORAGE="local"
UNDO=0
VNET=""
SENSOR_CTID=""
SENSOR_NET_INDEX=""
EXISTING_SENSOR_TAPS=""
EXCLUDE_VMIDS=""
ONLY_VMIDS=""

usage() {
  cat <<'EOF'
Usage:
  mirror-vnet-guests.sh --vnet <name> --sensor-ctid <ctid> \
                         --sensor-net-index <N> \
                         [--existing-sensor-taps <tap1,tap2,...>] \
                         [--storage <storage-name>]

  mirror-vnet-guests.sh --undo --vnet <name>

Options:
  --vnet <name>                 Vnet bridge name to mirror every guest on
                                 (must match a bridge= value in `qm config`/
                                 `pct config` for the guests you want covered)
  --sensor-ctid <ctid>          LXC CTID of the sensor (e.g. the Zeek container)
  --sensor-net-index <N>        The sensor's netN that is its dedicated capture
                                 NIC (firewall=0, no IP)
  --existing-sensor-taps <list> Comma-separated extra taps (e.g. from a prior
                                 setup-mirror.sh run) to fold into the
                                 sensor's own hookscript, so a sensor restart
                                 re-applies those too, not just this script's
  --exclude-vmids <list>        Space- or comma-separated VMIDs to skip even
                                 if they have a NIC on this vnet -- always
                                 pass the router's own VMID here if it's also
                                 on this vnet, since setup-mirror.sh already
                                 gives it a dedicated hookscript
  --vmids <list>                Space- or comma-separated exact VMIDs/CTIDs
                                 to mirror, skipping full-host discovery
                                 entirely. Use this on a host with many
                                 guests (discovery calls `qm config`/`pct
                                 config` once per guest on the WHOLE host,
                                 which can take minutes if there are dozens
                                 unrelated to the vnet you care about) --
                                 confirmed live 2026-09-27 on a 99-guest
                                 host, where unscoped discovery took long
                                 enough to look hung. Each ID is checked
                                 against both `qm` and `pct` automatically.
  --storage <name>              Storage for hookscript snippets (default: local)
  --undo                        Remove this script's tc mirror rules and
                                 per-guest hookscripts (does not touch the
                                 sensor's hookscript or setup-mirror.sh's own
                                 router mirror — rerun this script without
                                 --undo, or setup-mirror.sh --undo, for those)
  -h, --help                    This help
EOF
}

while [ $# -gt 0 ]; do
  case "$1" in
    --vnet) VNET="$2"; shift 2 ;;
    --sensor-ctid) SENSOR_CTID="$2"; shift 2 ;;
    --sensor-net-index) SENSOR_NET_INDEX="$2"; shift 2 ;;
    --existing-sensor-taps) EXISTING_SENSOR_TAPS="$2"; shift 2 ;;
    --exclude-vmids) EXCLUDE_VMIDS="${2//,/ }"; shift 2 ;;
    --vmids) ONLY_VMIDS="${2//,/ }"; shift 2 ;;
    --storage) STORAGE="$2"; shift 2 ;;
    --undo) UNDO=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) echo "Unknown argument: $1" >&2; usage; exit 1 ;;
  esac
done

if [ -z "$VNET" ]; then
  echo "Error: --vnet is required." >&2
  usage
  exit 1
fi

# Finds every RUNNING, non-template guest (qm and pct) with a netN on the
# named bridge, printing "kind vmid tap" lines (kind = qm or pct, tap =
# tap<vmid>i<N> or veth<ctid>i<N>). Excludes:
#   - templates (`qm list` includes them; they have no live tap device at
#     all, so mirroring one fails outright with "Cannot find device")
#   - VMIDs in $EXCLUDE_VMIDS (space-separated, e.g. the router itself) --
#     the router already gets its own dedicated hookscript from
#     setup-mirror.sh, and treating it as "just another guest" here would
#     clobber that with a differently-named script doing the same job, for
#     no benefit.
discover_guests() {
  local vnet="$1"
  if [ -n "$ONLY_VMIDS" ]; then
    for vmid in $ONLY_VMIDS; do
      if qm config "$vmid" >/dev/null 2>&1; then
        local net_line index
        net_line=$(qm config "$vmid" 2>/dev/null | grep -E "^net[0-9]+: .*bridge=${vnet}(,|$)" || true)
        if [ -n "$net_line" ]; then
          index=$(echo "$net_line" | sed -E 's/^net([0-9]+):.*/\1/' | head -1)
          if ip link show "tap${vmid}i${index}" >/dev/null 2>&1; then
            echo "qm $vmid tap${vmid}i${index}"
          fi
        fi
      elif pct config "$vmid" >/dev/null 2>&1; then
        local net_line index
        net_line=$(pct config "$vmid" 2>/dev/null | grep -E "^net[0-9]+: .*bridge=${vnet}(,|$)" || true)
        if [ -n "$net_line" ]; then
          index=$(echo "$net_line" | sed -E 's/^net([0-9]+):.*/\1/' | head -1)
          if ip link show "veth${vmid}i${index}" >/dev/null 2>&1; then
            echo "pct $vmid veth${vmid}i${index}"
          fi
        fi
      else
        echo "Warning: no qm or pct guest found with ID $vmid, skipping." >&2
      fi
    done
    return
  fi
  for vmid in $(qm list 2>/dev/null | awk 'NR>1{print $1}'); do
    if [ -n "$EXCLUDE_VMIDS" ] && [[ " $EXCLUDE_VMIDS " == *" $vmid "* ]]; then
      continue
    fi
    if qm config "$vmid" 2>/dev/null | grep -q '^template: 1'; then
      continue
    fi
    local net_line index
    net_line=$(qm config "$vmid" 2>/dev/null | grep -E "^net[0-9]+: .*bridge=${vnet}(,|$)" || true)
    if [ -n "$net_line" ]; then
      index=$(echo "$net_line" | sed -E 's/^net([0-9]+):.*/\1/' | head -1)
      if ip link show "tap${vmid}i${index}" >/dev/null 2>&1; then
        echo "qm $vmid tap${vmid}i${index}"
      fi
    fi
  done
  for ctid in $(pct list 2>/dev/null | awk 'NR>1{print $1}'); do
    local net_line index
    net_line=$(pct config "$ctid" 2>/dev/null | grep -E "^net[0-9]+: .*bridge=${vnet}(,|$)" || true)
    if [ -n "$net_line" ]; then
      index=$(echo "$net_line" | sed -E 's/^net([0-9]+):.*/\1/' | head -1)
      if ip link show "veth${ctid}i${index}" >/dev/null 2>&1; then
        echo "pct $ctid veth${ctid}i${index}"
      fi
    fi
  done
}

SNIPPET_DIR="/var/lib/vz/snippets"

if [ "$UNDO" -eq 1 ]; then
  echo "Removing per-guest tc mirror rules and hookscripts for vnet '${VNET}'..."
  while read -r kind id tap; do
    [ -z "$kind" ] && continue
    tc qdisc del dev "$tap" ingress 2>/dev/null && echo "  removed ingress qdisc on $tap" || echo "  (nothing to remove on $tap)"
    if [ "$kind" = "qm" ]; then
      qm set "$id" --delete hookscript 2>/dev/null || true
    else
      pct set "$id" --delete hookscript 2>/dev/null || true
    fi
    rm -f "${SNIPPET_DIR}/mirror-guest-${id}.sh"
  done < <(discover_guests "$VNET")
  rm -f "/etc/cyberhawks/mirror-${VNET}.conf"
  if ! ls /etc/cyberhawks/mirror-*.conf >/dev/null 2>&1; then
    rm -f /etc/udev/rules.d/90-cyberhawks-mirror.rules /usr/local/sbin/cyberhawks-mirror-iface
    udevadm control --reload
  fi
  echo "Done. The sensor's own hookscript (if any) was not modified — edit/remove it by hand if needed."
  exit 0
fi

if [ -z "$SENSOR_CTID" ] || [ -z "$SENSOR_NET_INDEX" ]; then
  echo "Error: --sensor-ctid and --sensor-net-index are required (unless --undo)." >&2
  usage
  exit 1
fi

SENSOR_IFACE="veth${SENSOR_CTID}i${SENSOR_NET_INDEX}"

mapfile -t GUESTS < <(discover_guests "$VNET")
if [ "${#GUESTS[@]}" -eq 0 ]; then
  echo "Error: no qm/pct guest found with a NIC on bridge=${VNET}." >&2
  exit 1
fi

echo "Found ${#GUESTS[@]} guest(s) on vnet '${VNET}':"
printf '  %s\n' "${GUESTS[@]}"

mkdir -p "$SNIPPET_DIR"
ALL_TAPS=()

for entry in "${GUESTS[@]}"; do
  read -r kind id tap <<< "$entry"
  ALL_TAPS+=("$tap")

  tc qdisc del dev "$tap" ingress 2>/dev/null || true
  tc qdisc add dev "$tap" ingress
  tc filter add dev "$tap" parent ffff: protocol all u32 match u32 0 0 action mirred egress mirror dev "$SENSOR_IFACE"
  echo "  mirroring $tap ($kind $id) -> $SENSOR_IFACE"

  GUEST_SNIPPET_PATH="${SNIPPET_DIR}/mirror-guest-${id}.sh"
  cat > "$GUEST_SNIPPET_PATH" <<EOF
#!/bin/bash
# Auto-generated by mirror-vnet-guests.sh — re-applies mirroring when
# guest ${id} (vnet ${VNET}) restarts, since its tap/veth is recreated fresh.
PHASE="\$2"
SENSOR_IFACE="${SENSOR_IFACE}"
TAP="${tap}"

if [ "\$PHASE" != "post-start" ]; then
  exit 0
fi

if ! ip link show "\$SENSOR_IFACE" >/dev/null 2>&1; then
  exit 0
fi
if ! ip link show "\$TAP" >/dev/null 2>&1; then
  exit 0
fi

tc qdisc del dev "\$TAP" ingress 2>/dev/null || true
tc qdisc add dev "\$TAP" ingress
tc filter add dev "\$TAP" parent ffff: protocol all u32 match u32 0 0 action mirred egress mirror dev "\$SENSOR_IFACE"
EOF
  chmod +x "$GUEST_SNIPPET_PATH"

  if [ "$kind" = "qm" ]; then
    qm set "$id" --hookscript "${STORAGE}:snippets/$(basename "$GUEST_SNIPPET_PATH")"
  else
    pct set "$id" --hookscript "${STORAGE}:snippets/$(basename "$GUEST_SNIPPET_PATH")"
  fi
done

# Rebuild the SENSOR's own hookscript to cover every tap this script knows
# about, plus any pre-existing (e.g. router) taps passed in explicitly —
# a sensor restart needs to re-point ALL mirrors at its new ifindex, not
# just this script's own.
if [ -n "$EXISTING_SENSOR_TAPS" ]; then
  IFS=',' read -ra extra <<< "$EXISTING_SENSOR_TAPS"
  ALL_TAPS+=("${extra[@]}")
fi

SENSOR_SNIPPET_PATH="${SNIPPET_DIR}/mirror-sensor-${SENSOR_CTID}.sh"
TAPS_ARRAY_LITERAL=$(printf '"%s" ' "${ALL_TAPS[@]}")
cat > "$SENSOR_SNIPPET_PATH" <<EOF
#!/bin/bash
# Auto-generated by mirror-vnet-guests.sh — re-applies mirroring for every
# known source tap when the sensor CT (${SENSOR_CTID}) restarts, since its
# own capture interface is recreated with a new ifindex even though the
# name is unchanged. Includes both this script's per-guest taps and any
# --existing-sensor-taps passed in (e.g. from setup-mirror.sh's router mirror).
PHASE="\$2"
SENSOR_IFACE="${SENSOR_IFACE}"
TAPS=(${TAPS_ARRAY_LITERAL})

if [ "\$PHASE" != "post-start" ]; then
  exit 0
fi
if ! ip link show "\$SENSOR_IFACE" >/dev/null 2>&1; then
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
chmod +x "$SENSOR_SNIPPET_PATH"
pct set "$SENSOR_CTID" --hookscript "${STORAGE}:snippets/$(basename "$SENSOR_SNIPPET_PATH")"
echo "Sensor-side hookscript (CT ${SENSOR_CTID}) rebuilt to cover ${#ALL_TAPS[@]} tap(s) total."

# Re-mirror whenever an interface is (re)created, not only on a Proxmox start
# (2026-10-02). The hookscripts above run only when Proxmox itself starts the
# guest (`qm start`/`pct start`, the GUI). A reboot issued INSIDE an LXC
# container (`reboot` in the guest) restarts it through its systemd unit
# instead, which recreates its veth without running any hookscript, so the
# guest silently stops being mirrored. Seen live: the test CT (350) was
# rebooted in-guest at 14:20, and a Responder run from it at 14:39-15:00 was
# invisible to Zeek (its poisoned replies never reached the sensor) until a
# `pct start` at 15:04 re-applied the mirror. The same applies to the sensor's
# own capture veth. A udev rule fires on every interface add, however the
# guest was started, so it covers all of these cases. The hookscripts stay as
# a second path; applying the mirror twice is harmless (delete + recreate).
# The udev rule must NOT mirror at the moment of the add event: Proxmox's own
# network setup for the interface runs just after it (bridge attach, and the
# rate-limit setup, which deletes the interface's ingress qdisc when no rate is
# set), and that wiped a mirror applied at add time within seconds (seen live
# on the first version of this rule). So udev only schedules deferred checks
# (systemd-run timers, since udev kills anything left running from RUN), which
# re-apply a source's mirror only if it is missing, so a working capture is
# never interrupted.
MIRROR_CONF_DIR="/etc/cyberhawks"
MIRROR_HELPER="/usr/local/sbin/cyberhawks-mirror-iface"
MIRROR_UDEV_RULE="/etc/udev/rules.d/90-cyberhawks-mirror.rules"
mkdir -p "$MIRROR_CONF_DIR"
cat > "${MIRROR_CONF_DIR}/mirror-${VNET}.conf" <<EOF
# Auto-generated by mirror-vnet-guests.sh: interfaces on vnet ${VNET} that are
# mirrored to the sensor, read by ${MIRROR_HELPER}.
SENSOR_IFACE="${SENSOR_IFACE}"
SOURCES="${ALL_TAPS[*]}"
EOF
cat > "$MIRROR_HELPER" <<'EOF'
#!/bin/bash
# Auto-generated by mirror-vnet-guests.sh.
#   cyberhawks-mirror-iface <iface>           (from udev, on interface add)
#     schedules the deferred checks below and returns immediately.
#   cyberhawks-mirror-iface --ensure <iface>  (deferred)
#     guest interface: mirror it to its sensor unless a live mirror is there.
#     sensor capture interface: the same for every source of that sensor (their
#     old filters point at the sensor's dead ifindex, so they no longer match).
PATH=/usr/sbin:/usr/bin:/sbin:/bin
mirror() {
  tc qdisc del dev "$1" ingress 2>/dev/null || true
  tc qdisc add dev "$1" ingress
  tc filter add dev "$1" parent ffff: protocol all u32 match u32 0 0 action mirred egress mirror dev "$2"
}
# Mirror $1 to $2 unless a live mirror to $2 is already there. A filter whose
# target was recreated no longer resolves to that name, so it is re-applied too.
ensure() {
  ip link show "$1" >/dev/null 2>&1 && ip link show "$2" >/dev/null 2>&1 || return 0
  tc filter show dev "$1" ingress 2>/dev/null | grep -qF "Mirror to device $2)" || mirror "$1" "$2"
}
if [ "$1" != "--ensure" ]; then
  IFACE="$1"
  grep -qsw -- "$IFACE" /etc/cyberhawks/mirror-*.conf || exit 0
  for delay in 3 10 30; do
    systemd-run --quiet --no-block --collect --on-active="${delay}s" "$0" --ensure "$IFACE" >/dev/null 2>&1
  done
  exit 0
fi
IFACE="$2"
# One check at a time: udev can report an interface more than once (add, then
# move), and two checks interleaving their delete/add steps left a duplicate
# filter (every packet mirrored twice) in testing.
exec 9>/run/cyberhawks-mirror.lock
flock 9
for conf in /etc/cyberhawks/mirror-*.conf; do
  [ -f "$conf" ] || continue
  SENSOR_IFACE=""; SOURCES=""
  . "$conf"
  if [ "$IFACE" = "$SENSOR_IFACE" ]; then
    for src in $SOURCES; do ensure "$src" "$SENSOR_IFACE"; done
  elif [[ " $SOURCES " == *" $IFACE "* ]]; then
    ensure "$IFACE" "$SENSOR_IFACE"
  fi
done
exit 0
EOF
chmod +x "$MIRROR_HELPER"
cat > "$MIRROR_UDEV_RULE" <<EOF
# Auto-generated by mirror-vnet-guests.sh: re-apply sensor mirroring whenever a
# guest or sensor interface is created (see ${MIRROR_HELPER}).
SUBSYSTEM=="net", ACTION=="add|move", RUN+="${MIRROR_HELPER} %k"
EOF
udevadm control --reload
echo "udev re-mirror rule installed (${MIRROR_UDEV_RULE}, ${MIRROR_CONF_DIR}/mirror-${VNET}.conf)."

echo "Done. To verify: tc filter show dev <tap> parent ffff:"
echo "To undo the per-guest side: $0 --undo --vnet ${VNET}"
