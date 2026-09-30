#!/usr/bin/env python3
"""attacker-directory.py -- the IP -> attacker-name table behind Discord alerts.

Run this ON THE PROXMOX HOST (same reasoning as the other scripts here: it
reads Proxmox's own permission and VM config data, and pushes into the Splunk
container with `pct push`).

WHY THIS EXISTS:
  defense-tooling's `discord_alert` Splunk alert action titles each Discord
  embed with the alert name and describes it as "Full Name (IP)" -- the
  attacker behind the source IP. It resolves that name from
  lookups/attackers.csv inside the discord_alert app on the indexer. This
  script builds that file from two sources:

  1. Proxmox itself (automatic). Each attacker is a Proxmox user who holds a
     VM role (default: PVEVMAdmin) directly on their attacker VMs' ACL paths
     (/vms/<vmid>). Every static IP in those VMs' cloud-init config
     (ipconfigN, or netN for containers) maps to that user's first + last
     name. So granting a new attacker their VMs in Proxmox is all it takes.
  2. A manual file (MANUAL_CSV, default /etc/cyberhawks/attacker-ips.csv) for
     IPs Proxmox can't know about, e.g. an attacker's own machine joining over
     NetBird. Columns: user,ip,note -- `user` is the Proxmox user ID (`john`
     or `john@pve`), so the name still comes from Proxmox. Manual entries win
     over Proxmox-derived ones for the same IP. Edit it with `add`/`remove`
     below (or by hand, then run `sync`).

  The alert action re-reads the file on every alert, so a sync takes effect on
  the next fired alert with no Splunk restart. An IP in neither source shows
  in Discord as "Unknown (IP)".

USAGE (after `install`, the script is on PATH as `cyberhawks-attackers`):
  cyberhawks-attackers install                 # install + enable a 5-minute sync timer, then sync
  cyberhawks-attackers sync                    # rebuild and push if changed (what the timer runs)
  cyberhawks-attackers list                    # show the resolved IP -> name table
  cyberhawks-attackers add john 100.64.0.7 "NetBird laptop"
  cyberhawks-attackers remove 100.64.0.7

  Options (any command): --ct 510 (Splunk indexer CT), --role PVEVMAdmin
  (repeatable), --manual PATH. `install` bakes non-default options into the
  timer's command line.
"""
import argparse
import csv
import glob
import io
import ipaddress
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile

DEFAULT_CT = "510"
DEFAULT_ROLES = ["PVEVMAdmin"]
MANUAL_CSV = "/etc/cyberhawks/attacker-ips.csv"
DEST_PATH = "/opt/splunk/etc/apps/discord_alert/lookups/attackers.csv"
INSTALL_PATH = "/usr/local/sbin/cyberhawks-attackers"
UNIT_NAME = "cyberhawks-attackers"
OUTPUT_COLUMNS = ["ip", "name", "user", "source"]
MANUAL_COLUMNS = ["user", "ip", "note"]


def warn(msg):
    sys.stderr.write("attacker-directory: %s\n" % msg)


def pvesh(path):
    out = subprocess.run(["pvesh", "get", path, "--output-format", "json"],
                         check=True, capture_output=True, text=True).stdout
    return json.loads(out)


def display_name(user):
    name = " ".join(p for p in (user.get("firstname"), user.get("lastname")) if p and p.strip())
    return name.strip() or user["userid"].split("@", 1)[0]


def guest_ips(vmid):
    """Static IPs from a guest's cloud-init (QEMU ipconfigN) or network (LXC
    netN) config. Reads pmxcfs directly: one pvesh call per VM is far slower."""
    paths = (glob.glob("/etc/pve/nodes/*/qemu-server/%s.conf" % vmid)
             + glob.glob("/etc/pve/nodes/*/lxc/%s.conf" % vmid))
    ips = []
    for path in paths:
        with open(path, encoding="utf-8") as fh:
            for line in fh:
                if line.startswith("["):
                    break  # snapshot sections follow the live config
                key, _, value = line.partition(":")
                if not re.fullmatch(r"(ipconfig|net)\d+", key.strip()):
                    continue
                m = re.search(r"(?:^|,)\s*ip=([^,/\s]+)", value)
                if not m:
                    continue  # dhcp-less / ip6-only NIC
                try:
                    ips.append(str(ipaddress.ip_address(m.group(1))))
                except ValueError:
                    pass  # "dhcp" / "manual"
    return ips


def resolve_user(ref, users):
    """`john` or `john@pve` -> the full Proxmox userid, or None."""
    if ref in users:
        return ref
    matches = [u for u in users if u.split("@", 1)[0] == ref]
    return matches[0] if len(matches) == 1 else None


def read_manual(path):
    if not os.path.exists(path):
        return []
    with open(path, encoding="utf-8", newline="") as fh:
        lines = [l for l in fh if l.strip() and not l.lstrip().startswith("#")]
    return list(csv.DictReader(lines))


def write_manual(path, rows):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8", newline="") as fh:
        fh.write("# Manually assigned attacker IPs (e.g. NetBird). user = Proxmox user ID.\n"
                 "# Managed with `cyberhawks-attackers add|remove`; hand edits are fine too.\n")
        w = csv.DictWriter(fh, fieldnames=MANUAL_COLUMNS, extrasaction="ignore")
        w.writeheader()
        w.writerows(rows)


def build_table(roles, manual_path):
    users = {u["userid"]: u for u in pvesh("/access/users")}
    by_ip = {}  # ip -> list of (userid, source)

    for ace in pvesh("/access/acl"):
        m = re.fullmatch(r"/vms/(\d+)", ace.get("path", ""))
        if not m or ace.get("type") != "user" or ace.get("roleid") not in roles:
            continue
        userid, vmid = ace["ugid"], m.group(1)
        if userid not in users:
            continue
        for ip in guest_ips(vmid):
            by_ip.setdefault(ip, []).append((userid, "vm %s" % vmid))

    manual = {}
    for row in read_manual(manual_path):
        ref, ip = (row.get("user") or "").strip(), (row.get("ip") or "").strip()
        userid = resolve_user(ref, users)
        try:
            ip = str(ipaddress.ip_address(ip))
        except ValueError:
            warn("%s: skipping invalid IP %r" % (manual_path, ip))
            continue
        if not userid:
            warn("%s: skipping %s -- no single Proxmox user matches %r" % (manual_path, ip, ref))
            continue
        note = (row.get("note") or "").strip()
        manual[ip] = (userid, "manual" + (": %s" % note if note else ""))

    table = []
    for ip in sorted(set(by_ip) | set(manual), key=ipaddress.ip_address):
        if ip in manual:
            owners = [manual[ip]]
        else:
            owners = sorted(set(by_ip[ip]))
            if len({u for u, _ in owners}) > 1:
                warn("%s is configured on VMs of several attackers: %s"
                     % (ip, ", ".join("%s (%s)" % o for o in owners)))
        userids = sorted({u for u, _ in owners})
        table.append({
            "ip": ip,
            "name": " / ".join(display_name(users[u]) for u in userids),
            "user": " ".join(userids),
            "source": "; ".join(s for _, s in owners),
        })
    return table


def render(table):
    buf = io.StringIO()
    w = csv.DictWriter(buf, fieldnames=OUTPUT_COLUMNS, lineterminator="\n")
    w.writeheader()
    w.writerows(table)
    return buf.getvalue()


def ct_running(ct):
    r = subprocess.run(["pct", "status", ct], capture_output=True, text=True)
    return r.returncode == 0 and "running" in r.stdout


def push(ct, content):
    current = subprocess.run(["pct", "exec", ct, "--", "cat", DEST_PATH],
                             capture_output=True, text=True)
    if current.returncode == 0 and current.stdout == content:
        return False
    subprocess.run(["pct", "exec", ct, "--", "mkdir", "-p", os.path.dirname(DEST_PATH)], check=True)
    with tempfile.NamedTemporaryFile("w", encoding="utf-8", delete=False) as tmp:
        tmp.write(content)
    try:
        subprocess.run(["pct", "push", ct, tmp.name, DEST_PATH, "--perms", "0644"], check=True)
    finally:
        os.unlink(tmp.name)
    return True


def cmd_sync(args):
    table = build_table(args.role, args.manual)
    if not ct_running(args.ct):
        warn("CT %s is not running -- not pushed (the timer retries)" % args.ct)
        return 0
    changed = push(args.ct, render(table))
    print("%d attacker IP(s); %s CT %s:%s" % (len(table), "pushed to" if changed else "unchanged on",
                                              args.ct, DEST_PATH))
    return 0


def cmd_list(args):
    table = build_table(args.role, args.manual)
    width = max([len(r["ip"]) for r in table] + [2])
    for r in table:
        print("%-*s  %-28s %s" % (width, r["ip"], r["name"], r["source"]))
    return 0


def cmd_add(args):
    users = {u["userid"] for u in pvesh("/access/users")}
    userid = resolve_user(args.user, users)
    if not userid:
        sys.exit("no single Proxmox user matches %r" % args.user)
    try:
        ip = str(ipaddress.ip_address(args.ip))
    except ValueError:
        sys.exit("not an IP address: %r" % args.ip)
    rows = [r for r in read_manual(args.manual) if (r.get("ip") or "").strip() != ip]
    rows.append({"user": userid, "ip": ip, "note": args.note or ""})
    write_manual(args.manual, rows)
    print("assigned %s to %s" % (ip, userid))
    return cmd_sync(args)


def cmd_remove(args):
    rows = read_manual(args.manual)
    kept = [r for r in rows if (r.get("ip") or "").strip() != args.ip]
    if len(kept) == len(rows):
        sys.exit("%s is not in %s (Proxmox-derived IPs change in Proxmox, not here)"
                 % (args.ip, args.manual))
    write_manual(args.manual, kept)
    print("removed %s" % args.ip)
    return cmd_sync(args)


def cmd_install(args):
    shutil.copy(os.path.abspath(__file__), INSTALL_PATH)
    os.chmod(INSTALL_PATH, 0o755)
    if not os.path.exists(args.manual):
        write_manual(args.manual, [])
    opts = ""
    if args.ct != DEFAULT_CT:
        opts += " --ct %s" % args.ct
    if args.manual != MANUAL_CSV:
        opts += " --manual %s" % args.manual
    if args.role != DEFAULT_ROLES:
        opts += "".join(" --role %s" % r for r in args.role)
    with open("/etc/systemd/system/%s.service" % UNIT_NAME, "w") as fh:
        fh.write("[Unit]\nDescription=Sync the Discord alert attacker directory (IP -> name) into Splunk\n\n"
                 "[Service]\nType=oneshot\nExecStart=%s%s sync\n" % (INSTALL_PATH, opts))
    with open("/etc/systemd/system/%s.timer" % UNIT_NAME, "w") as fh:
        fh.write("[Unit]\nDescription=Sync the Discord alert attacker directory every 5 minutes\n\n"
                 "[Timer]\nOnBootSec=2min\nOnUnitActiveSec=5min\n\n[Install]\nWantedBy=timers.target\n")
    subprocess.run(["systemctl", "daemon-reload"], check=True)
    subprocess.run(["systemctl", "enable", "--now", "%s.timer" % UNIT_NAME], check=True)
    print("installed %s, manual IPs in %s, timer %s.timer enabled" % (INSTALL_PATH, args.manual, UNIT_NAME))
    return cmd_sync(args)


def main():
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--ct", default=DEFAULT_CT, help="Splunk indexer container ID (default %(default)s)")
    common.add_argument("--role", action="append", help="VM role marking an attacker's VMs (default PVEVMAdmin)")
    common.add_argument("--manual", default=MANUAL_CSV, help="manual IP file (default %(default)s)")

    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="command")
    sub.add_parser("sync", parents=[common]).set_defaults(func=cmd_sync)
    sub.add_parser("list", parents=[common]).set_defaults(func=cmd_list)
    sub.add_parser("install", parents=[common]).set_defaults(func=cmd_install)
    p = sub.add_parser("add", parents=[common])
    p.add_argument("user")
    p.add_argument("ip")
    p.add_argument("note", nargs="?")
    p.set_defaults(func=cmd_add)
    p = sub.add_parser("remove", parents=[common])
    p.add_argument("ip")
    p.set_defaults(func=cmd_remove)

    args = parser.parse_args()
    if not args.command:
        parser.print_help()
        return 1
    args.role = args.role or DEFAULT_ROLES
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
