# Defense Tooling

Ansible roles and Proxmox scripts for a Zeek and Splunk monitoring stack. This
includes the network-mirroring plumbing a Proxmox host needs to actually see
cross-network traffic in the first place.

It's standalone by design and works against any Proxmox host, router, and pair
of Debian 12 boxes. If you're using it alongside
[cyber-range](https://github.com/CyberHawks-IIT/cyber-range), see that repo's
[network layout doc](https://github.com/CyberHawks-IIT/cyber-range/blob/master/docs/network-and-infrastructure.md)
for the concrete addresses these examples are based on.

## What's here

| Component | What it does | Status |
|---|---|---|
| `zeek_sensor` role | Installs latest Zeek, configures a dedicated capture NIC | Built + verified |
| `splunk_indexer` role | Installs Splunk Enterprise, add-ons, receiving port, Zeek sourcetype mapping | Built + verified |
| `splunk_forwarder` role (Linux) | Installs the Universal Forwarder, forwards an explicit minimal allowlist of files (not a directory wildcard) | Built + verified |
| `splunk_forwarder_windows` role | Same, for Windows hosts (WinRM, `.msi`). Monitor channels are left empty until step 3 decides what's forwarded | Built + verified |
| `scripts/proxmox/setup-mirror.sh` | Mirrors a router's interfaces to a sensor via `tc` | Built + verified |
| `scripts/proxmox/create-privileged-lxc.sh` | Builds a privileged LXC without the linked-clone trap | Built + verified |
| `discord_alert` alert action | Optional. Posts every fired Splunk detection to a Discord webhook as an embed. See [docs/discord-alerting.md](docs/discord-alerting.md) | Built + verified |
| `scripts/proxmox/attacker-directory.py` | Keeps the IP to attacker-name table behind the Discord embeds in sync with Proxmox, plus manually assigned IPs | Built + verified |

**Not here:** detection content (searches, correlation logic). That lives in
[splunk-detections](https://github.com/CyberHawks-IIT/splunk-detections). This
repo only gets data in.

## Prerequisites

- A Proxmox host with a segment for your monitoring boxes and a router or
  firewall between the networks you want visibility across. The examples use
  pfSense.
- Two Debian 12 hosts on that segment. One for Zeek (a **privileged LXC** with
  two NICs, see the gotcha below), one for Splunk (ordinary).
- An Ansible control node with SSH access to both.
- Splunk packages downloaded by hand. See [docs/add-ons.md](docs/add-ons.md).
  Splunkbase requires a login, and nothing here can automate that.

## Getting started

> **Building the full CyberHawks range and monitoring?** Follow the end-to-end,
> step-by-step guide in cyber-range,
> **[range-with-monitoring.md](https://github.com/CyberHawks-IIT/cyber-range/blob/master/docs/setup/range-with-monitoring.md)**.
> It sequences this repo together with the range and the detection content. The
> steps below are the standalone, this-repo-only path.

1. Read [docs/add-ons.md](docs/add-ons.md) and download what you need.
2. Read [docs/manual-prerequisites.md](docs/manual-prerequisites.md), the
   one-time Proxmox host settings this repo assumes are done.
3. Copy `ansible/inventory/hosts.yml.example` to `hosts.yml` and
   `ansible/inventory/group_vars/all.yml.example` to `all.yml`, and fill in your
   values. Windows hosts also need
   `ansible-galaxy collection install -r ansible/requirements.yml` on the control
   node.
4. Run `ansible-playbook -i ansible/inventory/hosts.yml ansible/playbooks/site.yml`
   (or run the playbooks individually).
5. On the Proxmox host itself, run `scripts/proxmox/setup-mirror.sh --help` to
   wire up traffic mirroring into your sensor.

## Known gotchas

Full detail is in [CLAUDE.md](CLAUDE.md). Summary:

| Gotcha | Symptom | Fix |
|---|---|---|
| Proxmox's per-guest firewall silently eats mirrored traffic | Mirror looks configured correctly, sensor sees nothing, no error anywhere | Sensor's capture NIC needs `firewall=0` and its own dedicated interface |
| Cloning never changes privileged/unprivileged | Can't flip an existing container to privileged | Build fresh from the base template (`create-privileged-lxc.sh`), don't clone |
| Splunk downloads require a splunk.com login | No scriptable download path | Download by hand, see [docs/add-ons.md](docs/add-ons.md) |
| Zeek TSV vs. JSON | The installed add-on's full field coverage only exists for TSV | Roles leave Zeek on its TSV default. Don't switch to JSON |
| Sensor restart breaks the mirror too (not just a router restart) | Mirror looks configured (`tc filter show`), but shows `Egress Mirror to device *`, a dead interface reference | `setup-mirror.sh` hookscripts both the router and the sensor now, and always rebuilds rather than checking first |
| Zeek has no systemd unit of its own | After a reboot, `zeekctl status` reports `crashed` and nothing restarts it | `zeek_sensor` role deploys `zeek.service` and enables it |
| `group_vars` under `ansible/` never actually loads | Vars silently fall back to role defaults with no error, just wrong values (for example add-ons "installed" against an empty `splunk_addons_dir`) | Ansible only auto-discovers `group_vars` and `host_vars` next to the inventory file (or the playbook), not the repo root. It now lives at `ansible/inventory/group_vars/` |

## Repository layout

```
defense-tooling/
  README.md
  CLAUDE.md
  ansible/
    requirements.yml               # ansible.windows collection
    inventory/
      hosts.yml.example
      group_vars/all.yml.example   # lives here, not ansible/group_vars, because
                                    # Ansible only auto-discovers group_vars
                                    # relative to the inventory file itself
    roles/{zeek_sensor, splunk_indexer, splunk_forwarder, splunk_forwarder_windows}/
    playbooks/{zeek-sensor, splunk-indexer, splunk-forwarder, splunk-forwarder-windows, site}.yml
  scripts/proxmox/
    setup-mirror.sh
    create-privileged-lxc.sh
    attacker-directory.py
  docs/
    add-ons.md
    manual-prerequisites.md
    discord-alerting.md
```
