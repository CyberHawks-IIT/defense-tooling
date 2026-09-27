# Defense Tooling

Ansible roles + Proxmox scripts for a Zeek + Splunk monitoring stack —
including the network-mirroring plumbing a Proxmox host needs to actually
see cross-network traffic in the first place.

Standalone by design: works against any Proxmox host, router, and pair of
Debian 12 boxes. If you're using it alongside
[cyber-range](https://github.com/CyberHawks-IIT/cyber-range), see that
repo's [network layout doc](https://github.com/CyberHawks-IIT/cyber-range/blob/main/docs/network-and-infrastructure.md)
for the concrete addresses these examples are based on.

## What's here

| Component | What it does | Status |
|---|---|---|
| `zeek_sensor` role | Installs latest Zeek, configures a dedicated capture NIC | Built + verified |
| `splunk_indexer` role | Installs Splunk Enterprise, add-ons, receiving port, Zeek sourcetype mapping | Built + verified |
| `splunk_forwarder` role (Linux) | Installs the Universal Forwarder, wires it to the indexer | Built + verified |
| `splunk_forwarder` role (Windows) | Same, for DCs | Not built yet |
| `scripts/proxmox/setup-mirror.sh` | Mirrors a router's interfaces to a sensor via `tc` | Built + verified |
| `scripts/proxmox/create-privileged-lxc.sh` | Builds a privileged LXC without the linked-clone trap | Built + verified |

**Not here:** detection content (searches, correlation logic) — that's
[splunk-detections](https://github.com/CyberHawks-IIT/splunk-detections).
This repo only gets data *in*.

## Prerequisites

- Proxmox host with a segment for your monitoring boxes and a router/firewall between the networks you want visibility across (examples use pfSense).
- Two Debian 12 hosts on that segment — one for Zeek (**privileged LXC**, two NICs — see gotcha below), one for Splunk (ordinary).
- Ansible control node with SSH access to both.
- Splunk packages downloaded by hand — see [docs/add-ons.md](docs/add-ons.md) (Splunkbase requires a login; nothing here can automate that).

## Getting started

1. Read [docs/add-ons.md](docs/add-ons.md) and download what you need.
2. Read [docs/manual-prerequisites.md](docs/manual-prerequisites.md) — one-time Proxmox host settings this repo assumes are done.
3. Copy `ansible/inventory/hosts.yml.example` → `hosts.yml` and `ansible/group_vars/all.yml.example` → `all.yml`, fill in your values.
4. `ansible-playbook -i ansible/inventory/hosts.yml ansible/playbooks/site.yml` (or run the three playbooks individually).
5. On the Proxmox host itself: `scripts/proxmox/setup-mirror.sh --help` to wire up traffic mirroring into your sensor.

## Known gotchas

Full detail in [CLAUDE.md](CLAUDE.md) — summary:

| Gotcha | Symptom | Fix |
|---|---|---|
| Proxmox's per-guest firewall silently eats mirrored traffic | Mirror looks configured correctly, sensor sees nothing, no error anywhere | Sensor's capture NIC needs `firewall=0` and its own dedicated interface |
| Cloning never changes privileged/unprivileged | Can't flip an existing container to privileged | Build fresh from the base template (`create-privileged-lxc.sh`), don't clone |
| Splunk downloads require a splunk.com login | No scriptable download path | Download by hand — [docs/add-ons.md](docs/add-ons.md) |
| Zeek TSV vs. JSON | The installed add-on's full field coverage only exists for TSV | Roles leave Zeek on its TSV default — don't switch to JSON |

## Repository layout

```
defense-tooling/
  README.md
  CLAUDE.md
  ansible/
    inventory/hosts.yml.example
    group_vars/all.yml.example
    roles/{zeek_sensor, splunk_indexer, splunk_forwarder}/
    playbooks/{zeek-sensor, splunk-indexer, splunk-forwarder, site}.yml
  scripts/proxmox/
    setup-mirror.sh
    create-privileged-lxc.sh
  docs/
    add-ons.md
    manual-prerequisites.md
```
