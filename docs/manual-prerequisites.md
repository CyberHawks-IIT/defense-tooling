# Manual prerequisites

One-time, hypervisor-level steps this repo doesn't automate — either
because they're a genuine one-off (not worth scripting) or because they
depend on a network layout Ansible has no visibility into.

## 1. A `snippets`-capable storage on Proxmox

The mirror-persistence hookscript (`scripts/proxmox/setup-mirror.sh`) needs
somewhere to store its script file, and Proxmox hookscripts must live on
storage with the `snippets` content type enabled. Most default `local`
storage definitions don't have this enabled out of the box.

Check:

```bash
pvesm status -content snippets
```

If your storage isn't listed, enable it (example for the default `local`
storage — adjust the existing content list to match what you already have,
don't just overwrite it):

```bash
pvesm set local --content iso,vztmpl,backup,snippets
mkdir -p /var/lib/vz/snippets
```

`setup-mirror.sh` assumes this is already done and will fail with a clear
error from `qm set --hookscript` if it isn't.

## 2. A network segment for your monitoring boxes

This repo's roles don't create networking — they assume you already have a
segment (bridge/vnet) for the Zeek and Splunk hosts to live on, and that
your router/firewall has an interface on it too (for internet access,
DNS, and reachability from wherever you administer things from). See
`cyber-range`'s network layout doc for a concrete worked example if you
want one to copy.

## 3. Two Debian 12 hosts, one of them privileged

- **Splunk indexer**: an ordinary (unprivileged is fine) Debian 12
  container or VM. No special capabilities needed.
- **Zeek sensor**: must be a **privileged** LXC container if you're using
  LXC (raw packet capture needs it), with **two NICs** — one for
  management/log-forwarding, one dedicated purely to receiving mirrored
  traffic (`firewall=0`, no IP). See the "Cloning a container never changes
  privileged/unprivileged" and "Proxmox's per-guest firewall silently drops
  mirrored traffic" sections of [CLAUDE.md](../CLAUDE.md) for why both of
  these specifics matter — getting either wrong fails silently, not loudly.
  `scripts/proxmox/create-privileged-lxc.sh` handles the privileged part;
  the second NIC is provisioned by the `zeek_sensor` role's prerequisites
  (see that role's README/defaults for the exact `pct set` command, since
  Ansible can't create a container's NIC on the Proxmox host from inside
  the guest it's targeting).

## 4. SSH key access to both hosts

Standard Ansible prerequisite — both boxes need your control node's public
key in `authorized_keys` for whatever user your inventory specifies, with
passwordless sudo. Not scripted here since every project's bootstrap
process (cloud-init, a shared template, first-boot script, etc.) differs.
