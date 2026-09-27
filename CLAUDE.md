# Defense Tooling

Ansible roles + Proxmox scripts for a Zeek + Splunk monitoring stack. This
file is the running source of truth for context, decisions, and known
issues across sessions — mirrors the convention used in
[cyber-range](https://github.com/CyberHawks-IIT/cyber-range)'s own CLAUDE.md.

## Relationship to other repos

- **[cyber-range](https://github.com/CyberHawks-IIT/cyber-range)** — the
  range this stack is typically deployed *against*. Its
  `docs/network-and-infrastructure.md` documents the concrete Proxmox
  network layout (vnets, subnets, the `defense` segment, pfSense's role)
  that this repo's scripts/examples assume. This repo doesn't hardcode
  anything from that layout in its roles (everything's a variable), but the
  worked examples and the mirror script's defaults are written against it.
- **[splunk-detections](https://github.com/CyberHawks-IIT/splunk-detections)**
  — detection content (searches, correlation logic) that runs *on top of*
  the Splunk instance this repo builds. That repo assumes the sourcetypes
  and add-ons this repo installs (see `docs/add-ons.md`) are present.

## Origin

Built by working through the setup live against `cyber-range`'s actual
Proxmox host (VMID 511 for Zeek, VMID 510 for Splunk, both on the `defense`
vnet, 10.0.10.0/24) and generalizing what worked into these roles/scripts.
Every gotcha below was hit for real, not anticipated in the abstract.

## Status

- **Zeek sensor role**: built and verified — Zeek 9.0.0 installed via the
  official OBS repo, TSV logging (not JSON — see "Add-on JSON vs TSV" below),
  dedicated capture interface, promiscuous mode persisted across reboots,
  and (as of the reboot-testing pass) a systemd unit so Zeek itself comes
  back up after a reboot too — see "Zeek doesn't come back up on its own"
  below.
- **Splunk indexer role**: built and verified — Enterprise install, receiving
  port, add-on placement, and the Zeek dynamic-sourcetype `props.conf`/
  `transforms.conf` override are all scripted. Still manual: actually
  *downloading* the installer and add-ons (see `docs/add-ons.md`).
- **Splunk forwarder role (Linux)**: built and verified — installs the UF,
  configures `inputs.conf`/`outputs.conf`, confirmed live end-to-end
  (established TCP connection, real throughput in the indexer's
  `metrics.log`). `inputs.conf` forwards an explicit minimal allowlist of
  files (`splunk_uf_monitor_files`), not a directory wildcard — see "What
  gets forwarded vs. how it's typed" below.
- **Splunk forwarder role (Windows)**: built and verified — `splunk_forwarder_windows`
  installs the UF via `.msi` over WinRM, deploys `outputs.conf`, confirmed
  live end-to-end (real `ESTAB` connections on the indexer's `:9997` from
  all 7 `cyberhawks.lab` AD range VMs). Like the Linux role,
  `splunk_uf_win_monitor_channels` is deliberately left empty for now —
  install + connect only, per monitoring rollout plan step 1 vs. step 3
  below. `Splunk_TA_windows` and `Splunk_TA_microsoft_sysmon` confirmed
  already present on the indexer.
- **Proxmox mirror script**: built and verified — `tc` ingress mirroring
  from a router VM's interfaces to a sensor's capture NIC, persisted via
  hookscripts on **both** the router VM and the sensor CT (a sensor restart
  breaks the mirror just as thoroughly as a router restart — see "A sensor
  restart silently breaks the mirror too" below). Verified by actually
  rebooting the sensor twice and confirming self-healing both times, not
  just by reading the script.
- **Privileged-LXC script**: built and verified — see the gotcha below for
  why this needs its own script rather than just `pct clone`.

## Known gotchas

### Proxmox's per-guest firewall silently drops mirrored traffic

A guest NIC with `firewall=1` gets an intermediate `fwbr<vmid>i<n>` bridge
inserted by Proxmox for stateful conntrack-based filtering. `tc mirred`
injecting a frame onto that NIC's host-side veth looks, to that filtering
layer, like unassociated traffic with no matching connection state — it gets
dropped with **no error anywhere** (not in `dmesg`, not in any Proxmox log).
The symptom is simply: the mirror is configured correctly (`tc filter show`
looks right), real cross-network traffic is definitely flowing (confirmed by
testing from an actual third host), and the sensor's capture log shows
nothing.

The fix: the sensor's capture NIC must have `firewall=0` and should be a
**second, dedicated NIC** — don't share it with the sensor's own management
IP, since that NIC likely has `firewall=1` for good reason (you probably
want the sensor's management traffic filtered normally). The `zeek_sensor`
role and `setup-mirror.sh` both assume this two-NIC layout.

### A sensor restart silently breaks the mirror too, not just a router restart

Found this the hard way running a real clear-logs/shutdown/snapshot/restart
cycle: restarting the *sensor* container breaks the mirror just as thoroughly
as restarting the router, and the original version of `setup-mirror.sh`
didn't handle it. When a container restarts, its veth is destroyed and
recreated with the same **name** but a new kernel **ifindex**. The `tc
mirred` action on the router's tap is bound to the old ifindex — the
qdisc/filter still exist (so a naive "does it already exist" idempotency
check says yes, nothing to do) but now point at a dead interface. `tc
filter show` reveals it: `Egress Mirror to device *` instead of the real
interface name. The sensor sees nothing, with no error anywhere, same as
the firewall gotcha above but from the opposite direction.

Fixed two ways, both now in `setup-mirror.sh`:
1. It always deletes and recreates the tc rule rather than checking first —
   there's no real cost to "over-applying" a rule that was already correct.
2. It installs a hookscript on **both** the router and the sensor, so
   either one restarting independently triggers a rebind. The original
   version only hooked the router.

Verified by actually rebooting the sensor (`pct reboot 511`) twice in a row
and confirming `tc filter show` came back correctly bound with zero manual
intervention both times.

### Splunk's own boot-start defaults to root, which then fails to actually start

`splunk enable boot-start` (no `-user` flag) generates an init script/systemd
shim that launches splunkd as **root** — and splunkd refuses to actually run
as root (prints the "deprecated" message and exits 1) unless `--run-as-root`
is also passed, which we don't want. The result: `systemctl is-enabled`
correctly reports the service as enabled, but every boot ends in `Active:
failed (Result: exit-code)` and splunkd never comes up — confirmed live on
the indexer after a container restart. The fix is `splunk enable boot-start
-user <the account splunkd should run as> --accept-license`; the
`splunk_indexer` role now passes `-user {{ ansible_user }}`.

This only bit the **indexer** — the Universal Forwarder's `.deb` postinst
handles this correctly on its own, installing a real systemd unit
(`SplunkForwarder.service`) running as a dedicated `splunkfwd` user with no
extra configuration needed (confirmed: it survived a full reboot with zero
intervention). Only the indexer's older LSB-style boot-start integration has
this trap.

Related, smaller trap in the same area: any task that runs `splunk start`/
`splunk restart` directly (not through systemd) hits the same root-refusal
if Ansible's `become: true` is in effect for that task — `splunkd` silently
fails to start with no further output, easy to mistake for the command
having simply done nothing. The first-time-start tasks and the indexer's
restart handler in both `splunk_indexer` and `splunk_forwarder` now set
`become: false` for exactly this reason; the forwarder's restart handler
goes through `systemctl restart SplunkForwarder.service` instead, since
calling the CLI directly as the connecting user can't signal a process
owned by `splunkfwd` anyway.

### Zeek doesn't come back up on its own after a reboot

Unlike the Universal Forwarder (its `.deb` installs its own systemd unit),
`zeekctl` ships no systemd integration at all. After a container reboot,
`zeekctl status` reports the node as `crashed` — Zeek was running before,
isn't now, and nothing restarts it. The `zeek_sensor` role now deploys a
small systemd unit (`files/zeek.service`, `Type=oneshot`,
`RemainAfterExit=yes`, `ExecStart=zeekctl start`) and enables it. Verified
by rebooting the sensor and confirming Zeek came back to `running` with no
manual `zeekctl deploy`.

### Cloning a container never changes privileged/unprivileged

`unprivileged` is a container property fixed at creation
(`pct create ... --unprivileged 0|1`) and copied as-is by `pct clone` —
linked or full, it doesn't matter, there's no clone-time override for it.
Proxmox's own "Create CT" wizard defaults to unprivileged, so **any fleet of
containers built by cloning a shared template inherits that template's
choice forever.**

Editing `unprivileged: 1` to `0` directly in `/etc/pve/lxc/<vmid>.conf`
looks tempting but doesn't actually work cleanly — the container's files on
disk were already `chown`'d according to the unprivileged UID/GID shift, so
flipping the flag without also correcting every file's ownership leaves a
broken container.

The only clean fix is building fresh from the base OS template (not from a
clone) with `--unprivileged 0` explicitly. `scripts/proxmox/
create-privileged-lxc.sh` does this — it does **not** try to preserve
anything from an existing shared template, so if that template has
meaningful customization beyond stock Debian, you'll need to reapply it (in
this project's case, that customization is exactly what the Ansible roles
in this repo do).

### Splunk downloads all require a splunk.com login

Splunk Enterprise, the Universal Forwarder, and every add-on on Splunkbase
are gated behind an authenticated splunk.com session — there is no
anonymous or scriptable download path. This is a hard stop for automation:
these roles take a local file path (`splunk_deb_path`, `splunk_addons_dir`,
etc.) as a variable and expect you to have already downloaded the files by
hand. See `docs/add-ons.md`.

### Zeek: TSV, not JSON — depends on which add-on you use

Zeek can log in TSV (its historical default) or JSON
(`redef LogAscii::use_json = T;`). Which one you want depends entirely on
the Splunk add-on you're using:

- **`Splunk_TA_zeek`** (the Corelight-authored add-on, Splunkbase app 5446)
  — its comprehensive field mappings (the `zeek:conn`, `zeek:kerberos`,
  `zeek:dce_rpc`, `zeek:ntlm`, etc. sourcetypes, with CIM-compliant lookups
  and field aliases) are built for **TSV**. It has *some* native JSON
  support (`bro:json`, `bro:conn:json` sourcetype stanzas), but as of the
  version used here (1.0.11) that JSON path doesn't cover the newer
  analyzers this project's detections rely on (no `bro:kerberos:json`,
  `bro:dce_rpc:json`, etc. — only the TSV-oriented `zeek:*` family has
  those).
- We evaluated switching to a different, more JSON-first add-on and decided
  against it — we don't have confident knowledge of a Splunkbase
  alternative that's a clear improvement, and guessing at one risks
  installing something worse. **TSV is the supported path with the add-on
  actually installed.** If you're starting fresh and know of a better
  JSON-native option, this is the place to reconsider it — but verify its
  actual sourcetype coverage before switching, the same way we did here.

The `zeek_sensor` role deliberately does **not** touch `local.zeek`'s
logging format — Zeek's TSV default is exactly what's wanted, so there's
nothing to configure.

### What gets forwarded vs. how it's typed — two separate, deliberate decisions

**What gets forwarded** (`splunk_uf_monitor_files`, `splunk_forwarder` role)
is a deliberately minimal, explicit allowlist — not a directory wildcard.
Only the Zeek logs `splunk-detections`' `detections/backlog.md` actually
depends on (currently `conn`, `dns`, `dce_rpc`, `kerberos`, `ldap` — five of
the 20+ logs Zeek can produce). Forwarding everything Zeek writes would mean
spending indexing license and storage on `http.log`, `ssl.log`, `files.log`,
and so on with no detection consuming any of it. When a new detection needs
a Zeek log not already in that list, add the file to
`splunk_uf_monitor_files` (role default *and*
`group_vars/all.yml.example`) *and* to `splunk-detections`' table — the two
are meant to stay in lockstep, and neither alone tells the whole story.

**How it's typed once it arrives** is a separate concern, and *is* still
generic: the `splunk_indexer` role deploys a `props.conf`/`transforms.conf`
local override on top of `Splunk_TA_zeek` that maps
`source::.../zeek/logs/*/*.log` to a dynamic sourcetype via regex
(`/logs/[^/]+/([a-zA-Z0-9_]+)\.log$` → `zeek:$1`). This means `conn.log`
becomes `zeek:conn`, `kerberos.log` becomes `zeek:kerberos`, and so on
automatically, with no changes needed if the *set* of forwarded logs above
changes — the forwarder's own `inputs.conf` just sets a placeholder
sourcetype (`zeek_placeholder`); the indexer-side transform assigns the
real one regardless of which specific files show up. This only works
because the transform lives on whichever tier does event parsing (the
indexer, in a plain UF→indexer topology) — it would need to move to a heavy
forwarder in a more layered deployment.

### `MSYS_NO_PATHCONV` when scripting this from Windows/Git Bash

If you're driving Ansible or raw `ssh`/`scp` from Git Bash on Windows, any
remote command argument starting with `/` (e.g. `/opt/splunk/bin/splunk`)
can get silently mangled by MSYS's automatic POSIX-to-Windows path
conversion before it ever reaches the remote host. Symptom: a nonsensical
`No such file or directory` error referencing a `C:/...` path you never
wrote. Fix: `MSYS2_ARG_CONV_EXCL="*"` on the specific command (not
`MSYS_NO_PATHCONV=1` globally — that also breaks conversion for things you
*do* want converted, like an `-i` key path given in POSIX form).

### `ansible/group_vars/` at the repo layout level never actually loads

Hit this rolling out the Windows forwarder role: `splunk_addons_dir` and
every other `group_vars/all.yml` value silently fell back to role defaults
(empty string / `[]`) when run via `ansible-playbook`, even though the exact
same variable resolved correctly through a plain `ansible ... -m debug`
ad-hoc command against the same inventory. No error either way — the
add-ons "install" task just quietly skipped its whole block.

Cause: Ansible only auto-discovers `group_vars`/`host_vars` directories
relative to (a) the inventory file's own directory and (b) the playbook
file's own directory — never the repo root, and never the current working
directory for `ansible-playbook` specifically (the ad-hoc `ansible` CLI's
discovery is more permissive about cwd, which is why it looked like it
"worked" there and masked the bug). This repo's layout had `group_vars/`
living directly under `ansible/`, a sibling of both `inventory/` and
`playbooks/` — neither search path ever pointed at it.

Fix: moved `group_vars/` (and added `host_vars/`) to live under
`ansible/inventory/`, i.e. `ansible/inventory/group_vars/`, so it's always
found via the inventory file regardless of which playbook runs or from
where. `ansible/inventory/group_vars/all.yml.example` is the tracked
template now; `.gitignore` was updated to match the new path. Also relevant
to `ansible.cfg` being silently ignored entirely under WSL2's DrvFs
mount (`Ansible is being run in a world writable directory... ignoring it`
— see `cyber-range`'s CLAUDE.md) and to role resolution: roles live at
`ansible/roles/`, not `ansible/playbooks/roles/`, so `ansible-playbook`
invocations from this project need `ANSIBLE_ROLES_PATH` set (or `-e`/an
explicit `ansible.cfg` load) pointing at `ansible/roles` — same root cause,
config discovery not landing where the repo's directories actually are.

### Per-host monitor config must not live in `group_vars/all.yml`

Related mistake made while fixing the above: `splunk_uf_monitor_files`
(Zeek's real allowlist) was set in `group_vars/all.yml`, which applies to
every host in the `splunk_forwarders` group — including the demo box, which
has no Zeek logs at all. First run against `demo` deployed an `inputs.conf`
pointing at nonexistent `/opt/zeek/logs/current/*.log` paths. Fix: moved
Zeek's monitor vars to `host_vars/zeek.yml` (host-specific), leaving
`group_vars/all.yml` to only set what's genuinely shared (indexer host/port,
package paths). Also added a "remove stale `inputs.conf` if the monitor
list is now empty" cleanup task to both forwarder roles, so shrinking a
host's list back to `[]` (or fixing a mistake like this one) is a clean
`ansible-playbook` re-run instead of a manual file removal on the target.

## Monitoring rollout plan (2026-09-27)

Full plan (5 steps, spans this repo + `cyber-range` + `splunk-detections`)
is documented in `cyber-range`'s CLAUDE.md under "Monitoring rollout plan"
— that's the hub. This repo owns steps 1, 3, and 4:

- **Step 1 — install the forwarder + add-ons on every monitored host.**
  **Done (2026-09-27).** The Linux `splunk_forwarder` role applied to the
  demo box (10.1.1.1); the new `splunk_forwarder_windows` role applied to
  all 7 `cyberhawks.lab` AD range VMs (dc1, dc2, ca, web, sql1, sql2,
  workstation). All 9 forwarders (7 Windows + demo + the pre-existing Zeek
  sensor) confirmed with live `ESTAB` connections to the indexer's `:9997`.
  `Splunk_TA_windows` and `Splunk_TA_microsoft_sysmon` confirmed already on
  the indexer; `Splunk_TA_nix`, the Splunk Add-on for Microsoft SQL Server,
  and Splunk DB Connect (the SQL Server add-on's actual dependency for
  DB-query inputs — not listed as a prerequisite in the original plan, added
  once installing the SQL Server add-on surfaced it) are now installed too
  (see `docs/add-ons.md` for exact installed folder names). Every forwarder
  is install + connect only — no monitor files/channels configured
  anywhere yet, that's still step 3.
- **Step 3 — forward a minimal, explicit set of logs.** Same principle
  already applied to Zeek (`splunk_uf_monitor_files` — an explicit
  allowlist, never a wildcard), extended to Windows. Open design question
  to resolve when this starts: Windows Event Forwarder inputs work at the
  **channel** level (`WinEventLog://Security`, `.../Directory Service`,
  `.../System`, plus the Sysmon/WinRM/WMI-Activity operational channels) —
  decide whether channel-level granularity is "minimal enough" or whether
  per-event-ID whitelisting (via the input's own whitelist/blacklist
  regexes) is worth the added complexity, especially for high-volume
  channels like Security.
- **Step 4 — organize ingested data in Splunk.** Decide whether Windows/
  Sysmon/Linux data gets its own index(es) separate from the `main` index
  Zeek already uses (open item below), confirm the installed add-ons'
  sourcetype/field-extraction coverage actually matches what
  `splunk-detections/detections/backlog.md` needs, and add whatever
  macros/tags/eventtypes make step 5's detections easier to write.

## Open items

1. A dedicated Splunk index for Zeek/range data — everything currently
   lands in the default `main` index. Revisit as part of step 4 above.
