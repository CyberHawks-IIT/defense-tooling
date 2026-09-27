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
  **Monitoring rollout plan step 4 (2026-09-27): done.** Deploys a new
  `dt_detection_content` app — the `zeek`/`windows`/`linux`/`mssql`/`iis`
  indexes, macros, eventtypes, and a `known_range_hosts` lookup supporting
  `splunk-detections/detections/backlog.md` — see "Organizing ingested data
  for step 5" below for the full design and what was confirmed vs. added.
  **Also now deploys Splunk DB Connect** (Java + JDBC driver + identity/
  connection/input config) for the SQL Server telemetry follow-up — see
  "IIS, SQL Server, and CA ingestion" below. **Confirmed fully live
  (2026-09-27):** all 4 inputs (`sql1`/`sql2` × `_mssql_xe_text`/`_mssql_audit`)
  scheduled, running, and indexing real rows into `index=mssql` with
  `errorCount=0`.
- **Splunk forwarder role (Linux)**: built and verified — installs the UF,
  configures `inputs.conf`/`outputs.conf`, confirmed live end-to-end
  (established TCP connection, real throughput in the indexer's
  `metrics.log`). `inputs.conf` forwards an explicit minimal allowlist of
  files (`splunk_uf_monitor_files`), not a directory wildcard — see "What
  gets forwarded vs. how it's typed" below. **The demo box's auditd log is
  now wired up too (2026-09-27)** — left at install+connect-only since step
  1, per backlog.md's own "ingestion not wired up yet" note; see "Organizing
  ingested data for step 5" below.
- **Splunk forwarder role (Windows)**: built and verified — `splunk_forwarder_windows`
  installs the UF via `.msi` over WinRM, deploys `outputs.conf`, confirmed
  live end-to-end (real `ESTAB` connections on the indexer's `:9997` from
  all 7 `cyberhawks.lab` AD range VMs). `Splunk_TA_windows` and
  `Splunk_TA_microsoft_sysmon` confirmed already present on the indexer.
  **Monitoring rollout plan step 3 (2026-09-27): done.** All 7 hosts now
  forward an explicit set of WinEventLog channels — see "Windows Event Log
  channel-level vs. per-event-ID filtering" below for the granularity
  decision and the exact channel/whitelist list. Confirmed live: the
  indexer's `metrics.log` shows real, ongoing throughput for the
  `forwarded_logs` sourcetype (tens of events/sec across the 7 hosts), and
  every host's `splunkd.log` is free of `WinEventLogChannel` subscribe
  errors after the Event Log Readers fix below. **Step 4 fixed the
  sourcetype itself (2026-09-27)** — `forwarded_logs` is gone; see
  "Organizing ingested data for step 5" below for why and what replaced it.
  **Also gained plain file monitoring (2026-09-27)** — `splunk_uf_win_monitor_files`,
  `monitor://` stanzas alongside the existing `WinEventLog://` ones, used
  for IIS logs on web/ca; see "IIS, SQL Server, and CA ingestion" below.
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

### Windows Event Log channel-level vs. per-event-ID filtering (monitoring rollout plan step 3, 2026-09-27)

The open design question from step 3 (see the plan below) is resolved:
**neither pure channel-level monitoring nor uniform per-event-ID filtering
— the granularity is decided per channel**, based on how far a whole-channel
firehose actually diverges from what `splunk-detections/detections/backlog.md`
needs from it.

- **Get an explicit `whitelist` of just the Event IDs backlog.md needs:**
  `Security` (by far the highest-volume channel here — every logon, ticket
  request, and object-access check on every domain-joined host), `System`,
  `Directory Service` (only relevant on dc1/dc2 — 1644 diagnostics logs
  *every* LDAP query verbatim once both Field Engineering thresholds are set
  to 0, so this is high-volume specifically because step 2 configured it to
  be), and `Microsoft-Windows-Windows Defender/Operational` (routine AV
  scan/signature-update noise alongside the tamper-protection events
  (5001-5013) actually wanted).
- **Left unfiltered (whole channel):** `Microsoft-Windows-Sysmon/Operational`
  (already scoped at the source — `cyber-range`'s Sysmon config only emits
  the event types asked for, so a second filter here would be redundant),
  `Microsoft-Windows-WMI-Activity/Operational`, and
  `Microsoft-Windows-WinRM/Operational` (both narrow-purpose channels with
  no meaningful volume in this lab).

Implementation shape: `splunk_uf_win_monitor_channels` (`splunk_forwarder_windows`
role) is now a list of `{channel, whitelist}` dicts — `whitelist` is optional,
a comma-separated Event ID/range list (e.g. `"5001-5013"`) passed straight
through to `inputs.conf`'s own `whitelist =` key. Real values: the common
baseline (all 7 hosts) lives in
`ansible/inventory/group_vars/splunk_forwarders_windows/monitor.yml`; the
DC-only `Directory Service` addition lives in `host_vars/dc1.yml` and
`host_vars/dc2.yml`, combined via
`splunk_uf_win_monitor_channels_common + splunk_uf_win_monitor_channels_extra`
— same "common group vars + host_vars addition" shape as the Zeek/demo split
under "Per-host monitor config must not live in `group_vars/all.yml`" below.
`host_vars/` is entirely gitignored (real hostnames/IPs), so
`host_vars/dc1.yml.example` and `host_vars/dc2.yml.example` are the tracked
templates — `.gitignore` gained a `!ansible/inventory/host_vars/*.yml.example`
exception for this, mirroring the existing `group_vars/*.yml.example` one.

IIS-based detections (web portal weak-password, ADCS ESC8 web enrollment)
and the SQL Server Audit/Extended Events source are deliberately **not**
forwarded — `cyber-range`'s `detection_logging` role never turned IIS
logging or SQL Server auditing on in the first place (see that repo's
CLAUDE.md, monitoring rollout plan step 2), so there's nothing there yet to
forward. Revisit once step 2 covers those sources.

### Splunk UF on Windows needs `Event Log Readers` membership for non-Security channels — and the fix must skip domain controllers

Turning on the channels above surfaced two more things, both now fixed in
`splunk_forwarder_windows`:

1. **The role's "copy installer, then check if already installed" order was
   backwards.** `Copy the Universal Forwarder package to this host` ran
   unconditionally, before the `Check whether the forwarder is already
   installed` stat task — harmless as long as `splunk_uf_win_msi_path` still
   pointed at a real file, but this deployment's path was an old session's
   scratchpad temp directory, since cleaned up. Re-running the playbook to
   apply the new `inputs.conf` (all 7 hosts already had the UF installed)
   failed immediately on the copy step with a missing-source-file error.
   Fixed by moving the stat check first and gating both the msi/admin-password
   assertion and the copy itself on `not uf_win_binary.stat.exists`, matching
   how the install step itself was already gated — a first-time install still
   needs the real installer path; a config-only re-run no longer does.
2. **Confirmed live:** after adding `Microsoft-Windows-Sysmon/Operational` to
   the monitored channels, `splunkd.log` logged
   `WinEventLogChannel::init: ... errorCode=5` (access denied) on 5 of the 7
   hosts (ca, web, sql1, sql2, workstation) — every host where the UF service
   runs as the virtual `NT SERVICE\SplunkForwarder` account rather than
   `LocalSystem` (dc1 and dc2, confirmed via `sc.exe qc SplunkForwarder`, are
   the two that got `LocalSystem` and were unaffected). The Splunk MSI
   installer grants its service account enough rights to read `Security`/
   `System` out of the box, but a custom channel like Sysmon's ships with its
   own restrictive default ACL (Administrators/SYSTEM/`Event Log Readers`
   only) that the virtual service account isn't part of.
   Fix: `ansible.windows.win_group_membership` adds
   `NT SERVICE\SplunkForwarder` to the local `Event Log Readers` group
   (Sysmon's channel ACL already grants that group read access, so this is
   the minimal fix — no channel ACL edit needed) — but **only** when the
   service isn't already `LocalSystem`, detected via `sc.exe qc
   SplunkForwarder`. This matters beyond redundancy: `Event Log Readers` is a
   local WinNT group, and a domain controller has no local SAM group of that
   name for `win_group_membership`'s WinNT provider to find — confirmed live,
   it throws `The parameter is incorrect` on dc1/dc2 if attempted
   unconditionally. Verified clean afterward: no `WinEventLogChannel` errors
   in any of the 7 hosts' `splunkd.log`, and the indexer's `metrics.log`
   shows sustained `forwarded_logs` throughput.

### Organizing ingested data for step 5 (monitoring rollout plan step 4, 2026-09-27)

**Index design: separate `zeek`/`windows`/`linux` indexes, not a renamed
`main`.** Everything from steps 1-3 was landing in Splunk's default `main`
index. Went with three named indexes instead of one renamed index — cheap
to do (a lab-scale deployment, no capacity/retention pressure driving the
decision either way), and it makes per-source-type searches
(`index=windows ...`) and any future retention/access-control split trivial
without touching a single detection. `main` itself is untouched — still
exists, just nothing points at it anymore. New Ansible variables:
`splunk_uf_index` (`splunk_forwarder` role, real value set in each Linux
host's `host_vars/` — `zeek` for the sensor, `linux` for the demo box) and
`splunk_uf_win_index` (`splunk_forwarder_windows` role, real value `windows`
in `group_vars/splunk_forwarders_windows/monitor.yml`). Deployed via a new
`dt_detection_content` Splunk app (`splunk_indexer` role,
`splunk_deploy_detection_content: true` by default) — see
`ansible/roles/splunk_indexer/files/dt_detection_content_indexes.conf`.
Already-indexed events sitting in `main` from before this change were left
alone by the reindex itself — see "Clearing logs" in this project's history
for the actual cutover (the same session that made this change also cleared
old data as part of a broader log-clearing pass, giving all three new
indexes a clean start rather than a mix of old-`main` and new-named-index
data).

**Splunk_TA_windows collapses `sourcetype` to a bare
`WinEventLog`/`XmlWinEventLog` — real per-channel typing lives in `source`,
not `sourcetype`.** This is the actual fix for the `forwarded_logs`
placeholder sourcetype step 3 left in place (mentioned above under Status).
Confirmed live via `splunk search ... | table sourcetype source`: every
Windows event's `sourcetype` field is just `WinEventLog` or
`XmlWinEventLog` (no channel suffix at all), regardless of what `inputs.conf`
sets — the TA's own `ta-windows-fix-sourcetype` transform
(`Splunk_TA_windows/default/transforms.conf`) truncates whatever sourcetype
arrives at the first `:`. The *channel-specific* value (e.g.
`WinEventLog:Security`) survives in `source` instead, rewritten there by a
companion transform (`ta-windows-fix-classic-source` /
`ta-windows-fix-xml-source`) that reads it back out of the raw event text
(`LogName=` for classic, `<Channel>` for XML) — and that's what the TA's own
per-channel `props.conf`/`eventtypes.conf` stanzas
(`[source::WinEventLog:Security]`, `wineventlog-ds`, etc.) actually key on.
Net effect: **every knowledge object in `dt_detection_content` that needs to
target a specific Windows Event Log channel filters on `source=`, never
`sourcetype=`** — a `sourcetype=`-based filter would silently match nothing,
which is exactly what the first draft of `dt_detection_content_macros.conf`
did before this was caught (fixed before it ever reached splunk-detections).
The Windows Event Log input side didn't need this understanding — Splunk's
own default channel-based sourcetype naming (`WinEventLog:<channel>`, no
explicit override) already produces exactly the `source` value these
add-ons expect; see the inputs.conf.j2 change below.

**Sysmon needed `renderXml: true` + an explicit `sourcetype` override —
the one exception to "let Splunk's native default typing handle it".**
Confirmed via `Splunk_TA_microsoft_sysmon/default/props.conf`: every one of
its field extractions (`Image`, `CommandLine`, `GrantedAccess`, `PipeName`,
etc.) is defined against `XmlWinEventLog:Microsoft-Windows-Sysmon/Operational`
only — there's no classic-mode stanza at all. Splunk's native default for an
unrendered channel is classic mode, which would give an unparsed `Message`
blob instead of real fields. `splunk_uf_win_monitor_channels` entries
gained two new optional keys for this: `renderXml` (bool) and `sourcetype`
(string, only meaningful paired with `renderXml: true`) — every other
channel omits both and gets Splunk's native `WinEventLog:<channel>`
default, which already lines up with what Splunk_TA_windows expects (see
above). Verified live: `TargetImage`/`GrantedAccess`/`SourceImage` extract
correctly from real Sysmon Event 10 data post-fix.

**Confirmed-vs-added coverage pass against backlog.md** (the "confirm the
installed add-ons' sourcetype/field-extraction coverage actually matches
what backlog.md needs" half of this step) — full detail and the resulting
knowledge objects live in `ansible/roles/splunk_indexer/files/
dt_detection_content_eventtypes.conf`'s own comments, summarized here:

- **Already covered by the installed add-ons, reused directly, nothing
  added:** most authentication events (`windows_logon_success`,
  `windows_logon_failure`, `windows_auth_ticket_granted`,
  `windows_service_ticket_granted`, `windows_pre_auth_failed`), account
  creation (`windows_account_created`), service/scheduled-task lifecycle
  (`windows_endpoint_services` — 4697/7040/7045 together), registry SACLs
  (`windows_security_endpoint_registry` — 4657), audit-log-cleared
  (`windows_audit_log_cleared` — 1102), Defender tamper events
  (`wineventlog_defender_operational_attack`/`_operations`), and WMI event
  subscription persistence (`ms-sysmon-wmimod` — Sysmon 19/20/21).
- **Confirmed gaps, filled with new `dt_*` eventtypes:** DCSync (4662 alone
  is too broad — needs the DS-Replication-Get-Changes* GUID filter, which
  no add-on provides), the full privileged-group-membership set
  (Splunk_TA_windows' own eventtype has 4732 but not 4728/4756 — half the
  real targets here), every directory-service-object-modified/created
  scenario (5136/5137 — RBCD, Shadow Credentials, ACL abuse, ScriptPath
  tampering, rogue DNS records; no add-on eventtype touches 5136/5137 at
  all), object-access-completed (4663 — SAM/LSA hive dumping, NTDS.dit
  extraction, DPAPI theft; the add-on only covers 4656, the *request*
  event, not 4663, the *completion* event these detections key on),
  detailed file share (5145), NTLMv1 logon (4624 plus the exact
  `Package Name (NTLM only)` field/value), Sysmon LSASS access (Event 10
  bundled with 10 unrelated codes in the add-on's own eventtype — needed
  its own GrantedAccess-mask-and-allowlist-aware version), Sysmon named-pipe
  coercion triggers (17/18, filtered to the five specific pipes backlog.md
  names), scheduled task creation on its own (4698, too tightly bundled
  with unrelated GPO/cert-services codes in the add-on's version to use
  directly), and 1644 LDAP query content.
- **Still not ingested at all (not a step 4 problem — a step 2 one):** IIS
  logs (web portal, ADCS ESC8) and SQL Server Audit/Extended Events — see
  Open items below. Also newly confirmed while doing this pass: the CA's
  own certification-authority operational log (needed for the ADCS
  RPC/ICPR detections) isn't being forwarded either, and `cyber-range`'s
  `detection_logging` role doesn't appear to enable any CA-specific
  auditing beyond what already applies to every domain member — same
  "log source doesn't exist yet" class of gap as IIS/SQL, just not
  previously written down anywhere.
- **One eventtype flagged unconfirmed, matching backlog.md's own honesty
  convention for unverified items:** `dt_vss_shadow_copy_created` (the VSS/
  shadow-copy-creation signal for the SAM/LSA/NTDS.dit hive-dumping
  detections) is a raw-text match against `Microsoft-Windows-WMI-Activity/
  Operational` — no add-on defines field extraction for that channel at
  all, and this hasn't been checked against a real triggered
  `Win32_ShadowCopy` `Create` event yet.

**`known_range_hosts` lookup** (`dt_detection_content`'s own
`lookups/dt_detection_content_known_hosts.csv` +
`transforms.conf`) — the `cyberhawks.lab` `ad` segment's fixed IP
assignments (the 7 range VMs + `computer`/`computer2-5`'s static IPs + the
demo box), for the NTLM-relay and unusual-source-IP detections that need to
distinguish a known host from anything else (`| lookup known_range_hosts ip
AS src_ip OUTPUT hostname`, then filter on `isnull(hostname)`).

**No `tags.conf` was added.** Considered it, decided against: the generic
event codes reused above already have extensive CIM tagging from
Splunk_TA_windows itself, and every *new* `dt_*` eventtype this pass added
is attack-specific (DCSync, RBCD, Shadow Credentials, ACL abuse, coercion
pipes) — none of these map cleanly onto standard CIM tag vocabulary, so
tagging them for tagging's sake would've been noise, not signal.

**The demo box's Linux forwarder had two of its own gaps, both fixed:**

1. Same unconditional-copy bug as the Windows role (see above) — the
   `.deb` path was also an old session's now-gone scratchpad temp file.
   Same fix: stat-check first, gate the assert/copy/install on
   `not uf_binary.stat.exists`.
2. **Confirmed live:** `/var/log/audit/audit.log` is `root:adm` mode `640`,
   and the UF's own dedicated `splunkfwd` service user (created by the
   `.deb` postinst) isn't a member of `adm` — so without a fix, the
   forwarder simply can't read the one file it's now been told to monitor.
   Fixed the same way as the Windows Event Log Readers issue: add
   `splunkfwd` to the `adm` group (Debian's own convention for granting log
   read access) rather than loosening the file's permissions. Sourcetype is
   `linux_audit` (Splunk_TA_nix), not the add-on's more basic `auditd`
   sourcetype — `linux_audit` is the one with the `ses AS session_id` field
   alias backlog.md's detection needs to tie the file-watch event back to
   the PAM `USER_LOGIN` event.

**Also fixed in passing:** the zeek sensor CT's `sysadmin` account had
`/home/sysadmin` owned by `root:root` (everything under it was correctly
owned, just the directory itself wasn't) — a leftover from `sysadmin` being
manually recreated on that CT after its privileged-container rebuild (see
"Cloning a container never changes privileged/unprivileged" above). This
silently broke every Ansible run against `zeek` (`Failed to create
temporary directory`) despite plain `ssh sysadmin@zeek` working fine, since
SSH itself doesn't need to write to `$HOME`. Fixed with a one-line `chown`
via `pct exec` from the Proxmox host.

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
- **Step 3 — forward a minimal, explicit set of logs.** **Done (2026-09-27).**
  Same principle already applied to Zeek (`splunk_uf_monitor_files` — an
  explicit allowlist, never a wildcard), extended to Windows. See "Windows
  Event Log channel-level vs. per-event-ID filtering" above for the
  channel/whitelist decision and exact list, and the gotcha right after it
  for two more fixes this surfaced. All 7 hosts confirmed forwarding live
  (sustained `forwarded_logs` throughput in the indexer's `metrics.log`, no
  `WinEventLogChannel` errors in any host's `splunkd.log`).
- **Step 4 — organize ingested data in Splunk.** **Done (2026-09-27).** Three
  named indexes (`zeek`/`windows`/`linux`) instead of the default `main`;
  confirmed the installed add-ons' sourcetype/field-extraction coverage
  against `splunk-detections/detections/backlog.md` (most generic event
  codes already covered, real gaps filled with new eventtypes); a
  `known_range_hosts` lookup; the demo box's auditd forwarding (left
  unwired since step 1) finished. Also fixed the `forwarded_logs` placeholder
  sourcetype step 3 left behind, and a handful of unrelated blockers this
  surfaced (Linux UF installer-copy ordering, `splunkfwd`/`adm` group
  membership, a broken home directory on the zeek sensor CT). Full detail in
  "Organizing ingested data for step 5" above.

## IIS, SQL Server, and CA ingestion (2026-09-27 follow-up)

Once `cyber-range` turned on SQL Server Audit/Extended Events and
Certificate Services auditing (that repo's CLAUDE.md, "SQL Server
telemetry + Certificate Services auditing"), this repo picked up all three
open items above. Two are fully live; one has a real blocker.

**IIS (web + ca): done, no cyber-range work needed.** Confirmed live before
touching anything: IIS logging was already on by default on both hosts
(W3C extended format, already capturing every field the portal/ESC8
detections need) — this was always a `defense-tooling`-side forwarding gap,
not a missing log source. Added plain file monitoring
(`splunk_uf_win_monitor_files`, new in `splunk_forwarder_windows` —
`monitor://` stanzas alongside the existing `WinEventLog://` ones) for
`C:\inetpub\logs\LogFiles\W3SVC1\*.log` on both hosts, sourcetype
`ms:iis:default` (Splunk_TA_microsoft-iis's own stanza for this exact log
format), landing in a new dedicated `iis` index. Verified live: real events
indexed, correct sourcetype. **Known field-extraction gap:** this box's IIS
sites use a customized, non-default W3C field order/set (confirmed via
`Get-WebConfigurationProperty`), and the TA's `ms:iis:default` field
extraction assumes the standard field layout — the `host` field specifically
comes back wrong (`EVAL-host = coalesce(s_computername, host)` picks up a
mis-aligned column). The real host is still in `_raw` and correctly tagged
in Splunk's actual metadata; only the TA's own computed display field is
affected. Leave this for step 5 to work around (a custom field-extraction
override, or normalizing the site's log field order to match what the TA
expects) rather than fixing blind now.

**Certificate Services auditing (ca): done.** Confirmed live: `AuditFilter`
registry value present (`7f`/127) and `Certification Services` audit
subcategory shows `Success and Failure`. Added the ADCS event ID range
(4886-4899) to ca's Security whitelist — but as an *extension* of the
existing whitelist, not a second channel entry: `splunk_uf_win_monitor_channels`
is a flat list keyed by channel name, and dc1/dc2's Directory Service
addition (a genuinely new channel) is a different shape from extending a
channel *already* in the common list. A naive copy of that pattern would
have produced two `[WinEventLog://Security]` stanzas in the same
`inputs.conf` — caught before it shipped. Fixed with a new
`splunk_uf_win_security_whitelist_extra` var that
`group_vars/splunk_forwarders_windows/monitor.yml`'s own Security whitelist
definition appends inline, defaulting to empty for every host except the
ones (just ca, so far) that set it. Verified live: `sc.exe`-equivalent
`auditpol`/`certutil -getreg` confirms the settings, and the whitelist now
resolves correctly per-host (`ansible -m debug` diff between ca and any
other host).

**SQL Server telemetry (sql1/sql2): done, fully live.** Was blocked on
network reachability; the user added a pfSense rule allowing `defense`
(10.0.10.0/24) → `ad` (10.0.2.0/24) on tcp/1433, and after that a further
chain of DB Connect-specific issues surfaced and got fixed (see "DB Connect
rising-mode gotchas" below for the four that came after the network fix).
Confirmed live end-to-end: `index=mssql | stats count by source,
sourcetype` shows real, growing counts on all four inputs
(`sql1_mssql_xe_text`, `sql1_mssql_audit`, `sql2_mssql_xe_text`,
`sql2_mssql_audit`), and the DB Connect server log shows
`status=success`/`errorCount=0` on every scheduled run. Everything up
through Splunk DB Connect itself is built and confirmed correct:
- A JRE (`openjdk-17-jre-headless`) and the Microsoft JDBC Driver for SQL
  Server, neither bundled with DB Connect (confirmed live: no `java` on
  PATH, `drivers/` had only a README) — both installed by the
  `splunk_indexer` role now (`splunk_deploy_mssql_dbconnect`).
- **Gotcha, same class as the Windows Event Log Readers one from step 3:**
  DB Connect's own task server (running as the same non-root user as
  splunkd) needs write access under its own app directory at runtime, for
  an internal secrets KV store collection — confirmed live via
  `splunkd.log`: `Cannot create directory: .../splunk_app_db_connect/local:
  Permission denied` → 500 from the task server → surfaced to us as a 503
  on every DB Connect REST call. Every directory this role (and
  `dt_detection_content`) creates inherits `root:root` ownership from this
  inventory's blanket `ansible_become: true`; this is the one app that
  actually needs write access back, so it's the one place that needed an
  explicit recursive `owner: {{ ansible_user }}` fix.
- The identity (`svc_sqlmonitor`) is created through DB Connect's own REST
  API (`db_connect/dbxproxy/identities`), since `identities.conf.spec`
  documents the password field as "the encrypted value" — there's no
  supported way to pre-compute that ourselves, unlike everything else this
  project templates directly.
- Connections and inputs, by contrast, hold no secrets (a connection just
  references the identity by name), so they're plain templated
  `db_connections.conf`/`db_inputs.conf` — **deliberately not** created
  through DB Connect's REST API for inputs, even though the identity is:
  confirmed live that the REST validator for inputs rejects the exact field
  names documented in `db_inputs.conf.spec` (`tail_rising_column_name`,
  `index_time_mode`) with opaque `"must not be null"`/`"Invalid index time
  mode"` errors regardless of casing tried, and its own minified frontend
  bundle uses yet a *third*, undocumented set of names
  (`rising_column_name`, `timestampType`) that aren't in any shipped spec
  file. Writing the conf files directly sidesteps that validator entirely,
  and — confirmed live via `splunk_app_db_connect_server.log` — it's
  genuinely picked up and scheduled by the task server's Quartz-based
  job runner the same as a REST-created input would be.
- Query design: one Extended Events (`detection_sql_text`) query per host
  covering `xp_cmdshell`/`xp_dirtree`/linked-server execution in one shot
  (all three arrive as `rpc_completed`/`sql_batch_completed` with full
  statement text in the `sql_text` action — confirmed against real
  captured events, including `cyber-range`'s own verification calls), and
  one audit (`detection_impersonation_audit`) query per host for `EXECUTE
  AS` impersonation. New `mssql` index, `mssql_xe_text`/`mssql_audit`
  sourcetypes (custom — `Splunk_TA_microsoft-sqlserver` has a real
  `mssql:audit` sourcetype, but its field mapping expects an `action_name`
  field the raw `sys.fn_get_audit_file()` output doesn't have under that
  name, so a custom sourcetype using the TVF's actual column names was
  safer than guessing at an undocumented translation), new `dt_sql_*`
  eventtypes matching the four `backlog.md` rows exactly.
- **The network blocker, now resolved:** raw TCP to `10.0.2.6:1433` and
  `10.0.2.7:1433` (sql1/sql2) timed out from the indexer (10.0.10.2,
  `defense` vnet) — `Connect timed out. ... Make sure that TCP connections
  to the port are not blocked by a firewall`, caught directly in DB
  Connect's own job-run log. Every other cross-segment data path in this
  project flows `ad`/`demo` → `defense` (each host's own Splunk UF
  connecting *out* to the indexer's `:9997`); this was the first one
  needing the *reverse* direction, `defense` → `ad`, which nothing so far
  had established was permitted. Fixed by the user adding a pfSense rule
  allowing `defense` (10.0.10.0/24) → `ad` (10.0.2.0/24) on tcp/1433 —
  chosen over the alternative (abandoning indexer-pull for a per-host
  scheduled-dump-to-file model) since the pull model was otherwise fully
  built and this was the only thing stopping it working as designed.
  Confirmed via raw `bash -c "</dev/tcp/host/1433"` before/after.

### DB Connect rising-mode gotchas (found after the network fix)

Four more issues surfaced in sequence once the network path was open, each
only visible after the previous one was fixed — none were reachable while
the connection itself was timing out, which is why they weren't caught
during the original build-out:

1. **No default checkpoint.** DB Connect's `rising` mode has no "start from
   scratch" behavior — first run of every input failed with
   `INPUT_CHECKPOINT_READ_ERROR`/"no init checkpoint found for input". Fixed
   by adding `tail_rising_column_init_ckpt_value = {"value": "1900-01-01
   00:00:00.000", "columnType": 93}` to every input stanza in
   `db_inputs.conf.j2` — `columnType: 93` is `java.sql.Types.TIMESTAMP`,
   required (not optional) per the frontend bundle's own validation.
2. **The rising column must be the query's first SELECT-list column.** The
   XE query originally had `event_time` second — DB Connect's argument
   binder assumes a fixed position and threw `NullPointerException:
   Cannot invoke "java.lang.Integer.intValue()"` in
   `DefaultArgumentRegisterImpl.registerArgumentsWithType`. Fixed by
   reordering the XE query's SELECT list (the audit query already had
   `event_time` first).
3. **The checkpoint isn't auto-applied — the query needs a literal
   `WHERE <col> > ? ORDER BY <col> ASC`.** Jobs reported `status=success`
   with `readCount: 0` even with real matching rows in SQL Server. DB
   Connect's non-optimised rising mode binds the checkpoint as an actual
   JDBC `PreparedStatement` parameter against a placeholder already present
   in the query text — it does not append any filter itself. Confirmed via
   the frontend bundle's `getSqlContent`. Both `mssql_xe_query.sql.j2` and
   `mssql_audit_query.sql.j2` now end in `WHERE event_time > ? ORDER BY
   event_time ASC`; the XE query wraps its `sys.fn_xe_file_target_read_file`
   call in a subquery first since `event_time` there is a computed XML
   `.value()` alias that can't be referenced in a same-level `WHERE`.
4. **Assumed audit columns that don't exist in this SQL Server version.**
   `sql1_mssql_audit` alone kept failing with `SQLServerException: Invalid
   column name 'client_ip'` even after the other three inputs were reading
   real rows — the query had assumed `client_ip`/`application_name` columns
   for `sys.fn_get_audit_file()` that this version's actual output doesn't
   have. Fixed by querying `SELECT TOP 0 * FROM sys.fn_get_audit_file(...)`
   directly via `sqlcmd` to get the real column list before rewriting the
   query — same lesson as the IIS field-order gap above: verify live,
   don't assume from memory/docs.

General takeaway carried into future DB Connect work: its rising-mode
behavior is inconsistently documented across `db_inputs.conf.spec`, its
REST API's validator, and its own frontend bundle — treat all three as
unreliable individually and verify behavior live (job logs, actual
`readCount`) rather than trusting any one of them.

## Zeek sourcetype/field-extraction incident (2026-09-27)

Found while starting real SPL implementation in `splunk-detections` (step 5):
every Zeek log had been landing in Splunk as a single generic
`zeek_placeholder` sourcetype with **zero field extraction** — `id.orig_h`,
`proto`, etc. never existed as searchable fields. Three independent bugs,
found and fixed in sequence:

1. **A custom index-time sourcetype-rename transform was missing
   `SOURCE_KEY = MetaData:Source` (and initially `WRITE_META = true`
   too).** Without `SOURCE_KEY`, its regex ran against `_raw` (the default),
   which never contains a file path, so the rename from `zeek_placeholder`
   to `zeek:conn`/`zeek:dns`/etc. silently never fired. This custom
   mechanism (`Splunk_TA_zeek/local/props.conf`+`transforms.conf`,
   `[source::.../zeek/logs/*/*.log]` → `zeek_set_sourcetype`) turned out to
   be unnecessary anyway — **removed entirely**, in favor of just seeding
   the forwarder's initial sourcetype as the literal `zeek` (was
   `zeek_placeholder`) so `Splunk_TA_zeek`'s own shipped `[zeek]` stanza
   (`TRANSFORMS-autotype = zeek_autotype,TrashComments`) does the same
   per-file retyping correctly, out of the box. Changed
   `splunk_uf_sourcetype_placeholder: zeek` in `host_vars/zeek.yml` (+
   `.example`).
2. **Dead end, since abandoned:** assumed `Splunk_TA_zeek`'s
   `INDEXED_EXTRACTIONS = tsv` (the mechanism its own `[zeek]` stanza uses)
   would then extract fields once the sourcetype was correct. It didn't —
   `splunkd.log` showed `CsvLineBreaker` logging repeated "has extra
   incorrect columns in certain fields" warnings against this range's real
   conn.log/dns.log data, with zero fields ever created, no error surfaced
   anywhere else. Also confirmed (per Splunk's own docs) that
   `INDEXED_EXTRACTIONS` must run on whichever process directly reads the
   file — installed the TA on the Zeek forwarder itself to test this
   (`splunk_uf_addons_dir`, briefly added to `splunk_forwarder` then
   removed again) — same warning, same zero fields. Not worth chasing
   further given a simpler standard alternative existed.
3. **Real fix: plain search-time delimiter extraction**, `REPORT-<name>` in
   `dt_detection_content/local/props.conf` pointing at `DELIMS`/`FIELDS`
   transforms in `dt_detection_content/local/transforms.conf` (files:
   `dt_detection_content_props.conf`, `dt_detection_content_transforms.conf`
   in `splunk_indexer/files/`). Confirmed live end-to-end for `zeek:conn`
   and `zeek:dns`. **Gotcha confirmed along the way:** a bare
   `FIELD_DELIMITER`/`FIELD_NAMES` in props.conf (tried before REPORT) turned
   out to be a companion setting for `INDEXED_EXTRACTIONS`'s own header
   parsing, not an independent search-time mechanism — it also silently
   extracted nothing. **Second gotcha:** Splunk silently normalizes a dotted
   field name declared in `FIELDS` (e.g. `id.orig_h`, matching Zeek/CIM
   convention) to underscores at search time (`id_orig_h`) — every detection
   in `splunk-detections` must reference the underscore form, not the dotted
   one `backlog.md`'s prose uses.
4. `dce_rpc.log`/`kerberos.log` FIELDS lists use Zeek's standard default
   field order (no live traffic existed yet on this range to read a real
   header from at the time this was fixed) — reverify against a real header
   the first time a detection using those fields doesn't behave as expected.
   `ldap.log` deliberately has no FIELDS entry yet for the same reason, plus
   it's a third-party Zeek package (not core Zeek) so field order isn't a
   safe assumption at all — needs a real header read before it can be added.

Both the Splunk indexer (510) and Zeek sensor (511) had all logs cleared and
were re-snapshotted (same "power off → snapshot → power on" process,
replacing their existing latest snapshot) after this fix, before any real
detection testing began.

## Open items

1. `dt_vss_shadow_copy_created` (see "Organizing ingested data for step 5"
   above) is unconfirmed — built from the documented WMI-Activity/Operational
   message format, not verified against a real triggered event.
2. IIS's `host` field comes back wrong in Splunk (see "IIS, SQL Server, and
   CA ingestion" above) — a field-extraction mismatch between this box's
   customized W3C log format and what `Splunk_TA_microsoft-iis` assumes,
   not a data-loss issue (the real host is still in `_raw`).
