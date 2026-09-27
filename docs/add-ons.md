# Splunk downloads (manual step)

Splunk Enterprise, the Universal Forwarder, and every add-on on Splunkbase
require a logged-in splunk.com account to download. None of this can be
scripted or automated — download these yourself, then point the relevant
Ansible role variable at the file(s).

## Core packages

| What | Where | Role variable |
|---|---|---|
| Splunk Enterprise (`.deb`, Linux x86_64) | [splunk.com/download](https://www.splunk.com/en_us/download/splunk-enterprise.html) | `splunk_deb_path` (role: `splunk_indexer`) |
| Universal Forwarder (`.deb`, Linux x86_64) | [splunk.com/download](https://www.splunk.com/en_us/download/universal-forwarder.html) | `splunk_uf_deb_path` (role: `splunk_forwarder`) |
| Universal Forwarder (`.msi`, Windows x64) | [splunk.com/download](https://www.splunk.com/en_us/download/universal-forwarder.html) | not yet used — no Windows forwarder role exists yet, see CLAUDE.md |

Grab the current version's direct download link from the page above (it
requires accepting the license and is tied to your session, so a
hardcoded URL here would go stale immediately).

## Add-ons (Splunkbase)

Installed on the indexer already, since this project's Splunk instance came
with them bundled. If you're starting from scratch, download these from
Splunkbase and point `splunk_addons_dir` (role: `splunk_indexer`) at a
directory containing the `.tgz`/`.spl` files — the role extracts everything
in that directory into `$SPLUNK_HOME/etc/apps/`.

| Add-on | Splunkbase | Why |
|---|---|---|
| Corelight Add-on for Zeek | [app/5446](https://splunkbase.splunk.com/app/5446) | Field extraction + CIM mapping for Zeek TSV logs (`zeek:conn`, `zeek:kerberos`, `zeek:dce_rpc`, `zeek:ntlm`, etc.) |
| Splunk Add-on for Microsoft Windows | Splunkbase | `WinEventLog` field extraction/CIM — needed once DC forwarders are wired up |
| Splunk Add-on for Microsoft Sysmon | Splunkbase | Sysmon event parsing — several of this project's planned detections rely on Sysmon Events 10/17/18/19/20/21 |
| Splunk Add-on for Microsoft IIS | Splunkbase | IIS log parsing — for the web-app-portal detections |
| Splunk Common Information Model (CIM) | Splunkbase | Dependency several of the above assume is present |

**Not yet installed, needed later:**

| Add-on | Why | Status |
|---|---|---|
| Splunk Add-on for Microsoft SQL Server | SQL Server Audit/Extended Events aren't plain text (`.sqlaudit`/`.xel` binary files) — this add-on's scripted DB-query inputs are the only non-custom way to get that data into Splunk | Not installed, no forwarder for SQL yet |
| Splunk Add-on for Unix and Linux (`Splunk_TA_nix`) | Cleaner timestamp parsing + multi-line correlation for auditd data (works without it too, just rougher) | Not installed, no forwarder for the Linux host yet |

## A note on `Splunk_TA_zeek` and JSON vs. TSV

This add-on's comprehensive field mappings are built for Zeek's **TSV**
output, not JSON — see the "Zeek: TSV, not JSON" section of
[CLAUDE.md](../CLAUDE.md) for the full reasoning and what we checked before
committing to that. If you swap in a different Zeek add-on, re-verify its
sourcetype coverage against the specific Zeek log types this project's
detections need (kerberos, dce_rpc, ntlm — not just conn/dns/http) before
assuming it's a drop-in replacement.
