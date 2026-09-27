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
| Universal Forwarder (`.msi`, Windows x64) | [splunk.com/download](https://www.splunk.com/en_us/download/universal-forwarder.html) | `splunk_uf_win_msi_path` (role: `splunk_forwarder_windows`) |

Grab the current version's direct download link from the page above (it
requires accepting the license and is tied to your session, so a
hardcoded URL here would go stale immediately).

## Add-ons (Splunkbase)

All installed on the indexer (confirmed present under `$SPLUNK_HOME/etc/apps/`
— installed folder name noted where it differs from the app title). If
you're starting from scratch, download these from Splunkbase and point
`splunk_addons_dir` (role: `splunk_indexer`) at a directory containing the
`.tgz`/`.spl` files — the role extracts everything in that directory into
`$SPLUNK_HOME/etc/apps/`.

**Do not rely on `Splunk_TA_zeek`'s `INDEXED_EXTRACTIONS = tsv` for field
extraction in this environment.** Found live 2026-09-27: against this
range's real conn.log/dns.log data, Splunk's `CsvLineBreaker` logs repeated
"has extra incorrect columns in certain fields" warnings and silently
produces zero extracted fields (no `id.orig_h`, `id.resp_h`, etc. — no error
anywhere, just absent fields). Installing the TA on the forwarder itself
(where `INDEXED_EXTRACTIONS` is actually supposed to run, per Splunk's own
docs — a universal forwarder does not otherwise parse) didn't change this.
Root-caused only as far as "the TA's TSV line-breaker doesn't tolerate this
data" — not worth chasing further given a much simpler, standard alternative
exists: plain search-time delimited extraction (`FIELD_DELIMITER` +
`FIELD_NAMES`), deployed indexer-side in `splunk_indexer`'s
`dt_detection_content_zeek_fields.conf` (see CLAUDE.md's Zeek
sourcetype/field-extraction incident writeup for the full debugging trail,
including a separate, now-fixed bug in a custom index-time sourcetype-rename
transform this project no longer uses — the TA's own shipped `[zeek]`
autotype transform handles that, as long as the forwarder seeds the literal
`zeek` sourcetype it expects).

| Add-on | Splunkbase | Installed as | Why |
|---|---|---|---|
| Corelight Add-on for Zeek | [app/5446](https://splunkbase.splunk.com/app/5446) | `Splunk_TA_zeek` | Field extraction + CIM mapping for Zeek TSV logs (`zeek:conn`, `zeek:kerberos`, `zeek:dce_rpc`, `zeek:ntlm`, etc.) |
| Splunk Add-on for Microsoft Windows | Splunkbase | `Splunk_TA_windows` | `WinEventLog` field extraction/CIM — needed once DC forwarders are wired up |
| Splunk Add-on for Microsoft Sysmon | Splunkbase | `Splunk_TA_microsoft_sysmon` | Sysmon event parsing — several of this project's planned detections rely on Sysmon Events 10/17/18/19/20/21 |
| Splunk Add-on for Microsoft IIS | Splunkbase | `Splunk_TA_microsoft-iis` | IIS log parsing — for the web-app-portal detections |
| Splunk Common Information Model (CIM) | Splunkbase | `Splunk_SA_CIM` | Dependency several of the above assume is present |
| Splunk Add-on for Microsoft SQL Server | [app/2648](https://splunkbase.splunk.com/app/2648) | `Splunk_TA_microsoft-sqlserver` | SQL Server Audit/Extended Events aren't plain text (`.sqlaudit`/`.xel` binary files) — this add-on's scripted DB-query inputs are the only non-custom way to get that data into Splunk |
| Splunk DB Connect | [app/2686](https://splunkbase.splunk.com/app/2686) | `splunk_app_db_connect` | The SQL Server add-on's scripted DB-query inputs actually run through this — installed alongside it, not optional for that data path |
| Splunk Add-on for Unix and Linux | [app/833](https://splunkbase.splunk.com/app/833) | `Splunk_TA_nix` | Cleaner timestamp parsing + multi-line correlation for the demo box's auditd data (works without it too, just rougher) |

Alongside these, the `splunk_indexer` role also deploys its own
`dt_detection_content` app (not from Splunkbase — it's this project's own
indexes/macros/eventtypes/lookup supporting
`splunk-detections/detections/backlog.md`; see CLAUDE.md's monitoring
rollout plan step 4 for the full design, including which of the above
add-ons' own coverage it reuses vs. fills gaps in).

## A note on `Splunk_TA_zeek` and JSON vs. TSV

This add-on's comprehensive field mappings are built for Zeek's **TSV**
output, not JSON — see the "Zeek: TSV, not JSON" section of
[CLAUDE.md](../CLAUDE.md) for the full reasoning and what we checked before
committing to that. If you swap in a different Zeek add-on, re-verify its
sourcetype coverage against the specific Zeek log types this project's
detections need (kerberos, dce_rpc, ntlm — not just conn/dns/http) before
assuming it's a drop-in replacement.
