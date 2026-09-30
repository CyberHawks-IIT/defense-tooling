#!/usr/bin/env python
"""Custom Splunk alert action: post a fired alert to a Discord channel webhook.

Splunk runs this as `discord_alert.py --execute` with a JSON payload on stdin
(see https://docs.splunk.com/Documentation/Splunk/latest/AdvancedDev/ModAlertsAdvanced).
The payload carries the action's configured params (webhook_url, max_rows,
optional field list, optional attacker field) and the path to the search's
gzipped results CSV.

Each result row becomes a Discord embed. The detections run in per-result
mode (alert.digest_mode = 0, so Splunk can throttle each attempt on its own
fields), where Splunk invokes this script once per result row and hands that
row over as the payload's `result`; with `param.per_result = 1` only that row
is posted. Otherwise (digest mode) every row of the results file is posted,
in messages of up to 10 embeds (Discord's per-message limit):
  - title       = the saved-search name (this project's convention: the
                  Splunk alert name IS the embed title)
  - description = the attacker, as "Full Name (IP)" -- the row's attacker IP
                  column (`attacker_ip` unless the search configures another)
                  resolved through lookups/attackers.csv. An IP not in that
                  file shows as "Unknown (IP)"; a multivalue IP column gives
                  one line per IP.
  - fields      = the configured field list in order (falling back to every
                  non-internal result column), as name/value pairs.

lookups/attackers.csv (ip,name,...) is NOT shipped with this app. It is
generated and kept current on the Proxmox host by defense-tooling's
scripts/proxmox/attacker-directory.py (Proxmox VM permissions + cloud-init
IPs, plus manually assigned IPs) and pushed into this directory. It is re-read
on every fired alert, so updates take effect without a Splunk restart.

No third-party imports -- only the Splunk-bundled Python stdlib.
"""
import csv
import gzip
import json
import os
import sys
import urllib.request

DISCORD_COLOR = 0xE01E5A  # a red, for "detection fired"
# Discord hard limits: <=10 embeds per message, <=25 fields per embed,
# field value <=1024 chars, description <=4096 chars.
MAX_EMBEDS = 10
# Digest mode posts at most this many rows (in messages of MAX_EMBEDS) so a
# runaway search can't flood the channel.
MAX_ROWS = 50
MAX_FIELDS = 25
MAX_FIELD_VALUE = 1024
MAX_DESCRIPTION = 4096

APP_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ATTACKERS_CSV = os.path.join(APP_DIR, "lookups", "attackers.csv")
UNKNOWN_ATTACKER = "Unknown"


def log(msg):
    # Splunk captures stderr into $SPLUNK_HOME/var/log/splunk/discord_alert_modalert.log
    sys.stderr.write("discord_alert: %s\n" % msg)


def load_attackers(path=ATTACKERS_CSV):
    """Map ip -> attacker display name. Missing/unreadable file = empty map
    (every attacker then renders as Unknown, but the alert still posts)."""
    attackers = {}
    try:
        with open(path, encoding="utf-8", newline="") as fh:
            for row in csv.DictReader(fh):
                ip = (row.get("ip") or "").strip()
                name = (row.get("name") or "").strip()
                if ip and name:
                    attackers[ip] = name
    except OSError as exc:
        log("attacker directory %s unavailable (%s) -- attackers will show as %s"
            % (path, exc, UNKNOWN_ATTACKER))
    return attackers


def read_rows(results_file, limit):
    rows = []
    try:
        with gzip.open(results_file, "rt", encoding="utf-8", newline="") as fh:
            for row in csv.DictReader(fh):
                rows.append(row)
                if len(rows) >= limit:
                    break
    except OSError as exc:
        log("could not read results file %s: %s" % (results_file, exc))
    return rows


def mv_values(value):
    """A result field's values as a list of non-empty strings. A multivalue
    field arrives as a Python list in the per-result JSON payload (result), or
    as newline-joined text in the digest-mode results CSV -- handle both, so a
    list never reaches Discord as its "['1', '10', ...]" repr."""
    items = value if isinstance(value, (list, tuple)) else str(value if value is not None else "").split("\n")
    return [str(v).strip() for v in items if str(v).strip()]


def describe_attacker(value, attackers):
    ips = mv_values(value)
    if not ips:
        return UNKNOWN_ATTACKER
    return "\n".join("%s (%s)" % (attackers.get(ip, UNKNOWN_ATTACKER), ip) for ip in ips)


def build_embed(search_name, row, field_names, attacker_field, attackers):
    # Which columns to show: the configured list, else all non-internal columns.
    if field_names:
        cols = [c for c in field_names if c in row]
    else:
        cols = [c for c in row.keys() if not c.startswith("_") and c != attacker_field]

    fields = []
    for col in cols:
        # Render a multivalue field as "a, b, c" -- never the list repr, never
        # a raw newline-joined blob.
        value = ", ".join(mv_values(row.get(col)))
        if not value:
            continue  # Discord rejects empty field values
        fields.append({"name": col, "value": value[:MAX_FIELD_VALUE], "inline": True})

    return {
        "title": (search_name or "Splunk alert")[:256],
        "description": describe_attacker(row.get(attacker_field), attackers)[:MAX_DESCRIPTION],
        "color": DISCORD_COLOR,
        "fields": fields[:MAX_FIELDS],
    }


def post(webhook_url, embeds):
    body = json.dumps({"embeds": embeds}).encode("utf-8")
    req = urllib.request.Request(
        webhook_url, data=body, method="POST",
        # Discord's edge (Cloudflare) rejects the default Python-urllib agent.
        headers={"Content-Type": "application/json", "User-Agent": "cyberhawks-discord-alert/1.1"},
    )
    with urllib.request.urlopen(req, timeout=15) as resp:
        return resp.status


def main():
    if "--execute" not in sys.argv:
        log("expected --execute from Splunk")
        return 1

    try:
        payload = json.load(sys.stdin)
    except (ValueError, OSError) as exc:
        log("could not parse payload: %s" % exc)
        return 1

    config = payload.get("configuration", {}) or {}
    webhook_url = (config.get("webhook_url") or "").strip()
    if not webhook_url:
        log("no webhook_url configured -- nothing to do")
        return 0  # not an error: Discord simply isn't set up

    try:
        max_rows = int(config.get("max_rows") or MAX_ROWS)
    except (TypeError, ValueError):
        max_rows = MAX_ROWS
    max_rows = max(1, min(max_rows, MAX_ROWS))
    per_result = str(config.get("per_result") or "").strip() in ("1", "true")

    field_names = [f.strip() for f in (config.get("fields") or "").split(",") if f.strip()]
    attacker_field = (config.get("attacker_field") or "").strip() or "attacker_ip"
    search_name = payload.get("search_name")

    if per_result and isinstance(payload.get("result"), dict):
        rows = [payload["result"]]
    else:
        results_file = payload.get("results_file")
        if not results_file:
            log("payload has no results_file")
            return 1
        rows = read_rows(results_file, max_rows)
    if not rows:
        log("no result rows -- nothing to post")
        return 0

    attackers = load_attackers()
    embeds = [build_embed(search_name, row, field_names, attacker_field, attackers) for row in rows]
    failed = False
    for i in range(0, len(embeds), MAX_EMBEDS):
        batch = embeds[i:i + MAX_EMBEDS]
        who = ", ".join(e["description"].replace("\n", " / ") for e in batch)
        try:
            status = post(webhook_url, batch)
            log("%s: posted %d embed(s) to Discord (HTTP %s): %s" % (search_name, len(batch), status, who))
        except Exception as exc:  # noqa: BLE001 -- report any delivery failure to Splunk
            log("%s: failed to post %d embed(s) to Discord (%s): %s" % (search_name, len(batch), who, exc))
            failed = True
    return 2 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
