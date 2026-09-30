#!/usr/bin/env python
"""Custom Splunk alert action: post a fired alert to a Discord channel webhook.

Splunk runs this as `discord_alert.py --execute` with a JSON payload on stdin
(see https://docs.splunk.com/Documentation/Splunk/latest/AdvancedDev/ModAlertsAdvanced).
The payload carries the action's configured params (webhook_url, max_rows,
optional field list, optional attacker field) and the path to the search's
gzipped results CSV.

Each result row becomes a Discord embed:
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


def describe_attacker(value, attackers):
    # Splunk's results CSV joins a multivalue field's values with newlines.
    ips = [ip.strip() for ip in str(value or "").split("\n") if ip.strip()]
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
        val = row.get(col, "")
        if val in (None, ""):
            continue  # Discord rejects empty field values
        fields.append({"name": col, "value": str(val)[:MAX_FIELD_VALUE], "inline": True})

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
        max_rows = int(config.get("max_rows") or 10)
    except (TypeError, ValueError):
        max_rows = 10
    max_rows = max(1, min(max_rows, MAX_EMBEDS))

    field_names = [f.strip() for f in (config.get("fields") or "").split(",") if f.strip()]
    attacker_field = (config.get("attacker_field") or "").strip() or "attacker_ip"
    search_name = payload.get("search_name")

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
    try:
        status = post(webhook_url, embeds)
        log("posted %d embed(s) to Discord (HTTP %s)" % (len(embeds), status))
    except Exception as exc:  # noqa: BLE001 -- report any delivery failure to Splunk
        log("failed to post to Discord: %s" % exc)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
