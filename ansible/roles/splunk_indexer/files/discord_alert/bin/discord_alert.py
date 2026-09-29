#!/usr/bin/env python
"""Custom Splunk alert action: post a fired alert to a Discord channel webhook.

Splunk runs this as `discord_alert.py --execute` with a JSON payload on stdin
(see https://docs.splunk.com/Documentation/Splunk/latest/AdvancedDev/ModAlertsAdvanced).
The payload carries the action's configured params (webhook_url, max_rows,
optional field list) and the path to the search's gzipped results CSV.

Each result row becomes a Discord embed:
  - title  = the saved-search name (this project's convention: the Splunk
             alert name IS the embed title)
  - fields = the configured field list in order (falling back to every
             non-internal result column), with `attacker_ip` shown as
             "Attacker".

No third-party imports -- only the Splunk-bundled Python stdlib.
"""
import csv
import gzip
import json
import sys
import urllib.request

DISCORD_COLOR = 0xE01E5A  # a red, for "detection fired"
# Discord hard limits: <=10 embeds per message, field value <=1024 chars.
MAX_EMBEDS = 10
MAX_FIELD_VALUE = 1024


def log(msg):
    # Splunk captures stderr into $SPLUNK_HOME/var/log/splunk/discord_alert_modalert.log
    sys.stderr.write("discord_alert: %s\n" % msg)


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


def build_embed(search_name, row, field_names):
    # Which columns to show: the configured list, else all non-internal columns.
    if field_names:
        cols = [c for c in field_names if c in row]
    else:
        cols = [c for c in row.keys() if not c.startswith("_") and c != "attacker_ip"]

    fields = []
    if row.get("attacker_ip"):
        fields.append({"name": "Attacker", "value": str(row["attacker_ip"])[:MAX_FIELD_VALUE], "inline": True})
    for col in cols:
        val = row.get(col, "")
        if val in (None, ""):
            continue
        fields.append({"name": col, "value": str(val)[:MAX_FIELD_VALUE], "inline": True})

    return {"title": search_name or "Splunk alert", "color": DISCORD_COLOR, "fields": fields}


def post(webhook_url, embeds):
    body = json.dumps({"embeds": embeds}).encode("utf-8")
    req = urllib.request.Request(
        webhook_url, data=body, headers={"Content-Type": "application/json"}, method="POST"
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
    search_name = payload.get("search_name")

    results_file = payload.get("results_file")
    if not results_file:
        log("payload has no results_file")
        return 1

    rows = read_rows(results_file, max_rows)
    if not rows:
        log("no result rows -- nothing to post")
        return 0

    embeds = [build_embed(search_name, row, field_names) for row in rows]
    try:
        status = post(webhook_url, embeds)
        log("posted %d embed(s) to Discord (HTTP %s)" % (len(embeds), status))
    except Exception as exc:  # noqa: BLE001 -- report any delivery failure to Splunk
        log("failed to post to Discord: %s" % exc)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
