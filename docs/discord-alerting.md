# Discord alerting

Optionally push every fired Splunk detection to a Discord channel as a rich
embed. This is an add-on for the "range + monitoring" setup (option 2); it does
nothing on its own without the detection content and the range producing events.

## How it works

Three pieces, split across two repos by ownership:

- **`discord_alert` custom alert action** (this repo). A small Splunk app —
  `bin/discord_alert.py` + `alert_actions.conf` — that Splunk runs whenever a
  wired saved search fires. It reads the search results and POSTs one embed per
  result row to the webhook. The `splunk_indexer` role installs it, and the
  webhook URL, only when `discord_webhook_url` is set.
- **Per-detection wiring** (the `splunk-detections` repo). `build_app.py --discord`
  adds `action.discord_alert = 1` to each saved search and passes the embed's
  field list. The `splunk_indexer` role runs the build with `--discord`
  automatically when a webhook is configured (so `splunk_detections_repo_dir`
  must point at a source checkout).
- **The embed content.** The embed title is the saved-search name (this
  project's convention: the Splunk alert name *is* the embed title). Each
  detection's `| table` already outputs exactly `attacker_ip` + the planner's
  additional fields, so the action renders those result columns as embed fields,
  showing `attacker_ip` as **Attacker**.

## Enabling it

1. In Discord: **Server Settings → Integrations → Webhooks → New Webhook**, pick
   the channel, **Copy Webhook URL**.
2. In `ansible/inventory/group_vars/all.yml` (vault the value):
   ```yaml
   discord_webhook_url: "https://discord.com/api/webhooks/…"
   # required so the searches can be rebuilt with --discord:
   splunk_detections_app_src: ../../../splunk-detections/app
   splunk_detections_repo_dir: ../../../splunk-detections
   ```
3. Re-run the indexer:
   ```bash
   ansible-playbook -i inventory/hosts.yml playbooks/splunk-indexer.yml
   ```

To turn it off, unset `discord_webhook_url` and re-run (rebuilds the searches
without the action; the `discord_alert` app can be left installed or removed).

## Notes

- The webhook URL is a secret. It is deployed into the app's
  `local/alert_actions.conf` (mode 0600), never committed — the app's
  `default/alert_actions.conf` ships an empty placeholder.
- `discord_max_rows` (default 10) caps how many result rows — one embed each —
  a single fired alert posts, so a burst can't flood the channel. Discord itself
  caps a message at 10 embeds.
- Delivery failures are logged to
  `$SPLUNK_HOME/var/log/splunk/discord_alert_modalert.log` on the indexer.
