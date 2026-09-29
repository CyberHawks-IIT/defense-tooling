# Discord alerting

Optionally push every fired Splunk detection to a Discord channel as a rich
embed. This is an add-on for the "range + monitoring" setup (option 2). On its
own it does nothing without the detection content and the range producing
events.

## How it works

There are three pieces, split across two repos by ownership.

- **The `discord_alert` custom alert action** (this repo). A small Splunk app,
  `bin/discord_alert.py` plus `alert_actions.conf`, that Splunk runs whenever a
  wired saved search fires. It reads the search results and posts one embed per
  result row to the webhook. The `splunk_indexer` role installs it, along with
  the webhook URL, only when `discord_webhook_url` is set.
- **The per-detection wiring** (the `splunk-detections` repo).
  `build_app.py --discord` adds `action.discord_alert = 1` to each saved search
  and passes the embed's field list. The `splunk_indexer` role runs the build
  with `--discord` automatically when a webhook is configured, so
  `splunk_detections_repo_dir` must point at a source checkout.
- **The embed content.** The embed title is the saved-search name. This project's
  convention is that the Splunk alert name is the embed title. Each detection's
  `| table` already outputs exactly `attacker_ip` plus the planner's additional
  fields, so the action renders those result columns as embed fields and shows
  `attacker_ip` as **Attacker**.

## Enabling it

1. In Discord, go to **Server Settings > Integrations > Webhooks > New Webhook**,
   pick the channel, and **Copy Webhook URL**.
2. In `ansible/inventory/group_vars/all.yml`, set these (vault the value):

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

To turn it off, clear `discord_webhook_url` and re-run. That rebuilds the
searches without the action. You can leave the `discord_alert` app installed or
remove it.

## Notes

- The webhook URL is a secret. It is deployed into the app's
  `local/alert_actions.conf` (mode 0600) and never committed. The app's
  `default/alert_actions.conf` ships an empty placeholder.
- `discord_max_rows` (default 10) caps how many result rows a single fired alert
  posts, one embed each, so a burst can't flood the channel. Discord itself caps
  a message at 10 embeds.
- Delivery failures are logged to
  `$SPLUNK_HOME/var/log/splunk/discord_alert_modalert.log` on the indexer.
