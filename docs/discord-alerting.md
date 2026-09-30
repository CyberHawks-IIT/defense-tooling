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
- **The attacker directory** (this repo, `scripts/proxmox/attacker-directory.py`).
  Runs on the Proxmox host and keeps `lookups/attackers.csv` in the
  `discord_alert` app up to date, mapping each attacker IP to a full name. See
  [Attacker names](#attacker-names) below.

## What an embed looks like

Each result row of a fired alert becomes one embed:

- **Title:** the saved-search name. This project's convention is that the
  Splunk alert name is the embed title.
- **Description:** the attacker, written as `Full Name (IP)`, for example
  `John Ford (192.168.1.11)`. The IP comes from the row's `attacker_ip` column.
  If the IP is not in the attacker directory, the name is `Unknown`. A search
  that returns several attacker IPs in one row gets one line per IP.
- **Fields:** the detection's additional fields from the Alert Embed Planner,
  as name and value pairs, in the planner's order. Each detection's `| table`
  already outputs exactly `attacker_ip` plus those fields.

A detection whose table has no `attacker_ip` column can name a different
column in its YAML (`embed.attacker_field`). Pass-the-Ticket uses
`destination`, the host reusing the ticket. A detection with no attacker
column at all shows `Unknown` as the description.

## Attacker names

Names come from Proxmox, so there is nothing to maintain when attackers change.
An attacker is a Proxmox user who has the `PVEVMAdmin` role directly on their
attacker VMs. Every static IP in those VMs' cloud-init network config maps to
that user's first and last name from Proxmox. For example, `john@pve` (John
Ford) has `PVEVMAdmin` on VMs 610 and 611, which are configured with
192.168.1.10 and 192.168.1.11.

Some attacker IPs are not in Proxmox at all, such as an attacker's own machine
connected over NetBird. Assign those by hand on the Proxmox host:

```bash
cyberhawks-attackers add john 100.64.0.7 "NetBird laptop"
```

The first argument is the Proxmox user ID (`john` or `john@pve`), so the name
still comes from Proxmox. The change reaches Splunk immediately. Other
commands:

```bash
cyberhawks-attackers list                 # show every IP and who it belongs to
cyberhawks-attackers remove 100.64.0.7    # undo a manual assignment
cyberhawks-attackers sync                 # rebuild and push now
```

Manual assignments live in `/etc/cyberhawks/attacker-ips.csv` (columns
`user,ip,note`). You can edit it by hand and then run `sync`. A manual entry
wins over a Proxmox-derived one for the same IP.

A systemd timer runs `sync` every 5 minutes, so Proxmox changes (a new attacker
user, a new VM, a changed cloud-init IP) show up on their own. It also restores
the file if the indexer is reverted to an older snapshot. The alert action reads
the file on every alert, so no Splunk restart is needed.

### Installing the attacker directory

Copy the script to the Proxmox host and run:

```bash
python3 attacker-directory.py install
```

This installs it as `/usr/local/sbin/cyberhawks-attackers`, creates the empty
manual file, enables the `cyberhawks-attackers.timer`, and runs a first sync.
It assumes the Splunk indexer is container 510. Pass `--ct <id>` to `install`
if yours differs.

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
- The action sends its own `User-Agent` header. Discord rejects Python's default
  one with HTTP 403 (error 1010), so without it no alert would ever arrive.
- Delivery failures are logged to
  `$SPLUNK_HOME/var/log/splunk/discord_alert_modalert.log` on the indexer.
