"""The Slack channel: an incoming webhook, with the same facts as the webhook payload, as a short message."""

from __future__ import annotations

import json

SLACK_HOST = "https://hooks.slack.com/"
HEADLINES = {
    "proposed": "A fix is waiting for approval",
    "needs_acceptance": "A fix needs acceptance: it adds critical or high findings",
    "ready": "A fix is verified and ready to publish",
    "published": "A fix was published as a pull request",
    "completed": "A fix is complete",
    "failed": "A fix failed",
}
MAX_LISTED = 5


def escape(text: object) -> str:
    """Slack's mrkdwn treats &, < and > as markup."""
    return str(text).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def _button(text: str, url: str, action_id: str) -> dict:
    return {"type": "button", "text": {"type": "plain_text", "text": text}, "url": url, "action_id": action_id}


def message(payload: dict) -> dict:
    """A Block Kit message, with `text` as the notification and screen-reader fallback."""
    if payload.get("event") == "test":
        text = "Scrutineering test notification: this channel is set up."
        return {"text": text, "blocks": [{"type": "section", "text": {"type": "mrkdwn", "text": text}}]}
    item = payload["remediation"]
    headline = HEADLINES.get(item["status"], item["label"])
    text = f"{escape(headline)}: remediation #{item['id']} for {escape(item['image'])}"
    fields = [
        {"type": "mrkdwn", "text": f"*Image*\n`{escape(item['image'])}`"},
        {"type": "mrkdwn", "text": f"*Status*\n{escape(item['label'])}"},
        {"type": "mrkdwn", "text": f"*Action*\n{escape(item['action'] or 'unknown')}"},
        {"type": "mrkdwn", "text": f"*Targeted findings*\n{item['targets']}"},
    ]
    blocks: list[dict] = [
        {"type": "section", "text": {"type": "mrkdwn", "text": f"*{escape(headline)}* · remediation #{item['id']}"}},
        {"type": "section", "fields": fields},
    ]
    if item["new_critical_high"]:
        listed = ", ".join(escape(cve) for cve in item["new_critical_high"][:MAX_LISTED])
        more = len(item["new_critical_high"]) - MAX_LISTED
        listed += f" and {more} more" if more > 0 else ""
        blocks.append({"type": "section", "text": {"type": "mrkdwn", "text": f"*New critical/high:* {listed}"}})
    if item["error"]:
        blocks.append({"type": "section", "text": {"type": "mrkdwn", "text": f"*Reason:* {escape(item['error'])}"}})
    buttons = []
    if item["url"]:
        buttons.append(_button("Open in Scrutineering", item["url"], "open_remediation"))
    if item["pull_request_url"]:
        buttons.append(_button("Pull request", item["pull_request_url"], "open_pull_request"))
    if buttons:
        blocks.append({"type": "actions", "elements": buttons})
    return {"text": text, "blocks": blocks}


def request(payload: dict) -> tuple[bytes, dict[str, str]]:
    raw = json.dumps(message(payload), separators=(",", ":")).encode()
    return raw, {"Content-Type": "application/json", "User-Agent": "scrutineering-notifications"}
