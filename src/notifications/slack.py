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
# Block Kit limits: a section's text 3,000 characters, a field's 2,000.
SECTION_LIMIT, FIELD_LIMIT = 3000, 2000


def clip(text: str, limit: int) -> str:
    return text if len(text) <= limit else text[: limit - 1] + "…"


def escape(text: object) -> str:
    """Slack's mrkdwn treats &, < and > as markup."""
    return str(text).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def _section(text: str) -> dict:
    return {"type": "section", "text": {"type": "mrkdwn", "text": clip(text, SECTION_LIMIT)}}


def _button(text: str, url: str, action_id: str) -> dict:
    return {"type": "button", "text": {"type": "plain_text", "text": text}, "url": url, "action_id": action_id}


def message(payload: dict) -> dict:
    """A Block Kit message, with `text` as the notification and screen-reader fallback."""
    if payload.get("event") == "test":
        text = "Scrutineering test notification: this channel is set up."
        return {"text": text, "blocks": [_section(text)]}
    item = payload["remediation"]
    headline = HEADLINES.get(item["status"], item["label"])
    text = f"{escape(headline)}: remediation #{item['id']} for {escape(item['image'])}"
    fields = [
        {"type": "mrkdwn", "text": clip(text, FIELD_LIMIT)}
        for text in (
            f"*Image*\n`{escape(item['image'])}`",
            f"*Status*\n{escape(item['label'])}",
            f"*Action*\n{escape(item['action'] or 'unknown')}",
            f"*Targeted findings*\n{item['targets']}",
        )
    ]
    blocks: list[dict] = [
        _section(f"*{escape(headline)}* · remediation #{item['id']}"),
        {"type": "section", "fields": fields},
    ]
    if item["new_critical_high"]:
        listed = ", ".join(escape(cve) for cve in item["new_critical_high"][:MAX_LISTED])
        more = len(item["new_critical_high"]) - MAX_LISTED
        listed += f" and {more} more" if more > 0 else ""
        blocks.append(_section(f"*New critical/high:* {listed}"))
    if item["error"]:
        blocks.append(_section(f"*Reason:* {escape(item['error'])}"))
    buttons = []
    if item["url"]:
        buttons.append(_button("Open in Scrutineering", item["url"], "open_remediation"))
    if item["pull_request_url"]:
        buttons.append(_button("Pull request", item["pull_request_url"], "open_pull_request"))
    if buttons:
        blocks.append({"type": "actions", "elements": buttons})
    return {"text": clip(text, SECTION_LIMIT), "blocks": blocks}


def request(payload: dict) -> tuple[bytes, dict[str, str]]:
    raw = json.dumps(message(payload), separators=(",", ":")).encode()
    return raw, {"Content-Type": "application/json", "User-Agent": "scrutineering-notifications"}
