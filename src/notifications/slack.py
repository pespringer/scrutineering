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
    if payload.get("event") == "report.ready":
        return _report_ready(payload["report"])
    if payload.get("event") == "scan.new_critical":
        return _new_critical(payload["scan"], payload["findings"])
    if payload.get("event") == "scan.failed":
        return _scan_failed(payload["scan"], payload["error"])
    item = payload["remediation"]
    if payload.get("event") == "remediation.deployment_stale":
        return _deployment_stale(item, payload["deployment"])
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


def _report_ready(report: dict) -> dict:
    """The weekly report's headline numbers and a link; never its contents."""
    start, end = report["period"]["start"][:10], report["period"]["end"][:10]
    text = f"Scrutineering weekly report, {start} to {end}"
    lines = [
        f"*Open critical / high:* {report['open_critical']} / {report['open_high']}",
        f"*New critical or high this week:* {report['new_critical_high']}"
        f" · *resolved:* {report['resolved_critical_high']}",
        f"*Fixes completed:* {report['fixes_completed']} · *failed:* {report['fixes_failed']}",
        f"*Containers on an older build:* {report['stale_containers']}",
    ]
    blocks: list[dict] = [_section(f"*{text}*"), _section("\n".join(lines))]
    if report["url"]:
        blocks.append({"type": "actions", "elements": [_button("Open the report", report["url"], "open_report")]})
    return {"text": text, "blocks": blocks}


def _new_critical(scan: dict, findings: dict) -> dict:
    """New critical CVEs in an image: which, how many have a fix, and links to the scan and the image."""
    count = findings["new_critical"]
    noun = "finding" if count == 1 else "findings"
    text = f"{count} new critical {noun} in {escape(scan['image'])}"
    fields = [
        {"type": "mrkdwn", "text": clip(value, FIELD_LIMIT)}
        for value in (
            f"*Image*\n`{escape(scan['image'])}`",
            f"*Scan*\n{escape(scan['trigger'] or 'unknown')}, {escape(scan['status'])}",
            f"*Open critical*\n{findings['open_critical']}",
            f"*New ones with a fix*\n{findings['fixable']} of {count}",
        )
    ]
    blocks: list[dict] = [_section(f"*{count} new critical {noun}*"), {"type": "section", "fields": fields}]
    if findings["cves"]:
        listed = ", ".join(escape(cve) for cve in findings["cves"][:MAX_LISTED])
        more = findings["cve_count"] - MAX_LISTED
        listed += f" and {more} more" if more > 0 else ""
        blocks.append(_section(f"*CVEs:* {listed}"))
    buttons = []
    if scan["url"]:
        buttons.append(_button("Open the scan", scan["url"], "open_scan"))
    if findings["url"]:
        buttons.append(_button("Open the image", findings["url"], "open_image"))
    if buttons:
        blocks.append({"type": "actions", "elements": buttons})
    return {"text": clip(text, SECTION_LIMIT), "blocks": blocks}


def _scan_failed(scan: dict, error: str | None) -> dict:
    """An image stopped being checked: its scan failed, and the one before it didn't."""
    text = f"A scan of {escape(scan['image'])} failed"
    fields = [
        {"type": "mrkdwn", "text": clip(value, FIELD_LIMIT)}
        for value in (f"*Image*\n`{escape(scan['image'])}`", f"*Scan*\n{escape(scan['trigger'] or 'unknown')}")
    ]
    blocks: list[dict] = [
        _section("*A scan failed*"),
        {"type": "section", "fields": fields},
        _section(clip(f"*Error:* {escape(error or 'no error recorded')}", SECTION_LIMIT)),
        _section("Further failures of this image send no message until a scan of it succeeds."),
    ]
    if scan["url"]:
        blocks.append({"type": "actions", "elements": [_button("Open the scan", scan["url"], "open_scan")]})
    return {"text": clip(text, SECTION_LIMIT), "blocks": blocks}


def _deployment_stale(item: dict, deployment: dict) -> dict:
    """A completed fix that the running containers haven't picked up yet."""
    stale = deployment["not_fixed"]
    text = (
        f"A fix isn't running yet: {len(stale)} of {deployment['containers']} container(s) of "
        f"{escape(item['image'])} still run an older build (remediation #{item['id']})"
    )
    listed = ", ".join(f"`{escape(name)}`" for name in stale[:MAX_LISTED])
    more = len(stale) - MAX_LISTED
    listed += f" and {more} more" if more > 0 else ""
    blocks: list[dict] = [
        _section(f"*A fix isn't running yet* · remediation #{item['id']}"),
        _section(
            f"The fix for `{escape(item['image'])}` completed over 24 hours ago, but {listed} still "
            "run an older build. Recreate them from the current tag."
        ),
    ]
    if item["url"]:
        blocks.append(
            {"type": "actions", "elements": [_button("Open in Scrutineering", item["url"], "open_remediation")]}
        )
    return {"text": clip(text, SECTION_LIMIT), "blocks": blocks}


def request(payload: dict) -> tuple[bytes, dict[str, str]]:
    raw = json.dumps(message(payload), separators=(",", ":")).encode()
    return raw, {"Content-Type": "application/json", "User-Agent": "scrutineering-notifications"}
