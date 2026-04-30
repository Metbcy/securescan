"""Per-receiver payload shaping for outbound webhooks (BE-WEBHOOKS).

The dispatcher sends a JSON body to whatever URL the operator
configured. For "neutral" URLs (their own server, an internal queue)
we send a generic shape -- ``{event, data, delivered_at}``. For
well-known chat receivers we reshape into the format those receivers
expect so the operator does not have to put a relay in front of us.

Detection is by hostname substring against the configured URL:

* ``hooks.slack.com``           -> Slack incoming-webhook block layout
* ``discord.com/api/webhooks``  -> Discord webhook with embed

Anything else falls through to the generic shape. We deliberately do
NOT attempt to detect Microsoft Teams / Mattermost / etc here -- the
list of chat formats is open-ended and getting it wrong is worse than
sending a generic JSON.

The function is pure (no IO, no clock); the dispatcher passes the
already-decoded ``data`` dict and the configured webhook URL.
"""

from __future__ import annotations

from datetime import datetime


def format_payload(webhook_url: str, event: str, data: dict) -> dict:
    """Detect Slack/Discord by URL and reshape; otherwise generic.

    The match is case-insensitive (Slack workspace URLs are sometimes
    pasted with mixed case from the admin console) and substring-based
    so the result is stable whether the URL has a query string or not.
    """
    lowered = webhook_url.lower()
    if "hooks.slack.com" in lowered:
        return _slack_format(event, data)
    if "discord.com/api/webhooks" in lowered or "discordapp.com/api/webhooks" in lowered:
        return _discord_format(event, data)
    return {
        "event": event,
        "data": data,
        "delivered_at": datetime.utcnow().isoformat(),
    }


def _slack_format(event: str, data: dict) -> dict:
    text = _summary_text(event, data)
    return {
        "text": text,
        "blocks": [
            {"type": "section", "text": {"type": "mrkdwn", "text": text}},
        ],
    }


def _discord_format(event: str, data: dict) -> dict:
    text = _summary_text(event, data)
    # 0xff8c00 = SecureScan brand orange. Discord ignores fields it
    # does not know so the embed stays valid even on schema bumps.
    return {
        "content": text,
        "embeds": [{"description": text, "color": 0xFF8C00}],
    }


def _summary_text(event: str, data: dict) -> str:
    """Render a human-readable one-liner.

    Uses .get() with safe defaults so a malformed event payload (e.g.
    ``scan.complete`` without a ``scan_id``) still produces a sensible
    string instead of a KeyError. The first 8 chars of a UUID is the
    convention used elsewhere in the dashboard.
    """
    if event == "scan.complete":
        scan_id = str(data.get("scan_id", "?"))[:8]
        findings = data.get("findings_count", 0)
        return f"\u2705 Scan {scan_id} completed \u2014 {findings} findings"
    if event == "scan.failed":
        scan_id = str(data.get("scan_id", "?"))[:8]
        err = data.get("error", "")
        return f"\u274c Scan {scan_id} failed: {err}"
    if event == "scanner.failed":
        scan_id = str(data.get("scan_id", "?"))[:8]
        scanner = data.get("scanner", "?")
        return f"\u26a0\ufe0f Scanner `{scanner}` failed in scan {scan_id}"
    if event == "webhook.test":
        return "\U0001f527 SecureScan webhook test"
    return f"{event}: {data}"
