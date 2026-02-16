"""
slack.py — Slack webhook client for ASMON.

Orchestrates the full alert pipeline:
  1. Receive a SurfaceDiff from the scan
  2. Filter to meaningful changes only            (filters.py)
  3. Deduplicate against recently sent alerts      (state.py)
  4. Format as Slack Block Kit payload             (messages.py)
  5. POST to webhook

If the webhook call fails the scan still succeeds — alerting is never
on the critical path.
"""

import logging
import requests

from asmon.models import SurfaceDiff
from asmon.alerters.filters import filter_diff
from asmon.alerters.state import AlertState
from asmon.alerters.messages import build_slack_payload

logger = logging.getLogger("asmon.alerters.slack")


class SlackAlerter:
    """
    End-to-end Slack alerter.

    Usage in asmon.py:
        alerter = SlackAlerter(webhook_url="https://hooks.slack.com/...")
        alerter.send(diff=diff, snapshot_id="abc123", baseline_id="xyz789")
    """

    def __init__(self, webhook_url: str, suppress_hours: int = 24):
        if not webhook_url or not webhook_url.startswith("https://"):
            raise ValueError("A valid HTTPS Slack webhook URL is required")

        self._webhook = webhook_url
        self._state = AlertState(suppress_hours=suppress_hours)

    def send(self, diff: SurfaceDiff, snapshot_id: str, baseline_id: str | None = None) -> bool:
        """
        Process a diff and send a Slack alert if there are meaningful,
        non-duplicate changes.

        Returns True if an alert was sent, False otherwise.
        """
        # 1. Filter to meaningful changes
        alerts = filter_diff(diff)
        if not alerts:
            logger.info("No alertable changes after filtering — skipping Slack")
            return False

        # 2. Deduplicate against recent alerts
        target = diff.target
        fresh_alerts: list[dict] = []
        for alert in alerts:
            if self._state.was_sent(target, alert["ip"], alert["alert_type"], alert["detail"]):
                logger.debug("Suppressed (already sent): %s %s", alert["ip"], alert["alert_type"])
                continue
            fresh_alerts.append(alert)

        if not fresh_alerts:
            logger.info("All alerts suppressed by dedup — skipping Slack")
            return False

        logger.info("%d fresh alert(s) to send for %s", len(fresh_alerts), target)

        # 3. Build Slack payload
        payload = build_slack_payload(
            target=target,
            alerts=fresh_alerts,
            snapshot_id=snapshot_id,
            baseline_id=baseline_id,
        )
        if payload is None:
            return False

        # 4. POST to webhook
        sent = self._post(payload)

        # 5. Record sent alerts (only if POST succeeded)
        if sent:
            for alert in fresh_alerts:
                self._state.record(target, alert["ip"], alert["alert_type"], alert["detail"])
            # Opportunistically clean old entries
            self._state.cleanup()

        return sent

    # ------------------------------------------------------------------
    # HTTP
    # ------------------------------------------------------------------

    def _post(self, payload: dict) -> bool:
        """POST JSON to Slack webhook. Returns True on success."""
        try:
            resp = requests.post(self._webhook, json=payload, timeout=10)

            if resp.status_code == 200 and resp.text == "ok":
                logger.info("Slack alert sent successfully")
                return True

            logger.error(
                "Slack webhook returned %d: %s",
                resp.status_code,
                resp.text[:200],
            )
            return False

        except requests.exceptions.Timeout:
            logger.error("Slack webhook timed out (10s)")
            return False
        except requests.exceptions.RequestException as exc:
            logger.error("Slack webhook request failed: %s", exc)
            return False
