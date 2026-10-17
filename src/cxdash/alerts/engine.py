"""Evaluates enabled rules, de-duplicates via ``alert_event`` (cooldown) and dispatches."""

from __future__ import annotations

import logging
from datetime import timedelta
from typing import Any

from jinja2 import Environment, PackageLoader, select_autoescape
from sqlalchemy import select

from cxdash.alerts.notifiers import Notifier, NotifyError, default_notifiers
from cxdash.alerts.rules import AlertCandidate, RuleEvaluator, evaluators_by_kind
from cxdash.container import Container
from cxdash.db import models as m
from cxdash.db.queries.base import utcnow

log = logging.getLogger(__name__)

_env = Environment(
    loader=PackageLoader("cxdash.alerts", "templates"),
    autoescape=select_autoescape(
        enabled_extensions=("html.j2",), default=False
    ),  # findings text is untrusted: HTML is always escaped
    trim_blocks=True,
    lstrip_blocks=True,
)


def render(candidate: AlertCandidate, as_html: bool) -> str:
    ext = "html" if as_html else "txt"
    return _env.get_template(f"{candidate.template}.{ext}.j2").render(c=candidate, d=candidate.data)


class AlertEngine:
    def __init__(
        self,
        container: Container,
        notifiers: dict[str, Notifier] | None = None,
        evaluators: dict[str, RuleEvaluator] | None = None,
    ) -> None:
        self._c = container
        self._notifiers = notifiers or default_notifiers(container.settings)
        self._evaluators = evaluators or evaluators_by_kind()

    def _recently_sent(self, rule_id: int, fingerprint: str, hours: int) -> bool:
        since = utcnow() - timedelta(hours=hours)
        with self._c.db.session() as s:
            events = s.scalars(
                select(m.AlertEvent.payload).where(
                    m.AlertEvent.rule_id == rule_id, m.AlertEvent.fired_at >= since
                )
            ).all()
        return any((p or {}).get("fingerprint") == fingerprint for p in events)

    def _record(self, rule_id: int, candidate: AlertCandidate, channels: list[str]) -> None:
        with self._c.db.session() as s:
            s.add(
                m.AlertEvent(
                    rule_id=rule_id,
                    fired_at=utcnow(),
                    payload={
                        "fingerprint": candidate.fingerprint,
                        "title": candidate.title,
                        "channels": channels,
                    },
                )
            )

    def _channels(self, rule: m.AlertRule) -> list[Notifier]:
        wanted = {"both": ["email", "webhook"]}.get(rule.channel or "webhook", [rule.channel or "webhook"])
        return [n for k in wanted if (n := self._notifiers.get(k)) and n.available()]

    def run(self) -> int:
        """Evaluate every enabled rule once; returns the number of notifications sent."""
        sent = 0
        with self._c.db.session() as s:
            rules = list(s.scalars(select(m.AlertRule).where(m.AlertRule.enabled.is_(True))))
        now = utcnow()
        for rule in rules:
            evaluator = self._evaluators.get(rule.kind or "")
            if evaluator is None:
                log.warning("unknown alert rule kind", extra={"rule": rule.id, "kind": rule.kind})
                continue
            try:
                candidates = evaluator.evaluate(rule, self._c, now)
            except Exception:
                log.exception("alert rule evaluation failed", extra={"rule": rule.id})
                continue
            for cand in candidates:
                hours = (
                    self._c.settings.alert_cooldown_hours
                    if cand.cooldown_hours is None
                    else cand.cooldown_hours
                )
                if hours and self._recently_sent(rule.id, cand.fingerprint, hours):
                    continue
                sent += self._dispatch(rule, cand)
        return sent

    def _dispatch(self, rule: m.AlertRule, cand: AlertCandidate) -> int:
        channels = self._channels(rule)
        if not channels:
            log.warning("alert has no usable channel", extra={"rule": rule.id})
            return 0
        recipients: list[str] = list((rule.params or {}).get("recipients", []))
        text, html = render(cand, False), render(cand, True)
        delivered: list[str] = []
        for n in channels:
            try:
                n.send(cand.title, text, html, recipients)
                delivered.append(n.name)
            except NotifyError as exc:
                log.error(
                    "notification failed", extra={"rule": rule.id, "channel": n.name, "error": str(exc)}
                )
        if delivered:
            self._record(rule.id, cand, delivered)
        return 1 if delivered else 0


def add_rule(c: Container, name: str, kind: str, params: dict[str, Any], channel: str) -> int:
    if kind not in evaluators_by_kind():
        raise ValueError(f"unknown rule kind {kind!r}; choose from {sorted(evaluators_by_kind())}")
    if channel not in ("email", "webhook", "both"):
        raise ValueError("channel must be email, webhook or both")
    if kind == "weekly_digest":
        from cxdash.alerts.rules import validate_cron

        validate_cron(str(params.get("cron", "0 8 * * 1")))
    with c.db.session() as s:
        rule = m.AlertRule(name=name, kind=kind, params=params, channel=channel, enabled=True)
        s.add(rule)
        s.flush()
        return rule.id
