"""
Ambient audit context.

Model-layer code records audit events, but the *actor* is a request-level fact.
Rather than thread a user through every service signature, the middleware parks
the current actor here and the audit recorder reads it back.

A thread-local is safe under gunicorn's sync workers (one request per thread at a
time) and under Celery's prefork pool. It is deliberately *not* relied upon for
correctness of authorisation — only for labelling.
"""

from __future__ import annotations

import contextlib
import json
import threading
from dataclasses import dataclass

_state = threading.local()


@dataclass(frozen=True)
class Actor:
    """Who caused a change, flattened so the label survives the user's deletion."""

    user_id: int | None
    display: str
    ip: str = ""
    user_agent: str = ""

    @classmethod
    def system(cls, label: str = "system") -> "Actor":
        """A scheduled job or management command, with no human behind it."""
        return cls(user_id=None, display=label)


def set_actor(actor: Actor | None) -> None:
    _state.actor = actor


def get_actor() -> Actor:
    """Current actor, falling back to an unattributed system actor."""
    return getattr(_state, "actor", None) or Actor.system()


def clear_actor() -> None:
    _state.actor = None


@contextlib.contextmanager
def acting_as(actor: Actor):
    """Temporarily set the audit actor (used by tasks and commands)."""
    previous = getattr(_state, "actor", None)
    _state.actor = actor
    try:
        yield
    finally:
        _state.actor = previous


def actor_from_request(request) -> Actor:
    """Build an :class:`Actor` from a Django request."""
    user = getattr(request, "user", None)
    if user is not None and getattr(user, "is_authenticated", False):
        user_id = user.pk
        display = user.get_full_name() or user.get_username()
    else:
        user_id = None
        display = "anonymous"

    return Actor(
        user_id=user_id,
        display=display,
        ip=_client_ip(request),
        # Truncated: the audit table is not a place to accumulate unbounded strings.
        user_agent=(request.META.get("HTTP_USER_AGENT") or "")[:200],
    )


def record(
    action: str,
    entity_type: str,
    *,
    entity_id: object = "",
    entity_label: str = "",
    summary: str = "",
    detail: dict | None = None,
    actor: Actor | None = None,
):
    """
    Append one entry to the audit trail.

    The actor defaults to whoever the middleware — or an :func:`acting_as` block — has
    in scope, so callers normally pass only what changed.

    ``AuditEvent`` is imported lazily: this module is imported *by* ``core.models``, so
    a module-level import would be circular.
    """
    from .models import AuditEvent  # noqa: PLC0415

    who = actor or get_actor()
    return AuditEvent.objects.create(
        actor_user_id=who.user_id,
        actor_display=(who.display or "system")[:150],
        actor_ip=who.ip or "",
        actor_user_agent=who.user_agent or "",
        action=action,
        entity_type=entity_type[:64],
        entity_id=str(entity_id)[:64] if entity_id not in (None, "") else "",
        entity_label=(entity_label or "")[:200],
        summary=(summary or "")[:255],
        detail=json.dumps(detail, default=str, sort_keys=True) if detail else "",
    )


def diff_summary(before: dict, after: dict) -> dict:
    """
    Reduce two field snapshots to only what changed.

    Keeps the audit payload small and the viewer readable — "status: in_progress →
    complete" is more useful than a dump of every field on the row.
    """
    changed = {}
    for key in sorted(set(before) | set(after)):
        old, new = before.get(key), after.get(key)
        if old != new:
            changed[key] = {"before": old, "after": new}
    return changed


def _client_ip(request) -> str:
    """
    Best-effort client IP.

    The app always sits behind Nginx Proxy Manager, so the left-most entry of
    X-Forwarded-For is the real client. This is used for the audit trail and login
    rate limiting only — never for authorisation — so a spoofed header is a
    logging-accuracy problem, not a security hole.
    """
    forwarded = request.META.get("HTTP_X_FORWARDED_FOR", "")
    if forwarded:
        return forwarded.split(",")[0].strip()[:45]
    return (request.META.get("REMOTE_ADDR") or "")[:45]
