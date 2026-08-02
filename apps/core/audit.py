"""
Ambient audit context.

Model-layer code records audit events, but the *actor* is a request-level fact.
Rather than thread a user through every service signature, the middleware parks
the current actor here and the audit recorder reads it back.

A thread-local is safe under gunicorn's sync workers (one request per thread at a
time) and under Celery's prefork pool. It is deliberately *not* relied upon for
correctness of authorisation — only for labelling.

One narrowing of that last sentence, added 2026-08-02 so it stays honest. Two facts
carried here *are* read for correctness: ``user_id``, to tell whether a writer is acting
on their own screening file, and the scoped flag, to tell whether their work needs
affirming. Both are questions about *who the person is*, never about *what they are
allowed to do* — every "may they?" is still answered from ``request.user`` in the view
and re-answered in the service. Both also fail closed: an unresolvable identity matches
nobody's record, and an unresolvable access level is treated as needing review.
"""

from __future__ import annotations

import contextlib
import json
import logging
import threading
from dataclasses import dataclass

logger = logging.getLogger("vms.audit")

_state = threading.local()


@dataclass(frozen=True)
class Actor:
    """Who caused a change, flattened so the label survives the user's deletion."""

    user_id: int | None
    display: str
    ip: str = ""
    user_agent: str = ""
    #: Whether the actor's access level is limited to particular departments. Carried
    #: here so a service
    #: function can tell whether its work needs somebody else's affirmation without
    #: growing a ``user`` parameter — see :func:`apps.review.recording.needs_review`.
    access_level_is_scoped: bool = False
    #: Set when the access level could not be resolved at all. Distinct from "unscoped":
    #: not knowing is not the same as knowing there is nothing to know. See
    #: :attr:`needs_review`.
    access_level_unknown: bool = False
    #: The departments they administer, used only to record *which* one gave them access
    #: to a volunteer. Provenance for the review queue, never authorisation.
    department_ids: tuple[int, ...] = ()

    @classmethod
    def system(cls, label: str = "system") -> "Actor":
        """
        A scheduled job or management command, with no human behind it.

        Holds no access level, so nothing it records is ever queued for review. That is
        correct — there is nobody to attribute it to and nobody it makes sense to send it
        back to — but it is only *safe* because none of the reviewed writers is reachable
        from the nightly sweep. Asserted by a test rather than assumed.
        """
        return cls(user_id=None, display=label)

    @property
    def needs_review(self) -> bool:
        """
        Whether this actor's work has to be affirmed by somebody else.

        Keyed on **scoped-ness**, not on the built-in slug. It used to compare against
        ``"department-admin"`` exactly, which meant a church that built its own limited
        level on the access-level screen — "Youth Admin", say — recorded work that never
        entered the review queue while still being refused as a reviewer. Silently: no
        error, no badge, nothing to notice. Fixed 2026-08-02.

        Reading the same flag :func:`apps.review.services.may_review` reads is the point.
        "A scoped admin's work needs affirming" and "only an unscoped admin may affirm"
        are now two statements about one axis, so they cannot drift apart.

        Not knowing fails **closed**. If the level could not be resolved and there is a
        person behind this actor, assume it needs review: a spurious item is a nuisance
        somebody can clear in one click, while a missing one reads as "somebody checked
        this" forever.
        """
        if self.access_level_unknown:
            return self.user_id is not None
        return self.access_level_is_scoped


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
    """
    Build an :class:`Actor` from a Django request.

    The access level and department set are read here because this runs once per request,
    where the alternative would be a lookup inside each service call. ``AuthenticationMiddleware``
    has already loaded the user, and ``apps.core.access`` caches the grant on the instance,
    so the whole thing costs at most one query per request and none at all for an
    anonymous one.
    """
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
        **_access_context(user),
    )


def _access_context(user) -> dict:
    """
    The acting user's access level and departments, or blanks.

    Kept tolerant on purpose. This runs for *every* request, including on the public
    schema where the access tables do not exist and on the sign-in page where nobody is
    authenticated yet, and a failure here would take down a request that has nothing to do
    with access levels.

    Tolerant is not the same as silent, and it used to be. Swallowing the error and
    returning blanks made the actor look *unscoped*, which made
    :attr:`Actor.needs_review` answer False — so one transient database hiccup meant a
    department admin's entry was recorded as though a Primary Admin had done it, with
    nothing anywhere to say so. The failure now sets ``access_level_unknown``, which the
    review gate treats as "needs review", matching
    :func:`apps.review.recording.open_if_unverified`'s posture of refusing to guess.
    """
    if user is None or not getattr(user, "is_authenticated", False):
        return {}

    try:
        from apps.core.access import grant_for, scope_department_ids

        grant = grant_for(user)
        if grant is None:
            # A signed-in administrator with no grant holds no access level at all, which
            # is a known state (the backfill exists to prevent it) rather than a failure.
            return {}
        scope = scope_department_ids(user)
        return {
            "access_level_is_scoped": grant.access_level.is_scoped,
            "department_ids": tuple(sorted(scope)) if scope else (),
        }
    except Exception:  # noqa: BLE001 - labelling must never break a request
        logger.error("Could not resolve the acting user's access level", exc_info=True)
        return {"access_level_unknown": True}


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

    **Outside a church, this is a no-op.** ``apps.core`` is a tenant app, so there is no
    ``core_auditevent`` table in the public schema and the insert would raise
    ``UndefinedTable``. That is reachable from ordinary use — a mistyped password on the
    shared sign-in page is handled in the public schema — so it has to degrade rather
    than 500. The event goes to the log instead. Console actions that genuinely belong
    to a church (a key export, a document-mode change) already switch into that
    church's schema first, so they are recorded properly.
    """
    from django.db import connection  # noqa: PLC0415
    from django_tenants.utils import get_public_schema_name  # noqa: PLC0415

    from .models import AuditEvent  # noqa: PLC0415

    who = actor or get_actor()

    if connection.schema_name == get_public_schema_name():
        logger.info(
            "Audit outside a tenant schema, logged only: action=%s entity=%s summary=%s",
            action,
            entity_type,
            summary,
        )
        return None

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
