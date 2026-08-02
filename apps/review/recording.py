"""
Opening a review item.

**This module must never import from** :mod:`apps.requirements` **or**
:mod:`apps.documents`. That is the one rule that keeps the dependency graph acyclic
rather than accidentally-working: those apps call *into* here when they record something,
and :mod:`apps.review.services` calls back *into* them to revert. Splitting the two apart
means neither direction ever needs the other's module at import time.

So nothing here knows what a requirement or a document is. Callers hand over the pieces:
what kind of thing it was, where it lives, whose file it belongs to, and a snapshot of
what it looked like before.
"""

from __future__ import annotations

import logging

from django.core.exceptions import ValidationError
from django.db import IntegrityError, transaction

from apps.core import audit
from apps.core.access import on_public_schema
from apps.core.models import AuditAction

from .models import ReviewItem, ReviewStatus

logger = logging.getLogger("vms.review")


#: The only keys allowed into ``before_state``. An allowlist rather than "whatever the
#: caller passed", because ``before_state`` is an unencrypted JSON column and a volunteer's
#: file has encrypted fields two attribute accesses away. PRD §5 draws that line; a test
#: walks every reviewable model and fails if an ``Encrypted*`` field name appears here.
SNAPSHOT_KEYS = frozenset(
    {
        "status",
        "started_on",
        "completed_on",
        "expires_on",
        "due_on",
        "due_reason",
        "screening_block",
        "is_current",
        "superseded_by_id",
        "result",
        "report_date",
        "ended_assignments",
    }
)


def clean_snapshot(raw: dict | None) -> dict:
    """Drop anything not on the allowlist, and stringify dates."""
    if not raw:
        return {}
    cleaned = {}
    for key, value in raw.items():
        if key not in SNAPSHOT_KEYS:
            logger.warning("Dropped '%s' from a review snapshot: not on the allowlist", key)
            continue
        cleaned[key] = value if value is None or isinstance(value, (str, int, bool, list)) else str(value)
    return cleaned


def needs_review(actor=None) -> bool:
    """
    Whether work by this actor has to be affirmed by somebody else.

    Reads the ambient audit actor by default. Two consequences worth stating, because both
    are silent:

    * ``Actor.system()`` carries no access level, so the nightly sweep, the seeders and
      every management command answer **False** and open nothing. That is only safe
      because none of the five writers is reachable from the sweep, which a test asserts
      rather than assumes.
    * A Primary Admin also answers False. Their own entries need no review, so a church
      with one administrator never has anything pending — the feature is invisible until
      a limited access level exists.
    """
    actor = actor or audit.get_actor()
    return bool(getattr(actor, "needs_review", False))


def open_if_unverified(
    *,
    kind: str,
    volunteer,
    entity_type: str,
    entity_id,
    entity_label: str = "",
    before_state: dict | None = None,
    affected_entity: tuple[str, object] | None = None,
    actor=None,
    summary: str = "",
) -> ReviewItem | None:
    """
    Open a review item, if the actor's work needs affirming.

    Returns the item, or None when it does not — so a caller can write
    ``item = open_if_unverified(...)`` and ignore the result.

    Must be called **inside a tenant schema** and inside the same transaction as the write
    it covers. Deliberately raises outside one rather than logging and carrying on, which
    is what :func:`apps.core.audit.record` does: a missing audit line is a logging
    inconvenience, while a missing review item is a compliance hole that reads as
    "somebody checked this".
    """
    actor = actor or audit.get_actor()
    if not needs_review(actor):
        return None

    if on_public_schema():
        raise ValidationError(
            "A review item cannot be opened outside a church schema — there is nobody to "
            "review it and no table to hold it."
        )

    affected_type, affected_id = affected_entity or ("", "")

    fields = {
        "kind": kind,
        "volunteer": volunteer,
        "entity_type": entity_type,
        "entity_id": str(entity_id),
        "entity_label": (entity_label or "")[:200],
        "affected_entity_type": affected_type,
        "affected_entity_id": str(affected_id) if affected_id else "",
        "before_state": clean_snapshot(before_state),
        "recorded_by_user_id": getattr(actor, "user_id", None),
        "recorded_by_display": (getattr(actor, "display", "") or "administrator")[:150],
        "department": _department_for(volunteer, actor),
    }

    # Re-recorded before anyone reviewed the last attempt: the earlier entry is no longer
    # what is on file, so close it and let the replacement stand in the queue. Checked
    # up front rather than left to the exception below, because catching an IntegrityError
    # inside an open transaction breaks it — nothing further can be queried until the
    # block unwinds, which is exactly what the recovery path needs to do.
    superseded = ReviewItem.objects.pending().filter(
        entity_type=entity_type, entity_id=str(entity_id)
    ).first()
    if superseded is not None:
        superseded.supersede()

    try:
        # A savepoint, so a genuine race — two requests inserting at once — rolls back to
        # here rather than poisoning the caller's transaction.
        with transaction.atomic():
            item = ReviewItem.objects.create(**fields)
    except IntegrityError:
        # The database decided who was first, which is the only arbiter that can. The
        # other request's item is now the open one; leave it alone and record nothing.
        logger.info(
            "Review item for %s/%s was opened concurrently; leaving the existing one",
            entity_type,
            entity_id,
        )
        return None

    if superseded is not None:
        superseded.superseded_by = item
        superseded.save(update_fields=["superseded_by", "updated_at"])
        audit.record(
            AuditAction.REVIEW_SUPERSEDED,
            entity_type,
            entity_id=entity_id,
            entity_label=item.entity_label,
            summary="Replaced before it was reviewed",
        )

    audit.record(
        AuditAction.REVIEW_OPENED,
        entity_type,
        entity_id=entity_id,
        entity_label=item.entity_label,
        summary=summary or f"{item.get_kind_display()} — awaiting a primary admin's affirmation",
    )
    logger.info(
        "Review opened kind=%s entity=%s/%s by=%s",
        kind,
        entity_type,
        entity_id,
        item.recorded_by_user_id,
    )
    return item


def _department_for(volunteer, actor):
    """
    Which of the recorder's departments gave them this volunteer.

    Provenance for the queue, so it still reads correctly after the assignment ends or the
    recorder's access changes. Never consulted for authorisation.
    """
    department_ids = getattr(actor, "department_ids", ()) or ()
    if not department_ids:
        return None

    from apps.org.models import Department

    return (
        Department.objects.filter(
            pk__in=department_ids,
            roles__assignments__volunteer=volunteer,
        )
        .order_by("name")
        .first()
    )


def close_open_items_for(entity_type: str, entity_id, *, replacement=None, by=None) -> int:
    """
    Supersede any open item on this row, because a primary admin has redone the work.

    Treated as superseded rather than affirmed on purpose: a primary admin re-recording
    something is a stronger statement than a click, but the trail should say what actually
    happened, and nobody affirmed the earlier entry.
    """
    closed = 0
    for item in ReviewItem.objects.pending().filter(
        entity_type=entity_type, entity_id=str(entity_id)
    ):
        item.supersede(by=by, replacement=replacement)
        audit.record(
            AuditAction.REVIEW_SUPERSEDED,
            entity_type,
            entity_id=entity_id,
            entity_label=item.entity_label,
            summary="Re-recorded by a primary administrator before review",
        )
        closed += 1
    return closed


def open_review_index(*, volunteer=None):
    """
    Every open review item, as one flat indexed lookup.

    There is no ORM relation to prefetch — the pointer is a pair of strings, deliberately
    — so the alternative is a query per rendered row. The volunteer file shows a dozen
    requirement rows and the dashboard iterates every instance in Python, so that would be
    the difference between one query and hundreds.
    """
    rows = ReviewItem.objects.filter(status=ReviewStatus.PENDING)
    if volunteer is not None:
        rows = rows.filter(volunteer=volunteer)
    return ReviewIndex(
        rows.values(
            "id",
            "kind",
            "entity_type",
            "entity_id",
            "affected_entity_type",
            "affected_entity_id",
            "recorded_by_display",
            "created_at",
        )
    )


class ReviewIndex:
    """Open review items keyed by both the row they cover and the row they affect."""

    def __init__(self, rows):
        self._by_key: dict[tuple[str, str], dict] = {}
        for row in rows:
            self._by_key[(row["entity_type"], row["entity_id"])] = row
            if row["affected_entity_type"]:
                key = (row["affected_entity_type"], row["affected_entity_id"])
                # Do not overwrite a direct hit with an indirect one: a requirement with
                # both its own pending completion and a pending document should read as
                # its own.
                self._by_key.setdefault(key, row)

    def __len__(self):
        return len({row["id"] for row in self._by_key.values()})

    def lookup(self, entity_type: str, entity_id) -> dict | None:
        return self._by_key.get((entity_type, str(entity_id)))

    def annotate(self, objects, *, entity_type: str):
        """
        Hang ``unverified_review`` on each object.

        Every render path must go through this, including the htmx row swap — a swapped-in
        row that has lost its badge makes the page quietly start lying.
        """
        for obj in objects:
            obj.unverified_review = self.lookup(entity_type, obj.pk)
        return objects
