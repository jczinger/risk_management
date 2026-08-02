"""
The review queue: what a department admin recorded, and whether a primary admin has
affirmed it.

A department admin does the screening work for their own departments, and a Primary Admin
signs off on it. What they record takes effect **immediately** — the volunteer counts as
compliant straight away, flagged unverified — and this table is the record of what is
still waiting to be checked. That was the owner's decision; the honest cost is that a
report can say "compliant" on evidence nobody has confirmed yet, which is why the backlog
is surfaced in four places rather than left to be noticed.

Why one table rather than ``verified_by``/``verified_at`` columns on each of the five
things that can be reviewed:

* The queue is one paginated query rather than a union of five.
* ``DiscretionaryOverride`` could not carry them at all — its ``save()`` raises on any
  second write, deliberately.
* Send-back needs a *snapshot* of what the record looked like before, and five copies of
  that would be five chances to snapshot the wrong fields.

The pointer to the reviewed row copies :class:`apps.core.models.AuditEvent` exactly —
``entity_type``/``entity_id``/``entity_label``, same lengths — including its reason for
not using a ``ContentType`` foreign key: ``django_content_type`` exists once per tenant
schema with its own sequence, so a cached id from one schema can be written into another.

Unlike ``AuditEvent`` this table is **not** append-only. A review has a lifecycle. The
immutable record of what happened is the audit trail, as everywhere else here.
"""

from __future__ import annotations

from django.core.exceptions import ValidationError
from django.db import models
from django.utils import timezone

from apps.core.fields import EncryptedTextField
from apps.core.models import NoDeleteModel, TimeStampedModel

#: How long an unreviewed entry may sit before it is called out as stale rather than
#: merely counted. Mirrors ``DUE_SOON_DAYS``'s precedent of a named module constant for a
#: policy-shaped number.
REVIEW_STALE_DAYS = 30


class ReviewKind(models.TextChoices):
    """
    What was recorded.

    Five, not four: a waiver and an override diverge completely on send-back — one has a
    reversal path that already exists, the other is immutable by design — so they cannot
    share a branch.
    """

    REQUIREMENT_COMPLETION = "completion", "Requirement marked complete"
    DOCUMENT = "document", "Document recorded"
    CRC = "crc", "Criminal record check"
    WAIVER = "waiver", "Requirement waived"
    OVERRIDE = "override", "Leadership override"


class ReviewStatus(models.TextChoices):
    PENDING = "pending", "Awaiting review"
    AFFIRMED = "affirmed", "Affirmed"
    SENT_BACK = "sent_back", "Sent back"
    SUPERSEDED = "superseded", "Superseded before review"


class ReviewItemQuerySet(models.QuerySet):
    def pending(self):
        return self.filter(status=ReviewStatus.PENDING)

    def stale(self, as_of=None, days: int = REVIEW_STALE_DAYS):
        """
        Pending items older than ``days``, excluding volunteers who have left.

        Chasing an affirmation for somebody who no longer serves is noise, and noise is
        what makes people stop reading the tile.
        """
        as_of = as_of or timezone.now()
        cutoff = as_of - timezone.timedelta(days=days)
        return self.pending().filter(created_at__lt=cutoff, volunteer__is_active=True)

    def for_volunteer(self, volunteer):
        return self.filter(volunteer=volunteer)


class ReviewItem(TimeStampedModel, NoDeleteModel):
    """One recorded action awaiting, or having had, a primary admin's affirmation."""

    volunteer = models.ForeignKey(
        "org.Volunteer",
        on_delete=models.PROTECT,
        related_name="review_items",
    )

    kind = models.CharField(max_length=32, choices=ReviewKind.choices, db_index=True)

    # The reviewed row. Same shape and same lengths as AuditEvent's pointer, for the same
    # reason — see the module docstring.
    entity_type = models.CharField(max_length=64, db_index=True)
    entity_id = models.CharField(max_length=64, db_index=True)
    entity_label = models.CharField(max_length=200, blank=True)

    # The row whose screen should read "unverified" when it is not the reviewed row
    # itself. A recorded document completes the requirement it backs, and it is the
    # requirement's row an admin is looking at — so one review item covers both and there
    # is only ever one thing to affirm.
    affected_entity_type = models.CharField(max_length=64, blank=True, db_index=True)
    affected_entity_id = models.CharField(max_length=64, blank=True, db_index=True)

    status = models.CharField(
        max_length=16,
        choices=ReviewStatus.choices,
        default=ReviewStatus.PENDING,
        db_index=True,
    )

    # Denormalised for the reason AuditEvent denormalises its actor: the queue has to stay
    # readable after the recording account is deactivated, and no email address belongs
    # in this table.
    recorded_by_user_id = models.IntegerField(null=True, blank=True, db_index=True)
    recorded_by_display = models.CharField(max_length=150, default="")

    # Which of the recorder's departments gave them access to this volunteer. Provenance
    # for the queue, never authorisation — that is decided from the request, every time.
    department = models.ForeignKey(
        "org.Department",
        on_delete=models.PROTECT,
        null=True,
        blank=True,
        related_name="review_items",
    )

    #: What the record looked like before. Plaintext only, behind an allowlist in
    #: :mod:`apps.review.recording` and a test — PRD §5 draws that line, and an encrypted
    #: value copied into a JSON column would step over it. This is also what makes an
    #: honest send-back possible: ``due_on`` is nulled by ``mark_complete`` and cannot be
    #: recovered from the row, so without a snapshot a reverted completion would silently
    #: lose a deadline.
    before_state = models.JSONField(default=dict, blank=True)

    reviewed_at = models.DateTimeField(null=True, blank=True, db_index=True)
    reviewed_by_user_id = models.IntegerField(null=True, blank=True)
    reviewed_by_display = models.CharField(max_length=150, blank=True)

    #: Mandatory on a send-back. Encrypted, matching ``RequirementInstance.waived_reason``:
    #: a reason can name a person or describe why evidence was inadequate.
    decision_reason = EncryptedTextField(blank=True, default="")

    superseded_by = models.ForeignKey(
        "self",
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="supersedes",
    )

    objects = ReviewItemQuerySet.as_manager()

    class Meta:
        # Oldest first — the queue's order, and the inverse of AuditEvent's.
        ordering = ("created_at", "id")
        indexes = [
            models.Index(fields=["status", "created_at"]),
            models.Index(fields=["status", "entity_type", "entity_id"]),
            models.Index(fields=["status", "affected_entity_type", "affected_entity_id"]),
            models.Index(fields=["volunteer", "status"]),
            models.Index(fields=["recorded_by_user_id", "status"]),
        ]
        constraints = [
            # At most one open item per reviewed row, as a database fact. The same partial
            # index trick as ``unique_active_assignment``, and what makes the supersede
            # path fail safely under a race rather than opening two items nobody expects.
            models.UniqueConstraint(
                fields=["entity_type", "entity_id"],
                condition=models.Q(status=ReviewStatus.PENDING),
                name="one_open_review_per_entity",
            ),
            models.CheckConstraint(
                condition=models.Q(status=ReviewStatus.PENDING)
                | models.Q(reviewed_at__isnull=False),
                name="closed_review_has_a_timestamp",
            ),
        ]
        verbose_name = "review item"
        verbose_name_plural = "review queue"

    def __str__(self):
        return f"{self.get_kind_display()} — {self.entity_label} ({self.status})"

    def clean(self):
        super().clean()
        # Cannot be a database constraint: ``decision_reason`` is ciphertext, so
        # ``~Q(decision_reason="")`` compares against a random-looking blob and means
        # nothing. Enforced here and again in the service.
        if self.status == ReviewStatus.SENT_BACK and not (self.decision_reason or "").strip():
            raise ValidationError(
                {"decision_reason": "A reason is required when sending an entry back."}
            )

    @property
    def is_open(self) -> bool:
        return self.status == ReviewStatus.PENDING

    @property
    def age_in_days(self) -> int:
        return (timezone.now() - self.created_at).days

    @property
    def is_stale(self) -> bool:
        return self.is_open and self.age_in_days >= REVIEW_STALE_DAYS

    def _close(self, status, *, by, reason: str = ""):
        """
        Move to a terminal state.

        All three are terminal and there is no re-open: re-recording the entry creates a
        new item instead. The closed door lives here rather than in each caller, the same
        way ``Volunteer.set_screening_block`` refuses to move off ``DISQUALIFIED``.
        """
        if not self.is_open:
            raise ValidationError(
                f"This entry has already been {self.get_status_display().lower()}; "
                "a review cannot be reopened. Record the entry again instead."
            )

        self.status = status
        self.reviewed_at = timezone.now()
        self.reviewed_by_user_id = getattr(by, "pk", None)
        self.reviewed_by_display = by.display_name if by is not None else "system"
        self.decision_reason = reason
        self.full_clean(exclude=["volunteer", "department", "superseded_by"])
        self.save(
            update_fields=[
                "status",
                "reviewed_at",
                "reviewed_by_user_id",
                "reviewed_by_display",
                "decision_reason",
                "updated_at",
            ]
        )
        return self

    def affirm(self, *, by):
        return self._close(ReviewStatus.AFFIRMED, by=by)

    def send_back(self, *, by, reason: str):
        if not (reason or "").strip():
            raise ValidationError({"reason": "A reason is required when sending an entry back."})
        return self._close(ReviewStatus.SENT_BACK, by=by, reason=reason)

    def supersede(self, *, by=None, replacement=None):
        """
        Close because the record moved on, not because anybody decided anything.

        Needed as a third terminal state rather than folded into one of the other two:
        without it, a send-back clicked after a newer entry replaced the target would roll
        back state the sent-back entry no longer owns.
        """
        self._close(ReviewStatus.SUPERSEDED, by=by)
        if replacement is not None:
            self.superseded_by = replacement
            self.save(update_fields=["superseded_by", "updated_at"])
        return self
