"""
Tenant-schema base models and the audit trail.

Two hard rules from the spec live here rather than in each app:

* **Volunteer data is never hard-deleted** (Build Spec §3, acceptance criterion
  "cannot be hard-deleted through any UI or ORM path"). ``NoDeleteModel`` removes
  the delete path at the model *and* queryset level, so a stray
  ``Volunteer.objects.filter(...).delete()`` raises instead of destroying records
  a church may be legally required to retain permanently.
* **The audit trail is append-only** (Build Spec §6). ``AuditEvent`` refuses
  updates and deletes through every ORM path.
"""

from __future__ import annotations

import json

from django.core.exceptions import ValidationError
from django.db import models
from django.utils import timezone

from .audit import get_actor
from .fields import EncryptedTextField


class ProtectedDeletionError(Exception):
    """Raised when something attempts to hard-delete a permanent record."""


# ---------------------------------------------------------------------------
# Abstract bases
# ---------------------------------------------------------------------------


class TimeStampedModel(models.Model):
    """Adds creation/modification stamps. Both are plaintext metadata."""

    created_at = models.DateTimeField(default=timezone.now, editable=False)
    updated_at = models.DateTimeField(auto_now=True, editable=False)

    class Meta:
        abstract = True


class NoDeleteQuerySet(models.QuerySet):
    """QuerySet whose bulk-delete path is closed off."""

    def delete(self):
        raise ProtectedDeletionError(
            f"{self.model.__name__} records are retained permanently and cannot be "
            "deleted. Deactivate the record instead."
        )

    def _raw_delete(self, using):
        raise ProtectedDeletionError(
            f"{self.model.__name__} records are retained permanently and cannot be "
            "deleted."
        )


class NoDeleteModel(models.Model):
    """
    A record that can be deactivated but never destroyed.

    Covers the volunteer file and everything hanging off it. Cascades are blocked
    too: related models use ``on_delete=PROTECT`` so removing a parent cannot take
    a volunteer's history with it.
    """

    objects = NoDeleteQuerySet.as_manager()

    class Meta:
        abstract = True

    def delete(self, *args, **kwargs):
        raise ProtectedDeletionError(
            f"{type(self).__name__} records are retained permanently and cannot be "
            "deleted. Deactivate the record instead."
        )

    def hard_delete_for_tests(self, *args, **kwargs):
        """
        Escape hatch used only by the test suite's own teardown.

        Named so that its presence in application code is obvious in review.
        """
        return models.Model.delete(self, *args, **kwargs)


# ---------------------------------------------------------------------------
# Audit trail
# ---------------------------------------------------------------------------


class AuditAction(models.TextChoices):
    CREATE = "create", "Created"
    UPDATE = "update", "Updated"
    DEACTIVATE = "deactivate", "Deactivated"
    REACTIVATE = "reactivate", "Reactivated"
    STATUS_CHANGE = "status_change", "Status changed"
    WAIVE = "waive", "Waived"
    # Its own action rather than a generic status change: reversing a waiver is exactly
    # the thing someone filters the trail for.
    WAIVER_REVERSED = "waiver_reversed", "Waiver reversed"
    UPLOAD = "upload", "Document uploaded"
    DOWNLOAD = "download", "Document viewed"
    LOGIN = "login", "Signed in"
    LOGIN_FAILED = "login_failed", "Sign-in failed"
    LOGOUT = "logout", "Signed out"
    # Their own actions rather than generic sign-ins: a link is the only way into an
    # account without a passkey, so "who was handed one, and did they spend it?" is
    # exactly the question someone filters the trail for after a suspected takeover.
    LINK_ISSUED = "link_issued", "Sign-in link issued"
    LINK_USED = "link_used", "Sign-in link used"
    CRC_RECORDED = "crc_recorded", "Criminal record check recorded"
    DISQUALIFIED = "disqualified", "Permanently disqualified"
    OVERRIDE = "override", "Leadership override recorded"
    KEY_BACKUP = "key_backup", "Encryption key backed up"
    NOTIFY = "notify", "Notification sent"
    SEED = "seed", "Template seeded"
    # Its own action rather than a generic update on the User row: "who widened whose
    # access, and when" is the first question asked after anything goes wrong, and it
    # should not have to be picked out of a list of profile edits.
    ACCESS_CHANGED = "access_changed", "Access level changed"
    # The review gate. Each of these answers a question the trail is actually asked, and
    # none of them is answerable from the others:
    #   opened     — which figures went in unverified, and when
    #   affirmed   — who signed off, and on what
    #   sent_back  — the entry a department admin is meant to read, with the reason
    #   superseded — which unverified entries were never reviewed because they were
    #                overwritten, which is a gap in the sign-off record rather than a
    #                decision anybody made
    # Kept out of the mutable ReviewItem table as well as in it, because that table can
    # be edited and the trail cannot.
    REVIEW_OPENED = "review_opened", "Recorded, pending affirmation"
    REVIEW_AFFIRMED = "review_affirmed", "Affirmed by a primary admin"
    REVIEW_SENT_BACK = "review_sent_back", "Sent back for correction"
    REVIEW_SUPERSEDED = "review_superseded", "Superseded before review"
    # The criminal record check's analogue of WAIVER_REVERSED, and worth its own action for
    # the same reason: a retracted clearance is exactly what somebody filters for.
    CRC_NOT_AFFIRMED = "crc_not_affirmed", "Criminal record check retracted"


class AuditEventQuerySet(models.QuerySet):
    """
    Append-only queryset.

    ``update()`` and ``delete()`` raise, so there is no ORM path to rewriting
    history — which is the whole point of an audit trail an insurer might read.
    """

    def update(self, **kwargs):
        raise ProtectedDeletionError("The audit trail is append-only; entries cannot be edited.")

    def delete(self):
        raise ProtectedDeletionError("The audit trail is append-only; entries cannot be deleted.")

    def _raw_delete(self, using):
        raise ProtectedDeletionError("The audit trail is append-only; entries cannot be deleted.")


class AuditEvent(models.Model):
    """
    One immutable entry per mutating action.

    Plaintext (so the viewer can filter and an insurer can read it): timestamp,
    actor name, action, entity type/id/label, and a short human summary.

    Encrypted (because a before/after diff of a volunteer record can contain an
    address, a phone number or a note): the structured ``detail`` payload.
    """

    occurred_at = models.DateTimeField(default=timezone.now, editable=False, db_index=True)

    # Denormalised actor: kept as text so the entry stays readable even if the
    # admin account is later removed.
    actor_user_id = models.IntegerField(null=True, blank=True, db_index=True)
    actor_display = models.CharField(max_length=150, default="system")
    actor_ip = models.CharField(max_length=45, blank=True)
    actor_user_agent = models.CharField(max_length=200, blank=True)

    action = models.CharField(max_length=32, choices=AuditAction.choices, db_index=True)

    # Generic pointer to the affected row, without a ContentType dependency —
    # ContentType lives in the public schema and its ids are not tenant-stable.
    entity_type = models.CharField(max_length=64, db_index=True)
    entity_id = models.CharField(max_length=64, blank=True, db_index=True)
    entity_label = models.CharField(max_length=200, blank=True)

    # One-line, PII-free description, e.g. "Criminal record check: Cleared".
    summary = models.CharField(max_length=255, blank=True)

    # JSON blob: {"before": {...}, "after": {...}} plus any extra context.
    detail = EncryptedTextField(blank=True, default="")

    objects = AuditEventQuerySet.as_manager()

    class Meta:
        ordering = ("-occurred_at", "-id")
        indexes = [
            models.Index(fields=["entity_type", "entity_id"]),
            models.Index(fields=["-occurred_at", "action"]),
        ]
        verbose_name = "audit event"
        verbose_name_plural = "audit trail"

    def __str__(self):
        return f"{self.occurred_at:%Y-%m-%d %H:%M} {self.actor_display} {self.action} {self.entity_type}"

    def save(self, *args, **kwargs):
        if self.pk is not None:
            raise ProtectedDeletionError(
                "The audit trail is append-only; an existing entry cannot be saved again."
            )
        return super().save(*args, **kwargs)

    def delete(self, *args, **kwargs):
        raise ProtectedDeletionError("The audit trail is append-only; entries cannot be deleted.")

    @property
    def detail_data(self) -> dict:
        """Parsed ``detail``, or ``{}`` when absent/unparseable."""
        if not self.detail:
            return {}
        try:
            return json.loads(self.detail)
        except (ValueError, TypeError):
            return {}


# ---------------------------------------------------------------------------
# Access levels
# ---------------------------------------------------------------------------


class AccessLevel(TimeStampedModel):
    """
    A named set of capabilities, optionally limited to particular departments.

    Called an "access level" and not a role because ``org.Role`` already means a
    *ministry* position — Sunday School Teacher, Nursery Helper — and the two sit
    beside each other in the same screens. See BUILD_NOTES §1.21.

    Two levels are seeded into every church. **Primary Admin** is what every admin
    used to be: everything, church-wide. **Department Admin** is scoped, and is
    reviewed — see :mod:`apps.review`.

    Why the capabilities are columns rather than a JSON list or Django's own
    ``auth.Permission``:

    * ``django.contrib.auth`` is in both SHARED_APPS and TENANT_APPS, so
      ``auth_permission`` exists twice and ``user.has_perm()`` would answer a
      different question depending on which schema is bound. Two sources of truth
      for one question is not a foundation to build authorisation on.
    * Django's permissions are per-model CRUD. ``can_record_screening`` spans five
      models and one product idea; the mapping would be ours to maintain anyway.
    * Columns get ``help_text``, which is where a church reads what a capability
      does *not* include. That is load-bearing here, not decoration.
    * Columns are filterable, which both the escalation rule and the lockout guard
      need.

    The cost, stated plainly: the set of capabilities is closed, and a church cannot
    invent one. That is the right trade, because a capability with no code enforcing
    it is a lie.
    """

    #: The stable key. Seeding and comparison match on this, never on ``name`` — a
    #: church will rename "Department Admin" to "Ministry Leader", and a seeder that
    #: matched on the display name would then create a duplicate.
    PRIMARY_ADMIN = "primary-admin"
    DEPARTMENT_ADMIN = "department-admin"

    name = models.CharField(max_length=150, unique=True)
    slug = models.SlugField(max_length=60, unique=True, editable=False)
    description = models.TextField(
        blank=True,
        help_text="Shown to whoever is choosing an access level for an administrator.",
    )

    is_scoped = models.BooleanField(
        default=True,
        verbose_name="limited to particular departments",
        help_text=(
            "When set, someone holding this level sees only volunteers who have served "
            "in the departments they are given. When unset, they see the whole church."
        ),
    )
    is_builtin = models.BooleanField(
        default=False,
        editable=False,
        help_text="Seeded by VMS. Cannot be removed, though its capabilities can be changed.",
    )
    is_active = models.BooleanField(
        default=True,
        help_text="Unset instead of deleting, so administrators who held it still resolve.",
    )

    can_view_volunteers = models.BooleanField(
        default=True,
        verbose_name="see volunteer records",
        help_text="Read the volunteer file, the dashboard, reports and stored documents.",
    )
    can_edit_volunteers = models.BooleanField(
        default=False,
        verbose_name="add and edit volunteers",
        help_text="Create a volunteer, correct their details, and mark them as no longer serving.",
    )
    can_manage_assignments = models.BooleanField(
        default=False,
        verbose_name="assign volunteers to ministry roles",
        help_text=(
            "Put a volunteer into a role and end an assignment. On a limited level this "
            "also adds that volunteer to what the holder can see, permanently."
        ),
    )
    can_record_screening = models.BooleanField(
        default=False,
        verbose_name="record screening progress",
        help_text=(
            "Mark requirements complete, record documents, waive a requirement, and "
            "record a leadership override."
        ),
    )
    can_record_crc = models.BooleanField(
        default=False,
        verbose_name="record criminal record checks",
        help_text=(
            "Record a check's outcome, and the convictions behind a Not Clear result. "
            "Recording a disqualifying conviction is permanent and cannot be undone."
        ),
    )
    can_manage_org = models.BooleanField(
        default=False,
        verbose_name="create departments and ministry roles",
        help_text="Add and edit the church's departments and the roles within them.",
    )
    can_manage_requirements = models.BooleanField(
        default=False,
        verbose_name="define requirements",
        help_text="Change what this church requires of its volunteers, and of which roles.",
    )
    can_view_audit = models.BooleanField(
        default=False,
        verbose_name="read the audit trail",
        help_text=(
            "The trail and the sent-email log. Cannot be combined with a level limited "
            "to particular departments: an audit entry does not record a department, so "
            "there is nothing to limit it by."
        ),
    )
    can_manage_users = models.BooleanField(
        default=False,
        verbose_name="manage administrators and access levels",
        help_text=(
            "Invite and deactivate administrators, and edit access levels. Nobody can "
            "grant an access level wider than their own."
        ),
    )

    #: Ordered, and the single source of truth for "what capabilities exist".
    #: ``apps.core.access.Capability`` is checked against it by a test in both
    #: directions, so neither can drift.
    CAPABILITY_FIELDS: tuple[str, ...] = (
        "can_view_volunteers",
        "can_edit_volunteers",
        "can_manage_assignments",
        "can_record_screening",
        "can_record_crc",
        "can_manage_org",
        "can_manage_requirements",
        "can_view_audit",
        "can_manage_users",
    )

    class Meta:
        ordering = ("is_scoped", "name")
        verbose_name = "access level"
        verbose_name_plural = "access levels"

    def __str__(self):
        return self.name

    def clean(self):
        super().clean()
        # Structural, not a preference. AuditEvent has no department and cannot get
        # one: its pointer to the affected row is a pair of strings, deliberately, so
        # there is no queryable path from an entry to a department. A partial filter
        # would be worse than none, because it would *look* scoped while missing every
        # RequirementInstance, Document and CRCRecord entry about the same person.
        if self.is_scoped and self.can_view_audit:
            raise ValidationError(
                {
                    "can_view_audit": (
                        "The audit trail cannot be limited to a department, because an "
                        "audit entry does not record one. Either remove the department "
                        "limit or leave the audit trail unticked."
                    )
                }
            )

    def capabilities(self) -> frozenset[str]:
        """The capability names this level grants, without the ``can_`` prefix."""
        return frozenset(
            field[len("can_") :] for field in self.CAPABILITY_FIELDS if getattr(self, field)
        )

    def covers(self, other: "AccessLevel") -> bool:
        """
        Whether this level is at least as wide as ``other`` in both dimensions.

        Deliberately not an integer rank. A church may legitimately create levels that
        are genuinely incomparable — a "Requirements Editor" is neither above nor below
        a "Department Admin" — and forcing a total order onto them is exactly where a
        privilege-escalation bug hides. Superset of capabilities, and no narrower in
        scope; anything else is "no".
        """
        if not other.capabilities() <= self.capabilities():
            return False
        # An unscoped level covers a scoped one; a scoped level never covers an
        # unscoped one. Two scoped levels are compared on departments by the caller,
        # which is the only place that knows the granting user's own department set.
        return not (self.is_scoped and not other.is_scoped)


class UserAccessGrant(TimeStampedModel):
    """
    One administrator's access level, and the departments it applies to.

    Lives in ``apps.core`` (TENANT_APPS only) rather than on the ``User`` model,
    and that is a schema constraint rather than a style choice. ``apps.accounts`` is
    in **both** app lists, so its migrations also run against ``public``; ``apps.org``
    is tenant-only, so ``org_department`` does not exist there. A ``ManyToManyField``
    from ``accounts.User`` to ``org.Department`` would therefore try to create a join
    table in ``public`` referencing a table that is not there, and every deploy would
    fail on its first step.

    ``user_id`` is a plain integer rather than a ``OneToOneField``, and that is worth
    explaining because a real foreign key looks like it should work. It does create
    cleanly — the constraint is built while ``search_path`` is ``"<tenant>", public``,
    where ``accounts_user`` exists. What breaks is **deletion**. A relation gives
    ``User`` a reverse accessor, and that accessor is a Python-level fact present in
    every schema, including ``public`` where ``core_useraccessgrant`` does not exist.
    So Django's cascade collector walks it on any ``User.delete()`` in the public
    schema and raises ``UndefinedTable`` — which is precisely how this was found, in
    the console tests' teardown.

    That is the deeper reason the rest of this codebase denormalises its user
    references (``AuditEvent.actor_user_id``, ``Document.uploaded_by``,
    ``DisqualifyingConviction.recorded_by``) rather than pointing a foreign key at
    ``User`` from a tenant app. The stated reason there is label durability; this is
    the other half of it.

    The cost is that a deleted user leaves an orphaned grant. Harmless: accounts are
    deactivated rather than deleted throughout VMS, and :func:`apps.core.access.grant_for`
    looks a grant up by user id, so an orphan is simply never read.

    One level per user, not many. Two would force a union rule for capabilities and a
    union-or-intersection rule for departments, and that ambiguity is where a leak
    hides. ``unique=True`` is what enforces it, in place of the one-to-one.
    """

    user_id = models.IntegerField(
        unique=True,
        db_index=True,
        help_text="The administrator's primary key in this schema's accounts_user table.",
    )
    access_level = models.ForeignKey(
        AccessLevel,
        on_delete=models.PROTECT,
        related_name="grants",
        help_text="What this administrator may do.",
    )
    departments = models.ManyToManyField(
        "org.Department",
        blank=True,
        related_name="access_grants",
        help_text=(
            "Only used when the access level is limited to particular departments. "
            "A limited level with no departments selected sees nothing."
        ),
    )
    #: Denormalised, following AuditEvent's actor: the record of who granted this
    #: should stay readable after that person's account is deactivated.
    granted_by_display = models.CharField(max_length=150, blank=True)

    class Meta:
        verbose_name = "access grant"
        verbose_name_plural = "access grants"

    def __str__(self):
        return f"user #{self.user_id} → {self.access_level_id}"


# `record()` and `diff_summary()` live in apps.core.audit, alongside the actor
# context they depend on. They are re-exported here because this is where the
# AuditEvent model is, and callers reasonably look for them next to it.
from .audit import diff_summary, record  # noqa: E402,F401  (re-export)
