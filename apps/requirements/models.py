"""
The requirement engine.

Two models carry the whole compliance model:

* :class:`RequirementDefinition` — *what this church requires*, of whom, how often.
  Fully editable by the church's own admins; seeded from a Plan to Protect template
  but not locked to it (Build Spec §4.1).
* :class:`RequirementInstance` — *where one volunteer stands* on one requirement.

Plus the criminal-record-check specifics, which the policy treats differently from
every other requirement and which carry the system's only irreversible state:
:class:`CRCRecord`, :class:`DisqualifyingConviction` and
:class:`DiscretionaryOverride`.

Everything the dashboard and reports filter on — type, status, dates — is plaintext.
Notes and reference-check content are encrypted.

Definitions are versionless in Stage 1: editing one applies going forward and does
not rewrite history on instances already completed.
"""

from __future__ import annotations

import calendar
import datetime

from django.core.exceptions import ValidationError
from django.core.validators import MaxValueValidator, MinValueValidator
from django.db import models
from django.urls import reverse
from django.utils import timezone

from apps.core.fields import EncryptedTextField
from apps.core.models import NoDeleteModel, NoDeleteQuerySet, TimeStampedModel
from apps.org.models import Role, Volunteer

#: How long "due soon" means on the dashboard (Build Spec §7).
DUE_SOON_DAYS = 60

#: Onboarding must complete inside three months (Build Spec §4.2 item 8).
ONBOARDING_WINDOW_MONTHS = 3

#: A volunteer turning 18 has three months to submit a criminal record check
#: (Build Spec §4.4).
TURNING_18_CRC_DEADLINE_MONTHS = 3


class RequirementType(models.TextChoices):
    """
    The requirement kinds named by the policy (Build Spec §4.1).

    ``CUSTOM`` is the escape hatch that keeps the engine "fully customisable": the
    items deliberately deferred from the policy review — renewal application form,
    child-welfare-check consent, driver/computer-policy agreements — are all
    addable by a church as custom requirements without a code change.
    """

    APPLICATION_FORM = "application_form", "Application form"
    WAITING_PERIOD = "waiting_period", "Waiting period"
    DECLARATION_OF_FAITH = "declaration_of_faith", "Statement / declaration of faith"
    LIABILITY_RELEASE = "liability_release", "Liability release"
    REFERENCE_CHECKS = "reference_checks", "Reference checks"
    INTERVIEW = "interview", "Interview"
    POLICY_AGREEMENT = "policy_agreement", "Plan to Protect policy agreement"
    CRIMINAL_RECORD_CHECK = "criminal_record_check", "Criminal record check"
    TRAINING_ORIENTATION = "training_orientation", "Orientation training"
    TRAINING_REFRESHER = "training_refresher", "Refresher training"
    SIGNED_AGREEMENT = "signed_agreement", "Signed agreement"
    LEADERSHIP_APPROVAL = "leadership_approval", "Leadership approval"
    CUSTOM = "custom", "Custom requirement"


class Cadence(models.TextChoices):
    """How often a requirement must be satisfied again."""

    ONE_TIME = "one_time", "One time only"
    ANNUAL = "annual", "Annually"
    EVERY_3_YEARS = "every_3_years", "Every 3 years"
    CUSTOM_MONTHS = "custom_months", "Every N months"


class AppliesTo(models.TextChoices):
    """
    Which roles a requirement attaches to.

    Two options are deliberately absent. "Roles that handle personal information" and
    "Positions of trust" were dropped once every role in this system became both by
    definition — see BUILD_NOTES.md §1.14. A requirement that would have used either now
    uses ``ALL_ROLES``, which is what they had come to mean.
    """

    ALL_ROLES = "all", "Everyone"
    SPECIFIC_ROLES = "specific", "Only the selected roles"
    LEADERSHIP = "leadership", "Roles flagged as leadership"


class AgeRule(models.TextChoices):
    """Age gating (Build Spec §4.1)."""

    NONE = "none", "Applies at any age"
    ADULTS_ONLY = "adults_only", "Adults only (18+)"


class RequirementStatus(models.TextChoices):
    """Where one volunteer stands on one requirement."""

    NOT_STARTED = "not_started", "Not started"
    IN_PROGRESS = "in_progress", "In progress"
    COMPLETE = "complete", "Complete"
    OVERDUE = "overdue", "Overdue"
    NOT_APPLICABLE = "not_applicable", "Not applicable"
    WAIVED = "waived", "Waived"
    BLOCKED = "blocked", "Blocked"

    @classmethod
    def satisfied_values(cls) -> list[str]:
        """Statuses that count as "nothing owed" for compliance reporting."""
        return [cls.COMPLETE, cls.NOT_APPLICABLE, cls.WAIVED]

    @classmethod
    def outstanding_values(cls) -> list[str]:
        return [cls.NOT_STARTED, cls.IN_PROGRESS, cls.OVERDUE, cls.BLOCKED]


def add_months_to(start: datetime.date, months: int) -> datetime.date:
    """
    Shift a date by whole months, clamping the day to the target month's length.

    31 January + 1 month is 28/29 February, not an error and not 3 March. Written out
    rather than pulled from a dependency because it is four lines and the clamping
    behaviour is a compliance-relevant decision worth having in view.
    """
    month_index = start.month - 1 + months
    year = start.year + month_index // 12
    month = month_index % 12 + 1
    day = min(start.day, calendar.monthrange(year, month)[1])
    return datetime.date(year, month, day)


class RequirementDefinitionQuerySet(models.QuerySet):
    def active(self):
        return self.filter(is_active=True)

    def for_role(self, role: Role):
        """Definitions that attach to ``role`` through any of the applies_to rules."""
        query = models.Q(applies_to=AppliesTo.ALL_ROLES)
        query |= models.Q(applies_to=AppliesTo.SPECIFIC_ROLES, roles=role)
        if role.is_leadership:
            query |= models.Q(applies_to=AppliesTo.LEADERSHIP)
        return self.filter(query).distinct()


class RequirementDefinition(TimeStampedModel, NoDeleteModel):
    """
    One thing this church requires of some or all of its volunteers.

    Not deletable — a definition with completed instances behind it is part of the
    church's screening history. Deactivate instead, which stops it applying to anyone
    new while leaving the record of who satisfied it intact.
    """

    name = models.CharField(max_length=200)
    description = models.TextField(
        blank=True,
        help_text="What this requires and how an admin should verify it.",
    )
    appendix_reference = models.CharField(
        max_length=100,
        blank=True,
        help_text=(
            "Where to find the form in your policy manual, e.g. 'Appendix 2d'. "
            "A pointer only — no policy text is stored in this system."
        ),
    )

    requirement_type = models.CharField(
        max_length=32, choices=RequirementType.choices, db_index=True
    )

    cadence = models.CharField(max_length=16, choices=Cadence.choices, default=Cadence.ONE_TIME)
    cadence_months = models.PositiveSmallIntegerField(
        null=True,
        blank=True,
        validators=[MinValueValidator(1), MaxValueValidator(600)],
        help_text="Only used when the cadence is 'Every N months'.",
    )

    applies_to = models.CharField(
        max_length=16, choices=AppliesTo.choices, default=AppliesTo.ALL_ROLES
    )
    roles = models.ManyToManyField(
        Role,
        blank=True,
        related_name="requirement_definitions",
        help_text="Used only when 'Only the selected roles' is chosen.",
    )

    age_rule = models.CharField(max_length=16, choices=AgeRule.choices, default=AgeRule.NONE)

    #: Where this sits in the onboarding sequence. Also used to warn when a
    #: dependency is satisfied out of order (e.g. references before the release).
    sequence = models.PositiveSmallIntegerField(
        default=100,
        help_text="Lower numbers come first in the onboarding checklist.",
    )
    is_onboarding = models.BooleanField(
        default=True,
        help_text="Part of the one-time onboarding sequence, rather than a recurring item.",
    )

    must_follow = models.ForeignKey(
        "self",
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name="followed_by",
        help_text=(
            "Optional ordering rule. The policy requires the liability release to be "
            "signed before reference checks are sought, for example."
        ),
    )

    requires_document = models.BooleanField(
        default=False,
        help_text="Expect a document (or a link, or a paper record) to evidence this.",
    )

    is_active = models.BooleanField(default=True, db_index=True)
    is_seeded = models.BooleanField(
        default=False,
        editable=False,
        help_text="Came from the Plan to Protect starter template. Editable like any other.",
    )

    objects = RequirementDefinitionQuerySet.as_manager()

    class Meta:
        ordering = ("sequence", "name")
        constraints = [
            models.UniqueConstraint(fields=["name"], name="unique_requirement_name"),
            models.CheckConstraint(
                condition=models.Q(cadence_months__isnull=False)
                | ~models.Q(cadence=Cadence.CUSTOM_MONTHS),
                name="custom_cadence_needs_months",
            ),
        ]
        indexes = [models.Index(fields=["is_active", "requirement_type"])]

    def __str__(self):
        return self.name

    def get_absolute_url(self):
        return reverse("requirements:definition_detail", args=[self.pk])

    def clean(self):
        super().clean()
        errors = {}

        if self.cadence == Cadence.CUSTOM_MONTHS and not self.cadence_months:
            errors["cadence_months"] = "Enter the number of months between renewals."
        if self.cadence != Cadence.CUSTOM_MONTHS and self.cadence_months:
            # Keep the field meaningless-but-empty rather than silently ignored.
            self.cadence_months = None

        if self.must_follow_id and self.must_follow_id == self.pk:
            errors["must_follow"] = "A requirement cannot depend on itself."

        if errors:
            raise ValidationError(errors)

    # -- Cadence ----------------------------------------------------------

    @property
    def interval_months(self) -> int | None:
        """Months between renewals, or None for a one-time requirement."""
        return {
            Cadence.ONE_TIME: None,
            Cadence.ANNUAL: 12,
            Cadence.EVERY_3_YEARS: 36,
            Cadence.CUSTOM_MONTHS: self.cadence_months,
        }.get(self.cadence)

    @property
    def is_recurring(self) -> bool:
        return self.interval_months is not None

    def expiry_for(self, completed_on: datetime.date) -> datetime.date | None:
        """When a requirement completed on ``completed_on`` next falls due."""
        months = self.interval_months
        return add_months_to(completed_on, months) if months else None

    @property
    def cadence_display(self) -> str:
        if self.cadence == Cadence.CUSTOM_MONTHS and self.cadence_months:
            return f"Every {self.cadence_months} months"
        return self.get_cadence_display()

    # -- Applicability ----------------------------------------------------

    def applies_to_role(self, role: Role) -> bool:
        """Whether this requirement attaches to ``role``."""
        if self.applies_to == AppliesTo.ALL_ROLES:
            return True
        if self.applies_to == AppliesTo.SPECIFIC_ROLES:
            return self.roles.filter(pk=role.pk).exists()
        if self.applies_to == AppliesTo.LEADERSHIP:
            return role.is_leadership
        return False

    def applies_to_volunteer(self, volunteer: Volunteer, roles=None) -> bool:
        """
        Whether this requirement attaches to ``volunteer`` given their current roles.

        Age is handled separately by :meth:`is_age_exempt` so that an adults-only
        requirement produces an explicit ``not_applicable`` instance — a visible
        "not required, and here is why" — rather than no instance at all.
        """
        roles = roles if roles is not None else list(volunteer.active_roles)
        return any(self.applies_to_role(r) for r in roles)

    def is_age_exempt(self, volunteer: Volunteer, on_date: datetime.date | None = None) -> bool:
        """
        True when the volunteer's age exempts them.

        This is the under-18 criminal-record-check rule: same screening as an adult,
        no criminal record check (Build Spec §4.4).
        """
        if self.age_rule != AgeRule.ADULTS_ONLY:
            return False
        return not volunteer.is_adult_on(on_date)

    @property
    def is_crc(self) -> bool:
        return self.requirement_type == RequirementType.CRIMINAL_RECORD_CHECK


class RequirementInstanceQuerySet(NoDeleteQuerySet):
    def outstanding(self):
        return self.filter(status__in=RequirementStatus.outstanding_values())

    def satisfied(self):
        return self.filter(status__in=RequirementStatus.satisfied_values())

    def overdue(self, as_of: datetime.date | None = None):
        as_of = as_of or timezone.localdate()
        return self.filter(
            models.Q(status=RequirementStatus.OVERDUE)
            | models.Q(
                status=RequirementStatus.COMPLETE,
                expires_on__lt=as_of,
            )
        )

    def due_soon(self, within_days: int = DUE_SOON_DAYS, as_of: datetime.date | None = None):
        as_of = as_of or timezone.localdate()
        return self.filter(
            status=RequirementStatus.COMPLETE,
            expires_on__gte=as_of,
            expires_on__lte=as_of + datetime.timedelta(days=within_days),
        )

    def for_department(self, department):
        return self.filter(
            volunteer__assignments__role__department=department,
            volunteer__assignments__is_active=True,
        ).distinct()

    def active_volunteers(self):
        return self.filter(volunteer__is_active=True)


class RequirementInstance(TimeStampedModel, NoDeleteModel):
    """
    One volunteer's standing on one requirement.

    Created when a requirement starts applying to someone and then kept, never
    removed: if a requirement stops applying it becomes ``not_applicable``, so the
    record of what was once required and satisfied survives.

    ``status`` and the two dates are plaintext because the dashboard and the
    compliance report filter and sort on them. ``notes`` is encrypted.
    """

    volunteer = models.ForeignKey(
        Volunteer, on_delete=models.PROTECT, related_name="requirement_instances"
    )
    definition = models.ForeignKey(
        RequirementDefinition, on_delete=models.PROTECT, related_name="instances"
    )

    status = models.CharField(
        max_length=16,
        choices=RequirementStatus.choices,
        default=RequirementStatus.NOT_STARTED,
        db_index=True,
    )

    started_on = models.DateField(
        null=True,
        blank=True,
        help_text="When work on this began. Used to warn if onboarding exceeds 3 months.",
    )
    completed_on = models.DateField(null=True, blank=True, db_index=True)
    expires_on = models.DateField(
        null=True,
        blank=True,
        db_index=True,
        help_text="Computed from the completion date and the cadence.",
    )

    #: Set when a requirement is activated by a rule rather than by an admin — the
    #: turning-18 criminal record check being the case that matters.
    due_on = models.DateField(
        null=True,
        blank=True,
        db_index=True,
        help_text="A hard deadline independent of the renewal cycle.",
    )
    due_reason = models.CharField(max_length=200, blank=True)

    waived_reason = EncryptedTextField(
        blank=True,
        default="",
        help_text="Required when waiving. Recorded in the audit trail.",
    )
    waived_by = models.CharField(max_length=150, blank=True)
    waived_on = models.DateField(null=True, blank=True)

    not_applicable_reason = models.CharField(
        max_length=200,
        blank=True,
        help_text="Plain, non-identifying reason, e.g. 'Under 18 — no CRC required'.",
    )

    notes = EncryptedTextField(blank=True, default="", help_text="Encrypted.")

    objects = RequirementInstanceQuerySet.as_manager()

    class Meta:
        ordering = ("definition__sequence", "definition__name")
        constraints = [
            models.UniqueConstraint(
                fields=["volunteer", "definition"], name="unique_instance_per_volunteer"
            )
        ]
        indexes = [
            models.Index(fields=["status", "expires_on"]),
            models.Index(fields=["volunteer", "status"]),
            models.Index(fields=["expires_on"]),
        ]

    def __str__(self):
        return f"{self.volunteer.display_name} — {self.definition.name}: {self.get_status_display()}"

    def clean(self):
        super().clean()
        errors = {}

        if self.status == RequirementStatus.COMPLETE and not self.completed_on:
            errors["completed_on"] = "Record the date this was completed."
        if self.status == RequirementStatus.WAIVED and not self.waived_reason:
            errors["waived_reason"] = "A waiver must record why it was granted."
        if self.completed_on and self.completed_on > timezone.localdate():
            errors["completed_on"] = "Cannot be in the future."
        if self.completed_on and self.started_on and self.completed_on < self.started_on:
            errors["completed_on"] = "Cannot be before the start date."

        if errors:
            raise ValidationError(errors)

    # -- Derived state ----------------------------------------------------

    @property
    def is_satisfied(self) -> bool:
        return self.status in RequirementStatus.satisfied_values() and not self.is_expired

    @property
    def is_expired(self) -> bool:
        return bool(self.expires_on) and self.expires_on < timezone.localdate()

    @property
    def is_past_due_date(self) -> bool:
        return bool(self.due_on) and self.due_on < timezone.localdate()

    @property
    def days_until_expiry(self) -> int | None:
        if not self.effective_due_date:
            return None
        return (self.effective_due_date - timezone.localdate()).days

    @property
    def effective_due_date(self) -> datetime.date | None:
        """
        The date this is actually owed by.

        A requirement can be under two clocks at once — a renewal expiry and a
        one-off deadline such as the three months a volunteer gets after turning 18.
        The earlier one governs.
        """
        dates = [d for d in (self.expires_on, self.due_on) if d]
        return min(dates) if dates else None

    @property
    def bucket(self) -> str:
        """Which dashboard column this belongs in (Build Spec §7)."""
        if self.status in (RequirementStatus.NOT_APPLICABLE, RequirementStatus.WAIVED):
            return "satisfied"
        if self.status == RequirementStatus.BLOCKED:
            return "overdue"
        if self.status == RequirementStatus.OVERDUE or self.is_expired or self.is_past_due_date:
            return "overdue"
        if self.status == RequirementStatus.COMPLETE:
            days = self.days_until_expiry
            if days is not None and days <= DUE_SOON_DAYS:
                return "due_soon"
            return "satisfied"
        # not_started / in_progress with no deadline yet: outstanding onboarding work.
        return "outstanding"

    @property
    def can_mark_complete(self) -> bool:
        """
        Whether to offer an admin a "mark complete" action on this requirement.

        One rule, in one place, because three different screens offer this action and
        they had drifted apart.

        Excluded, and why:

        * **Waived.** A waiver *is* the decision that this requirement is satisfied —
          it counts as satisfied for compliance, and it carries a reason and an audit
          entry. Offering "mark complete" beside it invites an admin to overwrite a
          recorded decision by clicking the obvious button.
        * **Not applicable.** Satisfied by a rule, not by anything an admin does — the
          under-18 exemption on the criminal record check, for instance.
        * **Blocked.** Pending the outcome of a criminal record check; the service
          refuses it outright.
        * **Needs a document.** Recording the document is what completes it. A separate
          tick would let the two disagree.
        * **The criminal record check.** Its own flow owns completion.

        A completed *recurring* requirement is still included: that is the "Renew"
        action.
        """
        if self.definition.is_crc or self.definition.requires_document:
            return False
        return self.status not in (
            RequirementStatus.WAIVED,
            RequirementStatus.NOT_APPLICABLE,
            RequirementStatus.BLOCKED,
        )

    def recompute(self, as_of: datetime.date | None = None) -> bool:
        """
        Bring ``status`` in line with the dates. Returns True if anything changed.

        The nightly job calls this for every instance (Build Spec §7). It only ever
        moves a completed-but-expired item to ``overdue`` or an ``overdue`` item back
        to ``complete`` — it does not invent completions.
        """
        as_of = as_of or timezone.localdate()
        original = self.status

        if self.status == RequirementStatus.COMPLETE:
            past_expiry = self.expires_on and self.expires_on < as_of
            past_deadline = self.due_on and self.due_on < as_of and not self.completed_on
            if past_expiry or past_deadline:
                self.status = RequirementStatus.OVERDUE
        elif self.status == RequirementStatus.OVERDUE:
            # A renewal recorded since the last sweep pulls it back into compliance.
            still_expired = self.expires_on and self.expires_on < as_of
            if self.completed_on and not still_expired:
                self.status = RequirementStatus.COMPLETE
        elif self.status in (RequirementStatus.NOT_STARTED, RequirementStatus.IN_PROGRESS):
            if self.due_on and self.due_on < as_of:
                self.status = RequirementStatus.OVERDUE

        if self.status != original:
            self.save(update_fields=["status", "updated_at"])
            return True
        return False

    def mark_complete(self, completed_on: datetime.date, *, notes: str = "") -> None:
        """Record completion and roll the renewal clock forward."""
        self.completed_on = completed_on
        self.expires_on = self.definition.expiry_for(completed_on)
        self.status = RequirementStatus.COMPLETE
        if notes:
            self.notes = notes
        # A satisfied requirement clears any one-off deadline that forced it.
        self.due_on = None
        self.due_reason = ""
        self.save(
            update_fields=[
                "completed_on",
                "expires_on",
                "status",
                "notes",
                "due_on",
                "due_reason",
                "updated_at",
            ]
        )


class CRCResult(models.TextChoices):
    """
    The outcome of a criminal record check.

    Plaintext and queryable, as specified — the compliance report needs to show it and
    the three-year clock runs off the report date (Build Spec §4.3).
    """

    CLEARED = "cleared", "Cleared"
    NOT_CLEAR = "not_clear", "Not Clear"


class CRCNotClearOutcome(models.TextChoices):
    """
    How a "Not Clear" result was resolved (Build Spec §4.3).

    Only two paths exist in the policy: supply a fingerprint-verified check with the
    convictions disclosed and verified, or withdraw.
    """

    PENDING = "pending", "Awaiting the volunteer's decision"
    FINGERPRINT_SUBMITTED = "fingerprint", "Fingerprint-verified check submitted"
    WITHDREW = "withdrew", "Volunteer withdrew"


class CRCRecord(TimeStampedModel, NoDeleteModel):
    """
    One criminal record check, including the vulnerable sector search.

    Retained permanently. A volunteer accumulates one of these every three years, and
    the history is part of their file.
    """

    volunteer = models.ForeignKey(
        Volunteer, on_delete=models.PROTECT, related_name="crc_records"
    )
    #: The requirement instance this check satisfies, if the church tracks CRC as a
    #: requirement (it does by default, from the seed template).
    instance = models.ForeignKey(
        RequirementInstance,
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name="crc_records",
    )

    # --- Plaintext, queryable (PRD §5) -----------------------------------
    result = models.CharField(max_length=16, choices=CRCResult.choices, db_index=True)
    report_date = models.DateField(
        db_index=True,
        help_text="The date on the clearance letter. This starts the three-year clock.",
    )
    includes_vulnerable_sector = models.BooleanField(
        default=True,
        help_text="A vulnerable sector search is required for positions of trust.",
    )
    is_fingerprint_verified = models.BooleanField(
        default=False,
        help_text="Set for a fingerprint-verified check following a 'Not Clear' result.",
    )

    not_clear_outcome = models.CharField(
        max_length=16,
        choices=CRCNotClearOutcome.choices,
        blank=True,
        default="",
        help_text="How a 'Not Clear' result was resolved.",
    )

    issuing_body = models.CharField(
        max_length=150,
        blank=True,
        help_text="e.g. 'BC Criminal Record Review Program' or the local police service.",
    )

    # --- Encrypted -------------------------------------------------------
    notes = EncryptedTextField(blank=True, default="", help_text="Encrypted.")

    superseded_by = models.ForeignKey(
        "self",
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name="supersedes",
        editable=False,
    )

    class Meta:
        ordering = ("-report_date", "-id")
        indexes = [
            models.Index(fields=["volunteer", "-report_date"]),
            models.Index(fields=["result", "report_date"]),
        ]
        verbose_name = "criminal record check"

    def __str__(self):
        return f"{self.volunteer.display_name} — {self.get_result_display()} ({self.report_date})"

    def clean(self):
        super().clean()
        errors = {}
        if self.report_date and self.report_date > timezone.localdate():
            errors["report_date"] = "Cannot be in the future."
        if self.result == CRCResult.CLEARED and self.not_clear_outcome:
            errors["not_clear_outcome"] = "Only applies to a 'Not Clear' result."
        if errors:
            raise ValidationError(errors)

    @property
    def expires_on(self) -> datetime.date:
        """Three years from the report date (Build Spec §4.2 item 9)."""
        return add_months_to(self.report_date, 36)

    @property
    def is_cleared(self) -> bool:
        return self.result == CRCResult.CLEARED

    @property
    def has_disqualifier(self) -> bool:
        return self.convictions.filter(is_automatic_disqualifier=True).exists()


class DisqualifyingConviction(TimeStampedModel):
    """
    A conviction recorded against a "Not Clear" criminal record check.

    ``is_automatic_disqualifier`` is the most consequential boolean in the system.
    The policy lists offences that bar someone from every position of trust with **no
    override available** — violent crime with a weapon, and crimes against children,
    youth or vulnerable adults including child abuse, abduction, murder/manslaughter,
    incest, rape and sexual assault (Build Spec §4.3).

    When it is set, the volunteer is permanently blocked and no view, form or service
    offers a way back. Anything else is a *discretionary* red flag, which leadership
    may decide on — but only by recording a :class:`DiscretionaryOverride` with
    reasoning and mitigation.

    The offence description is encrypted: it is among the most sensitive text in the
    system.
    """

    #: Shown in the UI as the checklist an admin works through. Kept as a plain
    #: constant rather than a model so it cannot drift per tenant — these are not
    #: church-configurable, they come from the policy.
    AUTOMATIC_CATEGORIES = [
        "Violent crime involving a weapon",
        "Crime against a child or youth",
        "Crime against a vulnerable adult",
        "Child abuse",
        "Abduction",
        "Murder or manslaughter",
        "Incest",
        "Rape",
        "Sexual assault",
    ]

    crc_record = models.ForeignKey(
        CRCRecord, on_delete=models.PROTECT, related_name="convictions"
    )

    # Plaintext: it is a policy category from a fixed list, not free text about a
    # person, and the audit trail and reports need to show which rule was applied.
    category = models.CharField(
        max_length=100,
        help_text="The policy category this conviction falls under.",
    )
    is_automatic_disqualifier = models.BooleanField(
        help_text=(
            "Automatic disqualifiers permanently bar this person from all positions "
            "of trust. This cannot be overridden."
        ),
    )

    description = EncryptedTextField(
        blank=True,
        default="",
        help_text="Details as disclosed and verified. Encrypted.",
    )
    conviction_date = models.DateField(null=True, blank=True)

    recorded_by = models.CharField(max_length=150, blank=True)

    class Meta:
        ordering = ("-is_automatic_disqualifier", "category")
        verbose_name = "conviction"

    def __str__(self):
        kind = "automatic disqualifier" if self.is_automatic_disqualifier else "discretionary"
        return f"{self.category} ({kind})"

    def delete(self, *args, **kwargs):
        # A recorded disqualifier is not erasable — that would silently unblock
        # someone the policy permanently bars.
        from apps.core.models import ProtectedDeletionError

        raise ProtectedDeletionError(
            "A recorded conviction cannot be deleted. It forms part of the permanent "
            "screening record."
        )


class DiscretionaryOverride(TimeStampedModel):
    """
    A leadership decision on a *discretionary* red flag.

    The policy allows leadership to decide, but only with a documented and permanently
    retained trail: the decision, the reasoning, and the mitigation steps
    (Build Spec §4.3). All three are mandatory here, and the row is immutable once
    written — an override that could be quietly edited afterwards would not be a trail.

    This model is reachable **only** for discretionary flags. Nothing constructs one
    for an automatic disqualifier.
    """

    class Decision(models.TextChoices):
        APPROVED = "approved", "Approved to serve"
        APPROVED_WITH_CONDITIONS = "conditional", "Approved with conditions"
        DECLINED = "declined", "Declined"

    crc_record = models.ForeignKey(
        CRCRecord, on_delete=models.PROTECT, related_name="overrides"
    )
    conviction = models.ForeignKey(
        DisqualifyingConviction,
        on_delete=models.PROTECT,
        related_name="overrides",
        null=True,
        blank=True,
    )

    decision = models.CharField(max_length=16, choices=Decision.choices)
    decided_on = models.DateField(default=timezone.localdate)
    decided_by = models.CharField(
        max_length=150,
        help_text="The leader or leadership body making this decision.",
    )

    # Encrypted: substantive content about a person's history.
    reasoning = EncryptedTextField(help_text="Why this decision was reached. Required.")
    mitigation_steps = EncryptedTextField(
        help_text="What safeguards are in place as a result. Required."
    )

    class Meta:
        ordering = ("-decided_on",)
        verbose_name = "leadership override"

    def __str__(self):
        return f"{self.get_decision_display()} by {self.decided_by} on {self.decided_on}"

    def clean(self):
        super().clean()
        errors = {}
        if not (self.reasoning or "").strip():
            errors["reasoning"] = "Recording the reasoning is mandatory for an override."
        if not (self.mitigation_steps or "").strip():
            errors["mitigation_steps"] = "Recording the mitigation steps is mandatory."
        if not (self.decided_by or "").strip():
            errors["decided_by"] = "Record who made this decision."

        # Belt and braces: refuse to attach an override to an automatic disqualifier
        # even if a caller somehow tried.
        if self.conviction_id and self.conviction.is_automatic_disqualifier:
            errors["conviction"] = (
                "Automatic disqualifiers under the Plan to Protect policy cannot be "
                "overridden."
            )

        if errors:
            raise ValidationError(errors)

    def save(self, *args, **kwargs):
        if self.pk is not None:
            from apps.core.models import ProtectedDeletionError

            raise ProtectedDeletionError(
                "A leadership override is a permanent record and cannot be edited. "
                "Record a new decision instead."
            )
        self.full_clean()
        return super().save(*args, **kwargs)

    def delete(self, *args, **kwargs):
        from apps.core.models import ProtectedDeletionError

        raise ProtectedDeletionError(
            "A leadership override is permanently retained and cannot be deleted."
        )
