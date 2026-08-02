"""
The church's organisational model and the volunteer file.

    Department (0..n)
    └── Role          — belongs to exactly one department
    Volunteer         — a person; the "Ministry Personnel file"
    └── RoleAssignment — volunteer ↔ role, with start/end dates

Two things here are load-bearing for the rest of the system:

* **Role flags.** ``is_leadership`` is the only one, and it marks a leadership position —
  screened exactly like anyone else (Build Spec §3), the flag only records what the
  position *is*. Requirements match roles through it, so it is plaintext and queryable.
  It grants access to nothing, and that stays true now that access levels exist — what an
  administrator may see is set by their :class:`apps.core.models.AccessLevel`, and being a
  *leadership* role in the ministry sense confers nothing in the application. Worth
  keeping straight because the two ideas now sit next to each other: an access level says
  what an **administrator** can do, a leadership flag says what a **volunteer's position**
  is. There are still no volunteer or leader logins at all. Every role is treated as a
  position of trust and as handling personal information, so neither is a flag.
* **A volunteer may be an administrator.** ``Volunteer.user_id`` points at the account, and
  it is what lets VMS refuse to let somebody record their own screening. It is *not* a
  login: the direction is administrator-has-a-file, never file-can-sign-in, and the line
  above stays true. See :func:`apps.core.access.may_record_against` and BUILD_NOTES §1.22.
* **The volunteer's date of birth is split.** ``birth_year`` and ``birth_month`` are
  plaintext integers, because the age rules have to be *queryable* — a nightly job
  finds everyone turning 18 this month. The full date is a separate encrypted field.
  This split was decided on 2026-07-23 and is recorded in PRD §5.

Nothing here can be hard-deleted. Volunteer records are retained permanently,
including after someone stops serving, and departments/roles are protected too so a
tidy-up cannot orphan a volunteer's screening history.
"""

from __future__ import annotations

import datetime

from django.core.exceptions import ValidationError
from django.core.validators import MaxValueValidator, MinValueValidator
from django.db import models
from django.urls import reverse
from django.utils import timezone

from apps.core.fields import (
    EncryptedCharField,
    EncryptedDateField,
    EncryptedEmailField,
    EncryptedTextField,
)
from apps.core.models import NoDeleteModel, NoDeleteQuerySet, TimeStampedModel

#: Nobody in the system predates this; guards against a typo'd birth year.
EARLIEST_BIRTH_YEAR = 1900


class Department(TimeStampedModel, NoDeleteModel):
    """A ministry area, e.g. Children's Ministry or Youth."""

    name = models.CharField(max_length=150, unique=True)
    description = models.TextField(
        blank=True,
        help_text="What this department does. Plain text; visible to all admins.",
    )
    is_active = models.BooleanField(
        default=True,
        help_text="Inactive departments are hidden from pickers but keep their history.",
    )

    class Meta:
        ordering = ("name",)

    def __str__(self):
        return self.name

    def get_absolute_url(self):
        return reverse("org:department_detail", args=[self.pk])


class Role(TimeStampedModel, NoDeleteModel):
    """
    A position within one department.

    Role descriptions are plain text in Stage 1 — the Markdown editor, versioning and
    acknowledgement tracking are explicitly Stage 2 (Build Spec §0).
    """

    department = models.ForeignKey(
        Department,
        on_delete=models.PROTECT,
        related_name="roles",
        help_text="A role belongs to exactly one department.",
    )
    name = models.CharField(max_length=150)
    description = models.TextField(
        blank=True,
        help_text="Plain-text description of the position and its responsibilities.",
    )

    is_leadership = models.BooleanField(
        default=False,
        db_index=True,
        verbose_name="leadership role",
        help_text=(
            "Tick for directors, coordinators and other leadership positions. They are "
            "screened exactly like any other volunteer (Build Spec §3); this only lets "
            "requirements target leadership roles. It grants no access to anything."
        ),
    )
    # There are deliberately no `handles_personal_info` or `is_position_of_trust`
    # flags. Every role in this system is both: a church only enters a volunteer here
    # because they are being screened, and everyone who serves encounters personal
    # information about the people they serve. Making them tickable invited a church to
    # untick one and quietly screen someone less. See BUILD_NOTES.md §1.14.

    is_active = models.BooleanField(default=True)

    class Meta:
        ordering = ("department__name", "name")
        constraints = [
            models.UniqueConstraint(
                fields=["department", "name"], name="unique_role_name_per_department"
            )
        ]

    def __str__(self):
        return f"{self.name} ({self.department.name})"

    def get_absolute_url(self):
        return reverse("org:role_detail", args=[self.pk])


class VolunteerQuerySet(NoDeleteQuerySet):
    """Query helpers that stay on the plaintext side of the encryption split."""

    def active(self):
        return self.filter(is_active=True)

    def serving(self):
        """Volunteers with at least one current role assignment."""
        return self.active().filter(assignments__is_active=True).distinct()

    def in_department(self, department):
        return self.filter(
            assignments__role__department=department, assignments__is_active=True
        ).distinct()

    def ever_in_departments(self, department_ids):
        """
        Volunteers who have **ever** held a role in one of these departments.

        The sibling of :meth:`in_department`, and deliberately next to it, because the
        difference is one clause and picking the wrong one is silent. ``in_department``
        filters ``assignments__is_active=True`` and answers "who is serving here now?" —
        the question a report filter asks. This one omits that clause and answers "whose
        file belongs to this department?" — the question *access scoping* asks.

        The distinction is a product decision, not an oversight: a department admin keeps
        access to the files they worked on after the volunteer stops serving, because
        records involving minors are retained permanently and somebody may have to answer
        a question about a past volunteer years later. One consequence follows and is
        intended — scope only ever grows. See BUILD_NOTES §1.21.
        """
        return self.filter(assignments__role__department_id__in=department_ids).distinct()

    def blocked(self):
        """Volunteers barred from positions of trust (disqualified or CRC not clear)."""
        return self.filter(screening_block__in=ScreeningBlock.blocking_values())

    def possible_matches_for(self, first_name: str, last_name: str):
        """
        Existing files that might already be this person.

        Name-only, because that is all there is: ``email`` is encrypted with a fresh
        nonce per value, so it cannot be compared without decrypting every row. Used to
        *refuse to guess* when an administrator is created — never to merge anything.
        """
        return self.filter(
            first_name__iexact=(first_name or "").strip(),
            last_name__iexact=(last_name or "").strip(),
        )

    def search_by_name(self, term: str):
        """
        Name search.

        Names are plaintext by design (PRD §5) precisely so this works; an encrypted
        name column would make the volunteer list unusable.
        """
        term = (term or "").strip()
        if not term:
            return self
        return self.filter(
            models.Q(first_name__icontains=term) | models.Q(last_name__icontains=term)
        )


class ScreeningBlock(models.TextChoices):
    """
    Why a volunteer is barred from serving, if they are.

    The distinction matters and is not cosmetic:

    * ``DISQUALIFIED`` — an automatic disqualifier under the policy. **Permanent, with
      no override path anywhere in the UI** (Build Spec §4.3).
    * ``CRC_NOT_CLEAR`` — a "Not Clear" result awaiting resolution. Recoverable: the
      volunteer either supplies a fingerprint-verified check, or withdraws.
    * ``WITHDRAWN`` — the volunteer chose not to continue.
    """

    NONE = "none", "Not blocked"
    CRC_NOT_CLEAR = "crc_not_clear", "Blocked — criminal record check not clear"
    DISQUALIFIED = "disqualified", "Permanently disqualified"
    WITHDRAWN = "withdrawn", "Withdrew from screening"

    @classmethod
    def blocking_values(cls) -> list[str]:
        return [cls.CRC_NOT_CLEAR, cls.DISQUALIFIED, cls.WITHDRAWN]


class Volunteer(TimeStampedModel, NoDeleteModel):
    """
    A person's Ministry Personnel file.

    Retained permanently, including after they stop serving — a requirement of the
    policy and of the permanent-retention rule for records involving minors
    (PRD §6). ``is_active`` is the only way to take someone out of circulation.
    """

    # --- Plaintext, queryable (PRD §5) ---------------------------------------
    first_name = models.CharField(max_length=100, db_index=True)
    last_name = models.CharField(max_length=100, db_index=True)
    preferred_name = models.CharField(
        max_length=100, blank=True, help_text="Optional. Used in lists where set."
    )

    # Birth year/month are plaintext so the age rules can be queried. This is the
    # deliberate exception to encrypting date of birth; see the module docstring.
    birth_year = models.PositiveIntegerField(
        null=True,
        blank=True,
        db_index=True,
        validators=[MinValueValidator(EARLIEST_BIRTH_YEAR), MaxValueValidator(2100)],
        help_text="Required to apply the under-18 and turning-18 rules.",
    )
    birth_month = models.PositiveSmallIntegerField(
        null=True,
        blank=True,
        db_index=True,
        validators=[MinValueValidator(1), MaxValueValidator(12)],
    )

    # --- Encrypted (PRD §5) --------------------------------------------------
    date_of_birth = EncryptedDateField(
        null=True,
        blank=True,
        verbose_name="full date of birth",
        help_text="Encrypted. The year and month are stored separately to drive age rules.",
    )
    email = EncryptedEmailField(blank=True, default="", help_text="Encrypted.")
    phone = EncryptedCharField(max_length=40, blank=True, default="", help_text="Encrypted.")
    address = EncryptedTextField(
        blank=True, default="", verbose_name="home address", help_text="Encrypted."
    )
    emergency_contact = EncryptedTextField(
        blank=True,
        default="",
        help_text="Name, relationship and phone number. Encrypted.",
    )
    medical_notes = EncryptedTextField(
        blank=True,
        default="",
        verbose_name="medical / allergy details",
        help_text="Encrypted. Record only what is needed to keep this person safe.",
    )
    notes = EncryptedTextField(blank=True, default="", help_text="Encrypted admin notes.")

    # --- Screening state -----------------------------------------------------
    attendance_since = models.DateField(
        null=True,
        blank=True,
        help_text=(
            "When regular attendance began. Drives the six-month waiting period; "
            "leave blank for a transfer with references from a previous minister."
        ),
    )
    is_transfer = models.BooleanField(
        default=False,
        help_text=(
            "Transferring from another church. The waiting period may be waived given "
            "three references including the previous minister."
        ),
    )

    screening_block = models.CharField(
        max_length=16,
        choices=ScreeningBlock.choices,
        default=ScreeningBlock.NONE,
        db_index=True,
        editable=False,
        help_text="Maintained by the criminal-record-check flow; not directly editable.",
    )
    screening_block_recorded_at = models.DateTimeField(null=True, blank=True, editable=False)

    is_active = models.BooleanField(
        default=True,
        db_index=True,
        help_text="Untick when someone stops serving. The file is always retained.",
    )
    stopped_serving_on = models.DateField(null=True, blank=True)

    # --- The administrator this file belongs to, if any ----------------------
    #
    # A plain integer, deliberately, and **not** a ``OneToOneField`` to ``User``. The
    # relation creates cleanly; what breaks is deletion. A relation gives ``User`` a
    # reverse accessor, and that accessor is a Python-level fact present in every schema
    # — including ``public``, where ``org_volunteer`` does not exist. Django's cascade
    # collector walks it on ``User.delete()`` and the delete dies with ``UndefinedTable``
    # in code that has nothing to do with volunteers. ``UserAccessGrant.user_id``
    # (apps/core/models.py) carries the same scar and the same comment; it cost 74
    # failing tests to learn once.
    #
    # ``unique`` with ``null=True`` is exactly the constraint wanted: Postgres permits
    # many NULLs in a unique index, so this reads "at most one file per administrator,
    # and most files belong to nobody".
    user_id = models.IntegerField(
        null=True,
        blank=True,
        unique=True,
        db_index=True,
        editable=False,
        verbose_name="linked administrator",
        help_text=(
            "Set when this volunteer is also a screening administrator. Nobody may "
            "record screening against their own file while somebody else could."
        ),
    )

    objects = VolunteerQuerySet.as_manager()

    class Meta:
        ordering = ("last_name", "first_name")
        indexes = [
            models.Index(fields=["last_name", "first_name"]),
            models.Index(fields=["birth_year", "birth_month"]),
            models.Index(fields=["is_active", "screening_block"]),
        ]

    def __str__(self):
        return self.display_name

    def get_absolute_url(self):
        return reverse("org:volunteer_detail", args=[self.pk])

    # -- Names ------------------------------------------------------------

    @property
    def display_name(self) -> str:
        first = self.preferred_name or self.first_name
        return f"{first} {self.last_name}".strip()

    @property
    def full_name(self) -> str:
        return f"{self.first_name} {self.last_name}".strip()

    @property
    def sort_name(self) -> str:
        return f"{self.last_name}, {self.first_name}".strip(", ")

    # -- Validation -------------------------------------------------------

    def clean(self):
        super().clean()
        errors = {}

        # Keep the plaintext year/month consistent with the encrypted full date, so
        # the age rules and the displayed date can never disagree.
        if self.date_of_birth:
            if self.birth_year and self.birth_year != self.date_of_birth.year:
                errors["birth_year"] = "Does not match the full date of birth."
            if self.birth_month and self.birth_month != self.date_of_birth.month:
                errors["birth_month"] = "Does not match the full date of birth."

        if (self.birth_month is not None) != (self.birth_year is not None):
            # A month with no year cannot place someone in time; a year alone is
            # usable but ambiguous, so require the pair.
            errors.setdefault(
                "birth_month" if self.birth_year else "birth_year",
                "Enter both a birth year and a birth month, or neither.",
            )

        if self.birth_year and self.birth_year > timezone.localdate().year:
            errors["birth_year"] = "Cannot be in the future."

        if not self.is_active and not self.stopped_serving_on:
            errors["stopped_serving_on"] = "Record the date this volunteer stopped serving."

        if errors:
            raise ValidationError(errors)

    def save(self, *args, **kwargs):
        # Derive the queryable parts from the full date whenever it is known, so a
        # caller cannot forget to keep them in step.
        if self.date_of_birth:
            self.birth_year = self.date_of_birth.year
            self.birth_month = self.date_of_birth.month
            if "update_fields" in kwargs and kwargs["update_fields"] is not None:
                kwargs["update_fields"] = set(kwargs["update_fields"]) | {
                    "birth_year",
                    "birth_month",
                }
        return super().save(*args, **kwargs)

    # -- Age rules (Build Spec §4.4) --------------------------------------

    @property
    def has_birth_date(self) -> bool:
        return self.birth_year is not None and self.birth_month is not None

    # The plaintext columns know the year and month but not the day, so age has to
    # be computed from an assumed day. VMS assumes the **1st of the birth month**.
    #
    # That single convention makes every age rule agree with itself: the CRC
    # requirement becomes applicable, and the turning-18 deadline starts, on exactly
    # the same date. It errs up to a month *early*, which is the compliance-safe
    # direction the spec asks for — "early is compliance-safe; never late"
    # (Build Spec §4.4). Erring the other way could leave a person who is already 18
    # serving without a criminal record check.

    def age_on(self, on_date: datetime.date | None = None) -> int | None:
        """Age in whole years on ``on_date``, treating the birthday as the 1st of the birth month."""
        if not self.has_birth_date:
            return None
        on_date = on_date or timezone.localdate()
        years = on_date.year - self.birth_year
        if on_date.month < self.birth_month:
            years -= 1
        return max(years, 0)

    @property
    def age(self) -> int | None:
        """Age from the plaintext year/month. May read up to a month high; see above."""
        return self.age_on()

    @property
    def exact_age(self) -> int | None:
        """
        Age from the full encrypted date of birth.

        Only for the volunteer's own detail page — it decrypts a field, so it must not
        be used in a list or report that renders many rows.
        """
        dob = self.date_of_birth
        if not dob:
            return None
        today = timezone.localdate()
        return today.year - dob.year - ((today.month, today.day) < (dob.month, dob.day))

    def is_adult_on(self, on_date: datetime.date | None = None) -> bool:
        """
        Whether this person counts as 18+ on ``on_date``.

        An unknown date of birth returns False, i.e. treated as a minor, which makes
        the criminal record check ``not_applicable`` rather than silently satisfied.
        The missing date of birth is surfaced separately as a gap on the volunteer's
        record, so it does not just disappear.
        """
        age = self.age_on(on_date)
        return age is not None and age >= 18

    @property
    def is_adult(self) -> bool:
        return self.is_adult_on()

    @property
    def is_minor(self) -> bool:
        return self.has_birth_date and not self.is_adult

    def eighteenth_birthday_trigger_date(self) -> datetime.date | None:
        """
        The date the criminal record check becomes due on turning 18.

        The 1st of the birth month of their 18th year — the same instant
        :meth:`is_adult_on` starts returning True. The policy then allows three
        months to submit the check (Build Spec §4.4).
        """
        if not self.has_birth_date:
            return None
        return datetime.date(self.birth_year + 18, self.birth_month, 1)

    # -- Blocks -----------------------------------------------------------

    @property
    def is_blocked(self) -> bool:
        return self.screening_block in ScreeningBlock.blocking_values()

    @property
    def is_permanently_disqualified(self) -> bool:
        """
        Permanently barred from all positions of trust.

        There is no route back from this state — no view, form or service offers one
        (Build Spec §4.3).
        """
        return self.screening_block == ScreeningBlock.DISQUALIFIED

    def set_screening_block(self, block: str) -> None:
        """
        Set or clear the screening block.

        Refuses to move off ``DISQUALIFIED``: an automatic disqualifier is permanent
        and has no override, so the model layer closes that door rather than relying
        on every caller to remember.
        """
        if self.screening_block == ScreeningBlock.DISQUALIFIED and block != ScreeningBlock.DISQUALIFIED:
            raise ValidationError(
                "An automatic disqualification under the Plan to Protect policy is "
                "permanent and cannot be lifted."
            )
        self.screening_block = block
        self.screening_block_recorded_at = (
            timezone.now() if block != ScreeningBlock.NONE else None
        )
        self.save(update_fields=["screening_block", "screening_block_recorded_at", "updated_at"])

    # -- Roles ------------------------------------------------------------

    @property
    def active_roles(self):
        return Role.objects.filter(assignments__volunteer=self, assignments__is_active=True)

    # -- Waiting period ---------------------------------------------------

    @property
    def waiting_period_satisfied(self) -> bool:
        """
        Six months of regular attendance, or a transfer with references.

        The transfer exception comes from the policy (Build Spec §4.2 item 1); the
        references themselves are tracked as their own requirement, so this only
        reflects the attendance side.
        """
        if self.is_transfer:
            return True
        if not self.attendance_since:
            return False
        months = (timezone.localdate() - self.attendance_since).days / 30.44
        return months >= 6


class RoleAssignment(TimeStampedModel, NoDeleteModel):
    """
    A volunteer serving in a role.

    Ending an assignment sets ``is_active`` False and records ``ended_on``; the row
    stays, because "who was serving where, when" is exactly what an insurer asks.
    """

    volunteer = models.ForeignKey(
        Volunteer, on_delete=models.PROTECT, related_name="assignments"
    )
    role = models.ForeignKey(Role, on_delete=models.PROTECT, related_name="assignments")

    started_on = models.DateField(default=timezone.localdate)
    ended_on = models.DateField(null=True, blank=True)
    is_active = models.BooleanField(default=True, db_index=True)

    class Meta:
        ordering = ("-is_active", "-started_on")
        constraints = [
            # One *current* assignment per volunteer/role pair. Historical rows are
            # unconstrained, so someone can serve, stop, and return.
            models.UniqueConstraint(
                fields=["volunteer", "role"],
                condition=models.Q(is_active=True),
                name="unique_active_assignment",
            )
        ]
        indexes = [models.Index(fields=["role", "is_active"])]

    def __str__(self):
        state = "" if self.is_active else " (ended)"
        return f"{self.volunteer.display_name} — {self.role.name}{state}"

    def clean(self):
        super().clean()
        errors = {}
        if self.ended_on and self.ended_on < self.started_on:
            errors["ended_on"] = "Cannot be before the start date."
        if not self.is_active and not self.ended_on:
            errors["ended_on"] = "Record when this assignment ended."

        # A permanently disqualified volunteer may not be placed in any role. Enforced
        # here as well as in the view, so no code path can bypass it.
        #
        # This used to exempt roles that were not marked a position of trust, which was
        # the only way a disqualified person could still be given something to do. Every
        # role is now a position of trust by definition, so the exemption is gone and
        # disqualification means they cannot serve anywhere.
        if (
            self.is_active
            and self.volunteer_id
            and self.role_id
            and self.volunteer.is_permanently_disqualified
        ):
            errors["role"] = (
                "This volunteer is permanently disqualified under the Plan to Protect "
                "policy and cannot be assigned to any role."
            )

        if errors:
            raise ValidationError(errors)

    def end(self, on: datetime.date | None = None) -> None:
        self.is_active = False
        self.ended_on = on or timezone.localdate()
        self.save(update_fields=["is_active", "ended_on", "updated_at"])
