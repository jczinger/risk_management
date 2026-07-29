"""
Forms for the requirement engine.

The criminal-record-check forms carry the system's sharpest edge. Note what is
deliberately absent: there is **no form, field or flow anywhere that lifts an automatic
disqualification**. :class:`DiscretionaryOverrideForm` only ever offers discretionary
convictions, and the service layer rejects the rest even if a request were forged
(Build Spec §4.3).
"""

from __future__ import annotations

from django import forms
from django.utils import timezone

from apps.org.models import Department, Role

from .models import (
    AgeRule,
    AppliesTo,
    Cadence,
    CRCNotClearOutcome,
    CRCResult,
    DependencyMode,
    DisqualifyingConviction,
    DiscretionaryOverride,
    RequirementDefinition,
)


class RequirementDefinitionForm(forms.ModelForm):
    """
    Create or edit a requirement.

    Definitions are versionless in Stage 1: an edit applies going forward and does not
    rewrite what volunteers have already completed. The form says so, because the
    difference matters to whoever is editing.
    """

    class Meta:
        model = RequirementDefinition
        fields = [
            "name",
            "requirement_type",
            "description",
            "appendix_reference",
            "cadence",
            "cadence_months",
            "applies_to",
            "roles",
            "age_rule",
            "sequence",
            "is_onboarding",
            "must_follow",
            "dependency_mode",
            "due_months_after_prerequisite",
            "requires_document",
            "is_active",
        ]
        widgets = {
            "description": forms.Textarea(attrs={"rows": 4}),
            "roles": forms.CheckboxSelectMultiple,
        }
        help_texts = {
            "sequence": "Lower numbers appear earlier in the onboarding checklist.",
            "age_rule": (
                "'Adults only' exempts under-18s automatically and switches the "
                "requirement on when they turn 18."
            ),
            "must_follow": (
                "Optional. The requirement that comes first — the liability release "
                "before references, or orientation training before the refresher."
            ),
        }

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields["roles"].queryset = Role.objects.filter(is_active=True).select_related(
            "department"
        )
        self.fields["roles"].label_from_instance = (
            lambda role: f"{role.department.name} → {role.name}"
        )
        self.fields["roles"].required = False

        must_follow = RequirementDefinition.objects.active()
        if self.instance.pk:
            # Exclude anything downstream of this requirement, not merely itself, so a
            # loop cannot be picked in the first place. The model's clean() is still the
            # backstop for anything that bypasses this form.
            must_follow = must_follow.exclude(pk__in=self.instance.dependent_pks())
        self.fields["must_follow"].queryset = must_follow
        self.fields["must_follow"].empty_label = "No dependency"

    def clean(self):
        cleaned = super().clean()

        if cleaned.get("cadence") == Cadence.CUSTOM_MONTHS and not cleaned.get("cadence_months"):
            self.add_error("cadence_months", "Enter the number of months between renewals.")

        if cleaned.get("applies_to") == AppliesTo.SPECIFIC_ROLES and not cleaned.get("roles"):
            self.add_error("roles", "Select at least one role, or choose a different rule.")

        follows = cleaned.get("must_follow")
        if not follows and cleaned.get("dependency_mode") == DependencyMode.GATE:
            self.add_error("must_follow", "Choose the requirement this one waits for.")
        if not follows and cleaned.get("due_months_after_prerequisite"):
            self.add_error(
                "due_months_after_prerequisite",
                "Only applies when this requirement follows another one.",
            )

        return cleaned


class RequirementCompleteForm(forms.Form):
    """Record a requirement as satisfied."""

    completed_on = forms.DateField(
        label="Date completed",
        initial=timezone.localdate,
        widget=forms.DateInput(attrs={"type": "date"}, format="%Y-%m-%d"),
    )
    notes = forms.CharField(
        label="Notes",
        required=False,
        widget=forms.Textarea(attrs={"rows": 3}),
        help_text=(
            "Encrypted. For reference checks, record what each referee said here."
        ),
    )

    def clean_completed_on(self):
        value = self.cleaned_data["completed_on"]
        if value > timezone.localdate():
            raise forms.ValidationError("Cannot be in the future.")
        return value


class RequirementWaiveForm(forms.Form):
    """Waive a requirement. A reason is mandatory and goes to the audit trail."""

    reason = forms.CharField(
        label="Why is this being waived?",
        widget=forms.Textarea(attrs={"rows": 3}),
        help_text="Required. Recorded permanently in the audit trail.",
    )
    waived_by = forms.CharField(
        label="Authorised by",
        max_length=150,
        help_text="The leader authorising this waiver.",
    )

    def clean_reason(self):
        value = (self.cleaned_data["reason"] or "").strip()
        if len(value) < 10:
            raise forms.ValidationError(
                "Please give a fuller reason — this is the permanent record of why the "
                "requirement was set aside."
            )
        return value


class WaiverReversalForm(forms.Form):
    """
    Undo a waiver. The comment is mandatory and is what the audit trail will show.

    ``reason`` is capped as well as floored. The comment is written into the audit
    entry's *summary*, because that is the only part of an entry the trail displays —
    and a summary is 255 characters. Capping it here means an admin's explanation is
    refused up front rather than silently cut in half after the fact.
    """

    #: Leaves room for the "Waiver reversed by <name>: " prefix inside a 255-char summary.
    MAX_REASON = 200

    reason = forms.CharField(
        label="Why is this waiver being reversed?",
        widget=forms.Textarea(attrs={"rows": 3}),
        max_length=MAX_REASON,
        help_text=(
            f"Required, up to {MAX_REASON} characters so it appears in full in the "
            "audit trail. Say what was wrong with the waiver."
        ),
    )
    reversed_by = forms.CharField(
        label="Authorised by",
        max_length=150,
        help_text="The leader authorising the reversal.",
    )

    def clean_reason(self):
        value = (self.cleaned_data["reason"] or "").strip()
        if len(value) < 10:
            raise forms.ValidationError(
                "Please give a fuller reason — this is the record of why a recorded "
                "decision was undone."
            )
        return value


class CRCRecordForm(forms.Form):
    """
    Record a criminal record check result.

    The report date drives the three-year clock, so it is the date on the clearance
    letter — not the date it was filed.
    """

    result = forms.ChoiceField(
        label="Result",
        choices=CRCResult.choices,
        widget=forms.RadioSelect,
    )
    report_date = forms.DateField(
        label="Date on the report",
        initial=timezone.localdate,
        widget=forms.DateInput(attrs={"type": "date"}, format="%Y-%m-%d"),
        help_text="The three-year renewal is counted from this date.",
    )
    includes_vulnerable_sector = forms.BooleanField(
        label="Includes the vulnerable sector search",
        required=False,
        initial=True,
        help_text="Required for positions of trust.",
    )
    is_fingerprint_verified = forms.BooleanField(
        label="Fingerprint-verified check",
        required=False,
        help_text="Tick if this is a fingerprint-verified check following a 'Not Clear' result.",
    )
    issuing_body = forms.CharField(
        label="Issued by",
        max_length=150,
        required=False,
        widget=forms.TextInput(
            attrs={"placeholder": "e.g. BC Criminal Record Review Program"}
        ),
    )
    notes = forms.CharField(
        required=False,
        widget=forms.Textarea(attrs={"rows": 3}),
        help_text="Encrypted.",
    )

    def clean_report_date(self):
        value = self.cleaned_data["report_date"]
        if value > timezone.localdate():
            raise forms.ValidationError("Cannot be in the future.")
        return value

    def clean(self):
        cleaned = super().clean()
        if cleaned.get("result") == CRCResult.CLEARED and not cleaned.get(
            "includes_vulnerable_sector"
        ):
            # Not an error — some roles are not positions of trust — but worth flagging.
            self.add_error(
                "includes_vulnerable_sector",
                "A vulnerable sector search is required for positions of trust. Untick "
                "only if this check genuinely did not include one.",
            )
        return cleaned


class ConvictionForm(forms.Form):
    """
    Record one conviction against a Not Clear result.

    The category list is fixed by the policy, not by the church, so it is a choice
    field rather than free text — and choosing an automatic category is what triggers a
    permanent, non-overridable disqualification. The form says that in plain language
    before the admin commits.
    """

    AUTOMATIC_CHOICES = [(c, c) for c in DisqualifyingConviction.AUTOMATIC_CATEGORIES]
    DISCRETIONARY_CHOICES = [
        ("Theft or fraud", "Theft or fraud"),
        ("Drug-related offence", "Drug-related offence"),
        ("Impaired driving", "Impaired driving"),
        ("Assault (no weapon, adult victim)", "Assault (no weapon, adult victim)"),
        ("Property offence", "Property offence"),
        ("Other — discretionary", "Other — discretionary"),
    ]

    category = forms.ChoiceField(
        label="Policy category",
        choices=[
            ("", "Select the category…"),
            (
                "Automatic disqualifiers — permanent, no override",
                AUTOMATIC_CHOICES,
            ),
            ("Discretionary — requires a leadership decision", DISCRETIONARY_CHOICES),
        ],
    )
    description = forms.CharField(
        label="Details as disclosed and verified",
        required=False,
        widget=forms.Textarea(attrs={"rows": 3}),
        help_text="Encrypted.",
    )
    conviction_date = forms.DateField(
        required=False,
        widget=forms.DateInput(attrs={"type": "date"}, format="%Y-%m-%d"),
    )
    acknowledge_permanent = forms.BooleanField(
        required=False,
        label=(
            "I understand that recording an automatic disqualifier permanently bars "
            "this person from every position of trust, and that this cannot be undone "
            "or overridden."
        ),
    )

    @property
    def is_automatic(self) -> bool:
        category = (self.data.get("category") or "").strip()
        return category in DisqualifyingConviction.AUTOMATIC_CATEGORIES

    def clean(self):
        cleaned = super().clean()
        category = cleaned.get("category", "")
        automatic = category in DisqualifyingConviction.AUTOMATIC_CATEGORIES

        # A deliberate speed bump. The consequence is permanent, so it takes a
        # separate, explicit acknowledgement.
        if automatic and not cleaned.get("acknowledge_permanent"):
            self.add_error(
                "acknowledge_permanent",
                "Please confirm you understand this is permanent before continuing.",
            )

        cleaned["is_automatic_disqualifier"] = automatic
        return cleaned


class NotClearOutcomeForm(forms.Form):
    """
    Record how a Not Clear result was resolved.

    Only the two outcomes the policy allows are offered.
    """

    outcome = forms.ChoiceField(
        label="Outcome",
        choices=[
            (CRCNotClearOutcome.FINGERPRINT_SUBMITTED, CRCNotClearOutcome.FINGERPRINT_SUBMITTED.label),
            (CRCNotClearOutcome.WITHDREW, CRCNotClearOutcome.WITHDREW.label),
        ],
        widget=forms.RadioSelect,
    )
    notes = forms.CharField(
        required=False,
        widget=forms.Textarea(attrs={"rows": 3}),
        help_text="Encrypted.",
    )


class DiscretionaryOverrideForm(forms.Form):
    """
    A leadership decision on a discretionary red flag.

    Reasoning and mitigation steps are both mandatory and permanently retained. The
    conviction dropdown lists **only** discretionary convictions — an automatic
    disqualifier is never offered here, and the service layer refuses one anyway.
    """

    conviction = forms.ModelChoiceField(
        queryset=DisqualifyingConviction.objects.none(),
        required=False,
        empty_label="The check as a whole",
        label="Which flag is this decision about?",
    )
    decision = forms.ChoiceField(
        choices=DiscretionaryOverride.Decision.choices,
        widget=forms.RadioSelect,
    )
    decided_by = forms.CharField(
        label="Decided by",
        max_length=150,
        help_text="The leader or leadership body making this decision.",
    )
    decided_on = forms.DateField(
        initial=timezone.localdate,
        widget=forms.DateInput(attrs={"type": "date"}, format="%Y-%m-%d"),
    )
    reasoning = forms.CharField(
        label="Reasoning",
        widget=forms.Textarea(attrs={"rows": 4}),
        help_text=(
            "Required. Why this decision was reached. Encrypted and retained permanently."
        ),
    )
    mitigation_steps = forms.CharField(
        label="Mitigation steps",
        widget=forms.Textarea(attrs={"rows": 4}),
        help_text=(
            "Required. What safeguards are being put in place — supervision "
            "arrangements, restrictions on the role, review points."
        ),
    )

    def __init__(self, *args, crc_record=None, **kwargs):
        super().__init__(*args, **kwargs)
        if crc_record is not None:
            self.fields["conviction"].queryset = crc_record.convictions.filter(
                is_automatic_disqualifier=False
            )

    def _clean_substantive(self, field: str, label: str) -> str:
        value = (self.cleaned_data.get(field) or "").strip()
        if len(value) < 20:
            raise forms.ValidationError(
                f"Please set out the {label} properly. This is the permanent record of "
                "a decision that will be reviewed by leadership and possibly an insurer."
            )
        return value

    def clean_reasoning(self):
        return self._clean_substantive("reasoning", "reasoning")

    def clean_mitigation_steps(self):
        return self._clean_substantive("mitigation_steps", "mitigation steps")


class RequirementFilterForm(forms.Form):
    """Filters shared by the dashboard and the compliance report."""

    department = forms.ModelChoiceField(
        queryset=Department.objects.filter(is_active=True),
        required=False,
        empty_label="All departments",
    )
    role = forms.ModelChoiceField(
        queryset=Role.objects.filter(is_active=True).select_related("department"),
        required=False,
        empty_label="All roles",
    )
    requirement_type = forms.ChoiceField(required=False, choices=[])
    bucket = forms.ChoiceField(
        required=False,
        label="Show",
        choices=[
            ("", "Everything outstanding"),
            ("overdue", "Overdue only"),
            ("due_soon", "Coming due (60 days)"),
            ("all", "Everything, including compliant"),
        ],
    )

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        from .models import RequirementType

        self.fields["requirement_type"].choices = [
            ("", "All requirement types")
        ] + list(RequirementType.choices)
        self.fields["role"].label_from_instance = (
            lambda role: f"{role.department.name} → {role.name}"
        )
