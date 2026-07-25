"""Forms for departments, roles and volunteer records."""

from __future__ import annotations

from django import forms
from django.db.models import Q
from django.utils import timezone

from .models import Department, Role, RoleAssignment, Volunteer


class DepartmentForm(forms.ModelForm):
    class Meta:
        model = Department
        fields = ["name", "description", "is_active"]
        widgets = {"description": forms.Textarea(attrs={"rows": 3})}
        help_texts = {
            "is_active": "Inactive departments are hidden from pickers but keep their history.",
        }


class RoleForm(forms.ModelForm):
    class Meta:
        model = Role
        fields = [
            "department",
            "name",
            "description",
            "leadership",
            "is_position_of_trust",
            "handles_personal_info",
            "is_active",
        ]
        widgets = {
            "description": forms.Textarea(
                attrs={
                    "rows": 5,
                    "placeholder": (
                        "What this position involves, who it reports to, and what "
                        "contact it has with children, youth or vulnerable adults."
                    ),
                }
            ),
        }

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        # Only offer live departments, but never hide the one already selected on an
        # existing role — that would silently reassign it on save.
        criteria = Q(is_active=True)
        if self.instance.pk and self.instance.department_id:
            criteria |= Q(pk=self.instance.department_id)
        self.fields["department"].queryset = Department.objects.filter(criteria)


class VolunteerForm(forms.ModelForm):
    """
    The Ministry Personnel file.

    Date of birth is a single field here; the model derives the plaintext year and
    month from it. Admins are not asked to enter the same thing twice.
    """

    class Meta:
        model = Volunteer
        fields = [
            "first_name",
            "last_name",
            "preferred_name",
            "date_of_birth",
            "email",
            "phone",
            "address",
            "emergency_contact",
            "medical_notes",
            "attendance_since",
            "is_transfer",
            "notes",
        ]
        widgets = {
            "attendance_since": forms.DateInput(attrs={"type": "date"}, format="%Y-%m-%d"),
            "address": forms.Textarea(attrs={"rows": 3}),
            "emergency_contact": forms.Textarea(
                attrs={"rows": 2, "placeholder": "Name, relationship, phone number"}
            ),
            "medical_notes": forms.Textarea(attrs={"rows": 2}),
            "notes": forms.Textarea(attrs={"rows": 3}),
        }
        labels = {"is_transfer": "Transferring from another church"}
        help_texts = {
            "date_of_birth": (
                "Encrypted. Needed to apply the under-18 exemption and the "
                "criminal-record-check rule on turning 18."
            ),
            "medical_notes": (
                "Encrypted. Record only what is needed to keep this person safe."
            ),
        }

    def clean_date_of_birth(self):
        dob = self.cleaned_data.get("date_of_birth")
        if dob and dob > timezone.localdate():
            raise forms.ValidationError("Cannot be in the future.")
        if dob and dob.year < 1900:
            raise forms.ValidationError("Please check the year.")
        return dob


class VolunteerDeactivateForm(forms.Form):
    """
    Take a volunteer out of service.

    Never a deletion: the record is retained permanently, which is both the policy's
    requirement and the law's for records involving minors.
    """

    stopped_serving_on = forms.DateField(
        label="Last day serving",
        initial=timezone.localdate,
        widget=forms.DateInput(attrs={"type": "date"}, format="%Y-%m-%d"),
    )
    end_assignments = forms.BooleanField(
        label="End all current role assignments",
        required=False,
        initial=True,
    )
    reason = forms.CharField(
        label="Reason (optional)",
        required=False,
        widget=forms.Textarea(attrs={"rows": 2}),
        help_text="Recorded in the audit trail.",
    )

    def clean_stopped_serving_on(self):
        value = self.cleaned_data["stopped_serving_on"]
        if value > timezone.localdate():
            raise forms.ValidationError("Cannot be in the future.")
        return value


class RoleAssignmentForm(forms.ModelForm):
    """Place a volunteer in a role."""

    class Meta:
        model = RoleAssignment
        fields = ["role", "started_on"]
        widgets = {
            "started_on": forms.DateInput(attrs={"type": "date"}, format="%Y-%m-%d"),
        }

    def __init__(self, *args, volunteer: Volunteer | None = None, **kwargs):
        self.volunteer = volunteer
        super().__init__(*args, **kwargs)

        queryset = Role.objects.filter(is_active=True, department__is_active=True).select_related(
            "department"
        )
        if volunteer is not None:
            # Don't offer a role they already hold.
            held = volunteer.assignments.filter(is_active=True).values_list("role_id", flat=True)
            queryset = queryset.exclude(pk__in=list(held))

            # A permanently disqualified volunteer cannot be placed in a position of
            # trust. The model refuses it too; excluding them here means the admin is
            # never offered an option that will be rejected.
            if volunteer.is_permanently_disqualified:
                queryset = queryset.filter(is_position_of_trust=False)

        self.fields["role"].queryset = queryset
        self.fields["role"].label_from_instance = (
            lambda role: f"{role.department.name} → {role.name}"
            + (f" ({role.get_leadership_display()})" if role.is_leadership else "")
        )

    def clean(self):
        cleaned = super().clean()
        if self.volunteer is not None:
            self.instance.volunteer = self.volunteer
        return cleaned


class RoleAssignmentEndForm(forms.Form):
    ended_on = forms.DateField(
        label="Last day in this role",
        initial=timezone.localdate,
        widget=forms.DateInput(attrs={"type": "date"}, format="%Y-%m-%d"),
    )


class VolunteerFilterForm(forms.Form):
    """The volunteer list's filters. Every field here is plaintext and queryable."""

    q = forms.CharField(
        label="Search by name",
        required=False,
        widget=forms.TextInput(
            attrs={"placeholder": "Name…", "autocomplete": "off"}
        ),
    )
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
    status = forms.ChoiceField(
        required=False,
        choices=[
            ("", "Everyone currently serving"),
            ("all", "Everyone, including past volunteers"),
            ("inactive", "No longer serving"),
            ("unassigned", "No current role"),
            ("blocked", "Blocked or disqualified"),
            ("minors", "Under 18"),
        ],
    )

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields["role"].label_from_instance = (
            lambda role: f"{role.department.name} → {role.name}"
        )
