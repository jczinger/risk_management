"""
Forms for departments, roles and volunteer records.

Several of these take a ``user`` and narrow a dropdown to what that person
administers. Two things to hold onto when reading them:

* A narrowed queryset is an **affordance, not a control**. It stops an admin picking
  something they should not, and it stops the page listing every department and role
  name at the church — an org-chart leak with no view behind it. What actually refuses a
  posted id is the field's own validation against that same queryset, plus the scoped
  lookup in the view.
* ``user=None`` means unscoped, so a caller that has no user (a management command, a
  test) behaves as before.
"""

from __future__ import annotations

from django import forms
from django.db.models import Q
from django.utils import timezone

from apps.core.access import scope_departments, scope_roles

from .models import Department, Role, RoleAssignment, Volunteer


def role_label(role: Role, leadership: bool = True) -> str:
    """How a role reads in a dropdown: department → role, flagged when it leads."""
    label = f"{role.department.name} → {role.name}"
    if leadership and role.is_leadership:
        label += " (leadership)"
    return label


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
            "is_leadership",
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

    def __init__(self, *args, user=None, **kwargs):
        super().__init__(*args, **kwargs)
        # Only offer live departments, but never hide the one already selected on an
        # existing role — that would silently reassign it on save.
        criteria = Q(is_active=True)
        if self.instance.pk and self.instance.department_id:
            criteria |= Q(pk=self.instance.department_id)
        # Scoped defensively. Creating departments and roles is Primary-Admin-only today,
        # so this changes nothing — but the capability is a tick on an access level, and
        # the moment a church grants MANAGE_ORG to a limited level, this field is how
        # they would otherwise create a role in somebody else's department.
        self.fields["department"].queryset = scope_departments(
            Department.objects.filter(criteria), user
        )


class VolunteerForm(forms.ModelForm):
    """
    The Ministry Personnel file.

    Date of birth is a single field here; the model derives the plaintext year and
    month from it. Admins are not asked to enter the same thing twice.

    On **creation** a starting ministry role is required; on an edit the field is not
    there at all. That asymmetry is the point. A volunteer belongs to a department only
    through a role assignment, so a volunteer created without one belongs to nowhere —
    and the department admin who just created them would immediately lose sight of them,
    because scoping works through exactly that relationship. Requiring the role at
    intake means that state never exists. By the time anyone edits the record, the
    assignment is there and is managed on its own screen.
    """

    starting_role = forms.ModelChoiceField(
        queryset=Role.objects.none(),
        label="Starting role",
        help_text=(
            "Every volunteer belongs to a department through the role they serve in. "
            "More roles can be added afterwards."
        ),
    )

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

    def __init__(self, *args, user=None, **kwargs):
        super().__init__(*args, **kwargs)
        if self.instance.pk:
            # An edit. The volunteer already has assignments, managed on their own file.
            del self.fields["starting_role"]
        else:
            self.fields["starting_role"].queryset = scope_roles(
                Role.objects.filter(is_active=True, department__is_active=True).select_related(
                    "department"
                ),
                user,
            )
            self.fields["starting_role"].label_from_instance = role_label

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

    def __init__(self, *args, volunteer: Volunteer | None = None, user=None, **kwargs):
        self.volunteer = volunteer
        super().__init__(*args, **kwargs)

        # Scoped: this is both the intake path and the only way a volunteer enters a
        # scoped admin's view, so the roles on offer must be ones they administer.
        queryset = scope_roles(
            Role.objects.filter(is_active=True, department__is_active=True).select_related(
                "department"
            ),
            user,
        )
        if volunteer is not None:
            # Don't offer a role they already hold.
            held = volunteer.assignments.filter(is_active=True).values_list("role_id", flat=True)
            queryset = queryset.exclude(pk__in=list(held))

            # A permanently disqualified volunteer cannot be placed in any role, since
            # every role is a position of trust. Emptying the list would render a silent
            # blank dropdown, so say why instead — the model refuses the assignment
            # regardless, this only stops the admin discovering that by trial.
            if volunteer.is_permanently_disqualified:
                queryset = queryset.none()
                self.fields["role"].empty_label = None
                self.fields["role"].help_text = (
                    "This volunteer is permanently disqualified under the Plan to "
                    "Protect policy and cannot be assigned to any role."
                )

        self.fields["role"].queryset = queryset
        self.fields["role"].label_from_instance = role_label

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

    def __init__(self, *args, user=None, **kwargs):
        super().__init__(*args, **kwargs)
        # Scoped even though the results would be empty anyway once volunteer_list is
        # scoped: an unscoped dropdown still enumerates every department and every role
        # name at the church, which is the org chart with no view attached to it.
        self.fields["department"].queryset = scope_departments(
            Department.objects.filter(is_active=True), user
        )
        self.fields["role"].queryset = scope_roles(
            Role.objects.filter(is_active=True).select_related("department"), user
        )
        self.fields["role"].label_from_instance = lambda role: role_label(role, leadership=False)
