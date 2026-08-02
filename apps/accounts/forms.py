"""Sign-in and account-management forms."""

from __future__ import annotations

from django import forms

from apps.core.blind_index import email_index, normalise_email

from .models import User


class RecoveryRequestForm(forms.Form):
    """
    Ask for a fresh sign-in link.

    Only an address, because there is nothing else to ask for — this is the path taken
    by somebody whose passkey is on a phone at the bottom of a lake. The view never
    reveals whether the address matched, so this form has nothing to validate beyond
    the shape of it.
    """

    email = forms.EmailField(
        label="Email address",
        widget=forms.EmailInput(
            attrs={"autocomplete": "username", "autofocus": True, "autocapitalize": "none"}
        ),
    )

    def clean_email(self):
        return normalise_email(self.cleaned_data["email"])


class AdminInviteForm(forms.Form):
    """
    Add another screening admin to this church, on a chosen access level.

    Administrators used to be uniform — "All have equal permissions within their church"
    (Build Spec §2) — so this form asked only who they were. Amended 2026-07-29; see
    BUILD_NOTES §1.21. The access level and its departments are asked for here rather
    than left to a second screen, because an account created with no level can do
    nothing, and an invitation to do nothing is not worth sending.

    The escalation rule is inherited from :class:`apps.core.forms.AccessGrantForm`,
    whose fields are grafted on below, so an inviter can never hand out more than they
    hold.
    """

    first_name = forms.CharField(max_length=100)
    last_name = forms.CharField(max_length=100)
    email = forms.EmailField(
        help_text="They will sign in with this address and receive renewal reminders."
    )

    def __init__(self, *args, granting_user=None, **kwargs):
        from apps.core.forms import AccessGrantForm

        super().__init__(*args, **kwargs)
        self.granting_user = granting_user
        # Composed rather than duplicated: one statement of which levels and departments
        # a given inviter may hand out, shared with the "change access" screen.
        self._access = AccessGrantForm(*args, granting_user=granting_user, **kwargs)
        self.fields["access_level"] = self._access.fields["access_level"]
        self.fields["departments"] = self._access.fields["departments"]

    def clean(self):
        cleaned = super().clean()
        # Runs the access form's own checks, and copies its errors onto this form so they
        # render against the right fields.
        if self._access.is_valid():
            cleaned["access_level"] = self._access.cleaned_data["access_level"]
            cleaned["departments"] = self._access.cleaned_data["departments"]
        else:
            for field, errors in self._access.errors.items():
                for error in errors:
                    self.add_error(field if field in self.fields else None, error)
        return cleaned

    def clean_email(self):
        email = normalise_email(self.cleaned_data["email"])
        if User.objects.filter(email_index=email_index(email)).exists():
            raise forms.ValidationError("An administrator with that address already exists.")
        return email


class AdminProfileForm(forms.ModelForm):
    """The bits of their own account an admin may edit."""

    class Meta:
        model = User
        fields = ["first_name", "last_name", "email"]
        help_texts = {
            "email": "Changing this changes the address you sign in with.",
        }

    def clean_email(self):
        email = normalise_email(self.cleaned_data["email"])
        clash = User.objects.filter(email_index=email_index(email)).exclude(pk=self.instance.pk)
        if clash.exists():
            raise forms.ValidationError("Another administrator already uses that address.")
        return email
