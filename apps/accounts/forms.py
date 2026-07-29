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


class PasskeyLabelForm(forms.Form):
    """Names a passkey at registration time, so a list of three is distinguishable."""

    label = forms.CharField(
        label="Name this device",
        max_length=100,
        required=False,
        widget=forms.TextInput(attrs={"placeholder": "e.g. work laptop, phone"}),
    )


class AdminInviteForm(forms.Form):
    """
    Add another screening admin to this church.

    All admins have equal permissions within their church (Build Spec §2), so there is
    no role to choose. Creating the account mints a single-use link; there is nothing
    to set here beyond who they are.
    """

    first_name = forms.CharField(max_length=100)
    last_name = forms.CharField(max_length=100)
    email = forms.EmailField(
        help_text="They will sign in with this address and receive renewal reminders."
    )

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
