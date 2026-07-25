"""Sign-in and account-management forms."""

from __future__ import annotations

from django import forms
from django.contrib.auth import authenticate
from django.contrib.auth.password_validation import validate_password

from apps.core.blind_index import email_index, normalise_email

from .models import User


class EmailPasswordForm(forms.Form):
    """
    The fallback sign-in step.

    Success here does **not** sign anyone in — it only establishes that the password is
    right, after which the TOTP step runs. The authenticated user is stashed on the
    form for the view to pick up.
    """

    email = forms.EmailField(
        label="Email address",
        widget=forms.EmailInput(
            attrs={"autocomplete": "username", "autofocus": True, "autocapitalize": "none"}
        ),
    )
    password = forms.CharField(
        label="Password",
        strip=False,
        widget=forms.PasswordInput(attrs={"autocomplete": "current-password"}),
    )

    #: Deliberately identical for a wrong address and a wrong password, so the form
    #: cannot be used to discover who has an account.
    GENERIC_ERROR = "That email address and password combination was not recognised."

    def __init__(self, request=None, *args, **kwargs):
        self.request = request
        self.user = None
        super().__init__(*args, **kwargs)

    def clean(self):
        cleaned = super().clean()
        email = normalise_email(cleaned.get("email") or "")
        password = cleaned.get("password") or ""

        if not email or not password:
            return cleaned

        user = authenticate(self.request, username=email, password=password)

        # Django's ModelBackend already refuses an inactive user, so this one message covers
        # every failure: no such address, wrong password, and deactivated account. That is
        # deliberate — a distinct "your account is deactivated" reply would confirm the
        # address exists to anyone who guessed it.
        if user is None:
            raise forms.ValidationError(self.GENERIC_ERROR, code="invalid_login")

        self.user = user
        return cleaned


class TOTPForm(forms.Form):
    """The second-factor step of the fallback path."""

    code = forms.CharField(
        label="Six-digit code",
        max_length=8,
        widget=forms.TextInput(
            attrs={
                "autocomplete": "one-time-code",
                "inputmode": "numeric",
                "pattern": "[0-9]*",
                "autofocus": True,
                "placeholder": "000000",
            }
        ),
    )

    def clean_code(self):
        return (self.cleaned_data["code"] or "").strip().replace(" ", "")


class TOTPEnrolForm(TOTPForm):
    """Confirms the authenticator app actually stored the secret."""

    code = forms.CharField(
        label="Enter the code your app shows now",
        max_length=8,
        widget=forms.TextInput(
            attrs={"autocomplete": "one-time-code", "inputmode": "numeric", "autofocus": True}
        ),
    )


class PasskeyLabelForm(forms.Form):
    """Names a passkey at registration time, so a list of three is distinguishable."""

    label = forms.CharField(
        label="Name this device",
        max_length=100,
        required=False,
        widget=forms.TextInput(attrs={"placeholder": "e.g. work laptop, phone"}),
    )


class SetPasswordForm(forms.Form):
    """Set or change the fallback password."""

    new_password1 = forms.CharField(
        label="New password",
        strip=False,
        widget=forms.PasswordInput(attrs={"autocomplete": "new-password"}),
        help_text="At least 12 characters.",
    )
    new_password2 = forms.CharField(
        label="Confirm new password",
        strip=False,
        widget=forms.PasswordInput(attrs={"autocomplete": "new-password"}),
    )

    def __init__(self, user, *args, **kwargs):
        self.user = user
        super().__init__(*args, **kwargs)

    def clean(self):
        cleaned = super().clean()
        first = cleaned.get("new_password1")
        second = cleaned.get("new_password2")
        if first and second and first != second:
            self.add_error("new_password2", "The two passwords do not match.")
        elif first:
            validate_password(first, self.user)
        return cleaned

    def save(self):
        self.user.set_password(self.cleaned_data["new_password1"])
        self.user.save(update_fields=["password"])
        return self.user


class AdminInviteForm(forms.Form):
    """
    Add another screening admin to this church.

    All admins have equal permissions within their church (Build Spec §2), so there is
    no role to choose. A blank password creates a passkey-only account.
    """

    first_name = forms.CharField(max_length=100)
    last_name = forms.CharField(max_length=100)
    email = forms.EmailField(
        help_text="They will sign in with this address and receive renewal reminders."
    )
    password = forms.CharField(
        label="Temporary password",
        required=False,
        strip=False,
        widget=forms.PasswordInput(render_value=False),
        help_text=(
            "Optional. Leave blank so they set up a passkey instead — the more secure "
            "option. If set, they must also enrol an authenticator app."
        ),
    )

    def clean_email(self):
        email = normalise_email(self.cleaned_data["email"])
        if User.objects.filter(email_index=email_index(email)).exists():
            raise forms.ValidationError("An administrator with that address already exists.")
        return email

    def clean_password(self):
        password = self.cleaned_data.get("password") or ""
        if password:
            validate_password(password)
        return password


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
