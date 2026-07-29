"""Forms for the super-admin console."""

from __future__ import annotations

from django import forms

from .models import DocumentMode, Domain, Tenant, validate_lead_days, validate_schema_name


class ProvisionChurchForm(forms.Form):
    """
    Everything needed to stand up a new church in one step.

    Deliberately a plain Form rather than a ModelForm: provisioning writes to two
    schemas and generates a key, so it goes through
    :func:`apps.tenants.services.provision_church` rather than ``form.save()``.
    """

    name = forms.CharField(
        label="Church name",
        max_length=200,
        widget=forms.TextInput(attrs={"placeholder": "First Open Arms Church"}),
    )
    schema_name = forms.CharField(
        label="Short code",
        max_length=41,
        help_text=(
            "Lowercase letters and digits, starting with a letter. Becomes the "
            "subdomain and the database schema, and cannot be changed later."
        ),
        widget=forms.TextInput(attrs={"placeholder": "firstoac", "autocapitalize": "none"}),
    )
    domain_name = forms.CharField(
        label="Own hostname (optional)",
        max_length=253,
        required=False,
        help_text=(
            "Leave blank — the church signs in at the shared address, and their email "
            "address selects them. Only fill this in if they need a hostname of their "
            "own, which needs its own DNS record and certificate."
        ),
        widget=forms.TextInput(attrs={"autocapitalize": "none"}),
    )

    document_mode = forms.ChoiceField(
        label="Document handling",
        choices=DocumentMode.choices,
        initial=DocumentMode.STORE,
        widget=forms.RadioSelect,
    )
    reminder_lead_days = forms.CharField(
        label="Reminder lead times",
        max_length=64,
        initial="60,30,7",
        validators=[validate_lead_days],
        help_text="Days before expiry to email this church's admins.",
    )

    contact_name = forms.CharField(label="Church contact", max_length=150, required=False)
    contact_email = forms.EmailField(label="Church contact email", required=False)

    admin_first_name = forms.CharField(label="First name", max_length=100)
    admin_last_name = forms.CharField(label="Last name", max_length=100)
    admin_email = forms.EmailField(
        label="Email address",
        help_text="They sign in with this address and receive renewal reminders.",
    )
    seed_template = forms.BooleanField(
        label="Seed the Plan to Protect requirement template",
        required=False,
        initial=True,
        help_text="14 standard requirements the church can then edit freely.",
    )

    def clean_schema_name(self):
        value = self.cleaned_data["schema_name"].strip().lower()
        validate_schema_name(value)
        if Tenant.objects.filter(schema_name=value).exists():
            raise forms.ValidationError("A church already uses this short code.")
        return value

    def clean_domain_name(self):
        return (self.cleaned_data.get("domain_name") or "").strip().lower()

    def clean(self):
        cleaned = super().clean()
        domain = cleaned.get("domain_name")

        # Blank is the normal case: no Domain row, and the church is reached through
        # the shared address. Earlier this defaulted to <short code>.<base domain>,
        # which minted a subdomain nobody had DNS for.
        if domain and Domain.objects.filter(domain=domain).exists():
            self.add_error("domain_name", f"'{domain}' already routes to another church.")

        return cleaned


class ChurchSettingsForm(forms.ModelForm):
    """The subset of church settings the super-admin may change after the fact."""

    class Meta:
        model = Tenant
        fields = [
            "name",
            "contact_name",
            "contact_email",
            "document_mode",
            "reminder_lead_days",
            "notifications_enabled",
            "is_active",
            "notes",
        ]
        widgets = {
            "document_mode": forms.RadioSelect,
            "notes": forms.Textarea(attrs={"rows": 3}),
        }
        help_texts = {
            "is_active": "Unsetting this refuses requests for the church without touching its data.",
        }


class KeyBackupConfirmForm(forms.Form):
    """The mandatory acknowledgement in front of the app for a new church."""

    confirmed = forms.BooleanField(
        required=True,
        label=(
            "I have saved this encryption key somewhere safe and offline, outside "
            "this system. I understand our records cannot be recovered without it."
        ),
        error_messages={
            "required": "You must confirm you have saved the key before continuing.",
        },
    )
    fingerprint_check = forms.CharField(
        label="Re-enter the last 4 characters of the key fingerprint",
        max_length=8,
        help_text="Confirms you are looking at the key you saved.",
    )

    def __init__(self, *args, expected_fingerprint: str = "", **kwargs):
        self.expected_fingerprint = expected_fingerprint or ""
        super().__init__(*args, **kwargs)

    def clean_fingerprint_check(self):
        value = (self.cleaned_data["fingerprint_check"] or "").strip().lower()
        if not self.expected_fingerprint.endswith(value) or not value:
            raise forms.ValidationError("That does not match the fingerprint shown above.")
        return value


class RestoreKeyForm(forms.Form):
    """Break-glass re-import of a DEK from the operator's escrow."""

    dek_b64 = forms.CharField(
        label="Escrowed key (base64)",
        widget=forms.Textarea(attrs={"rows": 2, "autocomplete": "off"}),
        help_text="Pasted from the Keeper Security entry for this church.",
    )
