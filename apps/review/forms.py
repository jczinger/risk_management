"""The send-back form: one field, and it is mandatory."""

from __future__ import annotations

from django import forms


class SendBackForm(forms.Form):
    reason = forms.CharField(
        label="Why are you sending this back?",
        widget=forms.Textarea(attrs={"rows": 4, "autofocus": "autofocus"}),
        max_length=240,
        help_text=(
            "Shown to the administrator who recorded it, and recorded in the audit trail. "
            "Say what needs to be different, not only that it was wrong."
        ),
    )

    def clean_reason(self):
        # Capped at 240 so it fits the audit summary, which is the only part anyone reads —
        # a reason kept solely in the encrypted detail would be invisible to its reader.
        reason = (self.cleaned_data["reason"] or "").strip()
        if not reason:
            raise forms.ValidationError("A reason is required.")
        return reason
