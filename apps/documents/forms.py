"""
Document forms.

One form, three shapes: the fields shown depend on the church's document mode, so an
admin at a hard-copy church is never asked to attach a file they do not have.
"""

from __future__ import annotations

from django import forms
from django.conf import settings
from django.utils import timezone

from apps.tenants.models import DocumentMode

from .models import ALLOWED_EXTENSIONS, DocumentKind


class DocumentForm(forms.Form):
    """Record a document. Field set adapts to the church's storage mode."""

    title = forms.CharField(
        max_length=200,
        label="Label",
        widget=forms.TextInput(
            attrs={"placeholder": "e.g. CRC clearance letter 2026"}
        ),
        help_text="A short label. Avoid personal details — this one is not encrypted.",
    )
    kind = forms.ChoiceField(choices=DocumentKind.choices, initial=DocumentKind.OTHER)
    document_date = forms.DateField(
        label="Date on the document",
        required=False,
        widget=forms.DateInput(attrs={"type": "date"}, format="%Y-%m-%d"),
    )

    upload = forms.FileField(
        label="File",
        required=False,
        help_text="",  # Set in __init__ so it can name the real size limit.
        widget=forms.ClearableFileInput(
            attrs={"accept": ",".join(sorted(ALLOWED_EXTENSIONS))}
        ),
    )
    external_url = forms.URLField(
        label="Link to the document",
        required=False,
        max_length=500,
        # A church's document store is https in every realistic case, and defaulting to
        # http would quietly downgrade a pasted bare hostname.
        assume_scheme="https",
        help_text="Where this document lives in your own document store.",
    )
    physical_location = forms.CharField(
        label="Where the hard copy is filed",
        required=False,
        max_length=200,
        widget=forms.TextInput(attrs={"placeholder": "e.g. Office cabinet 2, folder B"}),
    )

    notes = forms.CharField(
        required=False,
        widget=forms.Textarea(attrs={"rows": 2}),
        help_text="Encrypted.",
    )

    def __init__(self, *args, mode: str = DocumentMode.TRACK, **kwargs):
        self.mode = mode
        super().__init__(*args, **kwargs)

        self.fields["upload"].help_text = (
            f"PDF or image, up to {settings.VMS_MAX_UPLOAD_MB} MB. Encrypted with your "
            "church's key before it is written to disk."
        )

        # Drop the fields that make no sense in this mode, rather than showing them
        # disabled — an admin should not have to work out which half applies to them.
        if mode == DocumentMode.STORE:
            self.fields["upload"].required = True
            del self.fields["external_url"]
            del self.fields["physical_location"]
        elif mode == DocumentMode.LINK:
            self.fields["external_url"].required = True
            del self.fields["upload"]
            del self.fields["physical_location"]
        else:  # TRACK
            del self.fields["upload"]
            del self.fields["external_url"]

    def clean_document_date(self):
        value = self.cleaned_data.get("document_date")
        if value and value > timezone.localdate():
            raise forms.ValidationError("Cannot be in the future.")
        return value

    def clean_upload(self):
        upload = self.cleaned_data.get("upload")
        if upload and upload.size and upload.size > settings.VMS_MAX_UPLOAD_BYTES:
            raise forms.ValidationError(
                f"That file is {upload.size / 1024 / 1024:.1f} MB. The limit is "
                f"{settings.VMS_MAX_UPLOAD_MB} MB."
            )
        return upload
