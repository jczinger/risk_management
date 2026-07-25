"""
Document views.

Stored files are **never** served by the web server directly — the file on disk is
ciphertext, and only :func:`document_download` can decrypt it. That also means every
view of a document passes through Django, so every view is authenticated and audited.
"""

from __future__ import annotations

import logging

from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.core.exceptions import ValidationError
from django.http import FileResponse, Http404
from django.shortcuts import get_object_or_404, redirect, render
from django.views.decorators.http import require_http_methods

from apps.org.models import Volunteer
from apps.requirements.models import CRCRecord, RequirementInstance
from apps.tenants.models import DocumentMode

from .forms import DocumentForm
from .models import Document, DocumentKind
from .services import current_mode, read_document, store_document

logger = logging.getLogger("vms.documents")


@login_required
def document_list(request):
    """Every document at this church, newest first."""
    documents = (
        Document.objects.select_related("volunteer")
        .filter(is_current=True)
        .order_by("-document_date", "-created_at")[:200]
    )
    return render(
        request,
        "documents/document_list.html",
        {"documents": documents, "mode": current_mode(), "modes": DocumentMode},
    )


@login_required
@require_http_methods(["GET", "POST"])
def document_create(request, volunteer_pk: int):
    """
    Attach a document to a volunteer.

    A requirement instance or criminal record check can be passed in the query string
    so the document lands against the right item.
    """
    volunteer = get_object_or_404(Volunteer, pk=volunteer_pk)
    mode = current_mode()

    instance = None
    crc_record = None
    initial = {}

    instance_id = request.GET.get("instance") or request.POST.get("instance")
    if instance_id:
        instance = get_object_or_404(
            RequirementInstance.objects.select_related("definition"),
            pk=instance_id,
            volunteer=volunteer,
        )
        initial["title"] = instance.definition.name
        initial["kind"] = _kind_for_requirement(instance)

    crc_id = request.GET.get("crc") or request.POST.get("crc")
    if crc_id:
        crc_record = get_object_or_404(CRCRecord, pk=crc_id, volunteer=volunteer)
        initial.setdefault("title", f"Criminal record check {crc_record.report_date:%Y}")
        initial["kind"] = DocumentKind.CRC
        initial["document_date"] = crc_record.report_date

    form = DocumentForm(
        request.POST or None,
        request.FILES or None,
        mode=mode,
        initial=initial,
    )

    if request.method == "POST" and form.is_valid():
        data = form.cleaned_data
        try:
            document = store_document(
                volunteer=volunteer,
                title=data["title"],
                kind=data["kind"],
                upload=data.get("upload"),
                external_url=data.get("external_url", ""),
                physical_location=data.get("physical_location", ""),
                document_date=data.get("document_date"),
                notes=data.get("notes", ""),
                requirement_instance=instance,
                crc_record=crc_record,
                uploaded_by=request.user.get_full_name() or "administrator",
            )
        except ValidationError as exc:
            for field, errors in (exc.message_dict.items() if hasattr(exc, "message_dict") else []):
                for error in errors:
                    form.add_error(field if field in form.fields else None, error)
            if not hasattr(exc, "message_dict"):
                for error in exc.messages:
                    form.add_error(None, error)
        else:
            messages.success(request, f"'{document.title}' recorded.")
            if instance:
                return redirect("requirements:instance_detail", pk=instance.pk)
            if crc_record:
                return redirect("requirements:crc_detail", pk=crc_record.pk)
            return redirect("org:volunteer_detail", pk=volunteer.pk)

    return render(
        request,
        "documents/document_form.html",
        {
            "form": form,
            "volunteer": volunteer,
            "mode": mode,
            "modes": DocumentMode,
            "instance": instance,
            "crc_record": crc_record,
        },
    )


def _kind_for_requirement(instance: RequirementInstance) -> str:
    """Guess a sensible document kind from the requirement type."""
    from apps.requirements.models import RequirementType

    mapping = {
        RequirementType.CRIMINAL_RECORD_CHECK: DocumentKind.CRC,
        RequirementType.APPLICATION_FORM: DocumentKind.APPLICATION,
        RequirementType.REFERENCE_CHECKS: DocumentKind.REFERENCE,
        RequirementType.SIGNED_AGREEMENT: DocumentKind.AGREEMENT,
        RequirementType.POLICY_AGREEMENT: DocumentKind.AGREEMENT,
        RequirementType.TRAINING_ORIENTATION: DocumentKind.TRAINING,
        RequirementType.TRAINING_REFRESHER: DocumentKind.TRAINING,
        RequirementType.INTERVIEW: DocumentKind.INTERVIEW,
        RequirementType.LEADERSHIP_APPROVAL: DocumentKind.APPROVAL,
    }
    return mapping.get(instance.definition.requirement_type, DocumentKind.OTHER)


@login_required
def document_detail(request, pk: int):
    document = get_object_or_404(
        Document.objects.select_related("volunteer", "requirement_instance", "crc_record"), pk=pk
    )
    return render(
        request,
        "documents/document_detail.html",
        {"document": document, "modes": DocumentMode},
    )


@login_required
def document_download(request, pk: int):
    """
    Decrypt and serve a stored document.

    The response is marked no-store: a decrypted clearance letter should not sit in the
    browser's disk cache or in a proxy after the admin has looked at it.
    """
    document = get_object_or_404(Document.objects.select_related("volunteer"), pk=pk)

    if not document.has_file:
        raise Http404("This record has no stored file.")

    try:
        data = read_document(document)
    except ValidationError as exc:
        messages.error(request, "; ".join(exc.messages))
        return redirect("documents:detail", pk=document.pk)

    import io

    response = FileResponse(
        io.BytesIO(data),
        content_type=document.content_type or "application/octet-stream",
    )
    # inline so a PDF opens in the browser's viewer rather than forcing a download.
    disposition = "inline" if document.content_type == "application/pdf" else "attachment"
    response["Content-Disposition"] = f'{disposition}; filename="{document.display_filename}"'
    response["Content-Length"] = str(len(data))
    response["Cache-Control"] = "no-store, no-cache, must-revalidate, private"
    response["X-Content-Type-Options"] = "nosniff"
    return response
