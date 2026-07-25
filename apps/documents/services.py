"""
Document handling for the three storage modes.

In ``store`` mode the bytes are sealed with the church's DEK **before** they reach the
filesystem, so the media volume holds only ciphertext. That is the whole point: a
stolen volume, a stray backup or a misconfigured share yields nothing readable. The
plaintext exists only in memory, on the way in and on the way out.

Validation is done from the file's own leading bytes rather than the browser-supplied
Content-Type, which is a hint an attacker controls.
"""

from __future__ import annotations

import logging

from django.conf import settings
from django.core.exceptions import ValidationError
from django.core.files.base import ContentFile
from django.db import connection, transaction

from apps.core import audit
from apps.core.crypto import decrypt_bytes, encrypt_bytes
from apps.core.keys import get_current_key
from apps.core.models import AuditAction
from apps.tenants.models import DocumentMode

from .models import (
    ALLOWED_CONTENT_TYPES,
    ALLOWED_EXTENSIONS,
    Document,
    plaintext_digest,
    sniff_content_type,
)

logger = logging.getLogger("vms.documents")


def current_mode() -> str:
    """The document mode in force for the church handling this request."""
    tenant = getattr(connection, "tenant", None)
    return getattr(tenant, "document_mode", DocumentMode.TRACK)


def validate_upload(upload) -> tuple[bytes, str]:
    """
    Read and check an uploaded file. Returns ``(plaintext_bytes, content_type)``.

    The whole file is read into memory, which is safe because the size ceiling is
    enforced first — and necessary because sealing is an all-at-once operation.
    """
    max_bytes = settings.VMS_MAX_UPLOAD_BYTES

    if upload.size is not None and upload.size > max_bytes:
        raise ValidationError(
            f"That file is {upload.size / 1024 / 1024:.1f} MB. The limit is "
            f"{settings.VMS_MAX_UPLOAD_MB} MB."
        )

    import os

    extension = os.path.splitext(upload.name or "")[1].lower()
    if extension not in ALLOWED_EXTENSIONS:
        raise ValidationError(
            f"'{extension or upload.name}' is not an accepted file type. Upload a PDF "
            "or an image (JPG, PNG, HEIC, TIFF)."
        )

    data = upload.read()
    if len(data) > max_bytes:
        raise ValidationError(f"That file exceeds the {settings.VMS_MAX_UPLOAD_MB} MB limit.")
    if not data:
        raise ValidationError("That file is empty.")

    # Trust the bytes, not the declared type.
    sniffed = sniff_content_type(data[:32])
    if sniffed is None:
        raise ValidationError(
            "That file does not look like a PDF or an image. If it is a scan, try "
            "exporting it again as a PDF."
        )
    if sniffed not in ALLOWED_CONTENT_TYPES:
        raise ValidationError(f"Files of type {sniffed} are not accepted.")

    return data, sniffed


@transaction.atomic
def store_document(
    *,
    volunteer,
    title: str,
    kind: str,
    upload=None,
    external_url: str = "",
    physical_location: str = "",
    document_date=None,
    notes: str = "",
    requirement_instance=None,
    crc_record=None,
    uploaded_by: str = "",
    supersedes: Document | None = None,
) -> Document:
    """
    Record a document in whichever mode this church uses.

    ``store`` seals and writes the bytes; ``link`` keeps a URL; ``track`` keeps only the
    fact and the dates. The mode is stamped onto the row so a later mode change does not
    make existing records inconsistent.
    """
    mode = current_mode()

    document = Document(
        volunteer=volunteer,
        requirement_instance=requirement_instance,
        crc_record=crc_record,
        kind=kind,
        mode=mode,
        title=title.strip(),
        document_date=document_date,
        notes=notes,
        uploaded_by=uploaded_by[:150],
    )

    if mode == DocumentMode.STORE:
        if upload is None:
            raise ValidationError("Attach the file, or ask the platform operator to "
                                  "switch this church to link or track mode.")
        data, content_type = validate_upload(upload)

        document.original_filename = upload.name or ""
        document.content_type = content_type
        document.byte_size = len(data)
        document.plaintext_sha256 = plaintext_digest(data)

        sealed = encrypt_bytes(data, get_current_key())
        # The name passed here is only a hint; encrypted_upload_path replaces it with a
        # random UUID so the filename on disk reveals nothing.
        document.encrypted_file.save(
            "upload.enc", ContentFile(sealed), save=False
        )

    elif mode == DocumentMode.LINK:
        if not external_url:
            raise ValidationError({"external_url": "A link to the document is required."})
        document.external_url = external_url

    else:  # DocumentMode.TRACK
        document.physical_location = physical_location

    document.full_clean(exclude=["encrypted_file", "requirement_instance", "crc_record"])
    document.save()

    if supersedes is not None:
        supersedes.supersede_with(document)

    audit.record(
        AuditAction.UPLOAD,
        "Document",
        entity_id=document.pk,
        entity_label=f"{volunteer.display_name} — {document.title}",
        summary=f"{document.get_kind_display()} recorded ({mode} mode)",
        detail={
            "mode": mode,
            "kind": kind,
            "bytes": document.byte_size,
            "content_type": document.content_type,
            "sha256": document.plaintext_sha256,
            "supersedes": supersedes.pk if supersedes else None,
        },
    )
    logger.info(
        "Document recorded volunteer=%s mode=%s kind=%s bytes=%s",
        volunteer.pk,
        mode,
        kind,
        document.byte_size,
    )
    return document


def read_document(document: Document) -> bytes:
    """
    Decrypt and return a stored document's bytes.

    Verifies the plaintext hash on the way out, so silent corruption on the volume is
    caught rather than served as a broken file.
    """
    if not document.encrypted_file:
        raise ValidationError("This record has no stored file.")

    with document.encrypted_file.open("rb") as handle:
        sealed = handle.read()

    data = decrypt_bytes(sealed, get_current_key())

    if document.plaintext_sha256 and plaintext_digest(data) != document.plaintext_sha256:
        # AES-GCM would already have failed on tampering, so reaching here means the
        # stored hash and the stored file disagree — a bug or a botched restore.
        logger.error("Document %s failed its integrity check", document.pk)
        raise ValidationError(
            "This file failed its integrity check and has not been served. Contact the "
            "platform operator."
        )

    audit.record(
        AuditAction.DOWNLOAD,
        "Document",
        entity_id=document.pk,
        entity_label=f"{document.volunteer.display_name} — {document.title}",
        summary="Document viewed",
        detail={"bytes": len(data)},
    )
    return data
