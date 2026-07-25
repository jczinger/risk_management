"""
Document tests (Build Spec §5).

The three storage modes, and the guarantee that in ``store`` mode the bytes on disk are
ciphertext — a stolen media volume or a stray backup must yield nothing readable.
"""

from __future__ import annotations

from pathlib import Path

from django.core.exceptions import ValidationError
from django.core.files.uploadedfile import SimpleUploadedFile
from django.db import connection
from django.urls import reverse

from apps.core.crypto import DecryptionError, decrypt_bytes, generate_dek
from apps.core.keys import get_current_key
from apps.core.tests.base import TenantTestCase
from apps.documents.models import Document, DocumentKind, sniff_content_type
from apps.documents.services import read_document, store_document, validate_upload
from apps.tenants.models import DocumentMode

#: A minimal but structurally real PDF, so magic-byte sniffing behaves as it would live.
PDF_BYTES = (
    b"%PDF-1.7\n1 0 obj<</Type/Catalog/Pages 2 0 R>>endobj\n"
    b"trailer<</Root 1 0 R>>\n%%EOF\n"
)
PNG_BYTES = b"\x89PNG\r\n\x1a\n" + b"\x00" * 64
JPEG_BYTES = b"\xff\xd8\xff\xe0" + b"\x00" * 64


def pdf_upload(name="clearance.pdf", data=PDF_BYTES):
    return SimpleUploadedFile(name, data, content_type="application/pdf")


class UploadValidationTests(TenantTestCase):
    """The browser's Content-Type is a hint; the bytes are the fact."""

    def test_a_real_pdf_is_accepted(self):
        data, content_type = validate_upload(pdf_upload())
        self.assertEqual(data, PDF_BYTES)
        self.assertEqual(content_type, "application/pdf")

    def test_images_are_accepted(self):
        for name, payload, expected in (
            ("scan.png", PNG_BYTES, "image/png"),
            ("scan.jpg", JPEG_BYTES, "image/jpeg"),
        ):
            with self.subTest(name=name):
                _, content_type = validate_upload(SimpleUploadedFile(name, payload))
                self.assertEqual(content_type, expected)

    def test_a_disallowed_extension_is_refused(self):
        for name in ("payload.exe", "macro.docm", "script.js", "archive.zip"):
            with self.subTest(name=name), self.assertRaises(ValidationError):
                validate_upload(SimpleUploadedFile(name, PDF_BYTES))

    def test_a_file_lying_about_its_type_is_refused(self):
        """
        Renaming an executable to .pdf must not get it stored. The extension passes; the
        magic bytes do not.
        """
        with self.assertRaises(ValidationError):
            validate_upload(pdf_upload("evil.pdf", b"MZ\x90\x00 this is a PE binary"))

    def test_an_empty_file_is_refused(self):
        with self.assertRaises(ValidationError):
            validate_upload(pdf_upload("empty.pdf", b""))

    def test_an_oversized_file_is_refused(self):
        from django.conf import settings

        oversized = PDF_BYTES + b"0" * (settings.VMS_MAX_UPLOAD_BYTES + 1)
        with self.assertRaises(ValidationError) as caught:
            validate_upload(pdf_upload("big.pdf", oversized))
        self.assertIn("limit", str(caught.exception))

    def test_content_type_sniffing(self):
        self.assertEqual(sniff_content_type(PDF_BYTES), "application/pdf")
        self.assertEqual(sniff_content_type(PNG_BYTES), "image/png")
        self.assertEqual(sniff_content_type(JPEG_BYTES), "image/jpeg")
        self.assertEqual(sniff_content_type(b"II*\x00rest"), "image/tiff")
        self.assertIsNone(sniff_content_type(b"just some text"))


class StoreModeTests(TenantTestCase):
    """``store`` mode: we hold the file, encrypted."""

    def setUp(self):
        super().setUp()
        self.tenant.document_mode = DocumentMode.STORE
        self.tenant.save(update_fields=["document_mode"])
        connection.set_tenant(self.tenant)
        self.volunteer = self.make_volunteer()

    def _store(self, **extra):
        defaults = {
            "volunteer": self.volunteer,
            "title": "CRC clearance letter 2026",
            "kind": DocumentKind.CRC,
            "upload": pdf_upload(),
        }
        defaults.update(extra)
        return store_document(**defaults)

    def test_a_document_is_stored_with_its_metadata(self):
        document = self._store()

        self.assertEqual(document.mode, DocumentMode.STORE)
        self.assertEqual(document.content_type, "application/pdf")
        self.assertEqual(document.byte_size, len(PDF_BYTES))
        self.assertEqual(len(document.plaintext_sha256), 64)
        self.assertTrue(document.has_file)

    def test_the_bytes_on_disk_are_ciphertext(self):
        """
        The core guarantee of store mode. Read the file straight off the volume and confirm
        it is neither the PDF nor readable as one.
        """
        document = self._store()
        path = Path(document.encrypted_file.path)

        self.assertTrue(path.exists())
        on_disk = path.read_bytes()

        self.assertNotEqual(on_disk, PDF_BYTES)
        self.assertFalse(on_disk.startswith(b"%PDF"))
        self.assertNotIn(b"%PDF", on_disk)
        # Nonce + tag overhead over the plaintext.
        self.assertEqual(len(on_disk), len(PDF_BYTES) + 12 + 16)

    def test_the_stored_filename_reveals_nothing(self):
        """
        "jane-smith-crc.pdf" on disk would leak a name and a fact about her. The name is
        replaced with a random UUID and the original is kept encrypted.
        """
        document = self._store(upload=pdf_upload("jane-smith-crc-cleared.pdf"))
        stored_name = Path(document.encrypted_file.name).name

        self.assertNotIn("jane", stored_name.lower())
        self.assertNotIn("smith", stored_name.lower())
        self.assertTrue(stored_name.endswith(".enc"))
        self.assertEqual(document.original_filename, "jane-smith-crc-cleared.pdf")

    def test_the_original_filename_is_encrypted_in_the_column(self):
        document = self._store(upload=pdf_upload("jane-smith-crc.pdf"))

        with connection.cursor() as cursor:
            cursor.execute(
                "SELECT original_filename FROM documents_document WHERE id = %s", [document.pk]
            )
            (value,) = cursor.fetchone()

        self.assertTrue(value.startswith("v1."))
        self.assertNotIn("jane", value.lower())

    def test_reading_it_back_returns_the_original_bytes(self):
        document = self._store()
        self.assertEqual(read_document(document), PDF_BYTES)

    def test_the_file_cannot_be_read_with_another_key(self):
        document = self._store()
        sealed = Path(document.encrypted_file.path).read_bytes()

        self.assertEqual(decrypt_bytes(sealed, get_current_key()), PDF_BYTES)
        with self.assertRaises(DecryptionError):
            decrypt_bytes(sealed, generate_dek())

    def test_a_corrupted_file_is_refused_rather_than_served(self):
        document = self._store()
        path = Path(document.encrypted_file.path)

        blob = bytearray(path.read_bytes())
        blob[20] ^= 0xFF
        path.write_bytes(bytes(blob))

        with self.assertRaises((DecryptionError, ValidationError)):
            read_document(document)

    def test_download_serves_the_decrypted_file(self):
        document = self._store()
        client = self.signed_in_client()

        response = client.get(reverse("documents:download", args=[document.pk]))

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response["Content-Type"], "application/pdf")
        self.assertEqual(b"".join(response.streaming_content), PDF_BYTES)
        # A decrypted clearance letter must not linger in a cache.
        self.assertIn("no-store", response["Cache-Control"])

    def test_viewing_a_document_is_audited(self):
        from apps.core.models import AuditAction, AuditEvent

        document = self._store()
        read_document(document)

        self.assertTrue(
            AuditEvent.objects.filter(
                action=AuditAction.DOWNLOAD, entity_id=str(document.pk)
            ).exists()
        )

    def test_storing_requires_a_file_in_store_mode(self):
        with self.assertRaises(ValidationError):
            self._store(upload=None)

    def test_superseding_keeps_both_documents(self):
        first = self._store(title="CRC 2023")
        second = self._store(title="CRC 2026", supersedes=first)

        first.refresh_from_db()
        self.assertFalse(first.is_current)
        self.assertEqual(first.superseded_by_id, second.pk)
        self.assertEqual(Document.objects.count(), 2)

    def test_documents_cannot_be_deleted(self):
        from apps.core.models import ProtectedDeletionError

        document = self._store()
        with self.assertRaises(ProtectedDeletionError):
            document.delete()
        with self.assertRaises(ProtectedDeletionError):
            Document.objects.all().delete()

    def test_upload_through_the_view(self):
        client = self.signed_in_client()
        response = client.post(
            reverse("documents:create", args=[self.volunteer.pk]),
            {
                "title": "Application form",
                "kind": DocumentKind.APPLICATION,
                "upload": pdf_upload("app.pdf"),
            },
        )

        self.assertEqual(response.status_code, 302)
        document = Document.objects.get()
        self.assertEqual(document.title, "Application form")
        self.assertFalse(Path(document.encrypted_file.path).read_bytes().startswith(b"%PDF"))

    def tearDown(self):
        # Clean up the files this test class wrote to the media volume.
        for document in Document.objects.exclude(encrypted_file=""):
            if document.encrypted_file:
                path = Path(document.encrypted_file.path)
                if path.exists():
                    path.unlink()
        super().tearDown()


class LinkModeTests(TenantTestCase):
    """``link`` mode: the church keeps its own files; we track status and a URL."""

    def setUp(self):
        super().setUp()
        self.tenant.document_mode = DocumentMode.LINK
        self.tenant.save(update_fields=["document_mode"])
        connection.set_tenant(self.tenant)
        self.volunteer = self.make_volunteer()

    def test_a_link_is_recorded_and_no_file_is_stored(self):
        document = store_document(
            volunteer=self.volunteer,
            title="CRC clearance",
            kind=DocumentKind.CRC,
            external_url="https://sharepoint.example.ca/vols/crc-2026.pdf",
        )

        self.assertEqual(document.mode, DocumentMode.LINK)
        self.assertFalse(document.has_file)
        self.assertEqual(document.external_url, "https://sharepoint.example.ca/vols/crc-2026.pdf")

    def test_a_link_is_required(self):
        with self.assertRaises(ValidationError):
            store_document(
                volunteer=self.volunteer, title="CRC clearance", kind=DocumentKind.CRC
            )

    def test_the_form_does_not_offer_a_file_field(self):
        client = self.signed_in_client()
        response = client.get(reverse("documents:create", args=[self.volunteer.pk]))

        self.assertEqual(response.status_code, 200)
        self.assertNotIn("upload", response.context["form"].fields)
        self.assertIn("external_url", response.context["form"].fields)


class TrackModeTests(TenantTestCase):
    """``track`` mode: hard copy in a cabinet; we track status and dates only."""

    def setUp(self):
        super().setUp()
        self.tenant.document_mode = DocumentMode.TRACK
        self.tenant.save(update_fields=["document_mode"])
        connection.set_tenant(self.tenant)
        self.volunteer = self.make_volunteer()

    def test_only_the_fact_and_location_are_recorded(self):
        document = store_document(
            volunteer=self.volunteer,
            title="CRC clearance",
            kind=DocumentKind.CRC,
            physical_location="Office cabinet 2, folder B",
        )

        self.assertEqual(document.mode, DocumentMode.TRACK)
        self.assertFalse(document.has_file)
        self.assertEqual(document.external_url, "")
        self.assertEqual(document.physical_location, "Office cabinet 2, folder B")

    def test_the_form_offers_neither_upload_nor_link(self):
        client = self.signed_in_client()
        response = client.get(reverse("documents:create", args=[self.volunteer.pk]))

        fields = response.context["form"].fields
        self.assertNotIn("upload", fields)
        self.assertNotIn("external_url", fields)
        self.assertIn("physical_location", fields)

    def test_no_location_is_still_acceptable(self):
        """A church may simply not have recorded where it is filed yet."""
        document = store_document(
            volunteer=self.volunteer, title="CRC clearance", kind=DocumentKind.CRC
        )
        self.assertEqual(document.physical_location, "")


class ModeChangeTests(TenantTestCase):
    """Switching a church's mode must not break what is already stored."""

    def test_existing_documents_keep_the_mode_they_were_created_under(self):
        self.tenant.document_mode = DocumentMode.STORE
        self.tenant.save(update_fields=["document_mode"])
        connection.set_tenant(self.tenant)

        volunteer = self.make_volunteer()
        stored = store_document(
            volunteer=volunteer,
            title="CRC clearance",
            kind=DocumentKind.CRC,
            upload=pdf_upload(),
        )

        # The operator switches the church to hard-copy tracking.
        self.tenant.document_mode = DocumentMode.TRACK
        self.tenant.save(update_fields=["document_mode"])
        connection.set_tenant(self.tenant)

        stored.refresh_from_db()
        self.assertEqual(stored.mode, DocumentMode.STORE)
        # And it is still readable — a mode change is not a deletion.
        self.assertEqual(read_document(stored), PDF_BYTES)

        path = Path(stored.encrypted_file.path)
        if path.exists():
            path.unlink()
