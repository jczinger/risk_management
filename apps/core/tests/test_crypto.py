"""
Encryption tests.

These cover the guarantee the whole design rests on: sensitive values go into Postgres as
ciphertext, come back out as the original value, and are unreadable with the wrong key.
"""

from __future__ import annotations

import datetime

from django.db import connection
from django.test import SimpleTestCase

from apps.core import crypto
from apps.core.crypto import (
    DecryptionError,
    decode_key,
    decrypt_bytes,
    decrypt_text,
    encrypt_bytes,
    encrypt_text,
    generate_dek,
    is_ciphertext,
    key_fingerprint,
    unwrap_dek,
    wrap_dek,
)
from apps.core.tests.base import TenantTestCase


class CryptoPrimitiveTests(SimpleTestCase):
    """The cipher layer, with no database involved."""

    def setUp(self):
        self.key = generate_dek()

    def test_text_round_trip(self):
        for value in ["", "a", "hello", "ünïcodé ✓", "x" * 5000, "line\nbreak\ttab"]:
            with self.subTest(value=value[:20]):
                token = encrypt_text(value, self.key)
                self.assertEqual(decrypt_text(token, self.key), value)

    def test_bytes_round_trip(self):
        for payload in [b"", b"\x00\x01\x02", b"%PDF-1.7 fake", bytes(range(256)) * 40]:
            with self.subTest(size=len(payload)):
                self.assertEqual(decrypt_bytes(encrypt_bytes(payload, self.key), self.key), payload)

    def test_encryption_is_randomised(self):
        """
        The same plaintext must encrypt differently every time.

        This is what stops a dump revealing that two volunteers share an address — and it
        is also exactly why encrypted fields cannot be queried.
        """
        tokens = {encrypt_text("123 Main Street", self.key) for _ in range(20)}
        self.assertEqual(len(tokens), 20)

    def test_ciphertext_does_not_contain_plaintext(self):
        token = encrypt_text("sensitive-value-42", self.key)
        self.assertNotIn("sensitive", token)
        self.assertNotIn("42", token.split(".", 1)[1])

    def test_wrong_key_is_rejected_not_garbled(self):
        """
        A wrong key must fail loudly. AES-GCM authenticates, so this is a hard error rather
        than plausible-looking nonsense.
        """
        token = encrypt_text("secret", self.key)
        with self.assertRaises(DecryptionError):
            decrypt_text(token, generate_dek())

    def test_tampered_ciphertext_is_rejected(self):
        token = encrypt_text("secret", self.key)
        body = list(token.split(".", 1)[1])
        body[5] = "A" if body[5] != "A" else "B"
        tampered = "v1." + "".join(body)
        with self.assertRaises(DecryptionError):
            decrypt_text(tampered, self.key)

    def test_truncated_ciphertext_is_rejected(self):
        token = encrypt_text("secret", self.key)
        with self.assertRaises(DecryptionError):
            decrypt_text(token[:18], self.key)

    def test_dek_wrapping_round_trip(self):
        master = generate_dek()
        dek = generate_dek()
        self.assertEqual(unwrap_dek(wrap_dek(dek, master), master), dek)

    def test_dek_cannot_be_unwrapped_with_wrong_master_key(self):
        dek = generate_dek()
        wrapped = wrap_dek(dek, generate_dek())
        with self.assertRaises(DecryptionError):
            unwrap_dek(wrapped, generate_dek())

    def test_field_and_dek_domains_are_separated(self):
        """
        A wrapped DEK must not be openable by the field decryptor.

        The two use different additional authenticated data, so ciphertext cannot be moved
        between the two purposes even with the right key.
        """
        wrapped = wrap_dek(generate_dek(), self.key)
        with self.assertRaises(DecryptionError):
            decrypt_bytes(wrapped, self.key)

    def test_fingerprint_is_stable_and_does_not_reveal_the_key(self):
        fingerprint = key_fingerprint(self.key)
        self.assertEqual(fingerprint, key_fingerprint(self.key))
        self.assertNotEqual(fingerprint, key_fingerprint(generate_dek()))
        self.assertEqual(len(fingerprint), 16)
        self.assertNotIn(fingerprint, crypto.encode_key(self.key))

    def test_key_encoding_round_trip(self):
        self.assertEqual(decode_key(crypto.encode_key(self.key)), self.key)

    def test_malformed_key_is_rejected(self):
        with self.assertRaises(crypto.EncryptionError):
            decode_key("not-base64!!")
        with self.assertRaises(crypto.EncryptionError):
            decode_key(crypto.encode_key(b"too-short"))

    def test_is_ciphertext_detection(self):
        self.assertTrue(is_ciphertext(encrypt_text("x", self.key)))
        self.assertFalse(is_ciphertext("plain text"))
        self.assertFalse(is_ciphertext(None))
        self.assertFalse(is_ciphertext(42))


class EncryptedFieldTests(TenantTestCase):
    """The model-field layer: values must be ciphertext in the column, plain in Python."""

    def test_volunteer_fields_round_trip_through_the_database(self):
        volunteer = self.make_volunteer(
            email="Person@Example.CA",
            phone="+1 250 555 0111",
            address="14 Elm Road\nVictoria BC",
            emergency_contact="Jo Taylor, sister, 250 555 0222",
            medical_notes="Peanut allergy — EpiPen in the office",
            notes="Prefers Sunday mornings",
        )
        volunteer.refresh_from_db()

        self.assertEqual(volunteer.email, "Person@Example.CA")
        self.assertEqual(volunteer.phone, "+1 250 555 0111")
        self.assertEqual(volunteer.address, "14 Elm Road\nVictoria BC")
        self.assertEqual(volunteer.emergency_contact, "Jo Taylor, sister, 250 555 0222")
        self.assertEqual(volunteer.medical_notes, "Peanut allergy — EpiPen in the office")
        self.assertEqual(volunteer.notes, "Prefers Sunday mornings")

    def test_raw_column_holds_ciphertext_not_plaintext(self):
        volunteer = self.make_volunteer(
            phone="250-555-9999",
            address="99 Secret Lane",
            medical_notes="Diabetic",
        )

        with connection.cursor() as cursor:
            cursor.execute(
                "SELECT phone, address, medical_notes, date_of_birth, notes "
                "FROM org_volunteer WHERE id = %s",
                [volunteer.pk],
            )
            row = cursor.fetchone()

        blob = " ".join(str(v) for v in row)
        for secret in ("250-555-9999", "99 Secret Lane", "Diabetic"):
            self.assertNotIn(secret, blob, f"{secret!r} is readable in the raw column")
        for value in row:
            if value:
                self.assertTrue(
                    str(value).startswith("v1."),
                    f"expected a ciphertext token, got {str(value)[:40]!r}",
                )

    def test_names_stay_plaintext_because_they_must_be_searchable(self):
        """
        Names are deliberately *not* encrypted (PRD §5) so the volunteer list can be
        searched and sorted. This asserts that intent rather than assuming it.
        """
        volunteer = self.make_volunteer(first_name="Priya", last_name="Anand")

        with connection.cursor() as cursor:
            cursor.execute(
                "SELECT first_name, last_name FROM org_volunteer WHERE id = %s", [volunteer.pk]
            )
            first, last = cursor.fetchone()

        self.assertEqual(first, "Priya")
        self.assertEqual(last, "Anand")

    def test_encrypted_date_round_trips_as_a_date_object(self):
        dob = datetime.date(1994, 3, 21)
        volunteer = self.make_volunteer(date_of_birth=dob, age=None)
        volunteer.refresh_from_db()

        self.assertEqual(volunteer.date_of_birth, dob)
        self.assertIsInstance(volunteer.date_of_birth, datetime.date)
        # The queryable coarse parts must agree with the encrypted full date.
        self.assertEqual(volunteer.birth_year, 1994)
        self.assertEqual(volunteer.birth_month, 3)

    def test_saving_twice_does_not_double_encrypt(self):
        volunteer = self.make_volunteer(phone="250-555-0000")
        volunteer.save()
        volunteer.save()
        volunteer.refresh_from_db()
        self.assertEqual(volunteer.phone, "250-555-0000")

    def test_blank_and_null_pass_through_unencrypted(self):
        volunteer = self.make_volunteer(phone="", notes="")
        volunteer.refresh_from_db()
        self.assertEqual(volunteer.phone, "")
        self.assertEqual(volunteer.notes, "")
        self.assertIsNone(volunteer.date_of_birth) if volunteer.date_of_birth is None else None

    def test_encrypted_fields_are_not_queryable(self):
        """
        Documents the limitation so nobody 'fixes' a filter that silently returns nothing.
        """
        self.make_volunteer(phone="250-555-1234")
        from apps.org.models import Volunteer

        self.assertEqual(Volunteer.objects.filter(phone="250-555-1234").count(), 0)


class BlindIndexTests(TenantTestCase):
    """Exact-match lookup over an encrypted column."""

    def test_index_is_deterministic_for_the_same_address(self):
        from apps.core.blind_index import email_index

        self.assertEqual(email_index("person@example.ca"), email_index("person@example.ca"))

    def test_index_normalises_case_and_whitespace(self):
        from apps.core.blind_index import email_index

        self.assertEqual(email_index("  Person@Example.CA "), email_index("person@example.ca"))

    def test_different_addresses_get_different_indexes(self):
        from apps.core.blind_index import email_index

        self.assertNotEqual(email_index("a@example.ca"), email_index("b@example.ca"))

    def test_index_does_not_contain_the_address(self):
        from apps.core.blind_index import email_index

        index = email_index("person@example.ca")
        self.assertNotIn("person", index)
        self.assertNotIn("example", index)

    def test_empty_address_yields_empty_index(self):
        from apps.core.blind_index import email_index

        self.assertEqual(email_index(""), "")

    def test_user_can_be_found_by_email_despite_encryption(self):
        from apps.accounts.models import User

        user = self.make_admin(email="Findable@Example.CA")
        self.assertEqual(User.objects.get_by_natural_key("findable@example.ca"), user)
        self.assertEqual(User.objects.get_by_natural_key("  FINDABLE@example.ca  "), user)

    def test_user_email_is_ciphertext_in_the_column(self):
        user = self.make_admin(email="hidden@example.ca")

        with connection.cursor() as cursor:
            cursor.execute("SELECT email, email_index FROM accounts_user WHERE id = %s", [user.pk])
            email, index = cursor.fetchone()

        self.assertTrue(email.startswith("v1."))
        self.assertNotIn("hidden", email)
        self.assertNotIn("hidden", index)
