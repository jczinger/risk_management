"""
Renewal reminder tests (Build Spec §7 and §10).

The acceptance criterion: "Reminder emails fire at 60/30/7/overdue against seeded
near-expiry data."

Also covered: reminders go to admins and never to volunteers, everything is batched into one
daily digest per church, lead times are per-church configurable, every send is logged, and
the job is idempotent — a second run the same day must not re-mail anybody.
"""

from __future__ import annotations

import datetime

from django.core import mail
from django.db import connection
from django.utils import timezone

from apps.core.tests.base import TenantTestCase
from apps.notifications.models import EmailLog, NotificationStatus, ReminderKind, ReminderLog
from apps.notifications.services import (
    find_due_reminders,
    process_tenant_reminders,
    send_digest,
)
from apps.requirements.services import mark_requirement_complete, sync_volunteer_requirements


class ReminderBase(TenantTestCase):
    def setUp(self):
        super().setUp()
        mail.outbox = []
        self.seed()
        self.admin = self.make_admin(email="screening@church.ca")
        self.role = self.make_role(name="Teacher")
        self.volunteer = self.make_volunteer(first_name="Dana", last_name="Reed")
        self.assign(self.volunteer, self.role)
        sync_volunteer_requirements(self.volunteer)
        self.tenant = connection.tenant

    def code_of_conduct(self):
        return self.volunteer.requirement_instances.get(definition__name="Code of Conduct")

    def _expire_in(self, days: int):
        """Complete the annual Code of Conduct so that it expires in ``days`` days."""
        instance = self.code_of_conduct()
        target_expiry = timezone.localdate() + datetime.timedelta(days=days)
        # Annual cadence, so completing 365 days before the target sets that expiry.
        mark_requirement_complete(instance, target_expiry - datetime.timedelta(days=365))
        instance.refresh_from_db()
        return instance


class LeadTimeTests(ReminderBase):
    """The 60/30/7 schedule."""

    def test_reminder_is_found_at_each_configured_lead_time(self):
        for days in (60, 30, 7):
            with self.subTest(lead_days=days):
                ReminderLog.objects.all().delete()
                instance = self._expire_in(days)

                found = find_due_reminders(self.tenant)
                matching = [
                    e
                    for e in found
                    if e["instance"].pk == instance.pk and e["lead_days"] == days
                ]
                self.assertEqual(len(matching), 1, f"expected one reminder at {days} days")
                self.assertEqual(matching[0]["kind"], ReminderKind.LEAD_TIME)

    def test_no_reminder_on_a_day_that_is_not_a_lead_time(self):
        self._expire_in(45)
        self.assertEqual(find_due_reminders(self.tenant), [])

    def test_overdue_reminder_fires_the_day_after_expiry(self):
        instance = self._expire_in(-1)  # expired yesterday

        found = find_due_reminders(self.tenant)
        matching = [e for e in found if e["instance"].pk == instance.pk]
        self.assertEqual(len(matching), 1)
        self.assertEqual(matching[0]["kind"], ReminderKind.OVERDUE)
        self.assertEqual(matching[0]["lead_days"], 0)

    def test_overdue_reminder_does_not_repeat_every_day(self):
        """
        Once, then the dashboard carries it. Re-mailing daily is how a compliance tool gets
        filtered to a folder nobody opens.
        """
        self._expire_in(-10)
        self.assertEqual(find_due_reminders(self.tenant), [])

    def test_lead_times_are_per_church_configurable(self):
        self.tenant.reminder_lead_days = "90,14"
        self.tenant.save(update_fields=["reminder_lead_days"])
        self.assertEqual(self.tenant.lead_days, [90, 14])

        self._expire_in(90)
        found = find_due_reminders(self.tenant)
        self.assertEqual([e["lead_days"] for e in found], [90])

        ReminderLog.objects.all().delete()
        self._expire_in(60)  # no longer a configured lead time
        self.assertEqual(find_due_reminders(self.tenant), [])

    def test_turning_18_deadline_produces_its_own_reminder_kind(self):
        from apps.requirements.services import activate_turning_18_checks

        minor = self.make_volunteer(
            first_name="Alex", last_name="Young", date_of_birth=datetime.date(2008, 6, 25), age=None
        )
        self.assign(minor, self.role)
        sync_volunteer_requirements(minor, as_of=datetime.date(2026, 5, 1))
        activate_turning_18_checks(datetime.date(2026, 6, 1))

        # The deadline is 1 Sep 2026; 30 days earlier is 2 Aug 2026.
        found = find_due_reminders(self.tenant, as_of=datetime.date(2026, 8, 2))
        kinds = {e["kind"] for e in found if e["instance"].volunteer_id == minor.pk}
        self.assertIn(ReminderKind.TURNING_18, kinds)

    def test_not_applicable_and_waived_requirements_are_never_chased(self):
        from apps.requirements.services import waive_requirement

        instance = self._expire_in(30)
        waive_requirement(instance, reason="Held at the district office.", waived_by="Pastor")

        self.assertEqual(find_due_reminders(self.tenant), [])

    def test_inactive_volunteers_are_not_chased(self):
        self._expire_in(30)
        self.volunteer.is_active = False
        self.volunteer.stopped_serving_on = timezone.localdate()
        self.volunteer.save()

        self.assertEqual(find_due_reminders(self.tenant), [])


class DigestTests(ReminderBase):
    """One email per church per day, to admins only."""

    def test_digest_goes_to_the_admins(self):
        self._expire_in(30)
        result = process_tenant_reminders(self.tenant)

        self.assertTrue(result["sent"])
        self.assertEqual(len(mail.outbox), 1)
        self.assertEqual(mail.outbox[0].to, ["screening@church.ca"])

    def test_digest_never_goes_to_a_volunteer(self):
        """Stage 1 has no volunteer-facing features at all (Build Spec §0)."""
        self.volunteer.email = "dana.reed@example.ca"
        self.volunteer.save()
        self._expire_in(30)
        process_tenant_reminders(self.tenant)

        recipients = set(mail.outbox[0].to) | set(mail.outbox[0].cc) | set(mail.outbox[0].bcc)
        self.assertNotIn("dana.reed@example.ca", recipients)

    def test_all_admins_receive_it(self):
        self.make_admin(email="second.admin@church.ca")
        self._expire_in(30)
        process_tenant_reminders(self.tenant)

        self.assertCountEqual(
            mail.outbox[0].to, ["screening@church.ca", "second.admin@church.ca"]
        )

    def test_inactive_admins_are_excluded(self):
        other = self.make_admin(email="left@church.ca")
        other.is_active = False
        other.save()

        self._expire_in(30)
        process_tenant_reminders(self.tenant)
        self.assertNotIn("left@church.ca", mail.outbox[0].to)

    def test_everything_due_is_batched_into_one_email(self):
        second = self.make_volunteer(first_name="Robin", last_name="Cole")
        self.assign(second, self.role)
        sync_volunteer_requirements(second)

        for volunteer in (self.volunteer, second):
            instance = volunteer.requirement_instances.get(definition__name="Code of Conduct")
            mark_requirement_complete(
                instance,
                timezone.localdate() + datetime.timedelta(days=30) - datetime.timedelta(days=365),
            )

        result = process_tenant_reminders(self.tenant)

        self.assertEqual(len(mail.outbox), 1)
        self.assertEqual(result["claimed"], 2)
        body = mail.outbox[0].body
        self.assertIn("Reed, Dana", body)
        self.assertIn("Cole, Robin", body)

    def test_subject_says_what_is_inside(self):
        self._expire_in(30)
        process_tenant_reminders(self.tenant)

        subject = mail.outbox[0].subject
        self.assertIn("Test Church", subject)
        self.assertIn("coming due", subject)

    def test_overdue_and_upcoming_are_distinguished(self):
        second = self.make_volunteer(first_name="Robin", last_name="Cole")
        self.assign(second, self.role)
        sync_volunteer_requirements(second)

        upcoming = self.code_of_conduct()
        mark_requirement_complete(
            upcoming, timezone.localdate() + datetime.timedelta(days=30 - 365)
        )
        overdue = second.requirement_instances.get(definition__name="Code of Conduct")
        mark_requirement_complete(
            overdue, timezone.localdate() - datetime.timedelta(days=366)
        )

        process_tenant_reminders(self.tenant)

        body = mail.outbox[0].body
        self.assertIn("OVERDUE", body)
        self.assertIn("COMING DUE", body)
        self.assertIn("1 overdue", mail.outbox[0].subject)

    def test_html_alternative_is_attached(self):
        self._expire_in(30)
        process_tenant_reminders(self.tenant)

        alternatives = mail.outbox[0].alternatives
        self.assertEqual(len(alternatives), 1)
        self.assertEqual(alternatives[0][1], "text/html")
        self.assertIn("Reed, Dana", alternatives[0][0])

    def test_nothing_due_sends_nothing(self):
        result = process_tenant_reminders(self.tenant)
        self.assertEqual(result["claimed"], 0)
        self.assertFalse(result["sent"])
        self.assertEqual(len(mail.outbox), 0)

    def test_notifications_can_be_disabled_per_church(self):
        self.tenant.notifications_enabled = False
        self.tenant.save(update_fields=["notifications_enabled"])

        self._expire_in(30)
        result = process_tenant_reminders(self.tenant)

        self.assertEqual(len(mail.outbox), 0)
        self.assertFalse(result["sent"])

    def test_a_church_with_no_admin_addresses_does_not_crash(self):
        from apps.accounts.models import User

        User.objects.all().update(is_active=False)
        self._expire_in(30)

        result = process_tenant_reminders(self.tenant)
        self.assertEqual(len(mail.outbox), 0)
        self.assertFalse(result["sent"])


class IdempotenceTests(ReminderBase):
    """A job that runs twice must not mail anybody twice."""

    def test_running_the_job_again_the_same_day_sends_nothing(self):
        self._expire_in(30)

        first = process_tenant_reminders(self.tenant)
        self.assertEqual(first["claimed"], 1)
        self.assertEqual(len(mail.outbox), 1)

        second = process_tenant_reminders(self.tenant)
        self.assertEqual(second["claimed"], 0)
        self.assertEqual(len(mail.outbox), 1)

    def test_renewing_starts_a_fresh_reminder_cycle(self):
        """
        The reminder key includes the expiry in force, so next year's 30-day reminder is a
        different reminder and goes out normally.
        """
        instance = self._expire_in(30)
        process_tenant_reminders(self.tenant)
        self.assertEqual(len(mail.outbox), 1)

        # Renew, then move to 30 days before the new expiry.
        mark_requirement_complete(instance, timezone.localdate())
        instance.refresh_from_db()
        new_expiry = instance.expires_on

        found = find_due_reminders(
            self.tenant, as_of=new_expiry - datetime.timedelta(days=30)
        )
        self.assertEqual(len(found), 1)
        self.assertIsNone(ReminderLog.objects.filter(expiry_at_send=new_expiry).first())

    def test_each_lead_time_is_its_own_reminder(self):
        instance = self._expire_in(60)
        process_tenant_reminders(self.tenant)
        self.assertEqual(ReminderLog.objects.filter(instance=instance).count(), 1)

        # 30 days later, the 30-day reminder is a separate row.
        found = find_due_reminders(
            self.tenant, as_of=timezone.localdate() + datetime.timedelta(days=30)
        )
        self.assertEqual([e["lead_days"] for e in found], [30])


class EmailLogTests(ReminderBase):
    """Every send is logged, with the sensitive parts encrypted."""

    def test_a_successful_send_is_logged(self):
        self._expire_in(30)
        process_tenant_reminders(self.tenant)

        log = EmailLog.objects.get()
        self.assertEqual(log.status, NotificationStatus.SENT)
        self.assertEqual(log.recipient_count, 1)
        self.assertEqual(log.item_count, 1)
        self.assertEqual(log.provider, "locmem")
        self.assertEqual(log.recipients, "screening@church.ca")

    def test_recipients_and_body_are_encrypted_at_rest(self):
        self._expire_in(30)
        process_tenant_reminders(self.tenant)
        log = EmailLog.objects.get()

        with connection.cursor() as cursor:
            cursor.execute(
                "SELECT recipients, subject, body FROM notifications_emaillog WHERE id = %s",
                [log.pk],
            )
            recipients, subject, body = cursor.fetchone()

        for value in (recipients, subject, body):
            self.assertTrue(value.startswith("v1."))
        self.assertNotIn("screening@church.ca", recipients)
        self.assertNotIn("Reed", body)

    def test_metadata_stays_plaintext_for_diagnosis(self):
        self._expire_in(30)
        process_tenant_reminders(self.tenant)
        log = EmailLog.objects.get()

        with connection.cursor() as cursor:
            cursor.execute(
                "SELECT status, recipient_count, item_count, provider "
                "FROM notifications_emaillog WHERE id = %s",
                [log.pk],
            )
            status, recipient_count, item_count, provider = cursor.fetchone()

        self.assertEqual(status, "sent")
        self.assertEqual(recipient_count, 1)
        self.assertEqual(item_count, 1)
        self.assertEqual(provider, "locmem")

    def test_a_provider_failure_is_recorded_rather_than_swallowed(self):
        from unittest import mock

        from apps.notifications.providers import EmailSendError

        self._expire_in(30)
        with mock.patch(
            "apps.notifications.providers.LocMemProvider.send",
            side_effect=EmailSendError("relay refused the message"),
        ):
            result = process_tenant_reminders(self.tenant)

        self.assertFalse(result["sent"])
        log = EmailLog.objects.get()
        self.assertEqual(log.status, NotificationStatus.FAILED)
        self.assertIn("relay refused", log.error)

    def test_the_send_is_audited(self):
        from apps.core.models import AuditAction, AuditEvent

        self._expire_in(30)
        process_tenant_reminders(self.tenant)

        event = AuditEvent.objects.filter(action=AuditAction.NOTIFY).first()
        self.assertIsNotNone(event)
        self.assertIn("administrator", event.summary)


class ProviderTests(TenantTestCase):
    """The swappable provider layer (Build Spec §1)."""

    def test_configured_provider_is_returned(self):
        from apps.notifications.providers import LocMemProvider, get_provider

        self.assertIsInstance(get_provider(), LocMemProvider)

    def test_each_named_provider_resolves(self):
        from apps.notifications.providers import (
            ConsoleProvider,
            LocMemProvider,
            SMTPProvider,
            get_provider,
        )

        self.assertIsInstance(get_provider("smtp"), SMTPProvider)
        self.assertIsInstance(get_provider("console"), ConsoleProvider)
        self.assertIsInstance(get_provider("locmem"), LocMemProvider)

    def test_an_unknown_provider_is_an_error_not_a_silent_fallback(self):
        """
        Quietly printing renewal reminders to a log instead of emailing them would be a
        compliance failure nobody would notice.
        """
        from apps.notifications.providers import EmailSendError, get_provider

        with self.assertRaises(EmailSendError):
            get_provider("sendgrid")

    def test_smtp_provider_is_pointed_at_the_acs_relay(self):
        from apps.notifications.providers import SMTPProvider

        provider = SMTPProvider()
        self.assertEqual(provider.backend_kwargs["host"], "smtp.azurecomm.net")
        self.assertEqual(provider.backend_kwargs["port"], 587)
        self.assertTrue(provider.backend_kwargs["use_tls"])


class NightlySweepTests(ReminderBase):
    """The whole nightly job, in the order the spec requires."""

    def test_sweep_recomputes_activates_and_notifies(self):
        from apps.core.tasks import sweep_tenant

        # Something lapsed, and a minor who has just turned 18.
        instance = self._expire_in(-1)
        minor = self.make_volunteer(
            first_name="Alex", last_name="Young", date_of_birth=datetime.date(2008, 6, 25), age=None
        )
        self.assign(minor, self.role)
        sync_volunteer_requirements(minor, as_of=datetime.date(2026, 5, 1))

        summary = sweep_tenant(self.tenant, as_of=timezone.localdate())

        self.assertGreaterEqual(summary["statuses_recomputed"], 1)
        self.assertTrue(summary["sent"])

        instance.refresh_from_db()
        from apps.requirements.models import RequirementStatus

        self.assertEqual(instance.status, RequirementStatus.OVERDUE)

    def test_one_failing_church_does_not_stop_the_others(self):
        """
        ``sweep_all_tenants`` wraps each church, so a single bad row cannot silence every
        other church's reminders for the night.
        """
        from unittest import mock

        from apps.core.tasks import sweep_all_tenants

        with mock.patch("apps.core.tasks.sweep_tenant", side_effect=RuntimeError("boom")):
            results = sweep_all_tenants()

        for schema, outcome in results.items():
            self.assertTrue(outcome.get("error"), schema)
