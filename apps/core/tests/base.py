"""
Shared test bases.

Every tenant-side test needs a tenant schema with a real data-encryption key, since
touching any encrypted field without one is (correctly) a hard error. These bases set that
up once per run and give tests convenient factories.
"""

from __future__ import annotations

import datetime

from django.db import connection
from django.utils import timezone
from django_tenants.test.cases import FastTenantTestCase

from apps.core.crypto import generate_dek, key_fingerprint, wrap_dek
from apps.core.keys import forget_cached_keys


class TenantTestCase(FastTenantTestCase):
    """
    Base for tests that run inside a tenant schema.

    ``FastTenantTestCase`` creates and migrates the schema once for the whole run and wraps
    each test in a transaction, so the per-test cost is a rollback rather than a migration.
    """

    @classmethod
    def setup_tenant(cls, tenant):
        # Called before the tenant row is saved. The DEK has to exist by then: seeding runs
        # inside the same save, and anything encrypted would fail without a key.
        tenant.name = "Test Church"
        dek = generate_dek()
        tenant.dek_wrapped = wrap_dek(dek)
        tenant.dek_fingerprint = key_fingerprint(dek)
        # Tests are not the forced-backup flow; mark it satisfied so the middleware does
        # not redirect every request under test.
        tenant.key_backup_confirmed_at = timezone.now()
        tenant.reminder_lead_days = "60,30,7"
        return tenant

    #: Fixed, not derived from the connection. ``FastTenantTestCase`` calls this during
    #: setUpClass while the connection is still on the public schema, so computing it from
    #: ``connection.schema_name`` would register the domain under the wrong name — requests
    #: would then match no tenant and silently fall back to the public schema, which shows
    #: up as "relation does not exist" several tests later.
    TEST_DOMAIN = "fast-test.testserver"

    @classmethod
    def get_test_tenant_domain(cls):
        return cls.TEST_DOMAIN

    def setUp(self):
        super().setUp()
        # The key cache is process-global; a stale entry would leak across test classes.
        forget_cached_keys()

        # FastTenantTestCase holds ONE Tenant instance as a class attribute for the whole
        # run. A test that changes a church setting — reminder lead times, notifications on
        # or off — mutates that shared object, and while the database write is rolled back
        # the in-memory attribute is not. Later tests in the same class would then read the
        # previous test's settings. Reloading from the database each time restores it.
        self.tenant.refresh_from_db()

        # A request that fails to resolve a tenant leaves the connection on the public
        # schema. Re-bind so one such test cannot cascade into the rest of the class.
        connection.set_tenant(self.tenant)

    def tearDown(self):
        connection.set_tenant(self.tenant)
        super().tearDown()

    # -- Factories ---------------------------------------------------------

    def make_admin(self, email="admin@test.ca", password="TestPassw0rd!2026", **extra):
        from apps.accounts.models import User

        defaults = {"first_name": "Test", "last_name": "Admin"}
        defaults.update(extra)
        return User.objects.create_user(email=email, password=password, **defaults)

    def make_department(self, name="Children's Ministry", **extra):
        from apps.org.models import Department

        return Department.objects.create(name=name, **extra)

    def make_role(self, department=None, name="Helper", **extra):
        from apps.org.models import Role

        department = department or self.make_department()
        return Role.objects.create(department=department, name=name, **extra)

    def make_volunteer(self, first_name="Sam", last_name="Taylor", age=30, **extra):
        """
        Create a volunteer, defaulting to an adult.

        ``age`` is a convenience: it back-computes a date of birth that makes
        :meth:`Volunteer.age_on` return that number today.
        """
        from apps.org.models import Volunteer

        if "date_of_birth" not in extra and age is not None:
            today = timezone.localdate()
            extra["date_of_birth"] = datetime.date(today.year - age, today.month, 15)

        return Volunteer.objects.create(first_name=first_name, last_name=last_name, **extra)

    def assign(self, volunteer, role, **extra):
        from apps.org.models import RoleAssignment

        return RoleAssignment.objects.create(volunteer=volunteer, role=role, **extra)

    def seed(self):
        from apps.requirements.seed import seed_default_template

        return seed_default_template()

    def signed_in_client(self, user=None):
        """A test client with a signed-in admin, bypassing the passkey/TOTP ceremony."""
        from django.test import Client

        user = user or self.make_admin()
        client = Client(HTTP_HOST=self.TEST_DOMAIN)
        client.force_login(user)
        return client
