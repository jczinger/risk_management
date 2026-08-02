"""
Shared test bases.

Every tenant-side test needs a tenant schema with a real data-encryption key, since
touching any encrypted field without one is (correctly) a hard error. These bases set that
up once per run and give tests convenient factories.
"""

from __future__ import annotations

import datetime

from django.core.cache import cache
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

        # So is the rate-limit cache. LocMemCache lives for the whole process, and
        # django-ratelimit counts sign-in attempts per email and per IP — which in tests
        # means one address and one IP for the entire run. Without this, every login a
        # test performs is charged against the next test's budget, and somewhere past
        # LOGIN_RATELIMIT (10/5m) an unrelated test starts getting "too many attempts"
        # instead of a sign-in. That is order-dependent and looks like a real failure in
        # whichever test happens to be over the line. The two tests that assert on rate
        # limiting build their own counts from this clean slate.
        cache.clear()

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

    def make_admin(self, email="admin@test.ca", **extra):
        """
        An administrator. Passwordless, like every real one — there are no passwords.

        A **Primary Admin**, unless ``access_level`` says otherwise. That default is
        load-bearing: it is what a screening admin was before access levels existed, so
        every test written before them keeps meaning what it meant. Without a grant an
        account can do nothing at all, because ``has_capability`` fails closed.

        No passkey, which matters for anything going through the request stack:
        ``ForcePasskeyMiddleware`` redirects an account without one to enrolment. Use
        :meth:`make_passkey` when the test needs to get past that.
        """
        from apps.accounts.models import User
        from apps.core.seed import grant_primary_admin

        access_level = extra.pop("access_level", None)
        defaults = {"first_name": "Test", "last_name": "Admin"}
        defaults.update(extra)
        user = User.objects.create_user(email=email, **defaults)

        if access_level is None:
            grant_primary_admin(user.pk, granted_by_display="test fixture")
        else:
            self.grant_access(user, access_level)
        return user

    def grant_access(self, user, access_level, departments=()):
        """Put ``user`` on ``access_level``, replacing any grant they already hold."""
        from apps.core.models import UserAccessGrant

        grant, _ = UserAccessGrant.objects.update_or_create(
            user_id=user.pk,
            defaults={"access_level": access_level, "granted_by_display": "test fixture"},
        )
        grant.departments.set(departments)
        # grant_for caches on the instance, so a test that changes a grant mid-way would
        # otherwise keep reading the old one.
        self.forget_access(user)
        return grant

    def forget_access(self, user):
        """Drop the cached grant on a user instance."""
        from apps.core.access import _GRANT_CACHE_ATTR

        if hasattr(user, _GRANT_CACHE_ATTR):
            delattr(user, _GRANT_CACHE_ATTR)

    def department_admin_level(self):
        from apps.core.models import AccessLevel

        return AccessLevel.objects.get(slug=AccessLevel.DEPARTMENT_ADMIN)

    def make_department_admin(self, email="dept@test.ca", departments=(), **extra):
        """
        An administrator limited to ``departments``.

        Given a passkey by default, unlike :meth:`make_admin`, because almost every test
        that wants one is going through the request stack to check what they can reach.
        """
        user = self.make_admin(email=email, access_level=self.department_admin_level(), **extra)
        self.grant_access(user, self.department_admin_level(), departments)
        self.make_passkey(user)
        return user

    def make_passkey(self, user, label="Test device"):
        """
        A registered passkey, without the WebAuthn ceremony.

        The credential is not real — nothing here will verify a signature against it —
        but its presence is what ``has_passkey`` reads, and that is what the enrolment
        gate turns on.
        """
        import secrets

        from apps.accounts.models import Passkey

        return Passkey.objects.create(
            user=user,
            credential_id=secrets.token_urlsafe(24),
            public_key=b"not-a-real-key",
            label=label,
        )

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

    def make_own_file(self, user, role=None, **extra):
        """
        The volunteer record belonging to an administrator.

        Named for what it is used to test: "their own file", the thing nobody may record
        screening against while somebody else could. Takes the name from the account, so
        a test does not accidentally check the rule against a different person.
        """
        volunteer = self.make_volunteer(
            first_name=extra.pop("first_name", user.first_name or "Admin"),
            last_name=extra.pop("last_name", user.last_name or "Person"),
            user_id=user.pk,
            **extra,
        )
        if role is not None:
            self.assign(volunteer, role)
        return volunteer

    def seed(self):
        from apps.requirements.seed import seed_default_template

        return seed_default_template()

    def signed_in_client(self, user=None, *, with_passkey=True):
        """
        A test client with a signed-in admin, bypassing the WebAuthn ceremony.

        The user is given a passkey by default. Without one every request would be
        redirected to enrolment by ``ForcePasskeyMiddleware``, which is correct
        behaviour and would make this helper useless for testing anything else. Pass
        ``with_passkey=False`` when the gate itself is what is under test.
        """
        from django.test import Client

        user = user or self.make_admin()
        if with_passkey and not user.has_passkey:
            self.make_passkey(user)
        client = Client(HTTP_HOST=self.TEST_DOMAIN)
        client.force_login(user)
        return client
