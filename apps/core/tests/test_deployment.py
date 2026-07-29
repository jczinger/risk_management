"""
Deployment-shaped tests: the health check, tenant routing at the edge, and settings guards.

These cover the things that only bite in a real deployment — a container marked unhealthy
because its own probe cannot resolve a tenant, or a production boot that silently comes up
without an encryption key.
"""

from __future__ import annotations

from django.test import Client, SimpleTestCase, TestCase, override_settings

from apps.core.tests.base import TenantTestCase


class HealthCheckTests(TestCase):
    """
    ``/healthz/`` must answer on any hostname.

    Docker's health check and Nginx Proxy Manager both probe over the internal network, where
    the Host header is ``localhost`` or a container name that will never have a Domain row.
    Before the carve-out in VMSTenantMiddleware this 404'd and Docker kept restarting a
    perfectly healthy container.
    """

    def test_it_answers_on_an_unmapped_hostname(self):
        response = Client().get("/healthz/", HTTP_HOST="localhost")

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["status"], "ok")

    def test_it_answers_on_a_container_name(self):
        response = Client().get("/healthz/", HTTP_HOST="web")
        self.assertEqual(response.status_code, 200)

    def test_an_unknown_hostname_is_still_refused_for_real_pages(self):
        """
        The carve-out is for the health path only. Anything else on an unmapped hostname must
        stay refused, so a stray DNS entry cannot reach the operator's console.
        """
        for path in ("/", "/accounts/login/", "/org/volunteers/", "/reports/compliance/"):
            with self.subTest(path=path):
                response = Client().get(path, HTTP_HOST="notachurch.example.invalid")
                self.assertEqual(response.status_code, 404)

    def test_it_reveals_nothing_about_the_deployment(self):
        payload = Client().get("/healthz/", HTTP_HOST="localhost").json()
        self.assertEqual(set(payload), {"status"})

    def test_it_needs_no_csrf_token_or_session(self):
        client = Client(enforce_csrf_checks=True)
        self.assertEqual(client.get("/healthz/", HTTP_HOST="localhost").status_code, 200)


class TenantHealthCheckTests(TenantTestCase):
    """The health check also works on a hostname that *does* resolve to a church."""

    def test_it_answers_on_a_church_hostname(self):
        response = Client(HTTP_HOST=self.TEST_DOMAIN).get("/healthz/")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["status"], "ok")


class ProductionSettingsGuardTests(SimpleTestCase):
    """
    The production settings module refuses to import when something safety-critical is
    missing. Booting a misconfigured system is worse than not booting.
    """

    def test_the_guards_are_present_in_the_module(self):
        import inspect

        from config.settings import prod

        source = inspect.getsource(prod)

        for guard in ("PLATFORM_MASTER_KEY", "ALLOWED_HOSTS", "DJANGO_SECRET_KEY"):
            self.assertIn(guard, source, f"production settings must validate {guard}")
        self.assertIn("ImproperlyConfigured", source)

    def test_production_forces_debug_off(self):
        from config.settings import prod

        self.assertFalse(prod.DEBUG)

    def test_production_sets_secure_cookies(self):
        from config.settings import prod

        self.assertTrue(prod.SESSION_COOKIE_SECURE)
        self.assertTrue(prod.CSRF_COOKIE_SECURE)

    def test_the_proxy_scheme_header_is_honoured(self):
        """
        Nginx Proxy Manager terminates TLS and forwards plain HTTP, so without this Django
        would think every request was insecure — breaking secure cookies and the WebAuthn
        origin check.
        """
        from config.settings import base

        self.assertEqual(base.SECURE_PROXY_SSL_HEADER, ("HTTP_X_FORWARDED_PROTO", "https"))

    def test_the_health_check_is_exempt_from_the_ssl_redirect(self):
        """Otherwise the internal probe gets a 301 and the container reads as unhealthy."""
        from config.settings import prod

        self.assertIn(r"^healthz/$", prod.SECURE_REDIRECT_EXEMPT)

    def test_an_unknown_hostname_is_not_shown_the_public_schema(self):
        from config.settings import base

        self.assertFalse(base.SHOW_PUBLIC_IF_NO_TENANT_FOUND)


class SecurityHeaderTests(TenantTestCase):
    """Standard hardening (Build Spec §6)."""

    def test_responses_carry_the_expected_headers(self):
        client = self.signed_in_client()
        response = client.get("/")

        self.assertEqual(response["X-Frame-Options"], "DENY")
        self.assertEqual(response["X-Content-Type-Options"], "nosniff")
        self.assertEqual(response["Referrer-Policy"], "same-origin")

    def test_pages_are_marked_not_indexable(self):
        client = self.signed_in_client()
        self.assertContains(client.get("/"), "noindex")

    @override_settings(DEBUG=False)
    def test_csrf_is_enforced_on_a_state_changing_post(self):
        from django.urls import reverse

        user = self.make_admin()
        # With no passkey the enrolment gate returns a redirect during the request
        # phase, short-circuiting before CSRF is ever checked — so the assertion below
        # would pass for entirely the wrong reason.
        self.make_passkey(user)
        client = Client(HTTP_HOST=self.TEST_DOMAIN, enforce_csrf_checks=True)
        client.force_login(user)

        response = client.post(
            reverse("org:department_create"), {"name": "Youth", "is_active": "on"}
        )
        self.assertEqual(response.status_code, 403)


class LoggingHygieneTests(SimpleTestCase):
    """PII must not end up in the log stream (Build Spec §6)."""

    def test_sql_logging_is_off_by_default(self):
        """Query logging would print decrypted parameter values into the container log."""
        from config.settings import base

        self.assertEqual(base.LOGGING["loggers"]["django.db.backends"]["level"], "WARNING")

    def test_the_log_format_carries_no_request_body(self):
        from config.settings import base

        fmt = base.LOGGING["formatters"]["plain"]["format"]
        for forbidden in ("body", "POST", "params", "args"):
            self.assertNotIn(forbidden, fmt)
