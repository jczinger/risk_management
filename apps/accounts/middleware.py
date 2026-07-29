"""Gate that holds a signed-in account at passkey enrolment until it has one."""

from django.conf import settings
from django.shortcuts import redirect
from django.urls import reverse


class ForcePasskeyMiddleware:
    """
    Blocks an account with no passkey from doing anything except registering one.

    A passkey is the only way to sign in. The single-use link that got somebody here is
    spent, so an account that leaves without enrolling is an account that has to recover
    itself all over again next time — and, until it does, one whose entire security
    rests on a mailbox.

    A redirect out of the link-consume view would not be enough: the person is signed in
    at that point and could simply type another URL. Enforcing it on every request is
    what makes "immediately force them" true, and it is the same approach
    :class:`apps.tenants.middleware.ForceKeyBackupMiddleware` already takes for the
    encryption-key backup step.

    Ordered **before** that one in ``MIDDLEWARE``. A brand-new church's admin trips both
    gates on the same request; enrolling a passkey first and confirming the key backup
    second is the right sequence, and returning a redirect during the request phase
    means the later middleware simply does not run until this one is satisfied.
    """

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        user = getattr(request, "user", None)
        if user is None or not user.is_authenticated:
            return self.get_response(request)

        if self._is_exempt(request.path):
            return self.get_response(request)

        if user.has_passkey:
            return self.get_response(request)

        return redirect(reverse("accounts:passkey_required"))

    @staticmethod
    def _is_exempt(path: str) -> bool:
        exempt_prefixes = (
            settings.STATIC_URL or "/static/",
            "/healthz/",
            # Signing out must always work. Trapping someone on a page they cannot
            # complete — a browser with no authenticator, say — with no way off it
            # would be worse than the state this gate exists to prevent.
            "/accounts/logout/",
            "/accounts/login/",
            # The enrolment page itself, and the ceremony it drives.
            "/accounts/passkey-required/",
            "/accounts/webauthn/",
            # Spending a link signs someone in; it must not be bounced by this gate on
            # the way, or the redirect would land before the session exists.
            "/accounts/link/",
        )
        return path.startswith(exempt_prefixes)
