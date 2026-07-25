"""
Email provider abstraction.

Build Spec §1 fixes the transport — Azure Communication Services Email, Canada
geography, via the SMTP relay — but requires it to sit behind a swappable interface so
the ACS decision is not baked into every caller. Three implementations:

* :class:`SMTPProvider` — the real one. ACS SMTP relay on port 587 with STARTTLS.
* :class:`ConsoleProvider` — development. Prints to stdout.
* :class:`LocMemProvider` — tests. Collects into ``django.core.mail.outbox``.

ACS specifics worth knowing when configuring it: the SMTP username is
``<acs-resource-name>.<entra-app-id>.<entra-tenant-id>`` and the password is the Entra
app's client secret, so ``EMAIL_HOST_USER`` looks unusually long. The ``From`` address
must be a verified sender on the ACS domain, and SPF/DKIM/DMARC are set up on the
domain by the operator — none of which this code can check, so a misconfiguration
shows up as a provider error recorded in the email log.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass

from django.conf import settings
from django.core.mail import get_connection
from django.core.mail.message import EmailMultiAlternatives

logger = logging.getLogger("vms.notifications")


class EmailSendError(Exception):
    """The provider could not hand the message off."""


@dataclass
class Message:
    """One outbound email, provider-agnostic."""

    subject: str
    body_text: str
    recipients: list[str]
    body_html: str | None = None
    from_email: str | None = None

    def __post_init__(self):
        self.recipients = [r.strip() for r in self.recipients if r and r.strip()]


class EmailProvider:
    """Interface every provider implements."""

    name = "base"

    def send(self, message: Message) -> None:
        raise NotImplementedError


class DjangoBackendProvider(EmailProvider):
    """
    Base for providers that delegate to a Django email backend.

    Keeps the retry/logging behaviour in one place; subclasses only choose a backend.
    """

    backend_path = "django.core.mail.backends.console.EmailBackend"
    backend_kwargs: dict = {}

    def send(self, message: Message) -> None:
        connection = get_connection(backend=self.backend_path, **self.backend_kwargs)
        email = EmailMultiAlternatives(
            subject=message.subject,
            body=message.body_text,
            from_email=message.from_email or settings.DEFAULT_FROM_EMAIL,
            to=message.recipients,
            connection=connection,
        )
        if message.body_html:
            email.attach_alternative(message.body_html, "text/html")

        try:
            sent = email.send(fail_silently=False)
        except Exception as exc:  # noqa: BLE001 - normalised into one error type
            raise EmailSendError(f"{self.name}: {exc}") from exc

        if not sent:
            raise EmailSendError(f"{self.name}: the backend reported nothing was sent.")


class SMTPProvider(DjangoBackendProvider):
    """Azure Communication Services Email over SMTP."""

    name = "acs-smtp"
    backend_path = "django.core.mail.backends.smtp.EmailBackend"

    def __init__(self):
        self.backend_kwargs = {
            "host": settings.EMAIL_HOST,
            "port": settings.EMAIL_PORT,
            "username": settings.EMAIL_HOST_USER,
            "password": settings.EMAIL_HOST_PASSWORD,
            "use_tls": settings.EMAIL_USE_TLS,
            "timeout": settings.EMAIL_TIMEOUT,
        }


class ConsoleProvider(DjangoBackendProvider):
    """Development: writes the message to stdout."""

    name = "console"
    backend_path = "django.core.mail.backends.console.EmailBackend"


class LocMemProvider(DjangoBackendProvider):
    """Tests: appends to ``django.core.mail.outbox``."""

    name = "locmem"
    backend_path = "django.core.mail.backends.locmem.EmailBackend"


_PROVIDERS = {
    "smtp": SMTPProvider,
    "console": ConsoleProvider,
    "locmem": LocMemProvider,
}


def get_provider(name: str | None = None) -> EmailProvider:
    """
    Return the configured provider.

    An unrecognised ``EMAIL_PROVIDER`` is an error rather than a silent fallback to the
    console: quietly printing renewal reminders to a log instead of emailing them would
    be a compliance failure nobody would notice.
    """
    key = (name or settings.EMAIL_PROVIDER or "console").lower()
    try:
        return _PROVIDERS[key]()
    except KeyError as exc:
        raise EmailSendError(
            f"EMAIL_PROVIDER='{key}' is not recognised. Valid values: "
            f"{', '.join(sorted(_PROVIDERS))}."
        ) from exc
