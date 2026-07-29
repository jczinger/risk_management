"""
One-time sign-in links: issuing them, sending them, and spending them.

A link is the only way into an account that is not a passkey, and it exists for two
moments — the first sign-in after an account is created, and the recovery that follows a
lost passkey. Everything else about signing in is WebAuthn.

**What is in the URL.** A signed payload carrying two things: the schema the account
lives in, and a 256-bit secret. Only the secret's SHA-256 is stored, so the row cannot
be turned back into a working link.

The schema has to travel with the link because sign-in happens in ``public``, before
anything knows which church the visitor belongs to. The alternative — scanning every
schema for a matching token, the way :func:`~apps.tenants.routing.find_passkey_target`
has to for a passkey — is unnecessary here, because we know the answer at issue time.

It is *signed* for the same reason the tenant cookie is
(:mod:`apps.tenants.routing`): consuming a link calls ``bind_tenant()`` on that schema
name, and a value that reaches ``bind_tenant`` must not be attacker-chosen.

**Why the expiry is recorded twice.** ``signing.loads(max_age=...)`` enforces it, and so
does ``LoginLink.expires_at``. Both are set from the same number so they cannot
disagree. The row copy is what an administrator can read, and what survives a clock
change on the signer.
"""

from __future__ import annotations

import datetime
import hashlib
import logging
import secrets

from django.conf import settings
from django.core import signing
from django.db import connection
from django.template.loader import render_to_string
from django.urls import reverse
from django.utils import timezone
from django_tenants.utils import get_public_schema_name

from apps.core import audit
from apps.core.models import AuditAction

from .models import LinkPurpose, LoginLink, User

logger = logging.getLogger("vms.accounts")

SIGNING_SALT = "vms.login-link.v1"


class LinkError(Exception):
    """A link could not be spent. The message is safe to show a visitor."""


#: Deliberately identical for every failure — expired, already used, tampered with, or
#: never existed. Distinguishing them would tell someone holding a stale link whether
#: the account is real.
GENERIC_ERROR = "That sign-in link is no longer valid."


# ---------------------------------------------------------------------------
# Lifetimes
# ---------------------------------------------------------------------------


def lifetime(purpose: str) -> datetime.timedelta:
    """
    How long a link of this kind lives.

    An invite may sit unread in an inbox over a weekend. A recovery link is being used
    right now, so a short window limits what a forwarded or intercepted email is worth.
    """
    if purpose == LinkPurpose.RECOVERY:
        return datetime.timedelta(minutes=settings.VMS_RECOVERY_LINK_MINUTES)
    return datetime.timedelta(days=settings.VMS_INVITE_LINK_DAYS)


def describe_lifetime(purpose: str) -> str:
    """"7 days" or "30 minutes" — for the email body and the on-screen copy."""
    window = lifetime(purpose)
    if window >= datetime.timedelta(days=1):
        days = window.days
        return f"{days} day{'s' if days != 1 else ''}"
    minutes = int(window.total_seconds() // 60)
    return f"{minutes} minutes"


def _hash(secret: str) -> str:
    return hashlib.sha256(secret.encode()).hexdigest()


# ---------------------------------------------------------------------------
# Issuing
# ---------------------------------------------------------------------------


def issue_link(user: User, purpose: str, *, issued_by: User | None = None) -> tuple[LoginLink, str]:
    """
    Mint a link for ``user`` in the currently bound schema. Returns the row and the URL.

    Must be called with the connection already bound to the user's own schema — the
    schema name is read from the connection and baked into the payload, so issuing one
    from the wrong schema would produce a link that resolves to a stranger.
    """
    secret = secrets.token_urlsafe(32)
    window = lifetime(purpose)

    link = LoginLink.objects.create(
        user=user,
        token_hash=_hash(secret),
        purpose=purpose,
        issued_by=issued_by,
        expires_at=timezone.now() + window,
    )

    schema = getattr(connection, "schema_name", get_public_schema_name())
    payload = signing.dumps({"schema": schema, "token": secret}, salt=SIGNING_SALT)

    audit.record(
        AuditAction.LINK_ISSUED,
        "User",
        entity_id=user.pk,
        entity_label=user.get_full_name() or "administrator",
        summary=f"{LinkPurpose(purpose).label} link issued",
        detail={"purpose": purpose, "expires_at": link.expires_at.isoformat()},
    )
    logger.info("Issued %s link user=%s schema=%s", purpose, user.pk, schema)

    return link, absolute_url(payload)


def absolute_url(payload: str) -> str:
    """
    The full URL for a signed payload.

    Built from settings rather than the request, because a link is minted in three
    places — a web view, a console view, and the command line — and only two of them
    have a request. Using one source keeps the URL identical whichever it was.
    """
    path = reverse("accounts:link_consume", args=[payload])
    return f"{settings.VMS_LINK_SCHEME}://{settings.VMS_LINK_HOST}{path}"


# ---------------------------------------------------------------------------
# Spending
# ---------------------------------------------------------------------------


def consume_link(request, payload: str) -> tuple[User, LoginLink]:
    """
    Validate ``payload``, bind the connection to its schema, and mark it spent.

    Raises :class:`LinkError` for every failure with one shared message. The caller is
    responsible for signing the user in — this deliberately stops one step short, so the
    session is created by the same helper every other sign-in path uses.

    On success the connection is bound to the account's schema and stays that way, and
    ``request.vms_login_target`` carries the target for the tenant cookie.
    """
    from apps.tenants import routing

    try:
        data = signing.loads(payload, salt=SIGNING_SALT, max_age=_max_age())
    except signing.SignatureExpired:
        logger.info("Rejected an expired sign-in link")
        raise LinkError(GENERIC_ERROR) from None
    except signing.BadSignature:
        logger.warning("Rejected a sign-in link with a bad signature")
        raise LinkError(GENERIC_ERROR) from None

    schema = data.get("schema") or ""
    secret = data.get("token") or ""
    if not schema or not secret:
        raise LinkError(GENERIC_ERROR)

    target = _bind(request, routing, schema)

    link = LoginLink.objects.filter(token_hash=_hash(secret)).select_related("user").first()
    if link is None or not link.is_usable or not link.user.is_active:
        # Re-bind to public so a failed attempt does not leave the request pointed at a
        # church it never proved it belongs to.
        routing.bind_public(request)
        logger.info("Rejected an unusable sign-in link schema=%s", schema)
        raise LinkError(GENERIC_ERROR)

    link.consume()
    request.vms_login_target = target
    return link.user, link


def _max_age() -> int:
    """
    The longest any link may live, in seconds.

    The signer gets the *invite* window even for a recovery link, because the purpose is
    inside the payload and cannot be read until the signature has already been checked.
    The short recovery window is then enforced by ``expires_at`` on the row, which is
    what ``is_usable`` reads a few lines later. Both guards are load-bearing; neither is
    decoration.
    """
    return int(lifetime(LinkPurpose.INVITE).total_seconds())


def _bind(request, routing, schema: str):
    """Point the connection at ``schema``, refusing anything that is not a live tenant."""
    public = get_public_schema_name()
    if schema == public:
        routing.bind_public(request)
        return routing.LoginTarget(public, None, 0)

    tenant = routing.resolve_tenant(schema)
    if tenant is None:
        # An inactive or deleted church, or a schema name that never existed.
        raise LinkError(GENERIC_ERROR)

    routing.bind_tenant(request, tenant)
    return routing.LoginTarget(schema, tenant, 0)


# ---------------------------------------------------------------------------
# Sending
# ---------------------------------------------------------------------------


def send_link(user: User, url: str, purpose: str, *, church_name: str = "") -> bool:
    """
    Email the link. Returns whether it went.

    A failure is logged and swallowed rather than raised: the link is valid whether or
    not the email reached anybody, and the caller has other ways to hand it over. Making
    the recovery form 500 on a mail outage would be worse than useless.
    """
    template = "invite" if purpose == LinkPurpose.INVITE else "recovery"
    context = {
        "user": user,
        "url": url,
        "church_name": church_name,
        "expires_in": describe_lifetime(purpose),
    }
    subject = (
        "Set up your Volunteer Management System account"
        if purpose == LinkPurpose.INVITE
        else "Your Volunteer Management System sign-in link"
    )
    return _send(user, subject, f"accounts/email/{template}", context, item_count=1)


def notify_recovery_used(user: User) -> int:
    """
    Tell this church's *other* administrators that somebody recovered an account.

    Recovery is self-service by design, so this is what makes it loud. A takeover via a
    compromised mailbox cannot be prevented by anything in this system; being noticed
    the same morning is the realistic defence.

    Returns how many people were told. Zero in the ``public`` schema — the operator has
    no colleagues to notify.
    """
    if _is_public():
        return 0

    from apps.notifications.services import admin_recipients

    recipients = [address for address in admin_recipients() if address]
    others = [address for address in recipients if address != user.email]
    if not others:
        return 0

    context = {"user": user, "when": timezone.localtime()}
    sent = _send(
        user,
        "A sign-in link was used to recover an account",
        "accounts/email/recovery_used",
        context,
        recipients=others,
        item_count=1,
    )
    return len(others) if sent else 0


def _send(user, subject, template_base, context, *, recipients=None, item_count=0) -> bool:
    """Render, log and hand off one message. Never raises."""
    from apps.notifications.providers import EmailSendError, Message, get_provider

    to = recipients if recipients is not None else [user.email]
    to = [address for address in to if address]
    if not to:
        return False

    body_text = render_to_string(f"{template_base}.txt", context)
    body_html = render_to_string(f"{template_base}.html", context)

    entry = _open_log(to, subject, body_text, item_count)
    provider = get_provider()

    try:
        provider.send(
            Message(subject=subject, body_text=body_text, body_html=body_html, recipients=to)
        )
    except EmailSendError as exc:
        logger.warning("Could not send %s: %s", template_base, exc)
        if entry is not None:
            entry.mark_failed(str(exc), provider=provider.name)
        return False

    if entry is not None:
        entry.mark_sent(provider=provider.name)
    logger.info("Sent %s to %d recipient(s)", template_base, len(to))
    return True


def _open_log(recipients, subject, body, item_count):
    """
    Record the attempt in the church's email log, where there is one.

    ``EmailLog`` is a tenant table — ``apps.notifications`` is in TENANT_APPS only — so
    a link to the operator's console account has nowhere to write. That must not stop
    the send, so it degrades to a log line, exactly as :func:`apps.core.audit.record`
    does for the same reason.
    """
    if _is_public():
        logger.info("No email log outside a church schema; sending %r unlogged", subject)
        return None

    from apps.notifications.models import EmailLog

    return EmailLog.objects.create(
        recipients=", ".join(recipients),
        subject=subject,
        body=body,
        recipient_count=len(recipients),
        item_count=item_count,
    )


def _is_public() -> bool:
    return getattr(connection, "schema_name", get_public_schema_name()) == get_public_schema_name()
