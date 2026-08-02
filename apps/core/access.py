"""
The one place that answers "may this person do this, to whom?".

Before this module there were two authorisation gates in the whole codebase:
``@login_required`` on every church-side view, and ``is_superuser`` on the platform
console. Every screening admin at a church saw that church's whole file, which Build
Spec §2 stated positively. That changed on 2026-07-29 at the owner's direction; see
BUILD_NOTES §1.21.

There are two questions, and they get different answers on purpose:

**"May they do this at all?"** — a capability check, and a failure is **403**. Saying
"you cannot manage requirements" reveals nothing and is the useful answer.

**"May they do it to *this* record?"** — a scope check, and a failure is **404**.
This is not squeamishness. A 403 on ``/org/volunteers/412/`` tells a Youth admin that
volunteer 412 exists at this church and is not in Youth; walked over the id range,
that is a complete membership list, including which ids are minors. This system
encrypts addresses and medical notes precisely to avoid that class of exposure, and
leaking the same facts through a status code would make that effort pointless.

So scope is enforced by **narrowing the queryset ``get_object_or_404`` reads**, never
by a check after the fetch::

    volunteer = get_object_or_404(scope_volunteers(Volunteer.objects.all(), request.user), pk=pk)

That shape matters beyond the status code. It is one line with the same control flow
as the unscoped version, so a reviewer sees the whole decision at once. A separate
``if`` is a second statement that can be forgotten independently of the first — and
forgetting it fails *open*.

Two things this module deliberately does not do:

* **It does not scope inside the service layer, and there is no default manager
  scope.** ``sweep_tenant`` runs as ``Actor.system("nightly job")`` across every
  volunteer in the church and must keep doing so; the same goes for
  ``provision_church`` and the seeders. A thread-local-user manager scope would be
  tempting, would look elegant, and would silently break all three. Scoping belongs
  at the view and report-builder boundary, where there is a request and a user.
* **It does not consult the acting user from the audit thread-local.**
  ``apps.core.audit`` says of that thread-local that it "is deliberately *not* relied
  upon for correctness of authorisation — only for labelling", and that stays true.
  Authorisation reads ``request.user``.
"""

from __future__ import annotations

import functools

from django.contrib.auth.decorators import login_required
from django.core.exceptions import PermissionDenied
from django.db import connection
from django.db import models as django_models
from django_tenants.utils import get_public_schema_name


class Capability(django_models.TextChoices):
    """
    What an access level can grant.

    Each value is exactly the matching ``AccessLevel`` field name minus ``can_``, so
    the mapping is one derivation rather than a table to maintain. A test walks
    ``Capability`` and ``AccessLevel.CAPABILITY_FIELDS`` in both directions, so a new
    field without a member here — or the reverse — fails the suite rather than
    silently becoming unenforceable.
    """

    VIEW_VOLUNTEERS = "view_volunteers", "See volunteer records"
    EDIT_VOLUNTEERS = "edit_volunteers", "Add and edit volunteers"
    MANAGE_ASSIGNMENTS = "manage_assignments", "Assign volunteers to ministry roles"
    RECORD_SCREENING = "record_screening", "Record screening progress"
    RECORD_CRC = "record_crc", "Record criminal record check results"
    MANAGE_ORG = "manage_org", "Create departments and ministry roles"
    MANAGE_REQUIREMENTS = "manage_requirements", "Define requirements"
    VIEW_AUDIT = "view_audit", "Read the audit trail"
    MANAGE_USERS = "manage_users", "Manage administrators and access levels"


#: Cached on the user instance, so a request that scopes six querysets and renders
#: nine navigation guards costs one query rather than fifteen.
_GRANT_CACHE_ATTR = "_vms_access_grant"


def on_public_schema() -> bool:
    """
    Whether the connection is bound to ``public``.

    ``core_accesslevel`` does not exist there — ``apps.core`` is TENANT_APPS only —
    and three call paths genuinely reach this module from the public schema: the
    shared sign-in page, the context processor running for a console template, and
    the default-deny middleware. Guarded the way ``audit.record()`` guards itself.
    """
    return getattr(connection, "schema_name", get_public_schema_name()) == get_public_schema_name()


# ---------------------------------------------------------------------------
# Resolving what a user holds
# ---------------------------------------------------------------------------


def grant_for(user):
    """The user's :class:`~apps.core.models.UserAccessGrant`, or None."""
    if user is None or not getattr(user, "is_authenticated", False) or not user.is_active:
        return None
    if on_public_schema():
        return None

    cached = getattr(user, _GRANT_CACHE_ATTR, ...)
    if cached is not ...:
        return cached

    from .models import UserAccessGrant

    grant = (
        UserAccessGrant.objects.select_related("access_level").filter(user_id=user.pk).first()
    )
    setattr(user, _GRANT_CACHE_ATTR, grant)
    return grant


def level_for(user):
    """The user's :class:`~apps.core.models.AccessLevel`, or None."""
    grant = grant_for(user)
    return grant.access_level if grant is not None else None


def scope_department_ids(user) -> frozenset[int] | None:
    """
    The department ids this user is limited to, or ``None`` meaning *unscoped*.

    ``None`` and ``frozenset()`` are different answers and must never be conflated.
    ``None`` means every department; an empty set means **no** departments, which is what
    a half-finished Department Admin holds and which must show them nothing. That is also
    why ``AccessLevel.is_scoped`` is an explicit flag rather than derived from whether
    any departments happen to be attached — deriving it gets exactly this case backwards
    and turns an incomplete grant into church-wide access.

    Three inputs, three answers, and the first two look similar enough to be worth
    spelling out:

    * ``user=None`` — **no user in play at all**, so nothing to scope by: unscoped. This
      is the nightly sweep, ``provision_church``, the seeders and the management
      commands, none of which act on behalf of a person.
    * an authenticated account with no grant — **a person who has been granted nothing**:
      the empty set, and they see nothing. This is the fail-closed state the backfill
      migration exists to avoid.
    * ``AnonymousUser`` — also the empty set, via the same path.

    The asymmetry with :func:`has_capability`, which answers False for ``user=None``, is
    deliberate. Scoping is a filter applied by trusted code that already knows what it is
    doing; a capability check is a question about a person, and "no person" is not a
    reason to say yes.
    """
    if user is None:
        return None

    grant = grant_for(user)
    if grant is None:
        return frozenset()
    if not grant.access_level.is_scoped:
        return None
    return frozenset(grant.departments.values_list("pk", flat=True))


def has_capability(user, capability: str) -> bool:
    """
    The single authority on whether ``user`` holds ``capability``.

    Deliberately **not** short-circuited on ``is_superuser``. Church-side ``User``
    rows carry ``PermissionsMixin`` and ``createsuperuser`` behaves per-schema, so one
    run against the wrong schema would otherwise mint an unscoped church admin with no
    grant row — nothing on the access-level screen, and nothing to revoke. The
    platform console keeps its own separate gate in ``apps.tenants.views``; two gates,
    two purposes, and neither should learn about the other.
    """
    level = level_for(user)
    if level is None or not level.is_active:
        return False
    return bool(getattr(level, f"can_{capability}", False))


def is_unscoped(user) -> bool:
    """Whether this user sees the whole church. The reviewer test, among other uses."""
    return scope_department_ids(user) is None


# ---------------------------------------------------------------------------
# Nobody screens themselves
# ---------------------------------------------------------------------------


def another_unscoped_admin_exists(*, exclude_user_id) -> bool:
    """
    Whether some *other* active administrator sees the whole church.

    "Is there another responsible adult." Two rules depend on the answer — who may
    affirm a review item, and who may record screening against their own file — and
    they must not drift apart, so they read it from here. It used to live in
    ``apps.review.services`` as ``_another_reviewer_exists``; that function now calls
    this one.

    One limitation worth knowing: this tests *existence*, not usefulness. An unscoped
    level with ``view_volunteers`` switched off counts here but could not open the
    review queue, so the answer can be "yes" while pointing at somebody who cannot
    actually act. Erring that way is the safe direction — it refuses rather than
    permits — but it means a church can be told "ask someone else" with nobody to ask.
    """
    from apps.accounts.models import User

    from .models import UserAccessGrant

    if on_public_schema():
        return False

    candidates = (
        UserAccessGrant.objects.filter(
            access_level__is_scoped=False, access_level__is_active=True
        )
        .exclude(user_id=exclude_user_id)
        .values_list("user_id", flat=True)
    )
    return User.objects.filter(pk__in=list(candidates), is_active=True).exists()


def grant_of(user):
    """The grant a user holds right now, fresh from the database — no caching."""
    from .models import UserAccessGrant

    return (
        UserAccessGrant.objects.select_related("access_level")
        .filter(user_id=user.pk)
        .first()
    )


def no_access_level():
    """
    A stand-in level that grants nothing, for asking "what if this person were gone?".

    Unsaved, so it touches no data. Lets the deactivation path reuse
    :func:`would_strand_the_church` rather than restating the same query with the
    condition inverted.
    """
    from .models import AccessLevel

    return AccessLevel(name="(deactivated)", is_scoped=True, can_manage_users=False)


def access_snapshot(grant) -> dict:
    """What the audit diff records about a grant: the level, and its departments."""
    if grant is None:
        return {"access_level": "(none)", "departments": ""}
    return {
        "access_level": grant.access_level.name,
        "departments": ", ".join(sorted(grant.departments.values_list("name", flat=True))),
    }


def would_strand_the_church(subject, new_level) -> str:
    """
    Refuse a change that would leave the church with nobody who can manage access.

    The sibling of the existing "last active administrator" guard, and reopened by access
    levels: demoting or re-scoping the only unscoped admin who holds ``manage_users``
    locks the church out of the very screen needed to undo it. The only way back would be
    an operator with shell access.
    """
    from apps.accounts.models import User

    from .models import UserAccessGrant

    still_qualifies = not new_level.is_scoped and new_level.can_manage_users
    if still_qualifies:
        return ""

    others = (
        UserAccessGrant.objects.select_related("access_level")
        .filter(
            access_level__is_scoped=False,
            access_level__can_manage_users=True,
            access_level__is_active=True,
        )
        .exclude(user_id=subject.pk)
        .values_list("user_id", flat=True)
    )
    if User.objects.filter(pk__in=list(others), is_active=True).exists():
        return ""

    return (
        f"{subject.get_full_name()} is the only administrator who can manage access for "
        "the whole church. Give somebody else that access first, or this church would "
        "have no way to change it back."
    )


def own_review_backlog_unlocked_by_removing(actor, subject) -> str:
    """
    Refuse a deactivation that would hand the actor the right to affirm their own work.

    ``may_review`` refuses self-affirmation *while somebody else could do it*, and allows
    it when nobody could — an escape hatch for the church whose only other church-wide
    administrator has left, which would otherwise deadlock with a queue it cannot clear.

    The hatch turns out to be openable on purpose. An administrator sitting on a pile of
    their own unaffirmed entries could deactivate the last other reviewer, and the same
    entries they were refused a moment ago become theirs to wave through. Nothing else
    stopped it: the guards above protect against *lockout*, which is a different set of
    people — :func:`would_strand_the_church` asks who can manage access, not who can
    review.

    So: refused, with the count, while those entries exist. Work recorded *after* a
    church genuinely becomes single-administrator is untouched, because that is the
    situation the hatch is for. Added 2026-08-02; see BUILD_NOTES §1.22.
    """
    from apps.accounts.models import User
    from apps.review.models import ReviewItem

    from .models import UserAccessGrant

    if actor.pk == subject.pk or not is_unscoped(actor):
        return ""

    # Would any reviewer other than the actor survive this deactivation?
    others = (
        UserAccessGrant.objects.filter(
            access_level__is_scoped=False, access_level__is_active=True
        )
        .exclude(user_id__in=[actor.pk, subject.pk])
        .values_list("user_id", flat=True)
    )
    if User.objects.filter(pk__in=list(others), is_active=True).exists():
        return ""

    pending = ReviewItem.objects.pending().filter(recorded_by_user_id=actor.pk).count()
    if not pending:
        return ""

    one = pending == 1
    return (
        f"You have {pending} {'entry' if one else 'entries'} awaiting review, and "
        f"{subject.get_full_name()} is the only other administrator who can affirm "
        f"{'it' if one else 'them'}. Ask them to clear the queue first, then deactivate "
        "the account."
    )


def is_own_record(user, volunteer) -> bool:
    """Whether this volunteer file belongs to the person looking at it."""
    pk = getattr(user, "pk", None)
    linked = getattr(volunteer, "user_id", None)
    return pk is not None and linked is not None and pk == linked


def may_record_against(user, volunteer) -> tuple[bool, str]:
    """
    Whether ``user`` may write to ``volunteer``'s screening file, and why not if not.

    Plan to Protect presumes the screener and the screened are different people. Until
    administrators were linked to their own files, VMS had no way to express that: an
    administrator could tick their own training, record their own criminal record check
    as clear, and nothing would notice, because nothing knew it was them.

    Deliberately mirrors :func:`apps.review.services.may_review`, down to the escape
    hatch, so a church learns one rule rather than two:

    * Not their own file — allowed, and this is the overwhelmingly common answer.
    * Their own file, on a **limited** level — refused, always. Somebody with access to
      the whole church exists by construction, or that admin could not have been created.
    * Their own file, seeing the **whole church** — refused while another such
      administrator exists; allowed when they are the last one, because refusing would
      leave a single-administrator church unable to complete its own file at all. The
      review queue is what surfaces that a self-recording happened (see
      :func:`apps.review.recording.needs_review`).

    Reading is untouched. Seeing your own screening status is not a conflict of
    interest, and hiding it would only teach people to keep a second copy elsewhere.
    """
    if not is_own_record(user, volunteer):
        return True, ""

    why = _self_refusal(is_limited=not is_unscoped(user), user_id=user.pk)
    return why is None, why or ""


def _self_refusal(*, is_limited: bool, user_id) -> str | None:
    """
    The self-screening decision itself, shared by both enforcement layers.

    :func:`may_record_against` (request.user) and :func:`refuse_self_recording`
    (audit actor) deliberately stay separate — each reads identity from its own
    source — but the rule and its wording live once, here.
    """
    if is_limited:
        return (
            "This is your own screening file. Someone with access to the whole church "
            "has to record it."
        )
    if another_unscoped_admin_exists(exclude_user_id=user_id):
        return (
            "This is your own screening file. Ask another administrator with access to "
            "the whole church to record it."
        )
    return None


def require_own_record_not_touched(user, volunteer) -> None:
    """Raise ``PermissionDenied`` when ``user`` may not write to ``volunteer``.

    **403, not 404** — the opposite of the out-of-scope rule two sections down, and
    deliberately so. Out of scope hides the record because confirming it exists is
    itself the leak. Here they can already see the file; pretending it had vanished
    would be a lie, and the refusal is one they need explained rather than concealed.
    """
    allowed, why = may_record_against(user, volunteer)
    if not allowed:
        raise PermissionDenied(why)


def refuse_self_recording(volunteer, actor=None) -> None:
    """
    The service-layer twin of :func:`require_own_record_not_touched`.

    Same rule, read from the ambient audit actor instead of ``request.user``, so a
    screening write is refused even when it arrives from somewhere that is not a view —
    a management command, a future import, a caller written next year. This is the
    posture ``RoleAssignment.clean()`` already takes with the disqualification rule, and
    for the same reason: a rule enforced only at the edge is a rule with an inside.

    Every way this can fail to identify somebody fails *safe*. ``Actor.system()`` and
    every unattributed job carry ``user_id=None``, which matches no file. An actor whose
    access level could not be resolved is treated as limited, so it refuses rather than
    waves through. The one thing this trusts the thread-local for is *identity*, never
    permission — see :mod:`apps.core.audit`.
    """
    from apps.core import audit

    actor = actor or audit.get_actor()
    linked = getattr(volunteer, "user_id", None)
    if actor.user_id is None or linked is None or actor.user_id != linked:
        return

    why = _self_refusal(
        is_limited=actor.access_level_is_scoped or actor.access_level_unknown,
        user_id=actor.user_id,
    )
    if why:
        raise PermissionDenied(why)


# ---------------------------------------------------------------------------
# View decorators
# ---------------------------------------------------------------------------


def requires(*capabilities: str, any_of: bool = False):
    """
    Gate a view on one or more capabilities, and *declare* that it was gated.

    The declaration is the point as much as the check: ``AccessGateMiddleware`` reads
    ``view.vms_capabilities`` and refuses any view that never set it, so a future view
    written with ``@login_required`` alone fails closed instead of being reachable by
    everybody.
    """
    if not capabilities:
        raise ValueError("requires() needs at least one capability.")

    def decorator(view):
        @functools.wraps(view)
        def wrapped(request, *args, **kwargs):
            held = [has_capability(request.user, cap) for cap in capabilities]
            if not (any(held) if any_of else all(held)):
                raise PermissionDenied(
                    "This account does not have access to that part of VMS."
                )
            return view(request, *args, **kwargs)

        wrapped.vms_capabilities = frozenset(capabilities)
        return login_required(wrapped)

    return decorator


def open_to_any_signed_in_user(reason: str):
    """
    For views any signed-in administrator may reach, whatever their access level.

    The reason is mandatory and that is the whole design: it turns "no capability
    needed here" into a written decision that survives review, rather than an omission
    indistinguishable from a mistake. Used for a person's own profile and passkeys, and
    for the forced key-backup step — which ``ForceKeyBackupMiddleware`` redirects
    *every* authenticated user to, so gating it on a capability would trap a Department
    Admin on a page they cannot open.
    """
    if not reason:
        raise ValueError("open_to_any_signed_in_user() needs a reason.")

    def decorator(view):
        view.vms_capabilities = frozenset()
        view.vms_open_reason = reason
        return login_required(view)

    return decorator


def public_view(reason: str):
    """For views reachable without signing in: sign-in itself, recovery, health."""
    if not reason:
        raise ValueError("public_view() needs a reason.")

    def decorator(view):
        view.vms_public = True
        view.vms_open_reason = reason
        return view

    return decorator


# ---------------------------------------------------------------------------
# Queryset scoping
# ---------------------------------------------------------------------------
#
# Every function here keeps the same contract, so they are interchangeable at a
# glance and none of them can quietly be the odd one out:
#
#   * same queryset class in, same class out — which is what keeps NoDeleteQuerySet's
#     closed delete path closed;
#   * returned unchanged when the user is unscoped;
#   * ``.none()`` when the user has no grant at all.


def _scope(qs, user, unscoped_filter):
    ids = scope_department_ids(user)
    if ids is None:
        return qs
    if not ids:
        return qs.none()
    return unscoped_filter(qs, ids)


def scope_volunteers(qs, user):
    """Volunteers the user may see: those who have **ever** served in their departments."""
    return _scope(qs, user, lambda q, ids: q.ever_in_departments(ids))


def scope_departments(qs, user):
    return _scope(qs, user, lambda q, ids: q.filter(pk__in=ids))


def scope_roles(qs, user):
    return _scope(qs, user, lambda q, ids: q.filter(department_id__in=ids))


def scope_assignments(qs, user):
    """
    Assignments the user may act on, keyed on the assignment's **own** department.

    Not the volunteer's departments, and the difference is a real hole rather than a
    nicety: scoping by volunteer would let a Youth admin end a shared volunteer's
    Music assignment, which turns "end an assignment" into a way of reaching outside
    your own departments.
    """
    return _scope(qs, user, lambda q, ids: q.filter(role__department_id__in=ids))


def scope_instances(qs, user):
    return _scope(qs, user, lambda q, ids: q.ever_in_departments(ids))


def _by_volunteer_departments(qs, ids):
    return qs.filter(volunteer__assignments__role__department_id__in=ids).distinct()


def scope_documents(qs, user):
    return _scope(qs, user, _by_volunteer_departments)


def scope_crc_records(qs, user):
    return _scope(qs, user, _by_volunteer_departments)


def scope_audit_events(qs, user):
    """
    The audit trail, which is all of it or none of it.

    ``AuditEvent`` records no department and cannot be made to. Its pointer to the
    affected row is ``entity_type``/``entity_id`` — two strings, chosen deliberately
    because ContentType ids are not tenant-stable — so there is no queryable path from
    an entry to a department. A partial filter on ``entity_type="Volunteer"`` would be
    *worse* than refusing, because it would look scoped while missing every
    RequirementInstance, Document and CRCRecord entry about the same person.

    So a scoped level cannot hold ``view_audit`` at all: ``AccessLevel.clean()``
    refuses the combination, and this function returning nothing is the second layer
    in case a row is ever written past the first.
    """
    ids = scope_department_ids(user)
    return qs if ids is None else qs.none()
