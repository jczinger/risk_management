"""
The administrator ↔ volunteer-file link (BUILD_NOTES §1.22).

An administrator is also a person who serves, and Plan to Protect screens people who
serve — so every administrator account carries its own Ministry Personnel file. These
helpers create, find and attach that file; the views in :mod:`apps.accounts.views`
stay at the request/response altitude and call down here for the policy.
"""

from __future__ import annotations

from django.core.exceptions import PermissionDenied
from django.db.models import Q
from django.http import Http404
from django.shortcuts import get_object_or_404

from apps.core import audit
from apps.core.access import scope_volunteers
from apps.core.models import AuditAction
from apps.org.models import Volunteer


def volunteer_from_request(request):
    """
    The volunteer an invitation is *for*, from ``?volunteer=``, or None.

    Scoped, so an out-of-scope pk 404s rather than leaking that it exists. Refuses a
    permanently disqualified person: somebody barred from every position of trust under
    the policy should not be administering the screening of others, and saying so is
    better than quietly omitting the button they already clicked.
    """
    pk = request.GET.get("volunteer") or request.POST.get("volunteer")
    if not pk:
        return None

    volunteer = get_object_or_404(
        scope_volunteers(Volunteer.objects.all(), request.user), pk=pk
    )
    if volunteer.user_id is not None:
        raise Http404("That volunteer is already linked to an administrator.")
    if volunteer.is_permanently_disqualified:
        raise PermissionDenied(
            "This person is permanently disqualified under the Plan to Protect policy "
            "and cannot be made a screening administrator."
        )
    return volunteer


def file_for_new_admin(user, existing_file=None) -> str:
    """
    Give a new administrator a volunteer file, or explain why one was not created.

    Returns a warning to show the inviter, or an empty string when there is nothing to
    say. Must run inside the caller's transaction.

    Three cases, and the middle one is the whole reason this is not a one-liner:

    * **An explicit file was chosen** — link it. No guessing was involved.
    * **A file already exists under that name** — create nothing and say so. Two people
      genuinely can share a name, and silently attaching an administrator to somebody
      else's screening record, or silently merging two, is worse than a second click.
      There is no merge tool if it goes wrong.
    * **Nothing matches** — create a file from their name and address, with **no**
      ministry role. That leaves it invisible to every limited access level, including
      the new administrator's own, because scope runs through role assignments; a
      Primary Admin completes it. Intended, and stated here so it is not discovered.
    """
    if existing_file is not None:
        existing_file.user_id = user.pk
        existing_file.save(update_fields=["user_id", "updated_at"])
        audit.record(
            AuditAction.UPDATE,
            "Volunteer",
            entity_id=existing_file.pk,
            entity_label=existing_file.full_name,
            summary="Linked to a new screening administrator account",
        )
        return ""

    matches = Volunteer.objects.possible_matches_for(user.first_name, user.last_name)
    if matches.exists():
        return (
            f"{user.get_full_name()} was not given a volunteer record, because this "
            "church already has one under that name. Open the administrators list to "
            "link the existing record or create a separate one."
        )

    volunteer = Volunteer.objects.create(
        first_name=user.first_name,
        last_name=user.last_name,
        email=user.email,
        user_id=user.pk,
    )
    audit.record(
        AuditAction.CREATE,
        "Volunteer",
        entity_id=volunteer.pk,
        entity_label=volunteer.full_name,
        summary="Volunteer record created for a screening administrator",
    )
    return ""


def attach_volunteer_files(admins) -> None:
    """
    Hang each administrator's screening file — or the reason they have none — on the row.

    Three queries for the page rather than two per administrator, which matters less for
    correctness than for the fact that the alternative reads as fine and quietly does not
    scale. The name match is the same one :func:`file_for_new_admin` refuses to guess
    on, so the list offers exactly the choice the invite declined to make.
    """
    linked = {
        volunteer.user_id: volunteer
        for volunteer in Volunteer.objects.filter(user_id__in=[a.pk for a in admins])
    }

    unlinked = [a for a in admins if a.pk not in linked]
    candidates: dict[tuple[str, str], list] = {}
    if unlinked:
        names = Q()
        for admin in unlinked:
            names |= Q(first_name__iexact=admin.first_name, last_name__iexact=admin.last_name)
        for volunteer in Volunteer.objects.filter(names, user_id__isnull=True):
            key = (volunteer.first_name.lower(), volunteer.last_name.lower())
            candidates.setdefault(key, []).append(volunteer)

    for admin in admins:
        admin.volunteer_file = linked.get(admin.pk)
        admin.possible_files = (
            []
            if admin.volunteer_file
            else candidates.get((admin.first_name.lower(), admin.last_name.lower()), [])
        )
