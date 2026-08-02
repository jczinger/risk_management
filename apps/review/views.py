"""
The review queue.

Oldest first, because the thing that goes wrong with a review step is not that entries are
reviewed in the wrong order — it is that a few sit unlooked-at for weeks while the report
they feed keeps reading "compliant".
"""

from __future__ import annotations

import logging

from django.contrib import messages
from django.core.exceptions import ValidationError
from django.core.paginator import Paginator
from django.shortcuts import get_object_or_404, redirect, render
from django.views.decorators.http import require_POST, require_http_methods

from apps.core.access import Capability, is_unscoped, requires

from .forms import SendBackForm
from .models import REVIEW_STALE_DAYS, ReviewItem, ReviewStatus
from .services import affirm, may_review, send_back

logger = logging.getLogger("vms.review")

PAGE_SIZE = 50


@requires(Capability.VIEW_VOLUNTEERS)
def queue(request):
    """
    Everything awaiting affirmation.

    Gated on ``view_volunteers`` rather than a capability of its own: deciding an entry is
    refused by :func:`apps.review.services.may_review` anyway, and a department admin who
    can see the page can at least see what of *their* work is waiting. Which is worth
    something — the alternative is their sent-back entries being invisible to them.
    """
    show = request.GET.get("show", "pending")

    items = ReviewItem.objects.select_related("volunteer", "department")
    if show == "stale":
        items = items.stale()
    elif show == "closed":
        items = items.exclude(status=ReviewStatus.PENDING).order_by("-reviewed_at")
    else:
        items = items.pending()

    if request.GET.get("mine") == "1":
        # Keyed on who recorded it, not on current scope. The send-back reason exists to
        # be read by the person who recorded the entry, and scoping this by their present
        # access would hide it from them the moment the volunteer left their departments.
        items = items.filter(recorded_by_user_id=request.user.pk)

    paginator = Paginator(items, PAGE_SIZE)
    page = paginator.get_page(request.GET.get("page"))

    return render(
        request,
        "review/queue.html",
        {
            "page": page,
            "items": page.object_list,
            "total": paginator.count,
            "show": show,
            "mine": request.GET.get("mine") == "1",
            "pending_count": ReviewItem.objects.pending().count(),
            "stale_count": ReviewItem.objects.stale().count(),
            "stale_days": REVIEW_STALE_DAYS,
            # Whether to render the buttons at all. Per-item self-review is still checked
            # by the service on the way through, so this is presentation only.
            "can_review": is_unscoped(request.user),
        },
    )


@requires(Capability.VIEW_VOLUNTEERS)
@require_POST
def item_affirm(request, pk: int):
    """
    Affirm one entry, swapping its row over htmx.

    Copies ``instance_start``'s shape: an htmx ``outerHTML`` swap for the row, and a plain
    redirect when JavaScript is unavailable, so the button works either way.
    """
    item = get_object_or_404(ReviewItem, pk=pk)

    try:
        affirm(item, by=request.user)
    except ValidationError as exc:
        if request.headers.get("HX-Request"):
            return render(request, "review/_row.html", {"item": item, "error": "; ".join(exc.messages)})
        messages.error(request, "; ".join(exc.messages))
        return redirect("review:queue")

    if request.headers.get("HX-Request"):
        return render(request, "review/_row.html", {"item": item, "just_decided": True})

    messages.success(request, f"Affirmed: {item.entity_label}.")
    return redirect("review:queue")


@requires(Capability.VIEW_VOLUNTEERS)
@require_http_methods(["GET", "POST"])
def item_send_back(request, pk: int):
    """
    Send one entry back, with a mandatory reason.

    A full page rather than an inline swap, because the reason is required and because the
    page has to say what sending back *cannot* undo before the click — a disqualification,
    a recorded document, a leadership decision — rather than after.
    """
    item = get_object_or_404(ReviewItem, pk=pk)
    allowed, why = may_review(request.user, item)
    if not allowed:
        messages.error(request, why)
        return redirect("review:queue")

    form = SendBackForm(request.POST or None)
    if request.method == "POST" and form.is_valid():
        try:
            outcome = send_back(item, by=request.user, reason=form.cleaned_data["reason"])
        except ValidationError as exc:
            for message in exc.messages:
                form.add_error(None, message)
        else:
            if outcome["reverted"]:
                messages.success(
                    request, f"Sent back: {item.entity_label}. The record has been reverted."
                )
            else:
                messages.warning(
                    request,
                    f"Sent back: {item.entity_label}. Nothing was reverted — see the notes.",
                )
            for note in outcome["kept"]:
                messages.info(request, f"Still standing: {note}.")
            return redirect("review:queue")

    return render(
        request,
        "review/send_back.html",
        {"form": form, "item": item, "cannot_undo": _cannot_undo(item)},
    )


def _cannot_undo(item: ReviewItem) -> list[str]:
    """
    What sending this entry back will *not* reverse, stated before the click.

    Deliberately duplicated from what the service reports afterwards. The reviewer needs
    to know the consequences while deciding, not once it is done — and for a permanent
    disqualification "once it is done" is far too late to be useful.
    """
    from apps.org.models import ScreeningBlock

    from .models import ReviewKind

    notes = []
    if item.kind == ReviewKind.OVERRIDE:
        notes.append(
            "The leadership decision is permanently retained. Sending it back records "
            "that you dispute it; to change the outcome you must record your own decision."
        )
    if item.entity_type == "DisqualifyingConviction":
        notes.append(
            "The recorded convictions cannot be removed, and the Plan to Protect policy "
            "provides no route back from a permanent disqualification — not here, not "
            "anywhere in VMS."
        )
        if item.volunteer.screening_block == ScreeningBlock.DISQUALIFIED:
            notes.append(
                "This volunteer is permanently disqualified and will remain so."
            )
    ended = (item.before_state or {}).get("ended_assignments") or []
    if ended:
        notes.append(
            f"{len(ended)} role assignment(s) ended by this entry ({', '.join(ended)}) "
            "cannot be restored automatically and would have to be re-created by hand."
        )
    if item.kind == ReviewKind.DOCUMENT:
        notes.append(
            "The document itself is kept — the record that it was presented is part of "
            "the trail. It stops counting as current evidence."
        )
    return notes
