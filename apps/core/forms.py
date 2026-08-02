"""
Forms for access levels and the grants that assign them.

**Nobody may grant access wider than their own.** That rule is enforced in two places,
and it is worth being precise about which, because an early draft of this module claimed
three and one of them was unreachable:

1. **The form's querysets.** These are not merely an affordance. A
   ``ModelChoiceField`` validates a submitted primary key *against its own queryset*, so
   narrowing the queryset also refuses a hand-crafted POST — there is no need for a
   second check in ``clean()``, and a check there would never run.
2. **:func:`apply_grant`.** The one that matters for a caller who never built a form: a
   management command, a future API, a test taking a shortcut. This is the
   ``RoleAssignment.clean()`` posture — the rule lives below the form, so no code path
   can get past it by not going through the UI.

``AccessLevelForm.clean()`` does carry a check of its own, and that one is reachable:
capabilities are plain booleans rather than a queryset, so nothing else would refuse a
level built with a capability its author does not hold.
"""

from __future__ import annotations

from django import forms
from django.core.exceptions import ValidationError

from .access import Capability, level_for, scope_department_ids
from .models import AccessLevel, UserAccessGrant


class AccessLevelForm(forms.ModelForm):
    """
    Create or edit an access level.

    ``slug`` is not editable: it is the key seeding and comparison match on, and a church
    renaming a level must not detach it from the code that knows what it is.
    """

    class Meta:
        model = AccessLevel
        fields = ["name", "description", "is_scoped", "is_active", *AccessLevel.CAPABILITY_FIELDS]
        widgets = {"description": forms.Textarea(attrs={"rows": 3})}

    def __init__(self, *args, user=None, **kwargs):
        self.granting_user = user
        super().__init__(*args, **kwargs)
        if self.instance.pk and self.instance.is_builtin:
            self.fields["is_active"].disabled = True
            self.fields["is_active"].help_text = (
                "This is one of the two access levels VMS provides, so it cannot be "
                "deactivated. Its capabilities can still be changed."
            )

    def clean(self):
        cleaned = super().clean()

        # Delegated to the model so there is one statement of the rule, and so a level
        # created by a management command or a migration is refused too.
        self.instance.is_scoped = cleaned.get("is_scoped", self.instance.is_scoped)
        for field in AccessLevel.CAPABILITY_FIELDS:
            setattr(self.instance, field, cleaned.get(field, False))
        try:
            self.instance.clean()
        except ValidationError as exc:
            self.add_error(None, exc)

        # Nobody may build a level wider than their own. Without this, "manage access
        # levels" would be a one-step route to every capability, which would make every
        # other limit on the holder decorative.
        granting_level = level_for(self.granting_user) if self.granting_user else None
        if granting_level is not None:
            over_reach = self.instance.capabilities() - granting_level.capabilities()
            if over_reach:
                labels = sorted(Capability(c).label for c in over_reach)
                self.add_error(
                    None,
                    "You cannot grant a capability you do not hold yourself: "
                    + ", ".join(labels)
                    + ".",
                )
            if granting_level.is_scoped and not self.instance.is_scoped:
                self.add_error(
                    "is_scoped",
                    "Your own access is limited to particular departments, so you cannot "
                    "create a level that covers the whole church.",
                )
        return cleaned

    def save(self, commit=True):
        level = super().save(commit=False)
        if not level.slug:
            level.slug = _unique_slug(level.name)
        if commit:
            level.save()
        return level


def _unique_slug(name: str) -> str:
    from django.utils.text import slugify

    base = slugify(name)[:50] or "access-level"
    slug = base
    suffix = 2
    while AccessLevel.objects.filter(slug=slug).exists():
        slug = f"{base}-{suffix}"
        suffix += 1
    return slug


class AccessGrantForm(forms.Form):
    """
    Put one administrator on an access level, with the departments it applies to.

    Not a ``ModelForm``, because ``UserAccessGrant.user_id`` is a plain integer rather
    than a relation — see that model's docstring for why — and a ModelForm would offer it
    as a free-text number.
    """

    access_level = forms.ModelChoiceField(
        queryset=AccessLevel.objects.none(),
        label="Access level",
    )
    departments = forms.ModelMultipleChoiceField(
        queryset=None,
        required=False,
        widget=forms.CheckboxSelectMultiple,
        help_text=(
            "Only used by a level limited to particular departments. Leaving this empty "
            "on a limited level means they will see nothing."
        ),
    )

    def __init__(self, *args, granting_user=None, subject=None, **kwargs):
        from apps.org.models import Department

        self.granting_user = granting_user
        self.subject = subject
        super().__init__(*args, **kwargs)

        granting_level = level_for(granting_user) if granting_user else None
        levels = AccessLevel.objects.filter(is_active=True)
        if granting_level is not None:
            # Only levels the granter's own level covers. Recomputed in clean(), because
            # this queryset is an affordance and a posted pk never touched it.
            allowed = [level.pk for level in levels if granting_level.covers(level)]
            levels = levels.filter(pk__in=allowed)
        self.fields["access_level"].queryset = levels

        departments = Department.objects.filter(is_active=True)
        scope = scope_department_ids(granting_user) if granting_user else None
        if scope is not None:
            departments = departments.filter(pk__in=scope)
        self.fields["departments"].queryset = departments

    def clean(self):
        cleaned = super().clean()
        # No escalation check here on purpose. Both fields are model-choice fields whose
        # querysets were narrowed in __init__, and Django validates a submitted primary
        # key against the field's own queryset — so a hand-crafted POST is already
        # refused, and a check at this point could never run. The rule's second home is
        # apply_grant, which covers the callers that never reach a form.
        #
        # Note also what is deliberately *not* an error: a limited level with no
        # departments. It is a legitimate, if useless, state — "revoke everything but keep
        # the account" — and it is safe, because the holder sees nothing. The view warns
        # on screen instead of refusing.
        return cleaned


class AccessEscalationError(ValidationError):
    """Raised when a grant would hand out more than the granter holds."""


def apply_grant(
    subject,
    access_level,
    departments=(),
    *,
    granted_by=None,
    granted_by_display: str = "",
):
    """
    Write a grant, refusing anything ``granted_by`` could not legitimately give.

    The rule's home below the form layer. ``granted_by=None`` skips the check, which is
    what provisioning, the backfill and the repair command want — none of them acts on
    behalf of a person, and each is already gated by having shell access to the host.
    Anything driven by a request must pass it.
    """
    if granted_by is not None:
        granting_level = level_for(granted_by)
        if granting_level is not None:
            if not granting_level.covers(access_level):
                raise AccessEscalationError(
                    f"'{access_level.name}' is wider than {granted_by}'s own access."
                )
            scope = scope_department_ids(granted_by)
            if scope is not None:
                outside = sorted(d.name for d in departments if d.pk not in scope)
                if outside:
                    raise AccessEscalationError(
                        "Cannot grant departments the granter does not administer: "
                        + ", ".join(outside)
                    )

    if not access_level.is_scoped and departments:
        # Harmless but misleading: an unscoped level ignores its departments, and leaving
        # the rows behind would make the screen read as though they mattered.
        departments = ()

    grant, _ = UserAccessGrant.objects.update_or_create(
        user_id=subject.pk,
        defaults={"access_level": access_level, "granted_by_display": granted_by_display},
    )
    grant.departments.set(departments)
    return grant
