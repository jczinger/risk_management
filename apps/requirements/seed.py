"""
The starter requirement template every new church receives.

Fourteen requirements matching the UPC of BC Plan to Protect® screening sequence
(Build Spec §4.2), created once at provisioning and **fully editable afterwards** —
a church can rename, re-time, deactivate or add to any of it.

Licensing note (Build Spec §0, PRD §6): the Plan to Protect distribution licence
covers PtP *content*, and this system must not embed or redistribute it. So what
follows contains only requirement **names**, **cadences** and **appendix
references** — pointers into the church's own policy manual. Every ``description``
below is operational guidance written for this system, telling an admin what to do
in VMS. None of it reproduces policy or form wording.
"""

from __future__ import annotations

import logging

from .models import (
    AgeRule,
    AppliesTo,
    Cadence,
    DependencyMode,
    RequirementDefinition,
    RequirementType,
)

logger = logging.getLogger("vms.requirements")

# Ordered as the policy sequences onboarding. `key` is internal: it wires up the
# dependencies and lets a re-seed recognise what it already created.
#
# A prerequisite MUST appear before whatever depends on it — seed_default_template
# resolves `must_follow_key` against what it has created so far, in one pass.
SEED_TEMPLATE: list[dict] = [
    {
        "key": "waiting_period",
        "name": "Waiting period — 6 months regular attendance",
        "requirement_type": RequirementType.WAITING_PERIOD,
        "cadence": Cadence.ONE_TIME,
        "applies_to": AppliesTo.ALL_ROLES,
        "sequence": 10,
        "description": (
            "Confirm six months of regular attendance before screening proceeds. "
            "Record the attendance start date on the volunteer's record and this "
            "requirement will show whether the period is met. For a transfer from "
            "another church the waiting period may be waived where three references "
            "are obtained, one of them from the previous minister — tick 'transfer' "
            "on the volunteer record and note the exception here."
        ),
    },
    {
        "key": "application_form",
        "name": "Ministry Personnel Application Form",
        "requirement_type": RequirementType.APPLICATION_FORM,
        "cadence": Cadence.ONE_TIME,
        "applies_to": AppliesTo.ALL_ROLES,
        "sequence": 20,
        "appendix_reference": "Appendix 2 (adult) / Appendix 3 (youth)",
        "requires_document": True,
        "description": (
            "Collect the completed application form with a witnessed signature. Use "
            "the adult or youth version as appropriate to the applicant's age. Mark "
            "complete on the date the signed form was received."
        ),
    },
    {
        "key": "declaration_of_faith",
        "name": "Statement / Declaration of Faith",
        "requirement_type": RequirementType.DECLARATION_OF_FAITH,
        "cadence": Cadence.ONE_TIME,
        "applies_to": AppliesTo.ALL_ROLES,
        "sequence": 30,
        "requires_document": True,
        "description": (
            "Collect the applicant's statement of faith. The policy refers to this "
            "document by both names; it is one requirement."
        ),
    },
    {
        "key": "liability_release",
        "name": "Liability release",
        "requirement_type": RequirementType.LIABILITY_RELEASE,
        "cadence": Cadence.ONE_TIME,
        "applies_to": AppliesTo.ALL_ROLES,
        "sequence": 40,
        "requires_document": True,
        "description": (
            "Obtain the signed liability release. This must be in hand BEFORE any "
            "reference is contacted — the reference-checks requirement is configured "
            "to depend on it and will warn if taken out of order."
        ),
    },
    {
        "key": "reference_checks",
        "name": "Reference checks",
        "requirement_type": RequirementType.REFERENCE_CHECKS,
        "cadence": Cadence.ONE_TIME,
        "applies_to": AppliesTo.ALL_ROLES,
        "sequence": 50,
        "appendix_reference": "Appendix 4 / Appendix 5",
        "requires_document": True,
        "must_follow_key": "liability_release",
        # A warning, not a bar: an admin filing historical paperwork out of order is
        # told, not stopped (BUILD_NOTES §1.18).
        "dependency_mode": DependencyMode.WARN,
        "description": (
            "Obtain at least two references, one of which is from the applicant's "
            "current or previous pastor. Record the content of each reference in the "
            "notes on this requirement — those notes are encrypted. Do not contact "
            "referees before the liability release is signed."
        ),
    },
    {
        "key": "interview",
        "name": "Interview",
        "requirement_type": RequirementType.INTERVIEW,
        "cadence": Cadence.ONE_TIME,
        "applies_to": AppliesTo.ALL_ROLES,
        "sequence": 60,
        "appendix_reference": "Appendix 6",
        "description": (
            "Conduct the screening interview, face to face or online. Mark complete "
            "on the interview date and note who conducted it."
        ),
    },
    {
        "key": "policy_agreement",
        "name": "Plan to Protect policy agreement",
        "requirement_type": RequirementType.POLICY_AGREEMENT,
        "cadence": Cadence.ONE_TIME,
        "applies_to": AppliesTo.ALL_ROLES,
        "sequence": 70,
        "appendix_reference": "Appendix 2d",
        "requires_document": True,
        "description": (
            "Have the applicant read the church's Plan to Protect policy and sign the "
            "agreement. Record the date signed."
        ),
    },
    {
        "key": "leadership_approval",
        "name": "Leadership approval",
        "requirement_type": RequirementType.LEADERSHIP_APPROVAL,
        "cadence": Cadence.ONE_TIME,
        "applies_to": AppliesTo.ALL_ROLES,
        "sequence": 80,
        "requires_document": True,
        "description": (
            "The final step: leadership signs and dates their approval. The whole "
            "onboarding sequence is expected to complete within three months — the "
            "volunteer's record shows a warning once the earliest step is older than "
            "that and approval is still outstanding."
        ),
    },
    # --- Recurring -------------------------------------------------------
    {
        "key": "criminal_record_check",
        "name": "Criminal Record Check + Vulnerable Sector Search",
        "requirement_type": RequirementType.CRIMINAL_RECORD_CHECK,
        "cadence": Cadence.EVERY_3_YEARS,
        "applies_to": AppliesTo.ALL_ROLES,
        "age_rule": AgeRule.ADULTS_ONLY,
        "sequence": 90,
        "is_onboarding": False,
        "requires_document": True,
        "description": (
            "Required of everyone 18 and over, renewed every "
            "three years from the date on the clearance letter. Volunteers under 18 "
            "are screened the same way but are exempt from this check; the system "
            "marks it not applicable and activates it automatically on the 1st of "
            "their birth month in the year they turn 18, with three months to submit. "
            "Record the result through 'Record a criminal record check' on the "
            "volunteer's page so the three-year clock and the Not Clear handling apply."
        ),
    },
    {
        "key": "training_orientation",
        "name": "Plan to Protect orientation training",
        "requirement_type": RequirementType.TRAINING_ORIENTATION,
        "cadence": Cadence.ONE_TIME,
        "applies_to": AppliesTo.ALL_ROLES,
        "sequence": 100,
        "is_onboarding": False,
        "description": (
            "Orientation training, completed before the volunteer is placed. Enter the "
            "completion date manually — this system does not connect to the training "
            "provider. That date is what starts the refresher clock: the refresher "
            "falls due one year after it."
        ),
    },
    {
        "key": "training_refresher",
        "name": "Plan to Protect refresher training",
        "requirement_type": RequirementType.TRAINING_REFRESHER,
        "cadence": Cadence.ANNUAL,
        "applies_to": AppliesTo.ALL_ROLES,
        "sequence": 110,
        "is_onboarding": False,
        "must_follow_key": "training_orientation",
        "dependency_mode": DependencyMode.GATE,
        # No explicit offset: the annual cadence already supplies the twelve months.
        "description": (
            "Annual refresher training. Stays 'not applicable' until orientation "
            "training is recorded, then falls due one year after the orientation date, "
            "and annually from each refresher after that. Enter each year's completion "
            "date manually."
        ),
    },
    {
        "key": "code_of_conduct",
        "name": "Code of Conduct",
        "requirement_type": RequirementType.SIGNED_AGREEMENT,
        "cadence": Cadence.ANNUAL,
        "applies_to": AppliesTo.ALL_ROLES,
        "sequence": 120,
        "is_onboarding": False,
        "requires_document": True,
        "description": (
            "Signed annually. Collect the signature outside the system and record the "
            "date here — in-app signing arrives in a later release."
        ),
    },
    {
        "key": "covenant_of_care",
        "name": "Covenant of Care",
        "requirement_type": RequirementType.SIGNED_AGREEMENT,
        "cadence": Cadence.ANNUAL,
        "applies_to": AppliesTo.ALL_ROLES,
        "sequence": 130,
        "is_onboarding": False,
        "requires_document": True,
        "description": "Signed annually. Record the date signed.",
    },
    {
        "key": "confidentiality_agreement",
        "name": "Confidentiality Agreement",
        "requirement_type": RequirementType.SIGNED_AGREEMENT,
        "cadence": Cadence.ONE_TIME,
        "applies_to": AppliesTo.ALL_ROLES,
        "sequence": 140,
        "is_onboarding": False,
        "requires_document": True,
        "description": (
            "Required of every volunteer. Anyone serving encounters personal "
            "information about the people they serve, so the agreement is not "
            "conditional on the role."
        ),
    },
]


def seed_default_template() -> int:
    """
    Create the starter requirements in the current tenant schema.

    Returns how many were created. Safe to re-run: an existing definition with the same
    name is left **entirely** alone, its dependency settings included. Re-seeding adds
    what is missing and touches nothing else.

    Dependencies are wired at creation, which is why ``SEED_TEMPLATE`` must list a
    prerequisite before whatever depends on it — asserted by
    ``test_every_prerequisite_precedes_its_dependent``.

    This used to run a second pass that rewrote ``must_follow`` on rows it had just
    skipped, contradicting the paragraph above and silently overwriting an admin who had
    pointed a dependency somewhere else. It also meant a change to the template could
    alter a church's live behaviour the moment someone clicked "re-apply". Now it
    cannot: an existing church picks up a new dependency only when an admin sets it,
    deliberately, on the requirement's own page.

    Must be called inside a tenant schema with the tenant's key available — the
    definitions themselves hold no encrypted fields, but they live in the tenant's
    tables.
    """
    created = 0
    by_key: dict[str, RequirementDefinition] = {}

    for entry in SEED_TEMPLATE:
        spec = dict(entry)
        key = spec.pop("key")
        follows = spec.pop("must_follow_key", None)

        existing = RequirementDefinition.objects.filter(name=spec["name"]).first()
        if existing:
            by_key[key] = existing
            continue

        if follows:
            predecessor = by_key.get(follows)
            spec["must_follow"] = predecessor
            if predecessor is None:
                # The prerequisite already existed under a name this church changed, so
                # there is nothing to point at. Fall back to the harmless mode rather
                # than leaving a gate with no gate-keeper.
                spec.pop("dependency_mode", None)
                logger.warning(
                    "Seed: '%s' depends on '%s', which is not in this church's template; "
                    "created without the dependency",
                    spec["name"],
                    follows,
                )

        definition = RequirementDefinition.objects.create(is_seeded=True, **spec)
        by_key[key] = definition
        created += 1

    logger.info("Seeded %d requirement definitions", created)
    return created
