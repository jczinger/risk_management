# Acceptance criteria — Build Spec §10

Every criterion, how it was verified, and where to re-run that verification.

**Automated:** 748 tests, 86% statement coverage of `apps/`.

```bash
.venv/bin/python -m pytest -q
```

**Manual:** the Docker Compose stack was brought up from a clean host, provisioned, exercised,
backed up, destroyed and restored. Commands are given below so each check can be repeated.

---

## 1. Two tenants provisioned; data provably isolated (cross-schema access test fails)

**Status: passing.**

`apps/tenants/tests/test_isolation.py` — `TenantIsolationTests`, 14 tests.

Two churches are really provisioned, then isolation is attacked from several directions:

- A volunteer created in one church is invisible in the other.
- A primary key taken from one church resolves to nothing in the other.
- Administrators, audit trails and requirement edits are all scoped to their own church.
- **Within** a church, an administrator on a limited access level reaches only volunteers who
  have served in the departments they administer. Anything else returns 404, not 403 — a 403
  would confirm the record exists. Added 2026-07-29; see §3 below and BUILD_NOTES §1.21.
- **One church's key cannot decrypt another's data.** A ciphertext is read directly out of
  `alpha.org_volunteer` with raw SQL, decrypts correctly with alpha's key, and raises
  `DecryptionError` with beta's — so even bypassing schema separation entirely does not help.
- The `public` schema is asserted to contain **none** of the church-data tables.
- A request to an unmapped hostname is refused (404), not shown the public schema.
- A session cookie issued by one church is not honoured by another.

## 2. ~~Admin logs in with a passkey; fallback password+TOTP works; passwordless-only account possible~~

**Superseded 29 July 2026**, at the product owner's direction. Password and TOTP were removed from
the system entirely; the reasoning and what was traded away are in `BUILD_NOTES.md` §1.20. Kept
here struck through rather than deleted, so the criterion is visibly *changed* rather than quietly
missing.

## 2. A passkey is the only way to sign in; a single-use link covers first sign-in and recovery

**Status: passing.**

`apps/accounts/tests/test_auth.py`, `test_login_links.py`, `test_forced_enrolment.py` — 67 tests.

- **Passkey:** challenge issuance, verification, sign-in in one step, sign-counter advance,
  single-use challenges, five-minute expiry, unknown-credential refusal, deactivated account and
  deactivated passkey both refused.
- **Links:** single use, two independent expiry guards (the signer's `max_age` *and* the stored
  `expires_at`, each tested with the other neutralised), tampered payload, unknown token,
  deactivated account, suspended church. Every failure is asserted to render a byte-identical
  page, so the form cannot be used to discover who has an account.
- **Cross-schema:** a *validly signed* payload with the schema name swapped finds no token; a
  link binds the request to its own church; one address at two churches yields one link each.
- **Forced enrolment:** an account with no passkey is redirected to enrolment from every page,
  not merely the first; signing out and the WebAuthn endpoints stay reachable so nobody is
  trapped; registering a passkey releases the gate; with the key-backup gate also pending,
  enrolment goes first.
- **Recovery is announced:** using a recovery link emails the church's other administrators and
  writes a `link_used` audit entry. An invite link notifies nobody.
- **At rest:** only the SHA-256 of a link is stored, and a live link is asserted absent from a
  `pg_dump`. Every account holds a *distinct* unusable password marker — including after the
  removal migration, which is called directly by a test because it otherwise runs on no rows.
- **Rate limits:** both WebAuthn endpoints per IP; the recovery form per address and per IP.

The WebAuthn *cryptographic* verification is stubbed, because producing a real assertion requires
an authenticator to sign a challenge and cannot be done in-process. Everything around it —
challenge lifecycle, credential storage, session handling, the guards — is exercised for real.
Passkey registration and sign-in were additionally confirmed by hand in a browser against
`http://localhost:8000/`, which counts as a secure context.

## 3. New tenant gets the 14-item seed template; admin can edit, add, deactivate requirements

**Status: passing.**

`apps/requirements/tests/test_engine.py` — `SeedTemplateTests`, plus the console tests.

- Provisioning creates exactly 14 definitions, verified both in the test suite and against the
  live deployment.
- Each item's shape is asserted against Build Spec §4.2: the criminal record check is
  `every_3_years` / `adults_only`; refresher training is annual; Code of Conduct and Covenant of
  Care are annual; the Confidentiality Agreement applies to everyone (BUILD_NOTES §1.14); the
  liability release precedes reference checks as a **warning**, and refresher training follows
  orientation training as a **gate** (BUILD_NOTES §1.18).
- Editing, adding and deactivating are all tested, including that re-seeding **preserves** a
  church's edits rather than reverting them — dependencies included, which re-seeding used to
  overwrite.
- The template is asserted to contain no policy prose, guarding the licensing constraint.

## 4. Volunteer onboarded end-to-end; compliance status correct at each step

**Status: passing.**

`apps/reporting/tests/test_reports.py` — `EndToEndOnboardingTests::test_compliance_tracks_each_step`
walks one volunteer through six stages and asserts the compliance verdict at each:

1. Record with no role → nothing owed, compliant.
2. Role assigned → 13 requirements apply, "In progress".
3. Part-way through → still not compliant.
4. Everything except the criminal record check → still not compliant, exactly 1 outstanding.
5. Check cleared → **compliant**.
6. A year passes, the annual agreement lapses → "Overdue".

A companion test confirms a 16-year-old can reach full compliance without a criminal record check,
so the age exemption is not merely cosmetic.

## 5. Under-18 volunteer: CRC auto not_applicable; simulated turn-18 activates CRC with 3-month deadline

**Status: passing.**

`apps/requirements/tests/test_age_rules.py` — 23 tests.

- A 16-year-old's criminal record check is `not_applicable` with the reason
  "Under 18 — no criminal record check required", while every other requirement still applies.
- Turning 18 is simulated with explicit dates. For a volunteer born 25 June 2008: on 31 May 2026
  nothing activates; on **1 June 2026** the check activates with a deadline of **1 September 2026**
  — the 1st of the birth month, plus the policy's three months.
- Firing early rather than late is asserted directly.
- Activation is idempotent, skips volunteers whose role no longer requires it, skips inactive
  volunteers, and missing the deadline is confirmed to produce `overdue`.
- The consistency property that matters most: `is_adult_on()` flips to True on *exactly* the
  activation date, so the nightly job and the applicability check cannot disagree. See
  `BUILD_NOTES.md` §1.4 for why that needed a decision.

## 6. CRC: Cleared PDF upload sets a 3-year expiry; NOT CLEAR blocks; automatic disqualifier permanently blocks with no override path in the UI; discretionary red-flag override requires documented reasoning

**Status: passing.**

`apps/requirements/tests/test_crc.py` — 44 tests, plus `apps/documents/tests/test_documents.py`.

- **Cleared:** a check dated 15 March 2026 sets expiry 15 March 2029; the clock runs from the
  report date, not the filing date. The clearance PDF uploads, is encrypted, and reads back.
- **Not Clear:** the volunteer is blocked, the requirement is blocked and cannot be marked
  complete, and only the two policy outcomes (fingerprint-verified check, or withdrawal) are
  offered.
- **Automatic disqualifier — no override.** Tested from every angle a future change might open:
  - the model layer refuses to move off `DISQUALIFIED`;
  - a later cleared check cannot undo it;
  - `record_discretionary_override` refuses, both with and without naming the conviction;
  - the recorded conviction cannot be deleted;
  - assignment to **any** role is refused — every role is a position of trust;
  - reactivation through the view is refused;
  - **no URL reverses** to lifting it (`test_there_is_no_url_that_lifts_a_disqualification`);
  - the CRC detail page omits the override link entirely and says "no override".
- **Discretionary override:** refuses without reasoning, without mitigation steps, or without a
  named decision-maker; the record is immutable once written and cannot be deleted; reasoning and
  mitigation are confirmed encrypted at rest.
- The conviction form requires a separate explicit acknowledgement before an automatic category
  can be recorded.

## 7. A raw `pg_dump` inspected manually shows no readable DOB, address, phone, email, file contents, or notes

**Status: passing, and automated.**

`apps/core/tests/test_dump_leakage.py` — 6 tests.

A volunteer is seeded with a distinctive marker in **every** field the PRD classifies as
sensitive: date of birth, email, phone, address, emergency contact, medical notes, volunteer
notes, requirement notes, CRC notes, conviction description, override reasoning and mitigation,
waiver reason, document bytes, original filename, admin email. A real `pg_dump` then runs and is
searched for each marker. Any hit names the leaking field.

Three things make this a meaningful test rather than a passing one:

- `test_the_dump_does_contain_the_rows_so_the_test_is_meaningful` asserts the seeded row really is
  in the dump. (It initially was not — `pg_dump` opens its own connection and could not see rows
  inside the test transaction, so the leak check was passing vacuously. Fixed by moving to
  `TransactionTestCase`; recorded in `BUILD_NOTES.md` §3.)
- `test_deliberately_plaintext_fields_are_present_and_queryable` asserts the *other* direction —
  names, role names, birth year, the CRC flag and requirement types must be readable, because
  encrypting them would silently break the volunteer list and the compliance report.
- `test_the_document_on_disk_is_also_unreadable` covers the media volume, not just the database.

Also verified by hand against the live deployment:

```bash
docker compose exec db psql -U vms -d vms \
  -c "SELECT phone, address, medical_notes FROM firstoac.org_volunteer;"
# v1.ClUe2yeB9wNUaX4Y9anP3… | v1.… | v1.…
```

## 8. Reminder emails fire at 60/30/7/overdue against seeded near-expiry data

**Status: passing.**

`apps/notifications/tests/test_reminders.py` — 33 tests.

- A reminder is found at each of 60, 30 and 7 days, and **not** on a day that is not a configured
  lead time.
- The overdue notice fires the day after expiry, once — not daily.
- Lead times are per-church configurable (a church set to `90,14` gets those and not 60).
- Everything due is batched into **one** digest per church; the subject says what is inside.
- Reminders go to admins and never to volunteers
  (`test_digest_never_goes_to_a_volunteer`).
- Idempotent: running the job twice in a day mails once. Renewing a requirement starts a fresh
  reminder cycle.
- Every send is logged, with recipients, subject and body encrypted and the metadata plaintext.
  A provider failure is recorded rather than swallowed.
- The turning-18 deadline produces its own reminder kind.

Verified end to end in the live deployment: a requirement set to expire in 30 days, then
`sweep_tenant()`, produced `{'candidates': 1, 'claimed': 1, 'sent': True}` and this digest:

```
[First OAC] Volunteer screening: 1 coming due

COMING DUE (1)
  - Canary, Backup: Code of Conduct — due 23 Aug 2026 (30 days)
```

## 9. Compliance report, individual file, and audit trail render and print correctly

**Status: passing.**

`apps/reporting/tests/test_reports.py` — 34 tests.

- **Compliance report:** renders church-wide and scoped to one department; counts and the
  compliance rate are computed; past volunteers are excluded unless asked for; the printable view
  renders with the per-volunteer detail; PDF export returns a real PDF (`%PDF` magic bytes,
  `Content-Disposition: attachment`, `Cache-Control: no-store`). It is also asserted to contain
  **no** address, phone or medical detail — a report for an insurer carries the verdict, not the
  personal information.
- **Individual volunteer file:** renders with the full record including the decrypted personal
  fields (this is the one report meant to show them), lists roles, requirements, checks and
  documents, warns before printing, states a disqualification prominently, and exports to PDF.
- **Audit trail:** renders, filters by action / record type / record id / date range, tolerates an
  unreadable date, shows the decrypted before/after detail, and offers no edit or delete route.
- **Render sweep:** all 35 pages return 200 for a signed-in admin and redirect an anonymous one.

## 10. Volunteer records cannot be hard-deleted through any UI or ORM path

**Status: passing.**

`apps/org/tests/test_retention.py` — 32 tests.

Every deletion route is attempted and refused: `instance.delete()`, `queryset.delete()`,
`filter(...).delete()`, `_raw_delete()`, cascade from a parent department, and requirement
instances, CRC records and documents individually. No delete URL exists for a volunteer
(asserted via `NoReverseMatch` over four plausible names).

The supported route is tested instead: deactivation keeps the record and its history, is audited
with `record_retained: true`, and the volunteer can be returned to service.

The audit trail's own immutability is covered in the same file — `save()` on an existing entry,
`delete()`, `queryset.update()`, `queryset.delete()` and `_raw_delete()` all raise.

## 11. `docker compose up` from a clean host + documented env vars yields a working system behind a reverse proxy; backup/restore script round-trips successfully

**Status: passing.** Performed against the real stack, not simulated.

**Clean bring-up.** `docker compose down -v` then `docker compose build && docker compose up -d`:
`db` and `redis` healthy, `migrate` exited 0 after applying every migration, `web`, `worker` and
`beat` running. `celery@… ready.` and `beat: Starting...` confirmed in the logs.

Two real deployment bugs were found this way and fixed — neither was catchable by unit tests:

- `collectstatic` ran in the one-shot `migrate` container, so `web` started with no static
  manifest and 500'd on the first page. Static files now build into the image.
- The container health check probes `http://localhost:8000/healthz/`, and `localhost` will never
  have a `Domain` row, so it 404'd and Docker reported a healthy container unhealthy. The health
  path now answers on any hostname while everything else still 404s.

Both are recorded in `BUILD_NOTES.md` §2 and locked down by `apps/core/tests/test_deployment.py`.

**Verified working:**

```
healthz (any hostname):        200 {"status": "ok"}
unknown hostname, real page:   404          ← correct refusal
console on the platform domain: 302 → login
login page:                     200
hashed static asset:            200  /static/css/vms.4c6ddf197772.css
check --deploy (shipped defaults): no issues
```

Provisioning through the deployed stack created the schema, the key, the admin and 14
requirements.

**Backup/restore round-trip.** Seeded a volunteer with markers, then:

```bash
./scripts/backup.sh
# → database.dump 151,885 B · media.tar.gz 1,574 B · MANIFEST.txt · SHA256SUMS

docker compose exec db psql -U vms -d vms -c "DROP SCHEMA firstoac CASCADE;"
docker compose exec db psql -U vms -d vms -c "DELETE FROM public.tenants_tenant;"
# ← data really destroyed

./scripts/restore.sh 20260725T032609Z
# checksums verified → dump restored → media restored → migrations applied
# → "All 2 church(es) verified: keys unwrap and data decrypts."
```

After the restore, the data was confirmed **readable**:

```
name:     Backup Canary
dob:      1985-03-14
phone:    250-555-8888
address:  11 Roundtrip Road
medical:  ROUNDTRIP-MEDICAL-MARKER
reqs:     13
```

…and still ciphertext at rest: `v1.ClUe2yeB9wNUaX4Y9anP3 | v1.M6_Hac9LFWe1DOLuvamyE`.

The reverse proxy itself (Nginx Proxy Manager) is the operator's existing infrastructure and was
not reconfigured. The app was verified to behave correctly behind one: it publishes a single HTTP
port, honours `X-Forwarded-Proto`, and exempts the health path from the SSL redirect.

## 12. Automated test suite covers the requirement engine, age rules, encryption round-trips, and tenant isolation

**Status: passing.** All four named areas, and more.

| Area | File | Tests |
|---|---|---|
| Encryption round-trips | `apps/core/tests/test_crypto.py` | 28 |
| `pg_dump` leakage | `apps/core/tests/test_dump_leakage.py` | 6 |
| Deployment / health / hardening | `apps/core/tests/test_deployment.py` | 17 |
| Tenant isolation & provisioning | `apps/tenants/tests/test_isolation.py` | 29 |
| Super-admin console | `apps/tenants/tests/test_console.py` | 31 |
| Authentication | `apps/accounts/tests/test_auth.py` | 42 |
| Retention & audit immutability | `apps/org/tests/test_retention.py` | 32 |
| Requirement engine | `apps/requirements/tests/test_engine.py` | 45 |
| Age rules | `apps/requirements/tests/test_age_rules.py` | 23 |
| Criminal record checks | `apps/requirements/tests/test_crc.py` | 44 |
| Documents | `apps/documents/tests/test_documents.py` | 27 |
| Reminders & the nightly job | `apps/notifications/tests/test_reminders.py` | 33 |
| Dashboard & reporting | `apps/reporting/tests/test_reports.py` | 34 |
| **Total** | | **390** |

Encryption round-trips specifically cover: text, bytes, dates, empty and null, unicode, 5 KB
values, that the same plaintext encrypts differently every time, that a wrong key raises rather
than garbles, that tampered and truncated ciphertext are rejected, that field and DEK cipher
domains are separated, and that re-saving a model does not double-encrypt.

---

---

## 13. Access levels within a church

**Superseded 2026-07-29.** Build Spec §2 read "All have equal permissions within their church,"
and the acceptance criterion followed it. ~~Every screening admin at a church can reach every
screen and every volunteer in it.~~ That now describes a **Primary Admin** only.

The criteria in its place:

- **Two levels are seeded into every church**, and into every church that already existed — the
  backfill migration creates both, so no operator step is needed before the feature can be used.
- **Every existing administrator came out of the deploy as a Primary Admin.** Verified with
  `manage.py access_levels`, which reports rather than changes anything.
- **An account with no access level can do nothing.** `has_capability` fails closed. This is why
  the backfill is a migration and not a command.
- **Every church-side view declares what capability it needs.** A view that declares nothing is
  refused at runtime by `AccessGateMiddleware` and named at review time by a test that walks the
  URLconf. Both, because their weaknesses do not overlap.
- **A limited level sees only its own departments** — volunteers, departments, ministry roles,
  documents, requirement instances, dashboard counts, the per-department summary, and the
  department and role dropdowns. The dropdowns are included deliberately: the results would be
  empty anyway, and an unscoped dropdown is the church's org chart with no view behind it.
- **Out of scope is 404; a withheld capability is 403.**
- **Nobody can grant access wider than their own**, nor departments they do not administer.
  Enforced by the form's querysets and again in `apply_grant`.
- **A limited level cannot hold the audit trail.** Refused by `AccessLevel.clean()`, because an
  audit entry records no department and a partial filter would look scoped while missing most of
  what it should catch.
- **A church cannot lose the ability to change its own access.** The last active administrator
  with church-wide user management cannot be deactivated, demoted or re-scoped.
- **The nightly digest reaches unscoped administrators only.** Otherwise one shared body naming
  every overdue volunteer at the church would cross the boundary invisibly.

### The review step

- **Everything recorded on a limited level is affirmed by a Primary Admin** — completions,
  documents, criminal record checks, waivers and overrides.
- **A pending entry counts as compliant immediately**, flagged unverified. Deliberate; the
  backlog therefore appears on the dashboard, in the queue, on the compliance report, and in the
  nightly digest once anything has waited 30 days.
- **The badge appears on every render path**, including the htmx row swap and the printed file.
- **Sending an entry back requires a reason**, which reaches the audit summary where the
  recording administrator can actually read it.
- **A send-back never undoes what is permanent.** A recorded document is kept and marked not
  current; a leadership override stands; a permanent disqualification, its convictions and the
  assignments it ended all stand. The form says which of these apply *before* the click.
- **Nobody affirms their own entry** while another church-wide administrator exists.
- **Neither the nightly sweep nor any management command queues anything for review.**

---

## Not built, per Build Spec §0

Confirmed absent: in-app forms and e-signature; Markdown role-description editing, versioning or
acknowledgement tracking; volunteer or pastor logins; district rollups; SSO; SMS; BC-portal or
PtP-training integrations; billing; scheduling; disciplinary tracking.

Email-based account recovery, added in §1.20, is on none of these lists — that list forbids SSO,
volunteer and pastor logins, and SMS, and says nothing about how a screening admin gets back into
their own account.

Schema room was left for each without writing any of it — see `BUILD_NOTES.md` §1.12.

## Licensing constraint

No Plan to Protect® copyrighted text is embedded. The seed template carries requirement **names**,
**cadences** and **appendix references** only; every `description` is operational guidance written
for this system, telling an admin what to do in VMS. Asserted by
`test_template_contains_no_policy_prose`.

## 14. Separation of duties

Added 2026-08-02. Nothing previously connected an administrator's account to their own volunteer
record, so no criterion here could be stated about self-screening; see BUILD_NOTES §1.22.

- **An administrator has a volunteer record.** Created automatically with the account, from their
  name and address, with no ministry role until somebody gives them one.
- **VMS never guesses at a name match.** Where a volunteer already exists under that name, nothing
  is created and the administrators list offers an explicit link-or-create choice.
- **Nobody records screening against their own file** — not editing it, not assigning their own
  roles, not completing their own requirements, not their own criminal record check, not their own
  documents. Refused at each view and again in the screening services.
- **The last church-wide administrator may**, so a single-administrator church is never stuck, and
  the audit summary says which case applied.
- **Reading your own file is never refused.** The page explains why the buttons are absent.
- **Nobody can re-point or remove their own link**, which would otherwise be a way straight out of
  the rule above.
- **A permanently disqualified volunteer cannot be made an administrator.**

## 15. The four gaps closed on 2026-08-02

- **The in-church encryption key download requires `manage_users` and writes an audit entry.** It
  previously required neither, making `docs/SECURITY.md`'s claim that every key export is audited
  untrue for that route.
- **A church-created limited access level queues its work for review.** The gate reads `is_scoped`
  rather than matching the built-in slug, so it cannot apply to only one level again.
- **An unresolvable access level counts as needing review**, rather than silently as unscoped.
- **The last other reviewer cannot be deactivated** by somebody holding unaffirmed entries of
  their own.

---

## Open item, carried forward from the PRD

**Timeline.** PRD §8 records no target date for the Stage 1 launch, and that remains open. It is a
scheduling decision, not a build one.
