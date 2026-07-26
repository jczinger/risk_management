# Acceptance criteria — Build Spec §10

Every criterion, how it was verified, and where to re-run that verification.

**Automated:** 390 tests, 86% statement coverage of `apps/`.

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
- **One church's key cannot decrypt another's data.** A ciphertext is read directly out of
  `alpha.org_volunteer` with raw SQL, decrypts correctly with alpha's key, and raises
  `DecryptionError` with beta's — so even bypassing schema separation entirely does not help.
- The `public` schema is asserted to contain **none** of the church-data tables.
- A request to an unmapped hostname is refused (404), not shown the public schema.
- A session cookie issued by one church is not honoured by another.

## 2. Admin logs in with a passkey; fallback password+TOTP works; passwordless-only account possible

**Status: passing.**

`apps/accounts/tests/test_auth.py` — 42 tests.

- **Passkey:** challenge issuance, verification, sign-in, sign-counter advance, single-use
  challenges, five-minute expiry, unknown-credential refusal, deactivated account and
  deactivated passkey both refused. A passkey login is asserted **not** to prompt for TOTP.
- **Password + TOTP:** a correct password alone does not sign anyone in; it leads to the second
  factor. An account with a password but no authenticator app is forced through enrolment first.
  Full password → TOTP → signed-in path is tested, as is a wrong code, an expired pending step,
  and the clock-skew window.
- **Passwordless:** `test_an_account_can_exist_with_no_usable_password` and
  `test_a_passwordless_account_cannot_be_signed_into_with_a_password`.
- Argon2id confirmed against the raw column; TOTP secrets confirmed encrypted at rest.
- Lockout guards: the last passkey cannot be removed without a working fallback; TOTP cannot be
  removed from a password-only account; the last active admin cannot be deactivated.

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
  `every_3_years` / `adults_only` / positions-of-trust; refresher training is annual; Code of
  Conduct and Covenant of Care are annual; the Confidentiality Agreement targets the
  handles-personal-info flag; the liability release precedes reference checks.
- Editing, adding and deactivating are all tested, including that re-seeding **preserves** a
  church's edits rather than reverting them.
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

## Not built, per Build Spec §0

Confirmed absent: in-app forms and e-signature; Markdown role-description editing, versioning or
acknowledgement tracking; volunteer or pastor logins; district rollups; SSO; SMS; BC-portal or
PtP-training integrations; billing; scheduling; disciplinary tracking.

Schema room was left for each without writing any of it — see `BUILD_NOTES.md` §1.12.

## Licensing constraint

No Plan to Protect® copyrighted text is embedded. The seed template carries requirement **names**,
**cadences** and **appendix references** only; every `description` is operational guidance written
for this system, telling an admin what to do in VMS. Asserted by
`test_template_contains_no_policy_prose`.

---

## Open item, carried forward from the PRD

**Timeline.** PRD §8 records no target date for the Stage 1 launch, and that remains open. It is a
scheduling decision, not a build one.
