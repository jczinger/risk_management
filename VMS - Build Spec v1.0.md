# VMS Build Specification v1.0 — Stage 1

*Authoritative build document for the AI build/deployment agent. Source of truth: PRD v1.2 (signed off 2026-07-23). This document is self-contained — the agent should not need any other file. Where this spec is silent, prefer the simplest conventional Django solution and flag the choice in the build notes.*

---

## 0. Mission

Build and deploy **Stage 1** of a multi-tenant **Volunteer Management System (VMS)** for churches following the UPC of BC **Plan to Protect®** risk-management policy. The system tracks volunteer ("Ministry Personnel") screening, training, and recurring compliance, with proactive renewal alerts and reporting. Users are church **screening admins** plus one platform **super-admin**. No volunteer-facing features in Stage 1.

**DO NOT BUILD (deferred to later stages):** in-app forms or e-signature; Markdown role-description editor, versioning, or acknowledgement tracking; volunteer/pastor logins or portals; district rollup dashboards; SSO; SMS; BC-portal or PtP-training integrations; billing; scheduling; disciplinary tracking. Design the schema so these can be added without restructuring, but write no code for them.

**DO NOT EMBED** any Plan to Protect® copyrighted text (manual content, form wording, appendix bodies). The seed template may contain only requirement names, cadences, and appendix references.

## 1. Stack (fixed decisions — do not substitute)

| Concern | Decision |
|---|---|
| Backend | Python 3.12+, Django 5.x (latest LTS) |
| Database | PostgreSQL 16, **schema-per-tenant via `django-tenants`** |
| UI | Server-rendered Django templates + **HTMX** (minimal JS, no SPA framework) |
| Background jobs | Celery worker + Celery beat, Redis broker |
| Auth | Passkeys (WebAuthn) primary; password (Argon2) + TOTP fallback — **amended 2026-07-29: passkeys only, with a single-use emailed link for first sign-in and recovery. Password and TOTP removed. See BUILD_NOTES.md §1.20.** |
| Email | Azure Communication Services Email (Canada geography) via SMTP relay `smtp.azurecomm.net:587`, behind a provider abstraction (swappable interface; console backend for dev) |
| Deployment | **Docker Compose**: `web` (gunicorn), `worker`, `beat`, `redis`, `db` (Postgres 16 with named volume). One HTTP port exposed to the host; SSL terminated upstream by Nginx Proxy Manager (not part of this stack) |
| Config | All secrets/config via environment variables (`.env`, with a committed `.env.example`) |

Deployment constraints: `DEBUG=False` in production; `ALLOWED_HOSTS` and `CSRF_TRUSTED_ORIGINS` env-driven (app sits behind a reverse proxy — honor `X-Forwarded-Proto`); migrations run automatically on deploy; a management command bootstraps the super-admin; media/documents on a named volume; provide a documented `pg_dump` + volumes backup script. All data at rest stays on this host (Canada).

## 2. Tenancy & user model

- **Public schema:** `Tenant` (church: name, subdomain/domain entry, document storage mode, created), platform super-admin user, tenant provisioning.
- **Tenant schema:** everything else below.
- **Super-admin console** (public schema): create/provision a church, create its first admin user, view tenant list. The super-admin does not browse tenant data day-to-day.
- **Tenant users:** screening admins only. Multiple per church. ~~All have equal permissions within their church.~~ **Amended 2026-07-29 at the owner's direction:** each administrator holds an **access level**, which decides both what they can do and — for a limited level — which departments' volunteers they can see. What this line described is now the *Primary Admin* level. See BUILD_NOTES §1.21. **Further amended 2026-08-02:** an administrator also has a
**volunteer record of their own**, created with their account, and nobody records screening
against their own record while another administrator could. This is *not* a volunteer login —
§0 still holds, and the record has no credentials attached; it is the administrator's own
Ministry Personnel file, reachable only through their administrator account. See BUILD_NOTES
§1.22.
- **Login flow:** passkey-first UI; fallback link to email+password, which then requires TOTP. TOTP enrollment (QR) and passkey enrollment in account settings. Session security: standard Django, secure cookies.

## 3. Org & volunteer model

```
Tenant (church)
└── Department (0..n)
    └── Role (each role belongs to exactly ONE department)
        ├── leadership flag (director / secretary / none)
        └── description: plain text
Volunteer (a person; the "Ministry Personnel file")
└── RoleAssignment (volunteer ↔ role, active/inactive, start/end dates)
```

- Directors and secretaries are ordinary Roles with a leadership flag — same screening as any volunteer.
- Volunteers can hold multiple roles across departments.
- Volunteer records are **permanent**: deactivation, never deletion (no hard-delete anywhere for volunteer data; enforce at the model layer).

## 4. Requirement engine (the core)

### 4.1 Definitions

`RequirementDefinition` (per tenant, fully editable by admins):
- name, description, appendix reference (free text)
- **type**: application_form | waiting_period | declaration_of_faith | liability_release | reference_checks | interview | policy_agreement | criminal_record_check | training_orientation | training_refresher | signed_agreement | leadership_approval | custom
- **cadence**: one_time | annual | every_3_years | custom_months(n)
- **applies_to**: all roles / specific roles / roles with a given flag (e.g., leadership, handles-personal-info)
- **age rule**: none | adults_only (18+)
- active flag; definitions are versionless in Stage 1 (edits apply going forward)

`RequirementInstance` (per volunteer × definition):
- status: not_started | in_progress | complete | overdue | not_applicable | waived
- completed date, expiry date (computed from cadence), notes (encrypted)
- waived requires a reason (goes to audit trail)

### 4.2 Seed template (created for every new tenant; admin may edit freely)

One-time onboarding, in order:
1. Waiting period — 6 months regular attendance (transfer-exception note: 3 references incl. previous minister)
2. Ministry Personnel Application Form — witnessed signature (Appendix 2 adult / Appendix 3 youth)
3. Statement/Declaration of Faith (one requirement — the policy uses both names)
4. Liability release (must precede reference checks)
5. Reference checks — minimum 2, one from current/previous pastor (Appendix 4/5)
6. Interview — face-to-face or online (Appendix 6)
7. Plan to Protect policy agreement (Appendix 2d)
8. Leadership approval — signed + dated; entire onboarding within 3 months (surface a warning when an in-progress volunteer's earliest requirement start is >3 months old)

Recurring:

9. Criminal Record Check + Vulnerable Sector Search — every 3 years, **adults 18+ only**, retained permanently
10. PtP Orientation training — one-time, before placement
11. PtP Refresher training — annual
12. Code of Conduct — signed annually
13. Covenant of Care — signed annually
14. Confidentiality Agreement — one-time, applies to roles flagged handles-personal-info

### 4.3 Criminal record check specifics

`CRCRecord` per volunteer: result flag **"Cleared" / "Not Cleared"** (plaintext), report date (plaintext, drives the 3-year clock), uploaded clearance PDF (encrypted, per document mode), notes (encrypted).

**NOT CLEAR flow:** status becomes blocked; admin records the outcome — (a) fingerprint-verified CRC submitted with convictions disclosed/verified, or (b) volunteer withdrew.

**Automatic disqualifiers — HARD FAIL, NO OVERRIDE.** If the admin marks a conviction as an automatic disqualifier (violent crime with a weapon; crimes against children/youth/vulnerable adults incl. child abuse, abduction, murder/manslaughter, incest, rape, sexual assault), the volunteer is permanently blocked from all Positions of Trust. The UI must not offer an override path.

**Discretionary red flags — override allowed with mandatory trail.** Leadership decision recorded with decision, reasoning, and mitigation steps; permanently retained; full audit entry.

### 4.4 Age rules (decided 2026-07-23)

Plaintext queryable fields: **birth_year, birth_month** (full DOB is a separate encrypted field). Rules:
- Under 18 (computed from year/month, conservative: treat as under-18 until the month is unambiguous): CRC requirement = not_applicable.
- On turning 18: a nightly Celery beat job activates the CRC requirement on the **1st of the birth month** of the 18th year, with a **3-month deadline**. Firing up to a month early is intentional (early is compliance-safe; never late).

## 5. Documents

Per-tenant storage mode (chosen at provisioning, changeable by super-admin):
1. **store** — file uploaded and stored in-system, encrypted (see §6)
2. **link** — status/dates tracked + a URL to the church's external store
3. **track** — status/dates only (hard-copy churches)

Uploads accepted: PDF and common images. Virus-scan hook optional; size limit env-configurable (default 20 MB).

## 6. Security & encryption

**Threat model: database dump.** Application-level field encryption; TDE/disk encryption alone is insufficient.

- **Per-tenant data-encryption key (DEK)**, AES-256-GCM, randomized (non-deterministic — encrypted fields are not queryable). Route all sensitive fields through one encryption service module; size columns for ciphertext.
- **Plaintext (queryable):** names; department/role; role descriptions; requirement type/status/dates; CRC flag + report date; birth_year/birth_month.
- **Encrypted (tenant DEK):** full DOB; home address; personal phone; email (decrypt only at send time); all uploaded file bytes (incl. CRC PDFs); all notes/messages; medical/allergy; emergency contacts; reference-check content.
- **Key custody:** at tenant provisioning, generate the DEK and force a one-time key-backup step (display/download once, require confirmation checkbox before proceeding). The DEK is also stored wrapped by a platform master key (env: `PLATFORM_MASTER_KEY`) so the app can operate; provide a management command to export a tenant's DEK for the super-admin's escrow (stored by the operator in Keeper Security — outside this system). Break-glass = re-import from escrow.
- **Passwords:** Argon2. **Audit trail:** append-only model (no update/delete ORM paths), records actor, action, entity, timestamp, and before/after summary for every mutating action.
- Standard hardening: CSRF, secure cookies, HSTS via proxy, rate-limited login, no PII in logs.

## 7. Renewals & notifications

- Nightly job recomputes every RequirementInstance status and expiry.
- **Dashboard:** three buckets — overdue / due soon (≤60 days) / compliant — filterable by department, role, requirement type.
- **Email reminders to admins** (not volunteers): at 60, 30, and 7 days before expiry, and once on overdue; lead times configurable per tenant. Batched into one daily digest per tenant. Every send logged. Provider = ACS SMTP behind an `EmailProvider` interface; dev/test uses console backend.

## 8. Reporting

1. **Compliance report** — per department and church-wide: each volunteer × requirement, status, dates; on-screen (HTMX) + printable/PDF export; suitable for insurer/board.
2. **Individual volunteer file** — the complete Ministry Personnel file: roles, all requirement statuses/dates, CRC history, documents list; printable.
3. **Audit trail viewer** — filterable, read-only.

## 9. Build order (vertical slices, each shippable and tested)

1. Compose stack + django-tenants foundation + super-admin console + tenant provisioning (incl. DEK generation + forced backup step)
2. Auth: passkeys, password+TOTP fallback, admin user management
3. Departments → Roles → Volunteers CRUD (with encryption service + encrypted fields from day one)
4. Requirement engine + seed template + CRC flows (incl. age rules + disqualifier logic)
5. Documents (three modes) + encrypted uploads
6. Renewals job + dashboard + ACS email reminders
7. Reporting + audit trail viewer
8. Hardening pass + backup script + deployment docs

## 10. Acceptance criteria (Stage 1 is done when all pass)

- [ ] Two tenants provisioned; data provably isolated (cross-schema access test fails).
- [ ] Admin logs in with a passkey; fallback password+TOTP works; passwordless-only account possible. *(Amended 2026-07-29 — see BUILD_NOTES.md §1.20 and docs/ACCEPTANCE.md §2.)*
- [ ] New tenant gets the 14-item seed template; admin can edit, add, deactivate requirements.
- [ ] Volunteer onboarded end-to-end; compliance status correct at each step.
- [ ] Under-18 volunteer: CRC auto not_applicable; simulated turn-18 activates CRC with 3-month deadline.
- [ ] CRC: Cleared PDF upload sets a 3-year expiry; NOT CLEAR blocks; automatic disqualifier permanently blocks with no override path in the UI; discretionary red-flag override requires documented reasoning.
- [ ] A raw `pg_dump` inspected manually shows **no** readable DOB, address, phone, email, file contents, or notes.
- [ ] Reminder emails fire at 60/30/7/overdue against seeded near-expiry data.
- [ ] Compliance report, individual file, and audit trail render and print correctly.
- [ ] Volunteer records cannot be hard-deleted through any UI or ORM path.
- [ ] `docker compose up` from a clean host + documented env vars yields a working system behind a reverse proxy; backup/restore script round-trips successfully.
- [ ] Automated test suite covers the requirement engine, age rules, encryption round-trips, and tenant isolation.

## 11. Operational notes for the agent

- First real tenant: **First OAC**; first admin: **Josh Czinger** (josh.czinger@shiftit.ca).
- ACS Email resource provisioning (Canada geography, SPF/DKIM/DMARC on the app domain) is an operator task — consume it via env vars only.
- Keep a `BUILD_NOTES.md` recording every judgment call made where this spec was silent.
