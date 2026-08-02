# Volunteer Management System — Product Requirements Document (v1.2 — SIGNED OFF)

*Prepared for Josh Czinger · Signed off 2026-07-23 · Supersedes v1.0/v1.1. Changes in v1.2: policy corrections from district policy PDF verification, age-rule data decision, seed-template additions, Docker Compose deployment. Companion document: **VMS - Build Spec v1.0.md** (the document fed to the AI build agent).*

---

## 1. Problem

Churches and non-profit societies that adopt a **Plan to Protect®**-based risk-management policy carry a real, ongoing burden: every volunteer in a position of trust must be screened, trained, and re-certified on fixed schedules, and every step must be documented permanently to satisfy the policy, the insurer, and Canadian privacy law. Today this is tracked by hand — forms in SignNow, criminal record checks emailed from the BC portal, training registrations in spreadsheets, renewals remembered by whoever happens to remember. Things slip. An expired criminal record check or a lapsed annual sign-off is both a compliance gap and a liability exposure.

We want a purpose-built system that lets each society set up its roles and requirements once, then keeps its screening administrators on top of who is compliant, who is coming due, and who is overdue — across many societies from one platform.

## 2. Who it's for

The day-to-day users are **Screening Administrators / Ministry Leads** — the people who run screening, chase missing items, approve volunteers, upload clearance documents, and produce compliance reports. A church may have more than one screening admin. **Amended 2026-07-29:** they need not have equal access — each holds an *access level*, and a limited one is confined to its own departments and has its work affirmed by a Primary Admin. See BUILD_NOTES §1.21. **Amended 2026-08-02:** a screening admin is also somebody who serves, so each one has a volunteer record of their own — and may not record screening against it while another administrator could. See BUILD_NOTES §1.22. Above them sits a **platform super-admin** (Josh) who onboards and provisions churches and holds the break-glass keys. Volunteers, pastors, and district oversight are *not* users at initial launch; volunteers continue to receive and complete forms outside the system. Self-serve access for volunteers and read-only views for pastors/district arrive in a later stage.

## 3. Success criteria

- A screening admin can set up a church's departments, roles, and per-role requirements, and onboard a volunteer end-to-end without leaving the system.
- Nothing compliance-critical expires unnoticed: every criminal record check, annual training, and annual sign-off surfaces on a dashboard and triggers a proactive reminder before it lapses.
- At any moment the admin can produce a per-church (and per-department) compliance report suitable for handing to an insurer or board, plus a complete file for any individual volunteer.
- Every change is captured in an audit trail, and a database dump would expose no sensitive personal data — sensitive fields are encrypted, passwords are hashed.

## 4. Release stages

### Stage 1 — Initial launch

The foundation plus the full compliance loop, live for multiple churches from day one.

**Multi-tenant foundation.** Schema-per-tenant via `django-tenants`; a **super-admin console** to onboard and provision churches. Each church's data is isolated in its own Postgres schema.

**Authentication.** Passwordless **passkey as the primary login**; password + TOTP as fallback. Multiple screening admins per church. *(Amended 2026-07-29: passkeys only; a single-use emailed link covers first sign-in and recovery, and password + TOTP were removed. See BUILD_NOTES.md §1.20.)*

**Org model.** **Departments → Roles → Volunteers.** Directors and secretaries are leadership-flagged roles (0..n each per department), screened like any Ministry Personnel. Roles belong to exactly one department.

**Requirement engine.** Per-church, **fully customizable** requirements, seeded from a **Plan to Protect® default template**. Requirement types from the policy: application form (witnessed signature), waiting period, statement/declaration of faith, **liability release (before reference checks)**, reference checks, interview, **signed PtP policy agreement (Appendix 2d)**, criminal record check (+ vulnerable sector search), training (orientation + refresher), signed agreements (Code of Conduct, Covenant of Care, Confidentiality), leadership approval. Each carries a cadence (one-time / annual / every 3 years / custom).

**Special cases (corrected against the district policy PDF, 2026-07-23):**
- Under-18: same screening, no CRC.
- Turning 18: CRC must be submitted within 3 months to continue serving.
- CRC "NOT CLEAR": candidate either submits a fingerprint-verified CRC with disclosed/verified convictions, or withdraws.
- **Automatic disqualifiers are hard-fail with NO override** (violent crimes with a weapon; crimes against children/youth/vulnerable adults; child abuse, abduction, murder/manslaughter, incest, rape, sexual assault).
- **Discretionary red flags** get a leadership decision with a **documented, permanently retained override trail** (decision, reasoning, mitigation steps).

**Volunteer records.** A record per volunteer (the digital "Ministry Personnel file") holding roles and the status + dates of every requirement. Retained permanently, including after the volunteer stops serving.

**Criminal record checks & training — manual.** No BC-portal integration. The church admin **uploads the clearance PDF** and records the clearance date, which drives the 3-year clock. Training status entered manually.

**Documents.** Three storage modes, selectable **per church**: (1) store securely in-system, (2) track + link to an external store, (3) track status/dates only (hard-copy churches).

**Security & encryption** (see §5).

**Renewals — proactive.** A due / coming-due / overdue dashboard plus **email reminders** to admins ahead of each expiry (Azure Communication Services Email, Canada geography).

**Reporting.** Per-church compliance report (compliant / overdue), **viewable per department and church-wide**; an immutable **audit trail**; a printable **individual volunteer file**.

**Role descriptions — simple.** Plain-text description per role. Markdown editor, versioning, and acknowledgement tracking come in Stage 2.

**Agreements — status only.** Sign-offs tracked as **completed / not-completed** with dates; signatures collected outside the system. Native e-signature comes in Stage 2.

### Stage 2 — Native documents & role governance

- **In-app forms & e-signature** replacing SignNow (legal validity confirmed during design).
- **Role-description authoring:** Markdown editor, draft → publish, sequential integer versioning, whole-role snapshots, material-change flag, admin-side acknowledgement tracking.

### Stage 3 — Self-serve & oversight

- **Volunteer portal** (view, sign, acknowledge); **pastor read-only views**; **district cross-church rollup**; **per-tenant SSO**.

### Later / backlog

BC criminal-record-check portal and PtP training integrations; SMS; scheduling; billing. Also deferred from the policy review (church-addable via the custom requirement engine): renewal application form (Appendix 7), child-welfare-check consent, role-conditional agreements (Volunteer Driver Agreement, Computer Policy Agreement, Offenders Covenant), disciplinary tracking.

## 5. Data classification & encryption

**Threat model.** Primary concern is a **database dump**. Defense is **application-level field encryption** on sensitive columns (TDE alone does not protect against a dump). Field encryption ships in Stage 1.

**Guiding principle: encrypt the payload, not the pointers.** Metadata the app needs to search, filter, sort, and report on stays plaintext; substantive content and direct personal identifiers are encrypted with strong **randomized** encryption.

**Passwords** — salted and hashed (Argon2 preferred), never reversibly stored.

**Plaintext & queryable:** first and last name; department, role/position; role descriptions; requirement type, completion status, and dates; the CRC result flag ("Cleared"/"Not Cleared") plus report date; **birth year + birth month** (decided 2026-07-23 — needed to drive the under-18 exemption, the 18+ CRC rule, and the turning-18 trigger; the trigger fires on the 1st of the birth month, up to a month early — early is compliance-safe); and, for future incident reports, author/date/time/location.

**Field-encrypted with the per-tenant key:** full date of birth; home address; personal phone; email (decrypted only at send time); all uploaded file contents including CRC PDFs; all notes and messages; medical/allergy details; emergency contacts; reference-check content; future incident narratives.

**Key management.** Per-tenant key; admin **forced to back up the key** at setup; **break-glass escrow** to the platform super-admin (Josh) in Keeper Security. Accepted trade-off: the operator can technically decrypt tenant data, in exchange for guaranteed no-data-loss.

## 6. Constraints & key decisions

- **Stack:** Django + PostgreSQL; HTMX UI; Nginx Proxy Manager terminates SSL in front.
- **Multi-tenancy:** schema-per-tenant via `django-tenants`.
- **Auth:** passkey primary; password + TOTP fallback; per-tenant SSO is Stage 3. *(Amended 2026-07-29 — passkeys only, emailed link for recovery; see BUILD_NOTES.md §1.20.)*
- **Notifications:** ACS Email, Canada geography, `no-reply@` on the app's own domain (SPF/DKIM/DMARC), behind a provider abstraction. No SMS.
- **Deployment (decided 2026-07-23):** **Docker Compose** — app, Postgres, background worker — one exposed port behind NPM on Josh's server; eventual Azure migration.
- **Hosting & residency:** everything stays in Canada.
- **Legal/privacy:** PIPEDA + BC PIPA; permanent retention for records involving minors.
- **Licensing:** PtP distribution license (36 BC churches, expires May 2027) governs PtP *content*; the system must not embed or redistribute licensed PtP material — the seed template uses requirement names, cadences, and appendix references only.
- **Fidelity to policy:** defaults match the UPC of BC PtP policy (verified against the district policy PDF, 2026-07-23 — all 11 core claims confirmed).
- **Commercial model:** none — internal/district tool.

## 7. Build approach

1. ~~Sign off this PRD~~ — **done 2026-07-23.**
2. Hand **VMS - Build Spec v1.0.md** to the AI build agent.
3. Build Stage 1 in vertical slices (order defined in the build spec).
4. Onboard First OAC (Josh Czinger as first admin), then the wider district.

## 8. Remaining open item

- **Timeline** — no target date set for Stage 1 launch.
