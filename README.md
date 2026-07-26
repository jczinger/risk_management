# Volunteer Management System (VMS)

Multi-tenant screening and compliance tracking for churches following the UPC of BC
**Plan to Protect®** risk-management policy. One platform, one database schema per church, one
encryption key per church.

Stage 1 as specified in `VMS - Build Spec v1.0.md`, from `VMS - PRD v1.2.md`.

**Who uses it:** each church's **screening administrators**, plus one platform **super-admin**.
There are no volunteer or pastor logins in Stage 1.

---

## What it does

- **Departments → Roles → Volunteers.** Every role is treated as a position of trust that
  handles personal information, so screening is uniform; a `leadership` flag lets a church
  target extra requirements at leadership positions.
- **A requirement engine** seeded with the 14-item Plan to Protect template and fully editable
  per church — rename, re-time, add, deactivate.
- **Age rules.** Under-18s are screened identically but exempt from the criminal record check,
  which switches on automatically when they turn 18 with the policy's three-month deadline.
- **Criminal record checks.** Cleared sets a three-year clock from the report date. Not Clear
  blocks the volunteer. Automatic disqualifiers are permanent with no override anywhere.
  Discretionary red flags require a documented leadership decision.
- **Documents** in one of three per-church modes: encrypted in-system, linked to the church's own
  store, or status-and-dates only for hard copy.
- **Proactive renewals.** A three-bucket dashboard plus one daily email digest per church at
  configurable lead times, and once on overdue.
- **Reporting.** Compliance report per department or church-wide, printable and as PDF; a
  complete individual volunteer file; an append-only audit trail.
- **Encryption at the application layer**, because the threat model is a database dump.

---

## Documentation

| Document | What is in it |
|---|---|
| [`docs/DEPLOYMENT.md`](docs/DEPLOYMENT.md) | Standing it up on a host behind Nginx Proxy Manager, from nothing |
| [`docs/OPERATIONS.md`](docs/OPERATIONS.md) | Day-to-day running: churches, keys, backups, restores, troubleshooting |
| [`docs/SECURITY.md`](docs/SECURITY.md) | The threat model, what is encrypted and what is not, and why |
| [`docs/ACCEPTANCE.md`](docs/ACCEPTANCE.md) | Every Build Spec §10 criterion and how it was verified |
| [`BUILD_NOTES.md`](BUILD_NOTES.md) | Judgment calls made where the spec was silent, and bugs found on the way |

---

## Quick start (production)

Requires Docker with the Compose plugin. Everything runs on one host; SSL is terminated upstream
by Nginx Proxy Manager.

```bash
git clone git@github.com:jczinger/risk_management.git /var/www/risk_management
cd /var/www/risk_management
cp .env.example .env
```

Generate the two keys and put them in `.env`:

```bash
docker compose run --rm --no-deps web python manage.py generate_key --secret-key
```

> **Before going any further:** copy `PLATFORM_MASTER_KEY` into Keeper Security. It wraps every
> church's encryption key. Without it, no church's records can be read — not by you, not by
> anyone.

Fill in `ALLOWED_HOSTS`, `CSRF_TRUSTED_ORIGINS`, `VMS_BASE_DOMAIN`, `POSTGRES_PASSWORD` and the
ACS email settings, then:

```bash
docker compose up -d
docker compose exec web python manage.py bootstrap_superadmin \
    --email you@example.ca --first-name Your --last-name Name --password '…'
```

Point Nginx Proxy Manager at `127.0.0.1:8020` for the base domain, then sign in at
`https://<your base domain>/` and onboard the first church. One hostname serves the operator's
console and every church — which church you land in is decided by the email address you sign in
with, so onboarding needs no DNS or certificate work.

Full walkthrough, including the DNS and proxy configuration: [`docs/DEPLOYMENT.md`](docs/DEPLOYMENT.md).

---

## Local development

Requires Python 3.12+, Docker (for Postgres and Redis), and the WeasyPrint system libraries.

```bash
# Postgres and Redis
docker run -d --name vms-dev-db -e POSTGRES_DB=vms -e POSTGRES_USER=vms \
    -e POSTGRES_PASSWORD=devpassword -p 5433:5432 postgres:16-alpine
docker run -d --name vms-dev-redis -p 6380:6379 redis:7-alpine

# WeasyPrint needs these present at runtime (Debian/Ubuntu)
sudo apt-get install -y libpango-1.0-0 libpangoft2-1.0-0 libharfbuzz0b \
    libcairo2 libgdk-pixbuf-2.0-0 shared-mime-info

python3 -m venv .venv
.venv/bin/pip install -r requirements-dev.txt
```

Create a `.env` for development — `DJANGO_SETTINGS_MODULE=config.settings.dev`,
`POSTGRES_HOST=127.0.0.1`, `POSTGRES_PORT=5433`, `REDIS_URL=redis://127.0.0.1:6380/0`,
`VMS_BASE_DOMAIN=localhost` — and generate a `PLATFORM_MASTER_KEY` with
`.venv/bin/python manage.py generate_key`.

```bash
.venv/bin/python manage.py migrate_schemas --shared
.venv/bin/python manage.py bootstrap_superadmin --email you@example.ca --password '…' --domain localhost
.venv/bin/python manage.py provision_church --name "First OAC" --code firstoac \
    --domain firstoac.localhost --admin-email you@example.ca --admin-password '…'
.venv/bin/python manage.py runserver
```

The console is at <http://localhost:8000/> and the church at <http://firstoac.localhost:8000/>.
`*.localhost` resolves to 127.0.0.1 in every current browser, so no `/etc/hosts` editing is
needed.

Passkeys need a secure context. `localhost` counts as one, so passkey registration and sign-in
work in development without TLS.

### Tests

```bash
.venv/bin/python -m pytest              # everything
.venv/bin/python -m pytest --reuse-db   # faster on repeat runs
.venv/bin/python -m pytest apps/requirements  # one area
```

428 tests, including the `pg_dump` leak check, tenant isolation, shared-hostname routing, the
age rules, and a render sweep over every page.

---

## Layout

```
config/            Django project — settings (base/dev/prod/test), URLs, Celery
apps/
  core/            Encryption, blind indexes, audit trail, base models, nightly tasks
  tenants/         Public-schema church registry, provisioning, key custody
  accounts/        Screening admins, passkeys, TOTP
  org/             Departments, roles, volunteers, assignments
  requirements/    The requirement engine, seed template, criminal record checks
  documents/       Three storage modes, encrypted uploads
  notifications/   Email provider abstraction, reminder digests
  reporting/       Dashboard, compliance report, volunteer file, audit viewer
templates/         Server-rendered templates (HTMX, no SPA)
static/            CSS and JS, including a vendored htmx — no CDN
scripts/           backup.sh, restore.sh
docs/              Deployment, operations, security, acceptance
```

---

## Stack

Python 3.13 · Django 5.2 LTS · PostgreSQL 16 with `django-tenants` · HTMX · Celery + Redis ·
WebAuthn passkeys with Argon2 + TOTP fallback · Azure Communication Services Email (Canada) ·
Docker Compose.

All data at rest stays on the host. Canadian residency, PIPEDA and BC PIPA.

---

## Licensing

The Plan to Protect® distribution licence covers PtP **content**. This system stores requirement
**names**, **cadences** and **appendix references** only — pointers into a church's own policy
manual. No policy or form text is embedded or redistributed. Keep it that way when editing the
seed template in `apps/requirements/seed.py`.
