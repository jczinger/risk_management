# Operating VMS

Day-to-day running, for the platform operator. Every command runs from
`/var/www/risk_management`.

---

## Churches

### Onboarding one

From the console at `https://<base domain>/`, or:

```bash
docker compose exec web python manage.py provision_church \
    --name "Second Church" --code secondch \
    --admin-email admin@secondchurch.ca \
    --admin-first-name Sam --admin-last-name Lee \
    --document-mode store
```

`--document-mode` is one of `store` (encrypted in-system), `link` (their own document store), or
`track` (hard copy, dates only). Omit `--admin-password` for a passkey-only account.

Afterwards there is exactly one step: **escrow the printed key.** No DNS, no certificate, no
`ALLOWED_HOSTS` edit — the new church signs in at the same address as everyone else, and their
admin's email address is what selects them.

### Giving a church its own hostname

Optional, and rarely worth it. Pass `--domain church.example.ca` at provisioning (or fill in the
hostname field in the console). Then it *does* need DNS pointing here, a certificate, and entries
in both `ALLOWED_HOSTS` and `CSRF_TRUSTED_ORIGINS` in `.env`, followed by
`docker compose up -d web`.

Both routes work at once: a church with its own hostname is reachable there *and* through the
shared address.

### Changing a church's settings

Console → the church → **Settings**. Name, contact, document mode, reminder lead times,
notifications on/off, and active/inactive.

Changing the document mode affects **new** records only. Files a church has already entrusted to
the system are kept and stay readable — switching to `track` does not delete anything.

### Suspending one

Untick **Active** in the church's settings. Requests for it are refused; its data is untouched.
Records are never deleted by any part of this system.

---

## Encryption keys

### The two levels

```
PLATFORM_MASTER_KEY   in .env and Keeper Security, never in the database
    wraps
church DEK            one per church, stored wrapped, escrowed in Keeper Security
    encrypts
the sensitive fields
```

### Exporting a church's key for escrow

```bash
docker compose exec web python manage.py export_tenant_key secondch --i-am-the-platform-operator
```

The acknowledgement flag is required, and the export writes an entry into that church's own audit
trail — so a church can see when its key was exported, and can ask why.

### Checking every key still works

```bash
docker compose exec web python manage.py verify_keys
```

Run this after a restore, after moving hosts, and after any change to `PLATFORM_MASTER_KEY`. It
unwraps each key, checks the fingerprint against what was recorded, and decrypts real stored data
— which a row count would not tell you.

### Restoring a church's key from escrow

Needed after a master-key rotation or a restore onto new infrastructure. Console → the church →
**Re-import the key from escrow**, and paste the base64 value from Keeper Security.

A fingerprint mismatch is refused rather than applied. That guard matters: re-wrapping the wrong
key would make every encrypted value in that church permanently unreadable, which is the exact
disaster escrow exists to prevent.

### If a church loses its own copy

Not a crisis. Export it again from escrow and have them save it properly. Their copy exists so
they are not dependent on the operator; the operator's copy exists so they cannot lose their
records.

---

## Backups

### Taking one

```bash
VMS_BACKUP_DIR=/var/backups/vms ./scripts/backup.sh
```

Produces, under a UTC timestamp directory:

| File | Contents |
|---|---|
| `database.dump` | Custom-format `pg_dump` of everything — public registry and every church |
| `media.tar.gz` | The media volume: encrypted document files |
| `MANIFEST.txt` | What was taken, and each church's key fingerprint |
| `SHA256SUMS` | Checksums, verified on restore |

`PLATFORM_MASTER_KEY` is **not** in the archive, deliberately. Storing the key beside the data it
protects would undo the encryption. It lives in Keeper Security.

Nightly cron and off-host copying: see [`DEPLOYMENT.md`](DEPLOYMENT.md#8-set-up-backups).

### Restoring from a backup

Destructive: it drops and recreates the database.

```bash
./scripts/restore.sh                       # lists what is available
./scripts/restore.sh 20260724T193000Z
```

The script refuses to run without `PLATFORM_MASTER_KEY` in `.env`, verifies the checksums, asks
you to type the database name, restores the dump and the media volume, applies any newer
migrations, and finishes by running `verify_keys`.

Then check by hand: sign in to one church and open a volunteer's record. If the personal details
are readable, the key matches and the restore is genuinely good. Row counts prove nothing about
whether the data is decryptable.

### Rehearsing it

Do this on a scratch host, at least once, before you need it:

```bash
VMS_RESTORE_YES=1 ./scripts/restore.sh <stamp>
docker compose exec web python manage.py verify_keys
```

---

## The nightly job

`beat` schedules one sweep per night at `VMS_NIGHTLY_HOUR` (default 02:00 local). Per church, in
order:

1. Reconcile every volunteer's requirements against their current roles and age.
2. Activate the criminal record check for anyone who has turned 18, with a three-month deadline.
3. Recompute every requirement's status against today's date.
4. Send that church's single reminder digest.

The order matters — activation before recompute, or a newly activated requirement with a past
deadline would not show as overdue until the following night.

### Running it by hand

```bash
docker compose exec web python manage.py shell -c \
  "from apps.core.tasks import sweep_all_tenants; print(sweep_all_tenants())"
```

For one church, or replaying a specific date:

```bash
docker compose exec web python manage.py shell -c \
  "from apps.core.tasks import sweep_tenant; from apps.tenants.models import Tenant; \
   import datetime; \
   print(sweep_tenant(Tenant.objects.get(schema_name='firstoac'), as_of=datetime.date(2026,8,1)))"
```

Reminders are idempotent — a reminder already sent for a given requirement, lead time and expiry
is not sent again, so re-running is safe.

### Confirming it ran

```bash
docker compose logs beat | tail -20
docker compose logs worker | grep -i "sweep\|digest" | tail -20
```

Or in the app: **Reports → Reminder emails**, which lists every send with its status, recipient
count and any provider error.

---

## Administrators

Each church manages its own, under **Administrators**. All of them have equal permissions within
their church — there are no sub-roles by design.

The operator cannot add a church's administrators from the console. If a church has locked itself
out entirely:

```bash
docker compose exec web python manage.py shell -c "
from django_tenants.utils import tenant_context
from apps.tenants.models import Tenant
from apps.accounts.models import User
t = Tenant.objects.get(schema_name='firstoac')
with tenant_context(t):
    u = User.objects.create_user(email='rescue@church.ca', password='<temp>',
                                 first_name='Rescue', last_name='Admin')
    print('created', u.pk)
"
```

They will be required to enrol an authenticator app on first sign-in. Tell the church this
happened — it appears in their audit trail either way.

---

## Monitoring

**Health check.** `GET /healthz/` returns `{"status": "ok"}`, or 503 if Postgres is unreachable.
It answers on any hostname, so an uptime monitor needs no special configuration.

**What to watch:**

```bash
docker compose ps                      # all services up, db and redis healthy
docker compose logs --tail=50 web
docker compose logs --tail=50 worker
docker compose exec web python manage.py verify_keys
ls -la /var/backups/vms | tail -5      # last night's backup exists and is non-trivial
```

**Logs deliberately contain no PII.** SQL query logging is off, so decrypted parameter values are
never printed. Login failures record the source IP but not the address that was attempted.

---

## Common questions

**A church asks to delete a volunteer.** Not possible, by design. Volunteer records are retained
permanently — the policy requires it, and so does the law for records involving minors. Mark them
as no longer serving; the file is kept and they can return to service later.

**A church says someone was disqualified by mistake.** An automatic disqualification cannot be
lifted by anyone, including the operator. There is no code path for it. If a conviction was
recorded in error, that is a data-integrity incident: it needs a documented decision and a direct
database correction by the operator, and it should leave a written record outside this system
explaining what happened and why.

**A church wants a requirement the template does not have.** They add it themselves — the
requirement engine is fully editable per church, and the `custom` type plus the applies-to flags
cover everything the policy review deferred.

**Can a church see another church's data?** No. Separate Postgres schemas, separate encryption
keys, separate sessions. Tested in `apps/tenants/tests/test_isolation.py`.

**Everyone shares one web address — how does it know which church I am?** From the address you
sign in with. The choice is then held in a signed cookie naming your church's schema. Editing
that cookie does not get you into another church: your session only exists in your own schema,
so you would land back at the sign-in page. Tested in `apps/tenants/tests/test_shared_host.py`.

**Someone has admin accounts at two churches.** They need a different email address for each.
If the same address and password exist at two churches, sign-in picks the first alphabetically
and logs a warning — so give them `name+churchA@…` and `name+churchB@…`, which VMS treats as
two distinct addresses.

**Can the operator read a church's data?** Technically yes — the operator holds the master key.
That is an accepted trade-off recorded in PRD §5, made in exchange for a guarantee that no church
can lose its own records. Key exports are written into the church's audit trail, so the access is
visible to them.
