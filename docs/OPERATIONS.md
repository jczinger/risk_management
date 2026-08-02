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
`track` (hard copy, dates only). There is no password to set — every account signs in with a
passkey.

Afterwards there are two steps: **escrow the printed key**, and **give the admin the printed
sign-in link.** It is emailed to them as well, but it is shown once on the terminal (and on the
console page, if you provisioned through the browser) so you can hand it over another way if the
email does not land. It works once and expires in seven days; if it lapses they can ask for a new
one from the sign-in page. No DNS, no certificate, no
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

Each church manages its own, under **Administrators**. Adding one mints a single-use
sign-in link, emailed and shown on screen.

What each administrator may do is set by their **access level**, managed on the same screen.
Two are provided:

- **Primary Admin** — the whole church: every volunteer, every department, the audit trail,
  the administrators list. Primary Admins also review and affirm the work of anyone on a
  limited level.
- **Department Admin** — limited to the departments they are given. They see only volunteers
  who have served in those departments, and everything they record is affirmed by a Primary
  Admin before anybody has confirmed the evidence behind it.

A church can add its own levels. Two rules are enforced and cannot be turned off: nobody can
grant an access level wider than their own, and a level limited to particular departments
cannot be given the audit trail — an audit entry does not record a department, so there is
nothing to limit it by.

Before 2026-07-29 every administrator at a church had identical access. See BUILD_NOTES
§1.21 for what changed and why.

Every administrator also gets a **volunteer record** of their own, because an administrator is
somebody who serves and Plan to Protect screens people who serve. It is created with their
account, from their name and address, and starts with no ministry role — so until you give them
one it is visible only to administrators who see the whole church.

**Nobody records screening against their own file** while somebody else could: not their own
criminal record check, not their own training, not their own ministry roles. They can read it in
full. The last church-wide administrator at a church is the exception, so a one-administrator
church is never stuck; the audit entry says when that happened. See BUILD_NOTES §1.22.

### An administrator has no volunteer record

Usually because a volunteer already existed under the same name, in which case VMS deliberately
created nothing rather than risk attaching them to somebody else's file or making a duplicate.
The **Administrators** screen shows the collision with a link-or-create choice; resolve it there.

To see the state of a whole church, or of every church:

```bash
docker compose exec web python manage.py link_admin_volunteers --schema <church>
```

That only reports. Add `--create` to create the records it says it would — it still refuses every
name collision, which stays a human decision. Run it after upgrading a church that predates
2026-08-02.

### Somebody needs their own screening recorded and they are the only administrator

Nothing to do: VMS allows it and says so in the audit trail. If there are two administrators and
one needs their own file completed, the other one does it.

### An administrator can suddenly do nothing

Check whether they hold an access level at all:

```bash
docker compose exec web python manage.py access_levels --schema <church>
```

An account with **NO ACCESS LEVEL** can do nothing — `has_capability` fails closed by
design. Repair it with `--email`, which makes that person a Primary Admin and never demotes
anybody:

```bash
docker compose exec web python manage.py access_levels --schema <church> --email admin@church.ca
```

The same command with no `--email` only reports, so it is safe to run first — and worth
running straight after any deploy that touches access, **before** signing out of a session
you might not get back.

### Nobody can reach the access-level screen

VMS refuses to let this happen: the last active administrator with church-wide access to
manage administrators cannot be deactivated, demoted or re-scoped. If a restore or a botched
migration produces it anyway, the repair command above is the way out. It needs shell access
to the host.

### Entries are piling up awaiting review

The dashboard shows a count, and the nightly digest carries a line once anything has been
waiting more than 30 days. Until an entry is affirmed the compliance report still counts it
as compliant, so a backlog does not look like a problem anywhere except those two places —
which is why they exist.

### Issuing a sign-in link by hand

The operator's break-glass, and the only way in when email is not working:

```bash
docker compose exec web python manage.py issue_magic_link --email admin@church.ca
```

It prints one link per church the address is found at. Add `--schema firstoac` to narrow it, or
`--purpose invite` for the longer-lived kind. The issue is written into that church's own audit
trail, so they can see it happened and ask why.

### If a church has locked itself out entirely

Every administrator has lost their passkey *and* cannot receive email. Create a rescue account and
issue it a link:

```bash
docker compose exec web python manage.py shell -c "
from django_tenants.utils import tenant_context
from apps.accounts.links import issue_link
from apps.accounts.models import LinkPurpose, User
from apps.tenants.models import Tenant
t = Tenant.objects.get(schema_name='firstoac')
with tenant_context(t):
    u = User.objects.create_user(email='rescue@church.ca',
                                 first_name='Rescue', last_name='Admin')
    print(issue_link(u, LinkPurpose.INVITE)[1])
"
```

Opening the printed link signs them in and holds them at passkey registration. Tell the church
this happened — it appears in their audit trail either way.

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
lifted by anyone, including the operator. There is no code path for it. Note that it now bars
them from **every** role, not just positions of trust — every role is one — so there is no
lesser position they can be moved into meanwhile. If a conviction was
recorded in error, that is a data-integrity incident: it needs a documented decision and a direct
database correction by the operator, and it should leave a written record outside this system
explaining what happened and why.

**An administrator has lost their passkey.** They ask for a link from the sign-in page —
"Email me a sign-in link" — and register a new one. Nothing is needed from you. When they use it,
every *other* administrator at that church is emailed and it lands in the audit trail as
**Sign-in link used**; that is deliberate, and worth explaining to a church before it surprises
them. If they cannot receive email either, use `issue_magic_link` above.

**Email is not configured yet, so no links are arriving.** Every place that mints one also shows
it on screen — adding an administrator, provisioning a church — and `issue_magic_link` prints one
on demand. With `EMAIL_PROVIDER=console` the message body also appears in `docker compose logs
web`. Nothing is blocked; the links are simply handed over by another route.

**Somebody keeps receiving sign-in links they did not ask for.** The recovery form is open to
anyone who knows an address, so this is somebody guessing rather than a breach — and the links
are useless to them, because they arrive in the target's mailbox. It is rate limited per address
and per source. Tell them to ignore the emails, and treat it as a prompt to check the mailbox
itself has a strong second factor: with no password in VMS, that mailbox is what protects the
account.

**A requirement was waived by mistake.** Fixable. On the volunteer's page the waived row offers
**Reverse waiver**; it asks for a comment saying what was wrong, clears the waiver, and puts the
requirement back where it stands — outstanding, or overdue if a date has passed. Both the original
waiver and the reversal stay in the audit trail, so the history of the decision survives. Filter
the trail by **Waiver reversed** to see them.

This is deliberately not the same as an automatic disqualification, which cannot be lifted by
anyone. A waiver is an administrator's judgement; a disqualification is a safeguarding
determination.

**A volunteer's refresher training shows as "Not applicable".** Expected, while their
orientation training is unrecorded — the row says which requirement it is waiting for. Record
the orientation and the refresher switches on, due one year after the orientation date.

**An existing church wants the orientation → refresher rule.** Re-applying the standard template
will not do it, deliberately: re-seeding never changes a requirement a church already has. Go to
Requirements → *Plan to Protect refresher training* → edit, set **Depends on** to the orientation
and the dependency rule to *"Does not apply until the prerequisite is complete"*. Warn them
first: anyone whose orientation is more than a year old goes overdue on the next nightly run.
That is accurate, but it will look like a sudden spike.

**A requirement is stuck as "Not applicable".** Check the prerequisite is still active and still
applies to that volunteer's roles — if either is false the gate lifts on the next sync, so a
requirement still stuck means the prerequisite is genuinely outstanding.

**A church wants a requirement the template does not have.** They add it themselves — the
requirement engine is fully editable per church, and the `custom` type plus the applies-to flags
cover everything the policy review deferred.

**Can a church see another church's data?** No. Separate Postgres schemas, separate encryption
keys, separate sessions. Tested in `apps/tenants/tests/test_isolation.py`.

**Everyone shares one web address — how does it know which church I am?** From your passkey, or
from the link you were sent — a link carries its church inside a signed payload. The choice is
then held in a signed cookie naming your church's schema. Editing that cookie does not get you
into another church; it selects a schema and grants nothing. Tested in
`apps/tenants/tests/test_shared_host.py`, and the mechanism is set out in docs/SECURITY.md.

**Someone has admin accounts at two churches.** This works. Asking for a sign-in link sends one
per church, each naming which, so both accounts stay reachable. Separate addresses
(`name+churchA@…`, `name+churchB@…`) are still tidier if they would rather not choose from an
inbox.

**Can the operator read a church's data?** Technically yes — the operator holds the master key.
That is an accepted trade-off recorded in PRD §5, made in exchange for a guarantee that no church
can lose its own records. Key exports are written into the church's audit trail, so the access is
visible to them.
