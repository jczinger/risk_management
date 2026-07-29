# Deploying VMS

From a clean host to a working system behind Nginx Proxy Manager. Assumes Debian or Ubuntu with
Docker and the Compose plugin; adjust package commands for other distributions.

---

## 1. What you need first

| Thing | Notes |
|---|---|
| A host with Docker + Compose plugin | 2 vCPU / 4 GB RAM is comfortable for the district |
| A domain | one hostname, e.g. `vms.example.ca` |
| Nginx Proxy Manager | Already running, terminating SSL |
| Keeper Security access | For the master key and each church's escrowed key |
| An ACS Email resource | Canada geography, with SPF/DKIM/DMARC on the domain |

**DNS.** One record, pointing at the host:

```
vms.example.ca        A     <host IP>
```

Every church signs in at that one address; which church you land in is decided by the email
address you sign in with. Onboarding a church therefore needs no DNS change, no certificate and
no config edit.

A wildcard is only needed if you intend to give individual churches hostnames of their own,
which is optional and off by default:

```
*.vms.example.ca      A     <host IP>          # optional
```

---

## 2. Get the code

```bash
sudo mkdir -p /var/www
sudo chown "$USER" /var/www
git clone git@github.com:jczinger/risk_management.git /var/www/risk_management
cd /var/www/risk_management
```

---

## 3. Configure

```bash
cp .env.example .env
```

Generate both keys:

```bash
docker compose run --rm --no-deps web python manage.py generate_key --secret-key
```

> ### Stop here and back up the master key
>
> `PLATFORM_MASTER_KEY` wraps every church's data-encryption key. If it is lost, every encrypted
> field in the system becomes unreadable — dates of birth, addresses, phone numbers, notes,
> uploaded documents. Restoring a database backup will not help, because the backup deliberately
> does not contain it.
>
> Put it in Keeper Security **now**, before provisioning any church.

Then edit `.env`:

```ini
DJANGO_SETTINGS_MODULE=config.settings.prod
DJANGO_SECRET_KEY=<from generate_key --secret-key>
DEBUG=False

# Keep `localhost` — the container's own health check probes over the internal network.
# The leading-dot entry is only needed if churches will get hostnames of their own.
ALLOWED_HOSTS=vms.example.ca,.vms.example.ca,localhost
CSRF_TRUSTED_ORIGINS=https://vms.example.ca
VMS_BASE_DOMAIN=vms.example.ca
VMS_HTTP_PORT=8020

PLATFORM_MASTER_KEY=<from generate_key>

POSTGRES_DB=vms
POSTGRES_USER=vms
POSTGRES_PASSWORD=<a long random password>

REDIS_URL=redis://redis:6379/0
TZ=America/Vancouver
VMS_NIGHTLY_HOUR=2

EMAIL_PROVIDER=smtp
EMAIL_HOST=smtp.azurecomm.net
EMAIL_PORT=587
EMAIL_USE_TLS=True
EMAIL_HOST_USER=<acs-resource>.<entra-app-id>.<entra-tenant-id>
EMAIL_HOST_PASSWORD=<entra app client secret>
DEFAULT_FROM_EMAIL=no-reply@vms.example.ca
```

`CSRF_TRUSTED_ORIGINS` needs an entry per hostname that submits forms. With shared hosting that
is just the one, and onboarding a church needs no change here. Add an entry only if you give a
church a hostname of its own, then `docker compose up -d web` to pick it up.

```bash
chmod 600 .env
```

### A note on `ALLOWED_HOSTS`

Django rejects an unlisted hostname before any middleware runs, so `localhost` must be present or
the container health check fails and Docker will keep restarting a healthy `web`. The leading-dot
form `.vms.example.ca` matches every subdomain; keep it if churches may get their own hostnames,
drop it if they never will.

---

## 4. Start it

```bash
docker compose up -d
docker compose ps
```

You should see `db` and `redis` healthy, `migrate` exited 0, and `web`, `worker` and `beat`
running. The `migrate` service applies migrations to the public schema and every existing church
before the app starts, so a redeploy needs nothing special.

```bash
curl -s localhost:8020/healthz/     # {"status": "ok"}
docker compose logs migrate         # confirm the migrations applied
```

---

## 5. Create the super-admin

```bash
docker compose exec web python manage.py bootstrap_superadmin \
    --email you@example.ca \
    --first-name Your --last-name Name
```

This also creates the registry row and hostname for the platform itself. It is safe to re-run.

There is no password to set. **The command prints a one-time sign-in link** — open it, register a
passkey, and that is how you reach the console from then on. If the link expires before you get
to it:

```bash
docker compose exec web python manage.py issue_magic_link \
    --email you@example.ca --schema public
```

That command is the operator's break-glass and needs shell access to this host, which is why it
can be trusted to hand out a sign-in without one.

---

## 6. Point Nginx Proxy Manager at it

One proxy host, forwarding to `127.0.0.1:8020` (or the host's Docker bridge address):

**The platform**
- Domain: `vms.example.ca`
- Scheme `http`, forward host `127.0.0.1`, port `8020`
- Block common exploits: on
- Websockets: not needed
- SSL: request a certificate, force SSL, HTTP/2, HSTS on

That single host serves both the operator's console and every church. Add a second, wildcard
proxy host (`*.vms.example.ca`, same forwarding, wildcard certificate via DNS-01 — Let's Encrypt
cannot issue a wildcard over HTTP-01) **only** if you intend to give churches hostnames of their
own.

Nginx Proxy Manager sets `X-Forwarded-Proto` by default, which is what tells Django the browser
used HTTPS — `SECURE_PROXY_SSL_HEADER` in the settings honours it. Without that header, secure
cookies and the WebAuthn origin check both misbehave.

Confirm end to end:

```bash
curl -I https://vms.example.ca/accounts/login/     # 200
curl -I https://vms.example.ca/healthz/            # 200
```

---

## 7. Onboard the first church

Either from the console at `https://vms.example.ca/`, or on the command line:

```bash
docker compose exec web python manage.py provision_church \
    --name "First OAC" \
    --code firstoac \
    --admin-email josh.czinger@shiftit.ca \
    --admin-first-name Josh --admin-last-name Czinger
```

This creates the schema, generates the church's encryption key, adds the first screening
administrator, and seeds the 14 Plan to Protect requirements. It prints the admin's one-time
sign-in link as well as the key — the link is emailed too, but give it to them directly if you
have any doubt the email will land.

**The command prints the church's encryption key once.** Copy it into Keeper Security under the
church's name and the fingerprint shown. If you lose it, it is still recoverable while the master
key is intact (`manage.py export_tenant_key`), but escrow it now rather than relying on that.

Nothing else to configure. The church's admin signs in at the same
`https://vms.example.ca/` as everyone else — their email address is what selects their church —
and is held at a mandatory key-backup step until they confirm they have saved their own offline
copy.

---

## 8. Set up backups

The script dumps the database and the encrypted media volume, and writes a manifest with each
church's key fingerprint.

```bash
sudo mkdir -p /var/backups/vms
sudo chown "$USER" /var/backups/vms

VMS_BACKUP_DIR=/var/backups/vms ./scripts/backup.sh
```

Nightly, via cron:

```cron
30 2 * * * cd /var/www/risk_management && VMS_BACKUP_DIR=/var/backups/vms VMS_KEEP_DAYS=30 ./scripts/backup.sh >> /var/log/vms-backup.log 2>&1
```

Then get those backups **off this host** — the whole point is surviving the loss of this machine.

**Rehearse the restore.** A backup you have never restored is a hypothesis. See
[`OPERATIONS.md`](OPERATIONS.md#restoring-from-a-backup).

---

## 9. Confirm it all works

```bash
docker compose exec web python manage.py verify_keys
```

Every church should report OK — that confirms the key unwraps *and* that real stored data
decrypts, which a row count alone would not.

Then, by hand:

1. Sign in to the console; the church is listed.
2. Open the church admin's sign-in link. It signs you in and stops at passkey registration —
   confirm that every other URL bounces back to it until a passkey exists.
3. Register a passkey. The key-backup gate appears next; confirm it.
4. Add a department and a role; add a volunteer; assign the role — their requirements appear.
5. Sign out and back in with the passkey. Open the used link again and confirm it is refused.
6. Open **Reports → Compliance report** and download the PDF.

---

## 10. Upgrading

```bash
cd /var/www/risk_management
VMS_BACKUP_DIR=/var/backups/vms ./scripts/backup.sh   # always first
git pull
docker compose build
docker compose up -d
docker compose logs migrate
```

The `migrate` service runs before the app comes up, so migrations are applied to the public
schema and every church automatically.

---

## Troubleshooting

**404 on every page, health check fine.** The hostname has no `Domain` row. Unknown hostnames are
refused on purpose. Check that DNS resolves to this host and that the hostname matches the one in
the registry — for the shared address that is the row for the `public` schema.

**400 Bad Request.** The hostname is not in `ALLOWED_HOSTS`.

**CSRF verification failed.** The submitting hostname is missing from `CSRF_TRUSTED_ORIGINS`
(scheme included, e.g. `https://vms.example.ca`), or the proxy is not forwarding
`X-Forwarded-Proto`.

**Signing in lands in the wrong church, or back at the login page.** The church comes from the
signed `vms_tenant` cookie set at sign-in. Clear cookies for the site and sign in again. If a
church was renamed at the schema level — which is not supported — the cookie will name a schema
that no longer exists; it is dropped automatically and the visitor is returned to sign-in.

**A sign-in link never arrives.** Check **Reports → Reminder emails** for the delivery attempt
and any provider error, then issue one by hand with `manage.py issue_magic_link --email …`. Every
place that mints a link also shows it on screen, so nobody is ever blocked on email working.

**"That sign-in link is no longer valid."** One page covers every cause — used, expired, tampered
with, or an address with no account — deliberately, so it cannot be used to find out whether an
account exists. The commonest real cause is an email client wrapping the URL across two lines.
Check which schemas hold an address with:

```bash
docker compose exec web python manage.py shell -c "from apps.tenants.routing import find_login_targets; print([(t.schema_name, t.label) for t in find_login_targets('admin@church.ca')])"
```

An empty list means no active account with that address anywhere — check the spelling, that the
account is active, and that the church is not suspended.

**Somebody is stuck on the "Set up your passkey" page.** That gate is deliberate and only a
passkey clears it. If their browser or device cannot do WebAuthn, they sign out from that page and
open a fresh link on one that can. Nothing is lost meanwhile.

**`web` restarts repeatedly.** `docker compose logs web`. Most often a settings guard refusing to
boot: a missing `PLATFORM_MASTER_KEY`, an empty `ALLOWED_HOSTS`, or a `DJANGO_SECRET_KEY` under 50
characters. Failing loudly is deliberate — the alternative is a system that appears to work while
storing recoverable plaintext.

**Passkeys will not register.** WebAuthn requires a secure context. Confirm the page is served
over HTTPS and that `WEBAUTHN_RP_ID` is the base domain (not a subdomain, and no scheme or port).

**Reminder emails are not arriving.** Check **Reports → Reminder emails** for the delivery log
with any provider error. Then confirm `EMAIL_PROVIDER=smtp`, that the ACS credentials are right,
and that `DEFAULT_FROM_EMAIL` is a verified sender on the ACS domain.

**PDF export returns HTML.** WeasyPrint's system libraries are missing. They are in the image, so
this only happens outside Docker; install `libpango-1.0-0 libpangoft2-1.0-0 libharfbuzz0b
libcairo2 libgdk-pixbuf-2.0-0`.
