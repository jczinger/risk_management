# Security model

What this system protects, from what, and what it does not protect against. From PRD §5 and Build
Spec §6.

---

## The threat model

**The primary concern is a database dump.**

That is a deliberate and narrow choice, and it drives everything else. A dump is what actually
leaks: a misconfigured backup, a stolen laptop with a copy on it, an over-broad database
credential, a decommissioned disk. It is produced by an authenticated client, which is precisely
why **transparent disk or tablespace encryption does not help** — TDE decrypts for any authorised
reader, and `pg_dump` is an authorised reader. The output is plaintext.

So VMS encrypts sensitive columns **in the application**, before they are ever handed to
Postgres. A dump yields base64 noise for every one of them.

### What this defends against

| Scenario | Outcome |
|---|---|
| A database dump leaks | Sensitive fields are ciphertext; the key is not in the dump |
| The media volume leaks | Documents are ciphertext; filenames are random UUIDs |
| An off-host backup leaks | Same, and the master key is deliberately not in the archive |
| A stolen database credential | Reads ciphertext only |
| One church's data reaching another | Separate schemas *and* separate keys — two independent barriers |
| Phishing for credentials | A passkey cannot be phished; it is bound to the origin |
| A guessed or reused password | There are none to guess. Nothing in the system accepts one |
| A stolen sign-in link | Works once, expires, and only reaches passkey enrolment |
| **Access to an administrator's mailbox** | **Not defended.** See below |

### What it does **not** defend against

Stated plainly, because a security model that overclaims is worse than none.

- **A compromised application host.** If someone has code execution as the app, they have
  `PLATFORM_MASTER_KEY` from the environment and can decrypt everything. Field encryption protects
  data *at rest*, not a live compromised server.
- **A malicious or compromised administrator.** A screening admin is authorised to read their
  church's records. The audit trail records what they did; it does not prevent it.
- **The platform operator.** The operator holds the master key and can decrypt any church's data.
  This is an accepted, documented trade-off (see below).
- **Traffic analysis of encrypted columns.** Ciphertext length leaks approximate plaintext length.
  A 400-character note is distinguishable from a 4-character one.
- **Existence.** That a volunteer record exists, that a criminal record check was recorded, and
  what its result was are all plaintext by design, because the system has to report on them.

---

## The encryption design

### Key hierarchy

```
PLATFORM_MASTER_KEY          32 bytes, base64, in the environment. Never in the database.
      │  wraps (AES-256-GCM)
      ▼
church DEK                   32 bytes, one per church. Stored only wrapped.
      │  encrypts (AES-256-GCM, fresh random nonce per value)
      ▼
field ciphertext             v1.<base64url nonce+ciphertext+tag>
```

**Cipher:** AES-256-GCM, 12-byte random nonce per value, authenticated. Randomized, so the same
plaintext encrypts differently every time and a dump reveals nothing by repetition — not even
that two volunteers share an address.

**Additional authenticated data** separates the two purposes (`vms:v1:field` and `vms:v1:dek`), so
a wrapped key can never be fed to the field decryptor or vice versa.

**Authentication is not optional.** A wrong key produces a hard error, not plausible-looking
nonsense. Anything else would risk silently writing corrupt data.

Implementation: `apps/core/crypto.py`, `apps/core/keys.py`, `apps/core/fields.py`.

### Key custody, and the trade-off

Each church's key is:

1. **Shown to the church's own admin once**, who is *forced* through a backup step before they can
   use the system — a confirmation checkbox plus re-typing the last four characters of the key
   fingerprint, so it cannot be clicked through blind.
2. **Escrowed by the operator** in Keeper Security.
3. **Stored wrapped** under the master key, so the application can operate.

The accepted trade-off, from PRD §5: *the operator can technically decrypt tenant data, in
exchange for a guarantee that no church can lose its own records.* For a district tool serving
churches with no IT staff, losing a key permanently would be the worse failure. Every key export
writes an entry into that church's own audit trail, so the access is visible to them.

---

## What is encrypted, and what is not

The split is a specification, not an implementation detail. Both halves are tested in
`apps/core/tests/test_dump_leakage.py` — including the plaintext half, because encrypting the
wrong thing breaks the system quietly.

### Plaintext, on purpose

Everything the app must **search, filter, sort or report on**:

| Field | Why it has to be plaintext |
|---|---|
| First and last name | The volunteer list is searched and sorted by name |
| Department, role, role flags | Reports group by them; requirements match on the flags |
| Role descriptions | Not personal information |
| Requirement type, status, dates | The dashboard buckets and the compliance report are built from them |
| CRC result flag + report date | The report shows the flag; the three-year clock runs off the date |
| **Birth year + birth month** | The nightly job must *query* for who is turning 18 |
| Audit action, entity, actor name, timestamp | The trail has to be filterable and readable |
| Email delivery metadata | So an admin can diagnose a failure without decrypting anything |

The birth year/month decision (2026-07-23, PRD §5) is the sharpest of these. Encrypting the full
date of birth and *also* needing to find everyone turning 18 this month is not satisfiable with
randomized encryption. Splitting it — coarse parts queryable, full date encrypted — gives the age
rules what they need while keeping the precise date protected. A birth month and year is
meaningfully less identifying than an exact date.

### Encrypted with the church's key

| Field | Where |
|---|---|
| Full date of birth | `Volunteer.date_of_birth` |
| Home address, personal phone | `Volunteer` |
| Email addresses | `Volunteer.email`, `User.email` — decrypted only at send time |
| Emergency contacts | `Volunteer.emergency_contact` |
| Medical and allergy details | `Volunteer.medical_notes` |
| All notes | Volunteer, requirement instance, CRC record, document |
| Reference-check content | Requirement instance notes |
| Conviction descriptions | `DisqualifyingConviction.description` |
| Override reasoning and mitigation | `DiscretionaryOverride` |
| Waiver reasons | `RequirementInstance.waived_reason` |
| **Uploaded file bytes** | On the media volume, sealed before writing |
| Original filenames | `Document.original_filename` |
| Audit before/after detail | `AuditEvent.detail` |
| Email recipients, subjects, bodies | `EmailLog` |
| Passkey labels | `Passkey` |

### The consequence you must design around

**Encrypted fields are not queryable.** `filter(phone="250-555-0000")` matches nothing —
silently. Ordering and `icontains` are equally meaningless. This is asserted in the test suite so
it cannot be discovered the hard way in production.

Where an exact lookup is genuinely required, use a **blind index**: a keyed hash stored alongside
the ciphertext. `User.email_index` is the only one, and it exists because login has to find a user
by address. See `apps/core/blind_index.py` for its properties and limits.

---

## Authentication

**A passkey is the only way to sign in.** Not phishable, no shared secret to steal, and no second
factor to add — the authenticator has already proven possession of an unlocked device. There is no
password path, no authenticator app, and no recovery codes; the code for them was removed rather
than disabled (BUILD_NOTES §1.20).

**A single-use link covers the two moments a passkey does not exist yet:** the first sign-in after
an account is created, and recovery after a lost passkey or a replaced device. A link is emailed,
works once, and expires — seven days for an invite, thirty minutes for a recovery. Opening one
signs the holder in and drops them at passkey enrolment.

**Only the hash of a link is stored** (SHA-256 of 256 bits of randomness), so a database dump
contains nothing that can be used to sign in. The URL carries a *signed* payload naming the
schema the account lives in, because consuming it binds the connection to that schema and nothing
attacker-chosen may reach that call.

**Enrolment is compulsory, not suggested.** `ForcePasskeyMiddleware` redirects every request from
an account with no passkey to the enrolment page. Only signing out, the WebAuthn endpoints and the
health check stay reachable — a redirect from one view would be escaped by typing another URL.

**Accounts hold Django's unusable password marker**, one distinct value per row. This is
load-bearing rather than cosmetic: see "Which church a request belongs to" below.

**Lockout guards.** The last active administrator at a church cannot be deactivated, and nobody
can deactivate themselves. Removing your last *passkey* is now allowed — it is no longer a
lockout, because recovery by email exists.

**Rate limiting.** The passkey endpoints are limited per source IP; they were previously
unmetered, which stopped being defensible once they became the only interactive way in. Recovery
requests are limited per address *and* per source IP, more tightly, because each one that lands
sends real mail to a real person.

**Enumeration.** An unknown address, a deactivated account and a suspended church all produce the
same page from the recovery form, so it cannot be used to discover who works at a church — or at
which church someone works. Every way a link can fail — expired, spent, forged, never real —
renders one identical refusal.

### What this costs, stated plainly

**Whoever controls an administrator's mailbox controls the account.** With no password and no
second factor, email is the root of trust. This is the standard arrangement for products of this
kind, and it is a real reduction from what came before, where a stolen password was useless
without a TOTP device.

Three things bound it rather than prevent it:

- A recovery link lives thirty minutes and works once.
- Using one is written to the church's audit trail as **Sign-in link used**.
- Using one **emails every other administrator at that church**. A takeover cannot be stopped by
  anything in this system; being noticed the same morning is the realistic defence.

A church that wants more should keep more than one administrator, and administrators should hold
mailboxes with their own strong second factor. Neither is something VMS can enforce.

---

## Tenant isolation

Two independent barriers, either of which would be sufficient:

1. **Schema separation.** Every church's data is in its own Postgres schema. Primary keys are
   per-schema, so an id from one church resolves to nothing in another. Sessions live in the
   tenant schema, so a cookie issued by one church is meaningless at another.
2. **Separate encryption keys.** Even if schema separation were bypassed — a bad raw query, a
   botched restore — one church's key cannot decrypt another's data.

### Which church a request belongs to

Churches share one hostname, and the church is chosen by the address entered at sign-in. The
choice is then carried in a **signed, host-only cookie** naming the schema, which the tenant
middleware reads before anything else runs.

The cookie is a **pointer, not a credential**, and that distinction is the whole security
argument:

* It is signed with `SECRET_KEY`, so it cannot be forged. An unsigned or tampered value is
  ignored *and deleted*.
* It names a schema; it does not authenticate anyone. Repoint the cookie at another church and
  you arrive **anonymous at the login page**, not inside someone else's data.

  Why, precisely — because the obvious answer is wrong and worth correcting. Sessions are *not*
  per church: `django.contrib.sessions` is in SHARED_APPS only, so one `django_session` table
  sits in `public` and every schema's search path reaches it. The row survives the swap. What
  fails is Django's `_auth_user_hash`, an HMAC over the user's `password` column, which
  `get_user()` recomputes against the user holding that primary key **in the newly bound
  schema**. Different person, different value, no session.

  That is why every account must hold a *distinct* password value. They are all unusable
  markers — nothing accepts a password — but `make_password(None)` yields forty random
  characters per call, so they stay distinct. One shared marker written across every row would
  turn this cookie into a credential; the passwordless migration is written the long way round
  for exactly that reason, and there is a test that fails if it is shortened.
* A cookie naming a suspended or unknown church is dropped and the visitor is treated as
  signed out.
* Signing out clears it, so the next person at that browser does not inherit the church.

Tested in `apps/tenants/tests/test_shared_host.py`.

A church can still be given a hostname of its own; that is opt-in per church. The cookie is
host-only, so it is never sent to such a hostname and the two routing schemes cannot shadow
each other. An unknown hostname is **refused** (`SHOW_PUBLIC_IF_NO_TENANT_FOUND = False`), so a
stray DNS entry cannot reach the operator's console. The single exception is `/healthz/`, which
answers on any hostname and returns nothing but `{"status": "ok"}`.

**What the recovery form does not reveal.** Finding which churches an address belongs to means
searching every schema for it. An unknown address, a deactivated account and a suspended church
all produce the same page, so the form cannot be used to discover that an address is known at
*some other* church. Nothing is decrypted during the search — only the blind index is compared —
so it never needs a church's key either.

An address held at two churches receives one link per church, each naming which. That is an
improvement on the password form it replaces, which had to pick one and picked the first
alphabetically, leaving the second account quietly unreachable.

The public schema holds no church data at all — only the registry, wrapped keys, and the
super-admin. The console does not browse tenant data.

Tested in `apps/tenants/tests/test_isolation.py`.

---

## Integrity and retention

**The audit trail is append-only.** `AuditEvent` refuses `save()` on an existing row, refuses
`delete()`, and its queryset refuses `update()`, `delete()` and `_raw_delete()`. There is no ORM
path to rewriting history — which is the whole point of a trail an insurer might read.

**Volunteer records cannot be hard-deleted.** Not through any view, and not through any ORM path:
`NoDeleteModel` closes both the instance and queryset routes, and related models use
`on_delete=PROTECT` so no cascade can reach a volunteer's history. Permanent retention is a policy
requirement and a legal one for records involving minors.

**A waiver, by contrast, can be reversed** — and the boundary is deliberate rather than
accidental. Setting a requirement aside is an administrator's judgement, and judgements can be
wrong. Reversing one requires a comment, clears the waiver from the record, and appends its own
audit entry; the original waiver entry is untouched, because the trail is append-only. What
cannot be undone is everything below.

**Leadership overrides are immutable.** A `DiscretionaryOverride` cannot be edited or deleted once
written. An override that could be quietly revised afterwards would not be a trail. To change a
decision, record a new one; the earlier one stays visible.

**Automatic disqualification is irreversible.** `ScreeningBlock.DISQUALIFIED` cannot be lifted by
any view, form, service call or management command. `Volunteer.set_screening_block` refuses to move
off it, no URL reverses to lifting it, and the tests in `apps/requirements/tests/test_crc.py`
actively hunt for a route back.

**Document integrity.** A SHA-256 of the plaintext is stored and verified on every read, so a
botched restore — where AES-GCM would pass but the stored file and its row disagree — is caught
rather than served as a broken file.

---

## Transport and application hardening

- TLS terminated by Nginx Proxy Manager; `SECURE_PROXY_SSL_HEADER` honours `X-Forwarded-Proto`.
- HSTS with `includeSubDomains` and preload; secure, HttpOnly, SameSite=Lax session cookies.
- CSRF protection on every mutating request; `CSRF_TRUSTED_ORIGINS` is explicit per hostname.
- `X-Frame-Options: DENY`, `nosniff`, `Referrer-Policy: same-origin`, `noindex` on every page.
- Uploads validated on **magic bytes**, not the browser-supplied content type; PDF and images
  only; size ceiling enforced before the file is read into memory.
- Decrypted documents and generated reports are served `no-store`, so a clearance letter does not
  linger in a browser or proxy cache.
- Stored documents are **never** served by the web server directly — the file on disk is
  ciphertext, so every view goes through Django and is authenticated and audited.
- **No CDN.** htmx is vendored locally. No third-party host sees a request from this app, which
  suits both the residency requirement and not depending on someone else's uptime.
- **No PII in logs.** SQL query logging is off, so decrypted parameter values are never printed.
  Failed logins record the source IP, never the attempted address.
- Production settings **refuse to boot** without `PLATFORM_MASTER_KEY`, with an empty
  `ALLOWED_HOSTS`, or with a weak `DJANGO_SECRET_KEY`. Failing loudly beats running misconfigured.

---

## Privacy and residency

- **All data stays in Canada.** One host, named Docker volumes, ACS Email in the Canada geography.
- **PIPEDA and BC PIPA.** Data minimisation is enforced in the interface — the volunteer form asks
  only for what the screening process needs, and the medical field says so in its help text.
- **Permanent retention** for volunteer records, including after someone stops serving, per the
  policy and the law on records involving minors.
- **Access is logged**, and the audit trail is visible to the church itself, not just the operator.

---

## Reporting a problem

Security issues in this system should go to the platform operator (Josh Czinger,
josh.czinger@shiftit.ca) directly, not to a public issue tracker. It holds the personal
information of volunteers, many of whom work with children.
