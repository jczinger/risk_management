# VMS Build Notes

Every judgment call made where **VMS - Build Spec v1.0.md** was silent, plus the places
where following the spec literally would have produced a broken system and what was done
instead. Required by Build Spec §11.

Nothing here changes a decision the spec made explicitly. Where a spec decision needed
*interpretation* to be implementable, that is flagged as such.

---

## 1. Decisions the spec left open

### 1.1 Where tenant users live

**Choice:** `apps.accounts` and `django.contrib.auth` are listed in **both** `SHARED_APPS`
and `TENANT_APPS`, so the user table exists in `public` *and* inside every church's schema.

**Why:** Build Spec §2 says the public schema holds the platform super-admin and "everything
else below" — including tenant users — lives in the tenant schema. Putting one shared user
table in `public` with a tenant foreign key would have been simpler, but a church's staff list
would then sit in the operator's schema, and the isolation criterion in §10 would be weaker
than it reads. With the model in both, `search_path = <tenant>,public` means a request bound
to a church resolves its own user table, and a dump of `public` shows no church's staff.

**Cost:** `createsuperuser` behaves per-schema, and permissions rows are created per-schema by
`post_migrate`. Neither matters here — there is exactly one super-admin and no permission
groups.

### 1.2 Email addresses are encrypted *and* searchable

**Choice:** `User.email` is encrypted; a keyed blind index (`User.email_index`) carries the
uniqueness constraint and answers the login lookup. See `apps/core/blind_index.py`.

**Why:** These two spec requirements collide head-on. PRD §5 classifies email as encrypted, and
§10 requires a `pg_dump` to show no readable email. But sign-in has to find a user *by* email,
and randomized AES-GCM ciphertext never matches itself. Storing the login address in plaintext
would fail the acceptance criterion; encrypting it without an index would make login
impossible. The blind index is an HMAC-SHA256 of the normalised address under a key derived
from `PLATFORM_MASTER_KEY` and the schema name.

**Consequences, stated plainly:** the index supports exact match only — no prefix or substring
search on email. It is deterministic within a schema (so a dump cannot correlate the same
person across two churches) and it is not reversible without the master key. An attacker who
has both the dump *and* the master key could confirm a guessed address — but that attacker can
already decrypt everything, so it concedes nothing against the actual threat model.

**Side effect:** Django's `auth.E003` check insists `USERNAME_FIELD` be unique. It is silenced
in `SILENCED_SYSTEM_CHECKS` with the reasoning inline in `config/settings/base.py`, because
uniqueness is genuinely enforced — just on the index column rather than the ciphertext one.

### 1.3 The public schema has its own encryption key

**Choice:** `bootstrap_superadmin` assigns a DEK to the `public` tenant row.

**Why:** The super-admin is a `User`, and `User.email` is encrypted. Without a key for `public`
the account could not be created at all. Encrypting it also means the operator's own address is
not the one readable email in the database.

### 1.4 One age convention, applied everywhere

**Choice:** age is computed treating the birthday as the **1st of the birth month**. So
`is_adult_on()` starts returning True on exactly the date the criminal record check is
activated.

**Why this needed a decision:** Build Spec §4.4 gives two rules that pull in opposite
directions. The under-18 exemption says "conservative: treat as under-18 until the month is
unambiguous", which would keep someone exempt until the birth month has *passed*. The
turning-18 trigger fires on the **1st of the birth month**, "up to a month early". Implemented
literally, a volunteer in their 18th birth month would be simultaneously activated by the
nightly job and exempted by the applicability check — the two would fight, and which won would
depend on job ordering.

The spec resolves the tie itself: *"early is compliance-safe; never late"*. So adulthood begins
at the trigger date. A person is treated as an adult from the 1st of their birth month, which
is at most a month early and never late. Being early means at worst a check is requested a few
weeks sooner than strictly required; being late would mean an 18-year-old serving without one.

`Volunteer.exact_age` uses the full encrypted date of birth for display on the volunteer's own
page, where decrypting one record is fine.

### 1.5 An unknown date of birth is treated as a minor

**Choice:** no date of birth ⇒ criminal record check `not_applicable`, with the reason
`"Date of birth not recorded — age rule cannot be applied"`, plus a warning banner on the
volunteer's record.

**Why:** The alternatives are worse. Recording the check as satisfied would be a false
compliance claim. Marking it overdue would put a data-entry gap in the same bucket as a lapsed
clearance, and the dashboard would stop meaning anything. `not_applicable` with a visible
reason keeps the gap on screen without pretending it is a screening failure.

### 1.6 Reminder deduplication and the overdue notice

**Choice:** `ReminderLog` has a unique constraint on
`(instance, kind, lead_days, expiry_at_send)`. The overdue notice is raised **once**, on the
first day past the deadline.

**Why:** Build Spec §7 requires "once on overdue" but does not say how to guarantee it. The
constraint makes the job idempotent by construction — a retry, a double-run or two workers
racing all collapse to one row and one email. Including the expiry in the key means renewing a
requirement legitimately starts a fresh reminder cycle. Re-mailing an ongoing overdue item
daily was rejected: the dashboard is what carries a standing gap, and a daily repeat is how a
compliance tool gets filtered into a folder nobody opens.

### 1.7 Static beat schedule, no `django-celery-beat`

**Choice:** the nightly schedule is declared in `config/celery.py`; the task fans out over
churches itself.

**Why:** A database-backed schedule has no natural home under schema-per-tenant — it would
either live in `public` (and need tenant awareness bolted on) or be duplicated per church. One
static entry plus an explicit loop is less machinery and easier to reason about.

### 1.8 Waivers, and the one requirement that cannot be waived

**Choice:** the criminal record check is not waivable. Everything else is, with a mandatory
reason.

**Why:** Build Spec §4.1 allows waivers generally, and §4.2/§4.4 make the criminal record check
mandatory for adults in positions of trust with exactly one exemption (age) and one exception
process (Not Clear). A waiver on it would be a back door around the policy's central control,
so both the form and the service refuse.

**A waiver can be reversed** (added 2026-07-28, at the operator's request). The spec never said
otherwise — §4.1 asks only that a waiver carry a reason and reach the audit trail. Permanence was
never a decision; it was an absence, and until recently there was an accidental way round it,
because "Mark complete" sat next to a waived requirement and would quietly overwrite it. Closing
that (§1.15) made the gap visible: an admin who waived the wrong volunteer had no way back.

Reversal takes a mandatory comment, clears the waiver from the record, and appends a
`waiver_reversed` audit entry. The requirement genuinely returns to play — outstanding again,
chased in reminder digests, possibly overdue immediately — which the confirmation screen says
plainly, since someone correcting a mis-click may not expect it.

Three details worth knowing:

* **Where it lands.** Derived from what survived the waiver: completed → complete, started → in
  progress, otherwise not started, then `recompute()` so an expired one shows overdue. Not
  restored is `due_on`/`due_reason`, which `waive_requirement` nulls unrecoverably — near-harmless
  in practice, since the criminal record check is the main user of hard deadlines and cannot be
  waived at all.
* **The comment goes in the audit *summary*, not just the detail.** After §1.16 removed the detail
  panel, `summary` is the only part of an entry anyone sees, so a reason recorded only in `detail`
  would be invisible to the reader it is written for. The form caps the comment at 200 characters
  so it fits a 255-character summary whole rather than being silently truncated.
* **Clearing the waiver fields loses the original reason from the interface.** It survives in the
  original entry's `detail`, which is no longer displayed. That is the accepted consequence of
  keeping the history in the audit trail rather than on the record.

**This is not a precedent for lifting a disqualification.** A waiver is an administrator's
judgement, and judgements can be wrong. An automatic disqualification is a safeguarding
determination, is irreversible by design (§4.3), and `apps/requirements/tests/test_crc.py`
actively hunts for a route back. The note at the top of `apps/requirements/urls.py` draws the
distinction so the two are not read as comparable.

### 1.9 Documents: filenames and integrity

**Choice:** stored files are named `<uuid>.enc`; the original filename is an encrypted column.
A SHA-256 of the *plaintext* is stored in the clear and verified on read.

**Why:** A filename like `jane-smith-crc-cleared.pdf` on the volume would leak a name and a
screening outcome to anyone who could list the directory, defeating the encryption for the
cheapest possible attack. The plaintext hash is not reversible and file contents are not
low-entropy, so keeping it in the clear is safe — and it catches a botched restore, where
AES-GCM would pass but the stored file and its row disagree.

Uploads are validated on **magic bytes**, not the browser-supplied `Content-Type`, which an
attacker controls.

### 1.10 Audit trail shape

**Choice:** plaintext actor name, action, entity type/id/label, one-line summary and timestamp;
the structured before/after `detail` is encrypted. Volunteer field changes record *which*
fields changed, not their old and new values.

**Why:** The viewer has to be filterable and an insurer has to be able to read it, so the
metadata stays queryable. But a before/after diff of a volunteer record contains addresses and
phone numbers, and copying those into a second table would widen the exposure the encryption
exists to prevent. "address changed" is the useful fact; the value itself is already on the
record.

The actor is stored as a denormalised name plus a user id, never an email — so the trail stays
readable after an account is deactivated, without putting an address in a second place.

### 1.11 A failed requirement sync does not fail the request

**Choice:** the `post_save` signal that resyncs requirements logs exceptions instead of raising.

**Why:** An assignment that succeeded should not 500 because a derived calculation hiccuped.
The nightly sweep re-runs the same reconciliation for everyone, so a missed sync self-heals
within a day. The views also call `sync_volunteer_requirements` directly, so the count shown to
the admin is accurate for that request.

### 1.12 One hostname, church chosen by the sign-in address

**Added 2026-07-25, after the initial build, at the operator's request.** This changes a
decision the spec made explicitly (§1: schema-per-tenant resolved from the hostname), so it
is recorded here in full rather than buried in a commit.

**The ask:** every church signs in at one address — `vms.<base domain>` — instead of getting
a subdomain. Per-church subdomains need a DNS record and a certificate each, which is real
operational friction for a district tool.

**The problem it creates:** django-tenants picks the Postgres schema from the Host header,
before anything else runs. If the hostname no longer identifies the church, nothing does
until the sign-in form is submitted — and the session, which is what makes a request
authenticated, lives *inside* a church's schema. You cannot read the session before you know
the schema, and you cannot know the schema before you read the form.

**What was built** (`apps/tenants/routing.py`):

1. Sign-in happens in `public`. `find_login_targets()` searches `public` and every active
   church for the submitted address, computing the blind index under each schema's own salt.
2. On success the connection is bound to that church **for the rest of the request** — not in
   a context manager, because the session is written during response processing and has to
   land in the church's schema.
3. The response carries a signed, host-only cookie naming the schema.
   `VMSTenantMiddleware` reads it before anything else and binds the schema from it.

**Why the session stays in the tenant schema.** The obvious alternative — move sessions to
`public` and store the tenant id in them — would have been less code and materially worse.
It would put a row per church admin in the operator's schema, and it would make the session
the only thing separating churches. Keeping sessions where they are means the cookie is a
*pointer, not a credential*: point it at another church and your session key does not exist
there, so you arrive anonymous at the login page. That property is asserted directly in
`test_a_valid_cookie_for_a_church_you_have_no_session_in_gives_nothing`.

**Passkeys needed the same treatment.** A discoverable-credential login sends no address at
all, so `find_passkey_target()` searches for the credential id across schemas instead. The
credential id is opaque, unique and already plaintext, so searching for it leaks nothing the
assertion does not already carry. The challenge row has to be consumed back in the schema
that wrote it, or the update silently touches zero rows and leaves the challenge replayable.

**Hostname routing was kept.** The cookie is host-only, so it is never sent to a church
subdomain and the two schemes cannot fight. A church can still be given its own hostname;
it is now opt-in (`--domain`) rather than the default, because the old default minted
`<code>.<base domain>` for churches that had no DNS for it.

**Known limitation.** If the same address *and* the same password exist at two churches,
sign-in resolves to the first by church name. It is logged as a warning. One address should
belong to one church; a proper fix would be a church chooser, which needs a way to hold the
half-authenticated state without a session — deferred rather than half-built.

**Cost:** one extra indexed lookup per schema per sign-in attempt. At district scale that is
a handful of primary-key hits, once per attempt, not per request.

### 1.13 Leadership is a flag, not a job title

**Changed 2026-07-25, at the operator's request.** Build Spec §3 line 44 specifies
`leadership flag (director / secretary / none)`. It is now a plain boolean,
`Role.is_leadership`.

**Why the distinction was dead weight.** Director vs Secretary drove nothing. The
requirement engine only ever asks whether a role is a leadership role at all —
`applies_to = leadership` matched `leadership != NONE` — and the specific value appeared
in exactly one badge and one dropdown label. No seeded requirement targets leadership,
no report groups by it, and no rule treats a director differently from a secretary. A
church that wants the distinction already has a better place for it: the role's name.

**Migration.** `org/0002` adds the boolean, sets it True for every existing Director or
Secretary, then drops the old column. The reverse restores `director` for flagged roles,
since the two values cannot be told apart once collapsed — noted in the migration rather
than left for someone to discover during a rollback.

**What did not change.** Leadership roles are screened exactly like any other volunteer,
which was the actual point of §3. `leadership_approval` — the requirement *type* for the
sign-off on a volunteer's completed file — is a separate concept and is untouched.

### 1.14 Every role is a position of trust, and handles personal information

**Changed 2026-07-25, at the operator's request.** `Role.handles_personal_info` and
`Role.is_position_of_trust` are gone. Build Spec §3 has both as per-role flags.

**The reasoning:** a church only enters someone here because they are being screened, and
anyone who serves encounters personal information about the people they serve. Both flags
were therefore true for every real role — and offering them as ticks was worse than
useless, because unticking one was a way to quietly screen a volunteer less than the
policy requires, with nothing in the interface flagging it.

**Knock-on effects, all intended:**

* The `AppliesTo` options "Roles that handle personal information" and "Positions of
  trust" are removed. A dead dropdown option would let an admin build a requirement that
  silently matches nobody.
* The two seeded requirements that used them — **Criminal Record Check** and
  **Confidentiality Agreement** — now target `all`. Both apply to every volunteer.
* **A permanently disqualified volunteer can no longer hold any role.** This is the sharp
  one. There used to be an escape hatch: a role with `is_position_of_trust` unticked could
  still be assigned to them, so a disqualified person could be given something harmless to
  do. With every role a position of trust the hatch closes — disqualification now means
  they cannot serve anywhere. `disqualify()` ends *every* active assignment rather than
  just the trusted ones, and the assignment form says why instead of rendering an empty
  dropdown. Asserted in `test_cannot_hold_any_role_at_all`.

**Migrations.** `requirements.0002` retargets the affected definitions to `all` and
narrows the choices; `org.0003` drops the two columns and *depends on* the requirements
migration, so the engine is never left querying a column that has gone. Neither is
meaningfully reversible — once retargeted there is no record of which definitions meant
which flag — and both say so.

**Widening a target means volunteers pick requirements up.** Existing volunteers who were
not previously covered acquire the Confidentiality Agreement and the criminal record check
on the next reconcile: the nightly sweep, or `sync_volunteer_requirements` on the next
edit. Nothing is retroactively marked overdue that was not already due.

### 1.15 Completion follows the evidence

**Changed 2026-07-27, at the operator's request.** "Mark complete" no longer appears on a
requirement that has a document behind it, or on one that is already satisfied.

**Why.** Two problems, one cause. A tick sitting next to "Add document" let the two disagree, and
a requirement reading complete with nothing behind it is precisely what an audit looks for. And a
*waived* requirement still offered the tick, even though a waiver already satisfies it — clicking
the obvious button would overwrite a recorded decision.

So recording the document now completes the requirement, in all three storage modes, using the
document's date and setting the next expiry. The rule lives in one place,
`RequirementInstance.can_mark_complete`, because three screens offer the action and they had
drifted apart.

Four cases deliberately do **not** auto-complete: the criminal record check (its own flow owns
clearance, disqualification and the three-year clock), waived and not-applicable (deliberate
decisions that a file arriving should not overturn), and blocked. A refused completion never
loses the document — the document is the primary act and is already saved.

**Not every requirement has a document.** The waiting period, the interview and the two training
items have none, so they keep the button; removing it everywhere would have left them satisfiable
only by waiver, putting a waiver on a permanent record for an ordinary interview.
`test_every_seeded_requirement_can_be_satisfied_somehow` fails if any requirement becomes a dead
end.

Also here: "Start" became "Mark as in progress" and swaps its own row over htmx. It previously
redirected to the top of the volunteer's file after every click, which reads as navigation rather
than a status change.

### 1.16 The audit entry page shows no before/after diff

**Changed 2026-07-27, at the operator's request.** Display only: `AuditEvent.detail` is still
written on every entry and the trail is still append-only.

The view stopped decrypting it too — with nothing rendering the diff, calling `detail_data` would
have decrypted personal information into a response for no reason.

**The consequence to design around:** `summary` is now the only part of an audit entry anyone
sees. Anything a human is meant to read has to go there, within 255 characters — see the waiver
reversal in §1.8.

### 1.18 Requirement dependencies: a warning by default, a gate by opt-in

**Added 2026-07-28, at the operator's request.** A requirement can now be held
not-applicable until its prerequisite is complete, and its first deadline counted from
the *prerequisite's* completion date. The driving case: refresher training is not owed
until orientation has happened, and then falls due a year after it.

**Extended `must_follow` rather than adding a second field.** The FK already existed and
the console already labelled it "Depends on" — but it was advisory only, read in exactly
one view function to render an "out of order" callout, and never reaching the service
layer. Two self-FKs both meaning "comes after X" would drift, double the cycle surface,
and need a rule for what happens when they disagree. So it gained a `dependency_mode`
instead: warn (the original behaviour) or gate.

**The default is the compatibility guarantee.** Every existing church has
`reference_checks → liability_release` in their database. `WARN` is the field default, so
the upgrade is inert — no data migration, nothing to remember at deploy time, and that
pair keeps behaving exactly as it did. Asserted by
`test_the_seeded_reference_check_dependency_is_only_a_warning`.

**The offset defaults to the dependent's own cadence.** An annual refresher following
orientation needs no configuration at all: annual already means twelve months. An
explicit `due_months_after_prerequisite` overrides it, for the "first one at six months,
annually after that" shape. A one-time dependent has neither, and gets no deadline — the
requirement simply becomes outstanding. No date is invented.

**What counts as the prerequisite being met**, and why each arm is what it is:

| Prerequisite | Met? | Anchor date |
|---|---|---|
| Has a completion date, even a lapsed one | Yes | that date |
| Waived | Yes | none |
| Not applicable (role or age) | Yes | none |
| Not applicable *because it is itself gated* | **No** | — |
| Blocked, not started, in progress, overdue with no completion | No | — |
| No instance — it does not apply to this volunteer | Yes | none |
| Its definition has been deactivated | Yes | none |

Two of those deserve the reasoning spelled out. **A lapsed prerequisite still counts**:
re-gating on a lapse would push the dependent back to not-applicable, which buckets as
*satisfied* — so a lapse would **reduce** the church's apparent workload. A gate asks
"has this ever happened", not "is it current"; the prerequisite's own overdue row is what
surfaces the lapse. **A waived one counts too**: holding a refresher behind a waived
orientation would silently exempt someone from refreshers forever.

**Everything fails open.** A missing instance, an inapplicable or retired prerequisite —
all leave the requirement ungated. A gate that wrongly holds is invisible non-compliance;
a gate that wrongly releases is visible work an admin can see and act on. Same
conservatism as §1.5.

**Age exemption wins when both apply.** An age exemption says "this person does not need
this"; a gate says "not yet". The age reason is the more useful thing to show. The nightly
turning-18 scan needed its own guard, because it calls `_activate` directly and would
otherwise switch on a requirement the sync is deliberately holding.

**Chains resolve one link per pass, not recursively.** A → B → C settles over successive
syncs, and the nightly sweep re-syncs everyone, so there is no chain walk at request time
and a loop written straight to the database cannot spin. `clean()` refuses loops up front;
the form goes further and excludes everything downstream from the dropdown, so one cannot
be picked.

**The accepted cost:** a gated requirement counts as compliant while it waits, because
`NOT_APPLICABLE` buckets as satisfied. Same trade as the under-18 exemption, and the
stated reason travels with the row onto the compliance table and the printed file.

**The seed no longer retro-applies dependencies.** It used to rewrite `must_follow` on
rows it had just skipped, every time an admin re-applied the template — contradicting its
own docstring and, once the template named a gate, able to change a church's live
behaviour with one click. Dependencies are now wired at creation only, which makes the
order of `SEED_TEMPLATE` load-bearing (a prerequisite must precede its dependent) and is
asserted by `test_every_prerequisite_precedes_its_dependent_in_the_template`. The
consequence, stated plainly: **an existing church does not get the orientation → refresher
rule automatically.** Their admin sets it on the refresher's own page, deliberately —
which is right, because switching it on can put volunteers straight into overdue.

### 1.19 Deliberate omissions

Checked against Build Spec §0 ("DO NOT BUILD"). No code exists for: in-app forms or
e-signature; Markdown role-description editing, versioning or acknowledgement tracking;
volunteer or pastor logins; district rollups; SSO; SMS; BC-portal or PtP-training integrations;
billing; scheduling; disciplinary tracking.

Schema room was left for them without writing any of it: `Role.description` is plain text that
a future `RoleDescriptionVersion` can hang off; `Document` already models supersession;
`RequirementDefinition.is_seeded` distinguishes template items from a church's own; and the
`custom` requirement type plus the `applies_to` flags cover every item the policy review
deferred (renewal application form, child-welfare-check consent, Volunteer Driver Agreement,
Computer Policy Agreement, Offenders Covenant) without a code change.

---

## 2. Where the spec needed a correction to work

### 2.1 Static files must be built into the image

**Spec text:** §1 lists `collectstatic` nowhere explicitly; the obvious reading is to run it as
part of the deploy step.

**What happened:** `deploy_migrate` originally ran `collectstatic`, and the `migrate` service is
a one-shot container. It wrote `/app/staticfiles` into its own filesystem and exited. `web`
started with an empty directory, and `CompressedManifestStaticFilesStorage` raised
`Missing staticfiles manifest entry for 'css/vms.css'` on the first page render. Caught by
bringing the real stack up rather than by any unit test.

**Fix:** `collectstatic` runs in the `Dockerfile`, so the manifest is part of the build artifact
and every container has an identical copy. `deploy_migrate --collectstatic` remains as an
opt-in for bare-host installs.

### 2.2 The health check has to bypass tenant resolution

**Spec text:** §1 requires one exposed port behind Nginx Proxy Manager; a container health check
is the conventional companion.

**What happened:** `SHOW_PUBLIC_IF_NO_TENANT_FOUND = False` is correct — a stray DNS entry must
not reach the operator's console. But Docker's health check probes
`http://localhost:8000/healthz/` from inside the compose network, and `localhost` will never
have a `Domain` row. The probe 404'd, so a healthy container was reported unhealthy.

**Fix:** `apps/core/middleware.VMSTenantMiddleware` overrides `no_tenant_found` to answer the
health path on any hostname and to keep refusing everything else. `localhost` also has to be in
`ALLOWED_HOSTS`, since Django rejects an unlisted host before any middleware hook runs — noted
in `.env.example`. Locked in by `apps/core/tests/test_deployment.py`.

### 2.3 The "display the key once" step, precisely

**Spec text:** §6 — "generate the DEK and force a one-time key-backup step (display/download
once, require confirmation checkbox before proceeding)".

**Interpretation:** the raw key is never persisted, but the app holds `PLATFORM_MASTER_KEY` and
can therefore always unwrap it. "Once" cannot mean cryptographically once. What is implemented:

* At provisioning, the console shows the key once, passed via the session rather than the URL so
  it stays out of proxy logs and browser history, and popped on first render.
* The church's own admin is then held at `/key-backup/` by `ForceKeyBackupMiddleware` until they
  confirm — a checkbox *and* re-typing the last four characters of the key fingerprint, so the
  confirmation cannot be clicked through without looking at the key.
* After confirmation the key is no longer shown in the UI at all. Retrieving it takes
  `manage.py export_tenant_key --i-am-the-platform-operator`, which writes an entry into that
  church's own audit trail — so a church can see when its key was exported, and by whom.

### 2.4 `provision_church` normalises the short code

Mixed case is folded to lowercase rather than rejected. The code becomes both a Postgres schema
name and a DNS label, and both are effectively case-insensitive; refusing `FirstOAC` would be
pedantry. Everything else about the format is enforced strictly.

---

## 3. Bugs found and fixed during the build

Recorded because each was a real defect, not a style preference.

| Where | Defect | Fix |
|---|---|---|
| `apps/accounts/models.py` | `User.save()` recomputed `email_index` on *every* save. The index derivation mixes in the schema name, so a partial save (`update_fields=["last_login"]`) while bound to another schema would write an index from the wrong salt and make the account unfindable at sign-in. | Only recompute when `email` is actually being written. |
| `apps/org/views.py` | The volunteer list paginated a queryset whose `distinct()` had dropped the model's `Meta.ordering`, so a row could appear on two pages or none. | Explicit `order_by("last_name", "first_name", "pk")`. |
| `Dockerfile` / `deploy_migrate` | Static manifest missing in `web`. | See §2.1. |
| `apps/core/middleware.py` | Health check 404'd on internal hostnames. | See §2.2. |
| `apps/core/keys.py` | `schema_context()` binds a lightweight `FakeTenant` carrying only a schema name, so key lookup failed for management commands and Celery tasks. | Fall back to reading the wrapped key from the registry by schema name, with a per-process cache. |
| `apps/core/tests/base.py` | `FastTenantTestCase` shares one `Tenant` instance across a whole test class. A test that changed a church setting mutated it for every later test in that class, because the DB write rolled back but the in-memory attribute did not. Two test classes were silently reading the previous test's settings. | `refresh_from_db()` in `setUp`. |
| `apps/core/tests/test_dump_leakage.py` | The leak check initially passed vacuously: `pg_dump` opens its own connection and cannot see rows inside a test's open transaction, so the dump was empty. | Moved to `TransactionTestCase` with a really provisioned church, plus a guard test asserting the dump contains the seeded row. |
| `apps/core/audit.py` | **Pre-existing.** `audit.record()` writes `AuditEvent`, which is a tenant table — so any call from the `public` schema raised `UndefinedTable`. Reachable before shared hosting (a mistyped password on the operator's console 500'd) and unavoidable after it, since sign-in is handled in `public`. | Degrade to a log line outside a tenant schema. Console actions that belong to a church already switch into its schema first, so those still record properly. Covered by `AuditOutsideATenantTests`. |
| `apps/core/middleware.py` | A tenant cookie with a bad signature was ignored but never cleared, so the browser resent it on every request and each one logged a warning. | Drop the cookie whenever it is present but unusable — forged, tampered with, or naming a church that has been suspended or removed. |

---

## 4. Things worth knowing before changing this code

* **Encrypted fields are not queryable.** `filter(phone=...)`, ordering and `icontains` on any
  `Encrypted*Field` silently match nothing. If something needs to be searched it must be
  plaintext by design or get a blind index. `apps/core/tests/test_crypto.py` asserts this so it
  cannot be discovered the hard way.
* **The plaintext/encrypted split is a specification, not an implementation detail.** PRD §5
  draws it field by field, and `test_dump_leakage.py` tests *both* directions — encrypting
  names or requirement statuses to be "safer" would break the volunteer list and the compliance
  report, and that test will say so.
* **`ScreeningBlock.DISQUALIFIED` is terminal.** `Volunteer.set_screening_block` refuses to move
  off it, `record_discretionary_override` refuses to attach to it, no URL reverses to lifting it,
  and `RoleAssignment.clean()` blocks assignment to positions of trust. Tests in
  `apps/requirements/tests/test_crc.py` actively hunt for a way back; if a future change opens
  one, they fail.
* **Nothing volunteer-facing may be added casually.** `test_reminders.py` asserts a volunteer's
  address never appears in a digest recipient list.
* **`PLATFORM_MASTER_KEY` is not in the backup**, on purpose. `scripts/restore.sh` refuses to run
  without it, because a restore without the key produces a system that looks healthy until
  someone opens a volunteer's record.

---

## 5. Verification performed

Full detail in `docs/ACCEPTANCE.md`. Summary: 519 automated tests pass, and the Docker Compose
stack was brought up from a clean host, provisioned, backed up, destroyed and restored, with the
restored personal data confirmed readable and still ciphertext at rest.

Shared-hostname routing (§1.12) was additionally verified against the running stack: an address
belonging to a church resolves to that church's schema and issues a signed cookie for it, the
super-admin's address reaches the console with no cookie, and a wrong password produces the
same generic refusal as an address that exists nowhere.
