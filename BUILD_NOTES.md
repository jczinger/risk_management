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

### 1.20 Passkeys only, with an emailed link as the way in and back

**This departs from a fixed decision in the spec**, at the product owner's direction (29 July
2026). Build Spec §1 lists auth as "Passkeys (WebAuthn) primary; password (Argon2) + TOTP
fallback"; PRD §6 repeats it; Build Spec §10 has it as an acceptance criterion. All three are
annotated to point here rather than rewritten, and `docs/ACCEPTANCE.md` §2 is marked superseded
rather than deleted, so the change is visible as a change.

What replaced it:

* A passkey is the only way to sign in.
* A **single-use link** covers the two moments a passkey does not exist yet — the first sign-in
  after an account is created, and recovery after a lost passkey or a replaced device.
* Enrolment is compulsory: `ForcePasskeyMiddleware` holds an account with no passkey at the
  enrolment page until it has one.

Password and TOTP were **removed, not disabled**: `totp.py` and `tenant_login.py` deleted, the
views, forms, URLs, templates and settings with them, and `pyotp`, `qrcode` and `argon2-cffi`
dropped from requirements. A disabled code path is one someone re-enables by accident.

**Why the link carries its schema, signed.** Sign-in happens in `public`, before anything knows
which church the visitor belongs to. A passkey has no choice but to scan every schema for its
credential id (`find_passkey_target`), but a link is *issued* by us, so the answer is known at
that moment and travels in the payload. It is signed for the same reason the tenant cookie is:
consuming a link calls `bind_tenant()` on that schema name, and nothing attacker-chosen may reach
that call.

**Why the expiry is recorded twice.** `signing.loads(max_age=...)` enforces one, and
`LoginLink.expires_at` the other. The signer necessarily gets the *invite* window even for a
recovery link, because the purpose sits inside the payload and cannot be read until the signature
has already been checked — so a recovery link inside its seven days but past its thirty minutes is
caught only by the row. Both guards are load-bearing; there is a test for each.

**Why enrolment is a middleware.** A redirect out of the link view would be escaped by typing any
other URL, and by then the link is spent. It is ordered *before* `ForceKeyBackupMiddleware`: a new
church's first admin trips both on the same request, and the passkey has to come first.

**A defect this nearly shipped with.** The passwordless migration wants to blank every stored
hash, and the obvious way to write that is
`User.objects.all().update(password=make_password(None))` — which writes **one** generated value
to every row. Django derives a session's `_auth_user_hash` from that column, and the session table
is shared across schemas (`django.contrib.sessions` is in SHARED_APPS only, so there is one
`django_session` in `public`). Identical passwords mean identical session hashes, and a session
for user 5 at one church would then validate as user 5 at another — precisely the hole the signed
tenant cookie exists not to open. The migration therefore updates row by row, and
`PasswordRemovalTests.test_the_migration_gives_every_row_a_distinct_marker` calls the migration
function directly and fails if it is ever shortened. Chasing this also turned up that
`apps/tenants/routing.py` had been explaining the isolation guarantee incorrectly — it claimed
sessions live in each church's schema, which they do not. That docstring and `docs/SECURITY.md`
now describe what actually enforces it.

**The accepted cost.** Whoever controls an administrator's mailbox controls the account. There is
no password to also need and no second factor to also hold. That is inherent in what was asked
for and is the usual arrangement for products of this kind, but it is a real reduction from "a
stolen password is useless without a TOTP device". Three things bound it: a recovery link lives
thirty minutes and works once; using one is written to the audit trail as its own action; and
using one emails **every other administrator at that church**. Nothing here can stop a mailbox
takeover — being noticed the same morning is the realistic defence, which is why the notification
is not optional.

**Links are shown on screen as well as emailed**, wherever an account is created. Not merely
because email is not configured yet: a church may want to hand one over in person, and an invite
that silently fails to arrive is worse than one the sender can see. `manage.py issue_magic_link`
is the operator's break-glass, and needs shell access to the host — a stronger control than the
password it replaces.

**Rate limits changed.** The WebAuthn endpoints had none, which was defensible while a
rate-limited password form stood beside them. They are now the only interactive way in, and a
`finish` call with an unknown credential costs a scan across every schema, so both halves are
metered per IP. The recovery form is metered more tightly still — per address *and* per IP —
because each request that lands sends real mail to a real person. The rates are read through a
callable rather than `rate=settings.X`, which freezes at import and quietly defeats both
`override_settings` and any retune without a restart.

---

### 1.21 Access levels, and a review step for the work done under them

**This departs from a positive statement in the spec**, at the product owner's direction (29
July 2026). Build Spec §2 says "Tenant users: screening admins only. Multiple per church. All
have equal permissions within their church," and the PRD, the README and OPERATIONS.md all
repeat it. That is now the description of a **Primary Admin**; a church can also create
limited access levels, and the first of them — **Department Admin** — sees only the volunteers
who have served in the departments it is given.

Nothing here touches the DO NOT BUILD list. That list forbids SSO, volunteer and pastor
logins, district rollups, SMS, billing and scheduling. Differentiated permissions *among
screening admins* is none of those; what it does contradict is a design statement, which is
why it is recorded here in full rather than buried in a commit.

**Named "access level", not "role."** `org.Role` already means a ministry position — Sunday
School Teacher, Nursery Helper — and the two sit next to each other on the same screens. A
church reading "role" in the Administrators section would reasonably think of the other kind.

**Capabilities are columns, not `auth.Permission` and not JSON.** `django.contrib.auth` is in
both SHARED_APPS and TENANT_APPS, so `auth_permission` exists twice per database and
`user.has_perm()` answers a different question depending on which schema is bound — two
sources of truth for one question, which is not a foundation for authorisation. Django's
permissions are also per-model CRUD, where `record_screening` spans five models and one
product idea. Columns get `help_text`, which is where a church reads what a capability does
*not* include, and they are filterable, which both the escalation rule and the lockout guard
need. The cost is that the set is closed and a church cannot invent one; that is the right
trade, because a capability with no code enforcing it is a lie.

**The scope link lives on the tenant side, and not as a foreign key to `User`.** Two separate
findings, both discovered the hard way:

* `apps.accounts` is in both app lists, so its migrations run against `public` too, where
  `org_department` does not exist. A `ManyToManyField` from `accounts.User` to
  `org.Department` would therefore try to create a join table in `public` referencing a
  missing table, and `deploy_migrate`'s first step would fail on every deploy.
* A *foreign key* from a tenant-only model to `accounts.User` creates cleanly — the constraint
  is built under `search_path = "<tenant>", public` — but it gives `User` a reverse accessor,
  and that accessor exists in every schema including `public`, where the table does not. So
  Django's cascade collector walks it on any `User.delete()` in the public schema and raises
  `UndefinedTable`. Found by the console tests' teardown. `UserAccessGrant.user_id` is a plain
  unique integer, which is the deeper reason the rest of this codebase denormalises its user
  references rather than pointing a foreign key at `User` from a tenant app.

**`is_scoped` is an explicit flag, not "has departments".** Deriving it gets the dangerous
case backwards: a Primary Admin with no departments must be *unscoped*, and a half-finished
Department Admin with no departments must see **nothing**. `None` and `frozenset()` are
different answers throughout `apps/core/access.py` for the same reason.

**Out of scope is 404; a missing capability is 403.** A 403 on `/org/volunteers/412/` would
confirm that this church has a volunteer with that id and that they are in some *other*
department — walked over the id range, a membership list, including which ids are minors.
This system encrypts addresses and medical notes precisely to avoid that class of exposure.
Scope is therefore enforced by narrowing the queryset `get_object_or_404` reads, never by a
check afterwards: it is one line with the same control flow, and a separate `if` is a second
statement that can be forgotten independently of the first — which fails *open*.

**Default deny is enforced twice, on purpose.** The failure mode is a future view written the
way all sixty used to be — `@login_required` and nothing else — which works for everybody,
errors nowhere, and has no test to fail because nobody thought about it. `AccessGateMiddleware`
refuses any view that declared nothing, and a test walks the URLconf and names the offending
view at review time. The middleware is the guarantee; the test is the fast feedback. Their
weaknesses do not overlap: the middleware covers views the test cannot see, and the test
catches somebody quietly adding a path to the middleware's exemption list.

**"Ever held a role" is monotonic, and that is intended.** A department admin keeps access to
files they worked on after the volunteer stops serving, because records involving minors are
retained permanently and somebody may have to answer a question about a past volunteer years
later. The consequence is that scope only ever grows: assigning a volunteer adds them
permanently, and ending the assignment does not take it away. Stated here rather than left to
be discovered.

**The escalation rule has two homes, and an earlier draft claimed three.** The form's
narrowed querysets are the control for the HTTP path — a `ModelChoiceField` validates a
submitted primary key against its own queryset, so a hand-crafted POST is already refused —
and `apply_grant` is the control for anything that never builds a form. A third check inside
`AccessGrantForm.clean()` was written, found to be unreachable, and removed. Verified by
neutering each surviving layer and confirming it fails its own two tests and nothing else.

**The audit trail cannot be scoped, so a limited level cannot have it.** `AuditEvent` records
no department and cannot be given one: its pointer to the affected row is a pair of strings,
deliberately, because ContentType ids are not tenant-stable. A partial filter on
`entity_type="Volunteer"` would be *worse* than refusing — it would look scoped while missing
every requirement, document and criminal-record-check entry about the same person. So
`AccessLevel.clean()` refuses the combination outright, and `scope_audit_events` — wired
into both audit views (2026-08-02, with a test that forges the forbidden row past
validation) — returning nothing is the second layer.

**Aggregates leak too.** `dashboard_headline`'s `blocked` and `minors` counts, the
per-department summary, and the department and role dropdowns name nobody, so none of them
would fail a "can they open volunteer X?" test — while between them describing the shape of
the whole church. All are scoped, and the dropdowns matter even where the results would be
empty anyway, because an unscoped dropdown is the org chart with no view attached to it.

#### The review step

Everything a Department Admin records is affirmed by a Primary Admin: requirement
completions, recorded documents, criminal record checks, and waivers and overrides.

**A pending entry counts as compliant immediately.** The owner's decision, chosen over
holding it as outstanding. The honest cost is that a report can read "compliant" on evidence
nobody has confirmed, which is why the backlog is surfaced in four places — a dashboard tile,
the queue, a note on the compliance report, and a line in the nightly digest — and why
anything unreviewed past 30 days is called out as stale rather than merely counted.

**One recorded action, one queue row.** Recording a document completes the requirement it
backs, which is two writes. Two rows would mean two clicks and would let the pair be affirmed
separately, which is the "file disagrees with itself" failure §1.15 exists to close. So
`mark_requirement_complete` grew `open_review=False` for the document path, and the document's
own item points at the requirement as well.

**A criminal-record-check send-back is a retraction, never a reversal — and the
disqualification is not reversible at all.** Every door is already bolted elsewhere by design:
`set_screening_block` refuses to move off `DISQUALIFIED`, `DisqualifyingConviction.delete()`
raises, `DiscretionaryOverride.save()` raises on a second write, and `RoleAssignment.end()`
has no inverse. So a *clearance* can be retracted when the check is current and carries no
convictions and no overrides — the wrong-volunteer correction — and nothing else can.

The owner was asked about this specifically and chose to let a Department Admin record a
disqualifying conviction, reviewed like the rest. It was recommended that the step be reserved
to a Primary Admin, on the grounds that affirmation cannot be honoured for an act with no
route back. The owner's decision stands; what the code does instead is refuse to pretend. The
send-back form lists what will not be undone **before** the click, names the role assignments
the decision ended, and the outcome says plainly that it recorded a dispute rather than
reversing anything.

**The nightly digest goes to unscoped administrators only.** This was a leak, not a
preference. The digest is one shared body built from a church-wide query, so left alone it
would have mailed every department admin a list naming every volunteer at the church with
anything overdue — through the new boundary, invisible in the UI, and permanent in `EmailLog`.
The owner chose this over per-admin scoped digests, which would have required the reminder
de-duplication key to gain the recipient: without that, a volunteer serving in two departments
is claimed once and silently reported to only one of the two admins who needed to know, which
is a subtle wrong answer in place of a plain absence.

**The thread-local labels; it never authorises.** `Actor` grew an `access_level` so a service
function can tell whether its work needs affirming without growing a `user` parameter, and
`apps/core/audit.py`'s existing statement — that the thread-local is "deliberately *not*
relied upon for correctness of authorisation" — stays true. `Actor.system()` carries no access
level, so the nightly sweep, the seeders and every management command queue nothing; that is
only *safe* because no reviewed writer is reachable from the sweep, which a test asserts
rather than assumes.

**The backfill is a migration, not a management command.** `has_capability` fails closed, so
between `migrate` finishing and a command being run by hand, every administrator at every
church would be locked out of everything — including the screen needed to fix it. Only a
migration guarantees the ordering. It also seeds both built-in levels rather than only the one
being granted, so a church that already exists comes out of the deploy with somewhere to put a
department admin instead of needing an operator first.

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

Full detail in `docs/ACCEPTANCE.md`. Summary: 545 automated tests pass, and the Docker Compose
stack was brought up from a clean host, provisioned, backed up, destroyed and restored, with the
restored personal data confirmed readable and still ciphertext at rest.

Shared-hostname routing (§1.12) was additionally verified against the running stack: an address
belonging to a church resolves to that church's schema and issues a signed cookie for it, the
super-admin's address reaches the console with no cookie, and a wrong password produces the
same generic refusal as an address that exists nowhere.

---

## 1.22 Administrators are volunteers too, and nobody screens themselves

**A gap, not a decision.** With `edit_volunteers`, `record_screening` and `record_crc`, an
administrator could create a volunteer record for themselves, assign themselves a ministry role,
tick their own Plan to Protect training, and record their own criminal record check as clear.
Nothing refused it, because nothing *knew* it was them: `accounts.User` and `org.Volunteer` had no
link of any kind — no foreign key, no integer pointer, and the string "user" did not occur
anywhere in `apps/org/models.py`. Plan to Protect presumes the screener and the screened are two
different people; the data model had no way to say so. §1.21, `docs/SECURITY.md`, the PRD and
`docs/ACCEPTANCE.md` were all silent on it. The owner found the same hole from the other side —
"an administrator should also be a volunteer" — and linking the records is what made the refusal
expressible, so both landed together (2 August 2026).

**The link is an integer, and that is a scar rather than a style.** `Volunteer.user_id` is an
`IntegerField(null=True, unique=True)`, not a `OneToOneField` to `User`, for exactly the reason
`UserAccessGrant.user_id` is. A relation gives `User` a reverse accessor, and that accessor is a
Python-level fact present in every schema — including `public`, where `org_volunteer` does not
exist. Django's cascade collector walks it on `User.delete()` and the delete dies with
`UndefinedTable` in code that has nothing to do with volunteers. It cost 74 failing tests to learn
the first time. `unique` with `null=True` is exactly the constraint wanted: Postgres permits many
NULLs in a unique index, so the column reads "at most one file per administrator, and most files
belong to nobody".

**The rule, and its one escape hatch.** `may_record_against` deliberately mirrors
`may_review` down to the shape of the exception, so a church learns one rule rather than two:

* Not their own file — allowed. The overwhelmingly common answer.
* Their own file, on a **limited** level — refused, always. Somebody with access to the whole
  church exists by construction, or that admin could not have been created.
* Their own file, seeing the **whole church** — refused while another such administrator exists;
  allowed when they are the last one. Refusing outright would leave a single-administrator church
  unable to complete its own file inside VMS at all, which only moves that screening onto paper
  where nothing tracks it. The audit summary records which of the two happened.

Reading is untouched throughout. Hiding somebody's own screening status from them would teach
them to keep a second copy on a spreadsheet, which is worse than showing it.

**403, not 404** — the opposite of the out-of-scope rule, and on purpose. Out of scope hides the
record because confirming it exists is itself the leak. Here they can already see the file;
pretending it had vanished would be a lie, and this refusal is one the person needs explained.

**Two layers, weaknesses disjoint.** Writable twins of the scoped fetch helpers
(`_writable_volunteer_or_404` and friends) are the control — a view cannot take the record without
also taking the check. A URL-walking test is the fast feedback, and is what catches a write view
added next year. The five screening writers additionally check the ambient actor's `user_id`, the
posture `RoleAssignment.clean()` already takes: a rule enforced only at the edge is a rule with an
inside. Every way that check can fail to identify somebody fails safe — `Actor.system()` carries
no user id and matches no file, and an actor whose access level cannot be resolved is treated as
limited.

`apps/core/audit.py`'s "the thread-local never authorises" is narrowed rather than contradicted:
two facts carried there are read for correctness — who the person is, and whether their level is
scoped — and neither is a question about what they are *permitted* to do.

**The record appears on its own, and VMS refuses to guess whose it is.** A new administrator gets
a volunteer file from their name and address at the moment their account is made, with **no**
ministry role. That leaves it invisible to every limited access level, including their own,
because scope runs through role assignments; a Primary Admin completes it. Intended, and stated
here so it is not discovered.

Where a volunteer already exists under that name, **nothing is created**. Two people genuinely can
share a name, and silently attaching an administrator to somebody else's screening record — or
silently merging two — has no undo, and VMS has no merge tool. The administrators list surfaces
the collision with an explicit link-or-create choice. `admin_invite` is now atomic, which it never
was: it could already strand a `User` with no access level, and a third write made that worth
fixing rather than documenting.

**Linking is not a back door.** The link is what makes the rule enforceable, so freedom to
re-point your own link would be a way straight out of it — aim it at a stranger's file and your
own becomes fair game. Choosing your own file is refused while another church-wide administrator
exists, and there is deliberately **no unlink**: detaching is the same escape by another name.

**The backfill is a management command, and that is the inverse of §1.21's.** That one had to be a
migration, because `has_capability` fails closed and any gap between `migrate` and the backfill
would have locked every administrator at every church out of everything. Nothing here is like
that: a missing volunteer record locks nobody out, and a migration would have to write
`Volunteer.email`, which is encrypted — needing the tenant data key that
`UserManager.use_in_migrations = False` exists to keep out of migrations.

**Refusing to make a disqualified volunteer an administrator** was not asked for. Somebody barred
from every position of trust under the policy should not be administering the screening of
others. Stated in the refusal rather than hidden by omitting the button.

### Four gaps found while doing it

Each was verified in the source before being reported, and each has a test named for what it
actually allowed.

**The encryption key download was wide open.** `key_backup_download` carried
`@open_to_any_signed_in_user`, so any signed-in administrator — including one on a limited level
holding not a single capability — could GET it at any time, long after the backup step was
finished, and receive the key that decrypts every volunteer record at the church. Its sibling
`key_backup` at least redirected away once the church had confirmed; this had no state check at
all. Worse, it wrote **no audit entry**, so `docs/SECURITY.md`'s promise that "every key export
writes an entry into that church's own audit trail" was true of the operator console's export and
not of this one: a church could have been drained and their own trail would show nothing.

The page stays open to anyone signed in — `ForceKeyBackupMiddleware` traps everybody there, and
somebody stuck on it needs to be told what is happening rather than shown a wall — but the key,
the download and the confirmation are all now behind `manage_users`. The confirmation especially:
it is a compliance record, the form only checks a fingerprint printed on the page, and somebody
who was never shown the key cannot truthfully make it.

**Custom access levels skipped review entirely.** `Actor.needs_review` compared the level's slug
against `"department-admin"` exactly. A church building its own limited level on the access-level
screen — which the form exposes `is_scoped` precisely to allow — produced work that never entered
the review queue, while `may_review` still refused that person as a reviewer: a limited admin
reviewed by nobody, reviewing nobody, silently. This holed §1.21's central feature one day after
it shipped. The gate now reads `is_scoped`, the same flag `may_review` reads, so "a scoped admin's
work needs affirming" and "only an unscoped admin may affirm" are two readings of one fact rather
than two facts that can drift.

**The review gate failed open on error.** `_access_context` swallowed any failure resolving the
grant and returned blanks — which meant *not scoped*, which meant no review item. One transient
database error and a limited admin's entry was recorded as though somebody with church-wide
responsibility had done it. `apps/review/recording.py` deliberately raises on the same class of
problem, for the reason written in its own docstring: a missing review item reads as "somebody
checked this". The two modules now agree. The tolerance stays — this runs on every request,
including sign-in — but failure sets `access_level_unknown`, and an actor with an unknown level
and a person behind it needs review. A spurious item is one click; a missing one is permanent.

**Self-affirmation could be unlocked on purpose.** `may_review` allows self-affirmation when
nobody else could do it, for the church whose last other reviewer left. That condition is
mutable: an administrator sitting on a pile of their own unaffirmed entries could deactivate the
only other church-wide administrator and wave the lot through. The existing guards did not cover
it — `_would_strand_the_church` asks who can manage access, which is a different set of people.
Deactivation is now refused while the actor holds pending entries of their own and the subject is
the last other reviewer. Work recorded *after* a church genuinely becomes single-administrator is
untouched, because that is the case the hatch exists for.

### Also corrected in passing

`templates/accounts/admin_invite.html` still told the inviter "they will have the same access you
do" — written before access levels and left contradicting the form directly beneath it, which asks
you to choose one.

`test_ciphertext_does_not_contain_plaintext` looked for the two characters `"42"` in roughly sixty
characters of base64. That collides about one run in seventy, so the suite failed at random and
blamed the crypto. The marker is now eight characters.

## 1.23 A simplification pass, and what it changed on purpose (2026-08-02)

A codebase-wide simplification review removed dead code, deduplicated copy-paste, and
reshaped self-defeating queries. Most of it changes nothing observable; four items
changed posture deliberately, each approved by the owner:

- **`scope_audit_events` is now actually wired in.** §1.21 described it as the second
  scoping layer behind `AccessLevel.clean()`, but nothing called it — the audit views
  now do, and a test forges the forbidden scoped-level-with-`view_audit` row past
  validation to prove the views answer with nothing.
- **`User.can_remove_last_passkey` is gone.** It was hardcoded `True` (the emailed
  link is always the way back in, §1.20), which made the lockout guard in
  `remove_passkey` unreachable — and that guard's error text still described the
  removed password+TOTP fallback. Removing your last passkey is allowed, by design.
- **`Passkey.transports` and `Passkey.is_discoverable` were dropped** (migration
  `accounts.0003`). Written at registration, read by nothing, ever.
- **`AccessGateMiddleware` lost its path-exemption list.** `/healthz/` passes the
  gate the same way every public page does — the `public_view` decorator on the view —
  and static files are answered by WhiteNoise before `process_view` runs. The
  health-path carve-out in `no_tenant_found` (§2.2) now calls the `healthz` view
  rather than duplicating its body.

Two real bugs were fixed in the same pass: the volunteer list's pager links replaced
the whole querystring, silently dropping active filters (now carried, with a
regression test); and the printed volunteer file omitted the "waived by" note on
recurring requirements — both row loops now render through one shared partial, so a
waived recurring requirement reads the same as a waived onboarding one.
