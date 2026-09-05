# Xero Ledger Airlock

**Xero validates the write. It does not validate that the write is still the one
you approved.**

Between reviewing a batch and it committing, a payment can land, an invoice can
be recoded, a period can close. The resulting write is still legal, so nothing in
Xero stops it. This module refuses it.

13 commands across invoices, payments, the chart of accounts and overdue-invoice
chasing. Every write is held behind RailCall's approval airlock and sealed into a
signed receipt.

**What it does not claim:** Xero refuses a void on a paid invoice, and an
overpayment, by itself. There this module is defence in depth — it refuses at
plan time. Each command says so in its output.

## Install

```bash
railcall market install shweta/xero-ledger
```

## Credentials

Create a **Web app** at https://developer.xero.com/app/manage and tick these
scopes on its Configuration page. The coarse names most tutorials use
(`accounting.transactions`) are rejected outright; that page is authoritative,
not the docs:

```
offline_access  accounting.settings  accounting.contacts
accounting.invoices  accounting.payments
```

Complete the OAuth consent once, then in Studio → Integrations add a
**xero-accounting** credential with `client_id`, `client_secret`,
`refresh_token`, and `tenant_id` (from `GET https://api.xero.com/connections`).

Run `verify_connection` to confirm. It reports what the token can read, live rate
quota, and whether the configured tenant matches — a mismatch would put writes in
the wrong org.

**Where the refresh token lives.** Xero rotates it on every use. RailCall's vault
is written only by an operator-approved save, so it cannot hold a self-changing
value; the rotating half is stored by this module in
`.railcall_workspace/xero_ledger_token.json`, mode 0600, never transmitted.

## Worked example

```
plan_invoice_post {"status": "DRAFT"}
  -> plan_fp 9f2c…   count 12   total 14203.50

apply_invoice_post {"plan_path": "…a1b2c3.json", "plan_fp": "9f2c…"}
  -> committed 0   failed 0   refused 12
     drift [{"invoice": "INV-0041", "reason": "AmountPaid 0.00 -> 250.00"}]
```

A payment landed while the batch sat in review. The post would still have been a
legal write. It was not the write you approved.

**`plan_fp` is required, not decorative.** A RailCall approval binds
`sha256(command_id + inputs)`. If apply took only a path, the approval would bind
a *filename*, and two different plan bodies at that path would be
indistinguishable in the receipt. The fingerprint puts plan **content** inside
the approved hash.

See `COMMANDS.md` for every command's inputs, output and limits.

## Dunning (v0.1.2)

Chasing an overdue invoice is a sequence, not an event. `plan_send_reminder` and
`apply_send_reminder` walk a configurable ladder — 7, 21, 45 days overdue by
default — and `list_contacts` supplies the recipient addresses, which are never
present on an invoice payload.

**Xero applies no deduplication to invoice emails.** Probed live: five sends of
one invoice produced five deliveries, five HTTP 204s and no warning. That is the
opposite of Xero's `Idempotency-Key` behaviour on invoice POST, so the
platform-wide assumption does not carry over — and `SentToContact` is a latch,
set once and never cleared, which cannot say *which* stage was sent.

So `xero_ledger_dunning_state.json` is the only thing standing between a re-run
and a customer receiving the same reminder twice. It is a hash-chained,
append-only event log, verified by `verify_ledger` alongside the write ledger,
and the duplicate check runs **twice** — at plan time so nobody approves a
duplicate, and again at apply time against freshly-read state, because approvals
have no expiry and a sibling run may have sent it in between.

**Three rules refuse at plan time**, each probed against the live API rather than
taken from documentation:

| Condition | What Xero does at send time |
|---|---|
| Contact has no email address | `HTTP 400` — *"Invoices for contacts with no email address assigned cannot be emailed"* |
| Invoice is DRAFT, VOIDED or DELETED | `HTTP 400` — *"Draft, voided or deleted invoices cannot be emailed"* |
| Stage already sent | Nothing. Xero sends it again. |

The third has no API-side guard at all, which is exactly why it is ours.

**One rung per run.** An invoice forty days overdue that has had nothing sent is
owed stage 7 — not stage 21, and never both in the same run. A workflow that has
not run for a fortnight therefore catches up one reminder at a time; two emails
in one day to somebody who heard nothing for two weeks reads as a malfunction.

**A part-payment holds the current stage for one cycle without resetting the
ladder.** Somebody paying part of an invoice is engaging with it, and chasing
them the next day punishes that. This is a business judgement rather than a
technical one, so the command states it in its own output instead of leaving an
operator to infer it. A *fully* paid invoice leaves the chain immediately, before
any stage arithmetic runs.

**A contact with no first name is refused by default.** Confirmed by reading
delivered mail: `FirstName = "Ayesha"` arrived as *"Hi Ayesha,"*, and two
contacts with no personal name both arrived as *"Hi ,"*. Xero greets by
`Contact.FirstName` and does not fall back to the company name. A contact
person's name is **not** counted — whether Xero falls back to one is unverified,
and accepting it would let a broken greeting through. Xero sends that happily —
it is not an API refusal, it is a quality one, and it is as unrecallable as any
other send. `allow_empty_greeting=true` overrides it. That override is an
**input**, so the decision to send a nameless greeting travels through the
approval hash and onto the receipt, rather than happening by accident.

**What is ours and what is not.** The email *wrapper* is Xero's — subject,
greeting and layout. The subject is fixed as
`Invoice #<number> from <org> is due`. The sender is
`messaging-service@post.xero.com` displayed under **the authorising Xero user's
name, not the organisation's** — so whoever's credential the module runs on is
the name a customer sees. The invoice **line descriptions do reach
the customer**, so the content of what they read about is ours even though the
envelope is not. That is the seam this module works along.

**What this does not do:** it cannot change the words. The message body is
Xero's own standard invoice template — probed live, the endpoint accepts and
discards any custom subject or body. This governs **when** a customer is chased,
how often, and when it stops being a reminder. It does not write the letter.

## Bugs this module found in itself

Five came from running v0.1 through the real airlock against a real Xero org;
none was reachable from a unit test. Nine more came from building v0.1.2 — two caught by tests written
to prove the opposite, three by sweeping for the class the first one revealed,
one only by driving the real airlock, and two by writing coverage for inputs no
test had ever supplied. All are covered now.

**A diagnostic field named `token` was destroyed in every receipt.**
`verify_connection` reported refresh-token rotation counts under a field called
`token`. The airlock's `redact()` masks by field *name* against `SECRET_HINT`, so
the block came back as `••••••` — the content held no secret, the name was the
bug. Renamed to `credential_state`.
`t_no_output_field_name_trips_the_airlock_redactor` mirrors `SECRET_HINT` and
fails if any output key would be masked.

**`plan_invoice_void` reported DRAFT invoices as voidable, and they are not.**
Xero *deletes* a draft and *voids* an authorised invoice; posting `VOIDED` to a
draft is refused with *"Invoice not of valid status for modification"*. The plan
said `voidable: True` for two drafts and the apply then failed on every row.
This is the serious one: a plan that promises a write the API will refuse spends
a human approval on something that could never land. The plan was the thing
lying — which is what this module exists to prevent, one level up.
`t_only_authorised_invoices_are_voidable` fails if a draft is ever reported
voidable again.

**Every drift refusal falsely claimed line items had been recoded.**
`line_fp()` hashes four fields including `LineItemID`; it was compared against a
three-field rebuild of the operator-facing display copy, which can never match.
The refusals were correct, the reasons were not. On a command whose whole value
is naming what moved, an invented reason is worse than a vague one.
`t_drift_reasons_do_not_fabricate_line_item_changes` asserts a payment-only
change reports only the payment.

**A lock date was destroyed on the way into the receipt.** `describe_org`
returned `PeriodLockDate` inline as `/Date(1222732800000+0000)/`. The airlock's
*identifier* scrubber reads the long digit run as an account number and rewrote
it to `/Date([account]+0000)/`, so the field an operator reads was destroyed
while the artifact kept the truth. Same class as the `token` field above,
different scrubber: that one masks by field **name**, this one by value
**shape** — renaming cannot fix a shape problem, so the value moved to the file
and the receipt now carries a verdict, `period_lock: "set" | "(none)"`. That is
the module's own file-vs-inline rule, which it was breaking.
`t_no_raw_xero_date_is_returned_inline` fails if any inline value ever looks
like a Xero date again.

**v0.1.2: the approved dunning stage was recorded but not bound.** The stage was
written into each plan entry with a comment claiming `plan_fp` therefore covered
it. It did not: `plan_fp_of` hashes only each entry's `fp` field, so the stage
could be edited from 7 to 45 after approval and the seal still validated — an
operator approving a gentle first nudge while a final notice went out. Found by
the test written to prove the opposite. The stage is now sealed through
`action_fp`, which `plan_fp_of` does hash, and apply recomputes it from the
declared stage so the two cannot drift apart. Entries without an `action_fp`
fingerprint exactly as before, so plans written by an earlier version still
verify. `t_the_approved_stage_is_bound_not_just_recorded` closes both tamper
routes; `t_a_plan_without_action_fp_still_fingerprints_as_before` guards the
compatibility.

**v0.1.2: a numeric input of zero was silently replaced by the default.**
`int(inputs.get("x") or default)` treats `0` as absent, because `0` is falsy.
So `overdue_days: 0` — "everything due today or later" — quietly became `1`,
and `max_findings: 0` became `1000`. The command did something other than what
was asked and said nothing about it: the quiet half of the same family as the
boolean bug, where an input is accepted and then ignored. Seven numeric inputs
were affected. All now go through `_as_int`, where only `None` and `""` mean
"not supplied". `t_a_numeric_input_of_zero_is_not_swallowed` and
`t_overdue_days_zero_is_honoured_not_replaced_by_the_default` cover it.

Found by writing coverage for inputs no test had ever supplied — which is the
real lesson. **Twelve declared inputs had never been set by any test**, so their
behaviour was unverified until a buyer set one. `allow_empty_greeting` was
simply the first to be caught, and only because a Studio run happened to use it.
`t_every_declared_input_is_exercised_somewhere_in_this_suite` now fails if a
declared input goes untested, and
`t_every_declared_input_is_actually_settable` pushes a well-formed value of each
declared type through a mirror of the airlock's own validator.

**v0.1.2: a boolean input was unusable, and the manifest looked fine.** The
Studio `approve` call rejected `allow_empty_greeting` with *"wrong type for
'allow_empty_greeting' (want boolean)"*. The airlock's validator knows `array`,
`string`, `number` and `object` — there is no `boolean` branch and no `integer`
branch — so a field declared as either is refused the moment a value is
supplied, while passing every lint and working fine as long as nobody sets it.
Both flags here are now declared with no type, and coerced through `_as_bool`
rather than a bare `bool()`, because a typeless field gets no validation at all
and `bool("false")` is `True` — which would silently invert an operator on the
one flag that gates a customer-facing send.
`t_no_input_type_the_airlock_cannot_validate` mirrors the platform's type list
and goes red if a manifest ever declares one outside it.

**v0.1.2: the payment amount was never inside the approval.** Found by sweeping
every plan field read at apply time, after the stage bug above showed the class
existed. `plan_fp` hashes each entry's `fp`, which is the *invoice's* state — so
`allocate_amount`, `allocate_date` and the plan-level `account_id` all sat
outside it while `apply_payment_allocate` read them straight from the file. A
sealed, validly-approved plan could be edited to move a different sum to a
different bank account, and the receipt would still verify. This is the same
defect as the stage bug on the one write in the module that moves money, and it
was live on the marketplace in v0.1.1. All three are now bound through
`action_fp`. `t_the_payment_amount_is_bound_to_the_approval`,
`t_the_destination_account_is_bound_to_the_approval` and
`t_the_payment_date_is_bound_to_the_approval` each fail if a binding is dropped.

**v0.1.2: the voidability verdict was a control, not a display field.**
`_void_guard` refuses at apply time on each entry's `blocked_because`, so
emptying that list on a sealed plan turned *"this invoice cannot be voided"* into
*"go ahead"* with the approval still valid. Xero independently refuses a void on
a paid invoice, but a period-lock or credit-note block was ours alone. Bound.

**v0.1.2: `plan_fp` was destroyed in roughly one receipt in twenty.** It is
returned inline as a bare 64-character hex digest, and the airlock's identifier
scrubber rewrites any run of 13+ digits to `[account]` — so the value an operator
copies into the apply command was being mangled at random, on all five plan
commands. Now grouped in eights, which caps the longest possible digit run at
eight; `load_plan` accepts either form.
`t_no_inline_fingerprint_can_trip_the_digit_scrubber` checks 200 digests rather
than trusting one lucky sample.

**v0.1.2: a fully paid invoice was classified as a part-payment.** The
part-payment hold was evaluated before the paid check, so an invoice settled in
full matched "paid more than at the last contact" and was held for a cycle —
kept inside the chain instead of released from it. Chasing somebody who has
already paid is the failure that destroys trust in the whole thing, so the paid
exit now runs first, before any stage arithmetic can reclassify it.
`t_a_paid_invoice_is_never_chased` fails if the order is swapped back.

**v0.1.2: a test passed for the wrong reason.** The check that no idempotency key
is sent on the email endpoint searched the whole function body for
`Idempotency-Key` — and matched the comment explaining why none is sent. It now
asserts on the API call itself.

**A spec correction.** `apply_invoice_post` failures read *"The document DueDate
field must be specified."* Xero validates required fields at the status
transition, so an invoice with no `DueDate` is a legal DRAFT and an illegal
AUTHORISED. The earlier probe conclusion — that a partial POST does not blank
unsent fields — was right but incomplete: a minimum body is not always
sufficient. Recorded in `COMMANDS.md`.

## Trust surface

Two things in the source that look like shortcuts and are not.

**The rotated refresh token is written to
`.railcall_workspace/xero_ledger_token.json`, not to the vault.** Xero rotates
its refresh token on every refresh and invalidates the previous one. The
platform's `oauth_refresh` helper explicitly never overwrites `refresh_token`,
which is correct for providers whose token is static, and no vault write helper
is injected into a handler's namespace — so a module handling a rotating
credential has nowhere else to put it. The file is 0600, on the same machine,
never transmitted; the vault keeps the credential you pasted. This is reported to
RailCall and the fix is small, so the arrangement is expected to be temporary.

**The token endpoint is called with raw `urllib`, not the injected
`http_post_form`.** That helper raises `RuntimeError` on any 4xx with the
response body flattened and truncated into the message string. `invalid_grant` —
the most important failure this module has — is a 400. Going through the helper
would mean substring-matching an exception message, which breaks the first time
Xero rewords anything. Raw `urllib` lets the handler read the JSON error body and
dispatch on the machine-readable `error` field.

## Limits

Drift detection is deliberately over-sensitive: a change to a field these
commands do not read still moves `UpdatedDateUTC` and still refuses, and it
cannot say which field moved. The local ledger is tamper-evident, not
tamper-proof — it detects edits and mid-chain deletion, not tail truncation.
Sales invoices (ACCREC) only in v0.1; bills, credit notes and bank transactions
are not covered and are not reported as clean. A recorded payment can be deleted
afterwards; a posted invoice cannot, only voided, and the void is permanent.

## Tests

```bash
python3 test_handler.py     # 24 tests, no network, no credentials
python3 mutation_test.py    # breaks the handler 12 ways, confirms tests catch it
```
