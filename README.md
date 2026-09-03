# Xero Ledger Airlock

**Xero validates the write. It does not validate that the write is still the one
you approved.**

Between reviewing a batch and it committing, a payment can land, an invoice can
be recoded, a period can close. The resulting write is still legal, so nothing in
Xero stops it. This module refuses it.

10 commands across invoices, payments and the chart of accounts. Every write is
held behind RailCall's approval airlock and sealed into a signed receipt.

**What it does not claim:** Xero refuses a void on a paid invoice, and an
overpayment, by itself. There this module is defence in depth — it refuses at
plan time, so you never approve what cannot succeed. Each command says so in its
output.

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

## Bugs this module found in itself

All five came from running the module through the real airlock against a real
Xero org. None was reachable from a unit test, and all five are now.

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

**A spec correction.** `apply_invoice_post` failures read *"The document DueDate
field must be specified."* Xero validates required fields at the status
transition, so an invoice with no `DueDate` is a legal DRAFT and an illegal
AUTHORISED. The earlier probe conclusion — that a partial POST does not blank
unsent fields — was right but incomplete: a minimum body is not always
sufficient. Recorded in `COMMANDS.md`.

## Limits

Drift detection is deliberately over-sensitive: a change to a field these
commands do not read still moves `UpdatedDateUTC` and still refuses, and it
cannot say which field moved. The local ledger is tamper-evident, not
tamper-proof — it detects edits and mid-chain deletion, not tail truncation by
whoever holds the file. Sales invoices (ACCREC) only in v0.1; bills, credit notes
and bank transactions are not covered and are not reported as clean. A recorded
payment can be deleted afterwards; a posted invoice cannot, only voided, and the
void is itself permanent.

## Tests

```bash
python3 test_handler.py     # 24 tests, no network, no credentials
python3 mutation_test.py    # breaks the handler 12 ways, confirms tests catch it
```
