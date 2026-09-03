# COMMANDS — Xero Ledger Airlock v0.1.1

All 10 commands. Every one requires credentials, so the station upgrades every
one to require runtime approval — **including the reads**. Modes below are what
the manifest declares, not what the station enforces.

Every example output on this page was **captured from a live run** against a
Xero demo organisation on 2026-09-03 and copied out of the signed receipt.
GUIDs, invoice numbers and workspace paths are replaced with placeholders; the
numbers, field names, limit strings and error messages are untouched.

Behaviour marked ✅ was verified against the live API. Nothing here is assumed
from documentation.

---

## 1. `verify_connection` · read · low

Probes each scope group with one cheap read and reports what the API refused.

**Inputs:** none.

**Example output**

```json
{"ready": "yes",
 "tenants": [{"name": "Demo Company (Global)",
              "id": "a1b2c3d1-0000-4000-8000-000000000001"}],
 "connection_id": "a1b2c3d2-0000-4000-8000-000000000002",
 "configured_tenant": "a1b2c3d1-0000-4000-8000-000000000001",
 "tenant_matches": true,
 "inferred_scopes": {"accounting.settings": "granted",
                     "accounting.contacts": "granted",
                     "accounting.invoices": "granted",
                     "accounting.payments": "granted"},
 "rate": {"X-MinLimit-Remaining": "55",
          "X-DayLimit-Remaining": "990",
          "X-AppMinLimit-Remaining": "9994"},
 "credential_state": {"rotations": 1,
                      "last_rotated": "2026-09-03T19:21:50Z",
                      "access_cached": true}}
```

✅ Xero has **no scope-introspection endpoint**, so this is inference. A missing
scope answers **401** (not 403); a disconnected app answers **403** on every
resource; `Attachments` answers **404** for a missing scope. All are treated as
not granted.

The block is called `credential_state`, not `token`: the airlock redacts any
field whose NAME contains token/key/secret before sealing a receipt, so a block
named `token` comes back as `••••••` even though it holds no secret.

`connection_id` is reported because `DELETE /connections/{id}` returns 204 and
silently kills every token — as does resetting a Xero demo org. From the error
alone that is indistinguishable from an expired token, and the fixes differ.

**Stated limits**

> reports which reads this token can perform, inferred from what the API
> refused. Xero publishes no granted-scope set, so a scope that is held but
> unused is reported as unknown, never as granted.

**Errors**

| Condition | What you get |
|---|---|
| No credential saved | `no xero-accounting credential saved. Add client_id, client_secret, refresh_token and tenant_id in Studio -> Integrations.` |
| Credential missing a field | `xero-accounting credential incomplete — need client_id, client_secret and refresh_token.` |
| App disconnected / org reset | `ready: "partial"`, `connection_id: null`, every scope `not granted (HTTP 403)`, plus a limit line saying the app holds no connection and re-authorising — not re-saving the credential — is the fix |
| Configured tenant not in the token's connections | limit line: the write would land in the wrong organisation, so every command will refuse |
| Refresh token already spent | see `invalid_grant` under §5 |

---

## 2. `describe_org` · read · low

The codes every other command needs. → **file**, because it is almost entirely
ids and codes a receipt would redact.

**Inputs:** none.

**Example output**

```json
{"artifact": "~/.railcall_workspace/xero_ledger_describe_2026-09-03T192639Z.json",
 "counts": {"accounts": 58, "tax_rates": 8, "tracking_categories": 1},
 "period_lock": "set"}
```

`period_lock` reports **whether** a lock is set; the date itself is in the
artifact, as `period_lock_date` (raw) and `period_lock_epoch` (parsed).

That split is not stylistic. A date returned inline cannot survive a receipt:
`/Date(1222732800000+0000)/` carries a long digit run, and the airlock's
identifier scrubber rewrites it to `/Date([account]+0000)/` before sealing. An
earlier version returned it inline and the field an operator reads was
destroyed while the artifact kept the truth. This is the same class as the
`token` field in §1, with a different scrubber: that one masks by field **name**,
this one by value **shape** — so renaming does not help, and only moving the
value does. It follows the module's own file-vs-inline rule: anything you act on
goes to the file, and the receipt carries the verdict.

✅ `PeriodLockDate` **is** exposed on `/Organisation`. ✅ Dates are Microsoft JSON
epoch, not ISO 8601. This module normalises them before hashing so a timezone
change cannot look like ledger drift.

**Stated limits**

> lists what this token can see. Something excluded by scope is absent, not
> reported as zero.

> dates are Microsoft JSON epoch (/Date(ms+offset)/), not ISO 8601. This module
> normalises them before hashing so a timezone change cannot look like ledger
> drift.

> period_lock reports only whether a lock is set. The date itself is in the
> artifact, not in this receipt: the airlock's identifier scrubber rewrites the
> epoch in /Date(...)/ to [account], so a date returned inline would be destroyed
> on the way into the receipt.

> EndOfYearLockDate is absent from this organisation's response. That means
> either no year-end lock is set or this org does not expose one — the API does
> not distinguish them, and neither does this command.

**Errors**

| Condition | What you get |
|---|---|
| `accounting.settings` not granted | `Organisation failed (HTTP 401)` |
| App disconnected | `Organisation failed (HTTP 403)` |
| Accounts page exceeds the cap | raises rather than truncating — see §3 |

---

## 3. `hygiene_scan` · read · low · schedulable

What is quietly rotting, each finding naming the command that fixes it.

**Inputs**

| Field | Type | Default |
|---|---|---|
| `draft_days` | number | 14 |
| `overdue_days` | number | 1 |
| `max_findings` | number | 1000 |

**Example output**

```json
{"artifact": "~/.railcall_workspace/xero_ledger_hygiene_2026-09-03T192356Z.json",
 "counts": {"overdue": 5},
 "total_findings": 5}
```

Findings: `draft_ageing`, `submitted_ageing`, `overdue` (bucketed 1-30 / 31-60 /
61-90 / 90+ for dunning), `overpaid`. Each row in the artifact carries the
invoice, contact, total, amount due and a `fixed_by` naming the governed command.

**Stated limits**

> lists what this token can see. Something excluded by scope is absent, not
> reported as zero.

> scans sales invoices (ACCREC) only. Bills, credit notes and bank transactions
> are not covered by this version and are not reported as clean.

**Errors**

| Condition | What you get |
|---|---|
| More than `max_findings` | `more than max_findings=1000. Refusing rather than truncating — a half-reported set is worse than an error when you are about to act on it. Narrow the window or raise the cap deliberately.` |
| `accounting.invoices` not granted | `Invoices refused (401) — this token does not hold the scope for it. Run verify_connection to see what it can read.` |

---

## 4. `verify_ledger` · read · low

Hash-chain integrity over every applied write and every refusal.

**Inputs:** none.

**Example output**

```json
{"entries": 6, "chain_intact": "yes", "first_break": "(none)"}
```

A broken chain reports `chain_intact: "NO"` and `first_break: "seq 3"`, naming
the first entry whose recorded `prev` or body hash does not recompute.

**Stated limits**

> tamper-evident, not tamper-proof: it detects edits and mid-chain deletion, not
> truncation of the tail by whoever holds the file.

**Errors**

Reads a local file only; it makes no API call and cannot fail on credentials or
scope. A missing ledger file is reported as `entries: 0`, `chain_intact: "yes"`
— an empty chain is intact, and that is not the same claim as "no writes have
ever happened", which this command cannot make.

---

## 5. `plan_invoice_post` · read · medium

**Inputs**

| Field | Type | Notes |
|---|---|---|
| `status` | string | `DRAFT` (default) or `SUBMITTED` |
| `contact_id` | string | restrict to one contact |
| `invoice_ids` | array | explicit list; overrides the selector |
| `max_invoices` | number | default 200 |

**Example output**

```json
{"artifact": "~/.railcall_workspace/xero_ledger_plan_invoice_post_9312eabe….json",
 "plan_id": "9312eabea7afc429",
 "plan_fp": "1c2342e801777c78…",
 "count": 6,
 "total": "1275.38"}
```

The fingerprint, per invoice:

```
sha256( InvoiceID, Status, Total, AmountDue, AmountPaid,
        normalise(UpdatedDateUTC),
        sha256( sorted line items: LineItemID, AccountCode, TaxType, LineAmount ) )
```

Line items are inside it because a total can stay identical while the account
coding underneath changes, and posting revenue to the wrong account is what an
accountant has to unpick later. Xero validates neither — the recoded invoice is
a legal write.

**Stated limits**

> moving an invoice to AUTHORISED is the point of no return: it can no longer be
> deleted, only voided, and the void is permanent too.

> refuses on any drift it can see. A change to a field this command does not
> read will still move UpdatedDateUTC and still refuse — deliberately, and it
> cannot tell you which field moved.

> reads only. Nothing is posted until apply_invoice_post runs with this plan_fp
> and a human approval.

**Errors**

| Condition | What you get |
|---|---|
| Nothing matches the selector | `count: 0`, no plan written, limit line saying so |
| More than `max_invoices` | `Invoices returned more than max_rows=200. Refusing rather than truncating — narrow the selector or raise the cap deliberately.` |
| Spent refresh token | `Xero rejected the stored refresh token (invalid_grant). Refresh tokens are single-use and rotate on every refresh; this one has been spent or has expired. If a previous run was interrupted, the last token Xero issued is in <path>.` |

---

## 6. `apply_invoice_post` · **write_requires_approval** · high

**Inputs**

| Field | Type | Required |
|---|---|---|
| `plan_path` | string | yes |
| `plan_fp` | string | yes |
| `composite_fp` | string | no — for a cross-module coordinator |

**Example output** — a real batch, three of six rejected by Xero *inside an HTTP
200*:

```json
{"committed": 3, "failed": 3, "refused": 0,
 "artifact": "~/.railcall_workspace/xero_ledger_custody_invoice_post_2026-09-03T191243Z.json"}
```

The artifact names every one:

```json
{"committed": [{"number": "INV-0001", "status": "AUTHORISED"}],
 "failed": [{"number": null,
             "errors": ["The document DueDate field must be specified."]}]}
```

✅ Uses `summarizeErrors=false` and reads the **per-element** verdict. Without
the parameter one bad element rejects the batch with HTTP 400; with it, Xero
returns **HTTP 200 with per-element failures inside**. A handler checking only
the status code would report success while elements failed.

✅ Sends the **minimum** body (`InvoiceID` + `Status`) — a partial POST does not
blank unsent fields.

⚠️ **But a minimum body is not always sufficient.** Xero validates required
fields *at the status transition*: an invoice with no `DueDate` is a legal DRAFT
and an illegal AUTHORISED, and the POST fails with *"The document DueDate field
must be specified."* Observed live 2026-09-03 — 3 of 6 invoices in a real batch
failed this way, inside an HTTP 200. The command reports them by number in the
artifact rather than claiming success. A future version should surface missing
required fields at **plan** time, so the operator sees them before approving.

✅ `Idempotency-Key` is a pure function of the approved plan, never a fresh uuid:
a new uuid per attempt would make every retry look like a new request. Xero
genuinely dedupes on it.

**Stated limits**

> moving an invoice to AUTHORISED is the point of no return: it can no longer be
> deleted, only voided, and the void is permanent too.

> refuses on any drift it can see. A change to a field this command does not
> read will still move UpdatedDateUTC and still refuse — deliberately, and it
> cannot tell you which field moved.

> 3 element(s) were rejected by Xero inside an HTTP 200 response. They are named
> in the artifact. Nothing was rolled back: a rollback is itself a write that can
> fail, and a half-rolled-back batch is worse than a halted one that is fully
> accounted for.

**Errors** — all observed live

| Condition | What you get |
|---|---|
| Invoice has no `DueDate` | `failed`, with `The document DueDate field must be specified.` in the artifact. Other elements in the same batch still commit |
| `plan_fp` does not match the plan | `result_status: failed_safely` and `APPROVAL DOES NOT MATCH THIS PLAN. You approved plan_fp=deadbeefdeadbeef; the file now fingerprints as 1c2342e801777c78. The approval binds plan CONTENT, not the filename — re-plan and re-approve.` |
| Plan file edited after the plan ran | `PLAN FILE ALTERED. Its recorded fingerprint no longer matches its own contents (recorded …, recomputed …). Re-run the plan command.` |
| Plan is for a different command | `plan at <path> is a 'payment_allocate' plan, not 'invoice_post' — wrong apply command.` |
| Ledger moved since approval | `refused: N` with a `drift` list naming each invoice and what changed |
| Approval replayed | the station blocks it: `approval already consumed by an earlier execute — approvals are single-use. Re-approve this payload to run again.` |

---

## 7. `plan_invoice_void` · read · medium

**Inputs**

| Field | Type | Required |
|---|---|---|
| `invoice_ids` | array | yes |
| `max_invoices` | number | no (default 200) |

**Example output**

```json
{"artifact": "~/.railcall_workspace/xero_ledger_plan_invoice_void_470bf8d7….json",
 "plan_id": "470bf8d794f09726",
 "plan_fp": "a64e137511d12929…",
 "voidable": 1,
 "blocked": 0}
```

Each plan entry carries `voidable` and `blocked_because`, plus the full payment
list, so the operator reads *why* before approving:

```json
{"number": "INV-0001", "voidable": false,
 "blocked_because": ["status is DRAFT — Xero DELETES a draft, it does not void
   one. This command only voids AUTHORISED invoices; deleting a draft is not
   wired in v0.1."]}
```

**Stated limits**

> a void is a new permanent entry, never a deletion. Xero itself refuses a void
> on an invoice with payments; this refuses earlier, at plan time, and says what
> changed — it is not the only guard.

> refuses on any drift it can see. A change to a field this command does not
> read will still move UpdatedDateUTC and still refuse — deliberately, and it
> cannot tell you which field moved.

**Errors**

| Condition | What you get |
|---|---|
| `invoice_ids` omitted | `invoice_ids is required.` |
| More than `max_invoices` | `more than max_invoices=200 — refusing rather than truncating.` |
| An id is not readable | `invoice <id> not readable (HTTP 404)` |

---

## 8. `apply_invoice_void` · **write_requires_approval** · high

**Inputs:** `plan_path` (required), `plan_fp` (required), `composite_fp`.

**Example output** — a real successful void:

```json
{"committed": 1, "failed": 0, "refused": 0,
 "artifact": "~/.railcall_workspace/xero_ledger_custody_invoice_void_2026-09-03T192428Z.json"}
```

⚠️ **Xero itself refuses a void on a paid invoice** (HTTP 400, probed — it does
*not* orphan the payment). This command is defence in depth: it refuses at plan
time so you never approve something that cannot succeed, and it names what
changed instead of returning a `ValidationException` blob.

**Stated limits**

> a void is a new permanent entry, never a deletion. Xero itself refuses a void
> on an invoice with payments; this refuses earlier, at plan time, and says what
> changed — it is not the only guard.

> refuses on any drift it can see. A change to a field this command does not
> read will still move UpdatedDateUTC and still refuse — deliberately, and it
> cannot tell you which field moved.

**Errors** — all observed live

| Condition | What you get |
|---|---|
| Invoice is DRAFT or SUBMITTED | refused at plan time. If a stale plan is applied anyway, Xero answers `Invoice not of valid status for modification` and the element is reported as failed |
| A payment landed since the plan | `refused`, drift reason `a payment landed since the plan was reviewed` |
| Invoice was not voidable at plan time | `refused`, reason `not voidable at plan time: <the plan's own blocked_because>` |
| `plan_fp` mismatch / plan altered / wrong command | as §6 |

---

## 9. `plan_payment_allocate` · read · medium

**Inputs**

| Field | Type | Required |
|---|---|---|
| `allocations` | array of `{invoice_id, amount, date}` | yes (`date` defaults to today) |
| `account_id` | string | yes — the bank account's `AccountID` |

**Example output**

```json
{"artifact": "~/.railcall_workspace/xero_ledger_plan_payment_allocate_758384ef….json",
 "plan_id": "758384ef0c9e77ec",
 "plan_fp": "c09646c386c66d99…",
 "count": 1,
 "total": "1546.88",
 "overpays": 0}
```

Each entry shows the resulting balance so the operator can read the effect:

```json
{"number": "INV-0001", "amount_due": 6187.5,
 "allocate_amount": 1546.88, "resulting_due": 4640.62, "overpays": false}
```

**Stated limits**

> consistent with the payment having been recorded in the ledger, never a
> confirmation that funds cleared. Xero itself refuses an overpayment; this flags
> it at plan time so you never approve one. Unlike a posted invoice, a payment
> recorded here can be deleted afterwards — the one reversible write in this
> module.

> refuses on any drift it can see. A change to a field this command does not
> read will still move UpdatedDateUTC and still refuse — deliberately, and it
> cannot tell you which field moved.

**Errors**

| Condition | What you get |
|---|---|
| `allocations` or `account_id` missing | `allocations and account_id are both required.` |
| An invoice is not readable | `invoice <id> not readable` |
| An allocation exceeds the amount due | `overpays: N` and an extra limit line: *N allocation(s) exceed the amount due. Xero will refuse those writes; they are flagged here so you do not approve a batch that cannot succeed.* |

---

## 10. `apply_payment_allocate` · **write_requires_approval** · high

**Inputs:** `plan_path` (required), `plan_fp` (required), `composite_fp`.

**Example output** — a real drift refusal. The plan was approved to pay 50.00; a
colleague recorded 10.00 against the same invoice while it sat in review:

```json
{"recorded": 0, "failed": 0, "refused": 1,
 "drift": [{"invoice": "INV-0001",
            "reason": "AmountPaid 25.0 -> 35.0; AmountDue 191.5 -> 181.5"}],
 "artifact": "~/.railcall_workspace/xero_ledger_plan_payment_allocate_c91a217c….json"}
```

Paying the approved 50.00 would still have been a legal write. It was not the
write the operator approved.

Posts one payment at a time and **halts on the first failure** — Xero has no
per-element verdict for `/Payments`, so a batch would be all-or-nothing on a 400
and the account of which ones landed would be lost.

⚠️ **Xero itself refuses an overpayment** (HTTP 400, probed). Flagged at plan
time so you never approve a batch that cannot succeed.

**Stated limits**

> consistent with the payment having been recorded in the ledger, never a
> confirmation that funds cleared. Xero itself refuses an overpayment; this flags
> it at plan time so you never approve one. Unlike a posted invoice, a payment
> recorded here can be deleted afterwards — the one reversible write in this
> module.

On a refusal it adds:

> REFUSED. A rising AmountPaid means a payment landed while this allocation sat
> in review — applying the reviewed amount now would overpay the invoice.

**Errors** — all observed live

| Condition | What you get |
|---|---|
| `AmountPaid` rose since the plan | `refused: 1` with the drift reason above |
| A payment fails mid-batch | halts; `failed` names it, and a limit line says how many were recorded before it and that each recorded payment **can** be deleted in Xero to reverse it |
| `plan_fp` mismatch / plan altered / wrong command | as §6 |
| Approval replayed | station-level: `approval already consumed by an earlier execute — approvals are single-use.` |

---

## Rate limits

✅ 60/minute per tenant · ✅ **1,000/day on the Starter plan** (not the 5,000 the
docs imply — read `X-DayLimit-Remaining` at runtime, it is plan-dependent) ·
✅ 10,000/minute app-wide.

Retry policy is **asymmetric**: reads retry freely, writes only through the
idempotency ledger. A retry never triggers a token refresh it does not need —
every refresh burns a single-use token, so the refresh happens once at the top of
each handler and a mid-command 401 is reported, not papered over.
