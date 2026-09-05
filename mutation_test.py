#!/usr/bin/env python3
"""Mutation test: break the handler deliberately, confirm a test catches it.

A green suite proves nothing until you have watched it go red for the right
reason. On the previous module several tests passed for the wrong reason until
this was run — one matched a prefix and let a renamed function through.

Each mutation below is a plausible "simplification" a future reader might make.
If a mutation survives (suite still green), the suite has a hole and the
mutation names it precisely.

Not shipped: excluded via .moduleignore.
"""
import re
import subprocess
import sys
import os

HERE = os.path.dirname(os.path.abspath(__file__))
HANDLER = os.path.join(HERE, "handlers", "handler.py")

MUTATIONS = [
    ("drop line items from the fingerprint",
     "        line_fp(inv),\n", "        # line_fp(inv),\n"),

    ("hash the raw date instead of the normalised one",
     "        normalise_date(inv.get(\"UpdatedDateUTC\")),",
     "        str(inv.get(\"UpdatedDateUTC\") or \"\"),"),

    ("add the timezone offset to the parsed instant",
     "        return int(m.group(1)) // 1000",
     "        return int(m.group(1)) // 1000 + (int(m.group(2) or 0) * 36)"),

    ("return the access token before persisting the rotation",
     "    helpers[\"jsave\"](_token_path(), {\n        \"refresh_token\": new_rt,",
     "    return parsed[\"access_token\"]  # MUTANT\n    helpers[\"jsave\"](_token_path(), {\n        \"refresh_token\": new_rt,"),

    ("make the idempotency key unique per attempt",
     "    return \"%s-%s-%d-%s\" % (plan_id[:8], plan_fp[:8], index, _sha(payload)[:12])",
     "    import random\n    return \"%s-%d\" % (plan_id[:8], random.randint(0, 10**9))"),

    ("trust the HTTP status and ignore per-element verdicts",
     "        if str(r.get(\"StatusAttributeString\") or \"\").upper() == \"ERROR\" or errs:",
     "        if False:"),

    ("skip the approval-vs-plan fingerprint check",
     "    if claimed != actual:", "    if False:"),

    ("skip the plan-file integrity check",
     "    if actual != plan.get(\"plan_fp\"):", "    if False:"),

    ("truncate instead of raising past the row cap",
     "            raise XeroApiError(\n                \"%s returned more than max_rows=%d. Refusing rather than \"",
     "            return rows[:max_rows], last_headers\n            raise XeroApiError(\n                \"%s returned more than max_rows=%d. Refusing rather than \""),

    ("write the ledger without chaining to the previous hash",
     "    prev = entries[-1][\"hash\"] if entries else None",
     "    prev = None"),

    ("drop the invalid_grant special case",
     "        if err == \"invalid_grant\":", "        if False:"),

    ("use a bare bool() on a flag the airlock cannot type-check",
     "    allow_empty_greeting = _as_bool(inputs.get(\"allow_empty_greeting\"))",
     "    allow_empty_greeting = bool(inputs.get(\"allow_empty_greeting\"))"),

    ("swallow a legitimate zero on a numeric input",
     "def _as_int(v, default):\n", "def _as_int(v, default):\n    return int(v or default)\n"),

    ("go back to `or default` on the overdue threshold",
     "    overdue_days = _as_int(inputs.get(\"overdue_days\"), 1)",
     "    overdue_days = int(inputs.get(\"overdue_days\") or 1)"),

    ("pass Xero's generic 500 blob through instead of naming it",
     "            if st >= 500:", "            if False:"),

    # ---- v0.1.2 greeting rule

    ("skip the empty-greeting check",
     "    if not allow_empty_greeting and not greeting:", "    if False:"),

    ("accept an unverified contact-person name as a greeting",
     "    return str((contact or {}).get(\"FirstName\") or \"\").strip()\n\n\ndef _contact_person_name",
     "    return (str((contact or {}).get(\"FirstName\") or \"\").strip()\n            or _contact_person_name(contact))\n\n\ndef _contact_person_name"),

    ("treat the company name as a greeting fallback",
     "    return str((contact or {}).get(\"FirstName\") or \"\").strip()\n\n\ndef _contact_person_name",
     "    return str((contact or {}).get(\"FirstName\") or (contact or {}).get(\"Name\") or \"\").strip()\n\n\ndef _contact_person_name"),

    ("treat a present-but-empty FirstName as a name",
     "    return str((contact or {}).get(\"FirstName\") or \"\").strip()\n\n\ndef _contact_person_name",
     "    return (\"x\" if \"FirstName\" in (contact or {}) else \"\")\n\n\ndef _contact_person_name"),

    # ---- v0.1.2 binding. The first is the one that moves money.

    ("stop binding the payment amount, date and destination account",
     "        e[\"action_fp\"] = _action_binding({\"account_id\": account_id,",
     "        e[\"action_fp\"] = \"\"  # MUTANT\n        _unused = ({\"account_id\": account_id,"),

    ("skip the action-binding check on the payment apply",
     "    if unbound:", "    if False:"),

    ("stop binding the voidability verdict",
     "        e[\"action_fp\"] = _action_binding({\"blocked_because\": sorted(reasons)})",
     "        e[\"action_fp\"] = \"\"  # MUTANT"),

    ("accept an entry that carries no action binding at all",
     "        if not e.get(\"action_fp\"):", "        if False:"),

    ("stop normalising a grouped fingerprint (would accept anything)",
     "    claimed = _ungrouped(claimed)", "    claimed = claimed"),

    ("return the fingerprint ungrouped, exposed to the digit scrubber",
     "            \"plan_fp\": _grouped(plan[\"plan_fp\"]),",
     "            \"plan_fp\": plan[\"plan_fp\"],"),

    # ---- v0.1.2 dunning. The first two are the ones that reach a customer.

    ("skip the duplicate-send check at PLAN time",
     "    if int(stage) in stages_sent(hist):", "    if False:"),

    ("skip the duplicate-send check at APPLY time",
     "        if stage in stages_sent(hist):", "        if False:"),

    ("treat a missing EmailAddress key as an address",
     "    return str((contact or {}).get(\"EmailAddress\") or \"\").strip()",
     "    return \"EmailAddress\" in (contact or {}) and \"x\" or \"\""),

    ("let a non-AUTHORISED invoice be emailed",
     "    if status != \"AUTHORISED\":", "    if False:"),

    ("allow two ladder rungs in one run",
     "    elif nxt != int(stage):", "    elif False:"),

    ("stop binding the approved stage into the fingerprint",
     "        e[\"action_fp\"] = _stage_binding(stage)",
     "        e[\"action_fp\"] = \"\"  # MUTANT"),

    ("send an idempotency key Xero ignores on this endpoint",
     "        st, hd, body = api(\"POST\", \"Invoices/%s/Email\" % e[\"id\"], token, body={})",
     "        st, hd, body = api(\"POST\", \"Invoices/%s/Email\" % e[\"id\"], token, body={},\n                           extra_headers={\"Idempotency-Key\": idem_key(plan[\"plan_id\"], plan[\"plan_fp\"], 0, {})})"),

    ("chase a fully paid invoice instead of releasing it",
     "            if float(inv.get(\"AmountDue\") or 0) <= 0:\n                excluded.append",
     "            if False:\n                excluded.append"),

    ("write the dunning chain without chaining to the previous hash",
     "    prev = events[-1][\"hash\"] if events else None",
     "    prev = None"),

    ("hold a part-payment forever by never recording the hold",
     "            dunning_append(iid, stage, DUNNING_HOLD,",
     "            _ = (lambda *a, **k: None)(iid, stage, DUNNING_HOLD,"),

    ("write files without the sandbox prefix",
     "FILE_PREFIX = \"xero_ledger_\"", "FILE_PREFIX = \"xero_\""),

    ("name the diagnostics block 'token' again (airlock redacts by field name)",
     '        "credential_state": {', '        "token": {'),

    ("return the raw lock date inline again (airlock redacts by value shape)",
     '            "period_lock": "set" if lock_raw else "(none)",',
     '            "period_lock_date": lock_raw or "(none set)",'),
]


def run_suite():
    r = subprocess.run([sys.executable, "test_handler.py"], cwd=HERE,
                       capture_output=True, text=True)
    return r.returncode == 0, r.stdout


def main():
    original = open(HANDLER, encoding="utf-8").read()
    ok, _ = run_suite()
    if not ok:
        print("baseline suite is RED — fix that before mutation testing")
        return 1
    print("baseline: green\n")

    survived = []
    try:
        for label, find, repl in MUTATIONS:
            if find not in original:
                print("  SKIP    %-56s (anchor not found)" % label)
                survived.append(label + " [anchor missing]")
                continue
            open(HANDLER, "w", encoding="utf-8").write(original.replace(find, repl, 1))
            green, _out = run_suite()
            if green:
                print("  SURVIVED %-55s <-- suite has a hole" % label)
                survived.append(label)
            else:
                print("  killed   %s" % label)
    finally:
        open(HANDLER, "w", encoding="utf-8").write(original)

    print("\n%d/%d mutations killed" % (len(MUTATIONS) - len(survived), len(MUTATIONS)))
    if survived:
        print("\nSURVIVORS — each names a gap in the suite:")
        for s in survived:
            print("  - %s" % s)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
