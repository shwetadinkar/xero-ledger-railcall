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
