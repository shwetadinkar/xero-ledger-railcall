#!/usr/bin/env python3
"""Fail when a stated command count disagrees with the manifest.

Counts drift silently: a command is added, the manifest is right, and the README
still says ten. A reviewer reading "10 commands" next to eleven rows draws the
obvious conclusion about the rest of the module. Cheap to check, so check it.

Also verifies every manifest command has a handler and that the docs mention
each command id at least once — a command nobody documented is a command nobody
can use.

Not shipped: excluded via .moduleignore.
"""
import json
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
fail = []

m = json.load(open(os.path.join(HERE, "module.json"), encoding="utf-8"))
n = len(m["commands"])
print("manifest declares %d commands" % n)

for doc in ("README.md", "COMMANDS.md"):
    text = open(os.path.join(HERE, doc), encoding="utf-8").read()
    if ("%d commands" % n) not in text:
        fail.append("%s does not state '%d commands'" % (doc, n))

# every command documented in COMMANDS.md
cmds = open(os.path.join(HERE, "COMMANDS.md"), encoding="utf-8").read()
for c in m["commands"]:
    short = c["id"].split(".", 1)[1]
    if short not in cmds:
        fail.append("COMMANDS.md never mentions %s" % c["id"])

# every command has a handler
src = open(os.path.join(HERE, "handlers", "handler.py"), encoding="utf-8").read()
for c in m["commands"]:
    fn = "def " + c["id"].replace(".", "_") + "("
    if fn not in src:
        fail.append("no handler for %s" % c["id"])

# the manifest description states the same count if it states one at all
desc = m.get("description", "")
for found in re.findall(r"\b(\d+)\s+commands\b", desc):
    if int(found) != n:
        fail.append("manifest description says %s commands, manifest has %d" % (found, n))

# ── output_schema vs what the handler actually returns (spec-core 4f-bis) ──
#
# NOTHING enforces output_schema at runtime — no test, no lint, no load-time
# check. Two stale declarations sat invisible in v0.1.2: verify_connection
# still declared a field named `token` (renamed to `credential_state` in the
# handler long before, and `token` is the exact name the redactor masks), and
# verify_ledger omitted fields a workflow needed to bind. A workflow composing
# against a stale schema fails at RUN time rather than at validation, so this
# is the only place it will ever be caught.
#
# Static, by design: check_counts runs in CI with no network and no
# credentials, so the return keys are read out of the AST rather than by
# executing anything.
import ast

tree = ast.parse(src)
funcs = {n.name: n for n in tree.body if isinstance(n, ast.FunctionDef)}


def return_keys(fn, depth=0):
    """Keys of every dict literal this function can return, or None if unknown.

    Handlers return `(output_dict, artifact)`. Some delegate wholesale to a
    shared helper (apply_invoice_post -> _apply_invoice_status), so a single
    `return <call>` is followed one level down.
    """
    if depth > 2:
        return None
    keys, unknown = set(), False
    for node in ast.walk(fn):
        if not isinstance(node, ast.Return) or node.value is None:
            continue
        v = node.value
        if isinstance(v, ast.Tuple) and v.elts:
            v = v.elts[0]
        if isinstance(v, ast.Dict):
            for k in v.keys:
                if isinstance(k, ast.Constant) and isinstance(k.value, str):
                    keys.add(k.value)
                else:
                    unknown = True
        elif isinstance(v, ast.Call) and isinstance(v.func, ast.Name) \
                and v.func.id in funcs:
            sub = return_keys(funcs[v.func.id], depth + 1)
            if sub is None:
                unknown = True
            else:
                keys |= sub
        elif isinstance(v, ast.Name):
            # `out = {...}` then `return out, None`, with later
            # `out["x"] = ...` additions. A common handler shape, and skipping
            # it left verify_connection — one of the two commands whose schema
            # WAS stale — unchecked by the very check written to catch it.
            got = set()
            found_literal = False
            for a in ast.walk(fn):
                if not isinstance(a, ast.Assign):
                    continue
                for t in a.targets:
                    if isinstance(t, ast.Name) and t.id == v.id \
                            and isinstance(a.value, ast.Dict):
                        found_literal = True
                        for k in a.value.keys:
                            if isinstance(k, ast.Constant) and isinstance(k.value, str):
                                got.add(k.value)
                            else:
                                unknown = True
                    if isinstance(t, ast.Subscript) \
                            and isinstance(t.value, ast.Name) and t.value.id == v.id \
                            and isinstance(t.slice, ast.Constant) \
                            and isinstance(t.slice.value, str):
                        got.add(t.slice.value)
            if found_literal:
                keys |= got
            else:
                unknown = True
        else:
            unknown = True
    return None if unknown and not keys else keys


checked = skipped = 0
for c in m["commands"]:
    fn = funcs.get(c["id"].replace(".", "_"))
    declared = set((c.get("output_schema") or {}))
    if fn is None:
        continue
    actual = return_keys(fn)
    if actual is None:
        skipped += 1
        # A skipped check is not a passed check (spec-core 14).
        print("  SKIP  %s — returns a shape this check cannot read statically; "
              "its output_schema is UNVERIFIED" % c["id"])
        continue
    checked += 1
    stale = sorted(declared - actual)
    undeclared = sorted(actual - declared)
    if stale:
        fail.append("%s declares output field(s) it never returns: %s"
                    % (c["id"], stale))
    if undeclared:
        fail.append("%s returns field(s) it does not declare: %s"
                    % (c["id"], undeclared))

print("output_schema verified against the handler for %d command(s), %d skipped"
      % (checked, skipped))

if fail:
    print("\nFAIL:")
    for f in fail:
        print("  - " + f)
    sys.exit(1)
print("all counts agree")
