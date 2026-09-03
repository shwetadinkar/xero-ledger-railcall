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

if fail:
    print("\nFAIL:")
    for f in fail:
        print("  - " + f)
    sys.exit(1)
print("all counts agree")
