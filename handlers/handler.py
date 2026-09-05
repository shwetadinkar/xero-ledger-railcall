#!/usr/bin/env python3
"""Xero Ledger Airlock — governed Xero invoices and payments. v0.1.2

THE IDEA, in one sentence:
  An approval binds to the exact ledger state a human reviewed. If any of it
  moved before the write commits, this refuses.

WHY THAT IS THE IDEA AND NOT SOMETHING LOUDER
  The first draft of this module claimed Xero would orphan a payment if you
  voided a paid invoice, and would let you overpay an invoice. Both were probed
  against the live API on 2026-09-03 and both are FALSE — Xero answers HTTP 400
  to each. A headline claim that is disprovable in one API call is worse than a
  narrower true one, so the claim moved to what is actually ours:

  Xero validates the write. It does not validate that the write is still the
  one you approved. It has no concept of approval-time state. A payment landing
  between plan and apply changes what the operator agreed to EVEN WHEN THE
  RESULTING WRITE IS STILL PERFECTLY LEGAL. Nothing in Xero stops that. This
  module does.

  Where Xero also guards something, the command output says so. See _LIMITS.

v0.1.2 ADDS DUNNING, AND ONE PROBED FACT SHAPES ALL OF IT
  Xero does NOT dedupe invoice emails. Five sends of one invoice produced five
  deliveries, five HTTP 204s, no warning — probed live 2026-09-04. That is the
  opposite of Xero's Idempotency-Key behaviour on invoice POST, which genuinely
  dedupes, so the platform-wide assumption does not carry over.

  Consequence: `xero_ledger_dunning_state.json` is the ONLY thing standing
  between a re-run and a customer receiving the same reminder twice. It is not
  reporting. A bug in it is a customer-facing failure, so the duplicate check is
  made twice — once at plan time so nobody approves a duplicate, and again at
  apply time against freshly-read state, because a sibling run may have sent it
  in between. `SentToContact` cannot help: it is a latch, set once and never
  cleared, and it does not record WHICH stage was sent.

HANDLER CONTRACT
  Each handler is `def xero_accounting_<name>(inputs, stamp) -> (output, artifact)`.
  Helpers arrive via __rc_helpers__. Output that an operator must ACT on goes to
  a file, because redact_output scrubs ids and date-shaped values out of a
  receipt; only counts, money totals and verdicts go inline.
"""
import hashlib
import json
import os
import re
import time
import urllib.error
import urllib.parse
import urllib.request

VERSION = "0.1.2"

TOKEN_URL = "https://identity.xero.com/connect/token"
CONNECTIONS_URL = "https://api.xero.com/connections"
API_BASE = "https://api.xero.com/api.xro/2.0"

# Xero access tokens are 30 minutes. Refresh with headroom so a long paged read
# does not 401 halfway through.
SKEW_SECONDS = 120

# Every file this module writes MUST start with this prefix. The manifest's
# requires.filesystem_writes allowlist is scoped to it, so a file written under
# any other name raises SandboxViolation at runtime. test_handler.py asserts it.
FILE_PREFIX = "xero_ledger_"


def _h():
    return globals()["__rc_helpers__"]  # noqa: F821


# ─────────────────────────────────────────────────────────── dates

_MS_DATE = re.compile(r"^/Date\((-?\d+)([+-]\d{4})?\)/$")


def parse_xero_date(value):
    """Xero returns Microsoft JSON epoch — `/Date(1222732800000+0000)/` — not
    ISO 8601. Every UpdatedDateUTC, every PeriodLockDate, every payment date.

    Returns epoch SECONDS as an int, or None.

    The offset suffix is deliberately ignored: the millisecond value is already
    UTC, and the suffix describes the org's display timezone. Adding it would
    shift the instant. This matters more than it looks — see normalise_date.
    """
    if isinstance(value, (int, float)):
        return int(value)
    if not isinstance(value, str):
        return None
    m = _MS_DATE.match(value.strip())
    if m:
        return int(m.group(1)) // 1000
    # Some endpoints return plain ISO. Accept it rather than dropping the field
    # from a fingerprint, which would silently weaken the drift check.
    try:
        t = value.strip().replace("Z", "").split(".")[0]
        return int(time.mktime(time.strptime(t, "%Y-%m-%dT%H:%M:%S")))
    except (ValueError, TypeError):
        return None


def normalise_date(value):
    """The fingerprint hashes THIS, never the raw string.

    Xero can return the same instant as `/Date(123+0000)/` or `/Date(123+1300)/`
    depending on the org's timezone setting, and an ISO string on some
    endpoints. Hashing the raw text would make a timezone change — or a Xero
    serialisation change we do not control — look like ledger drift, and the
    module would refuse a batch that had not moved at all. Phantom drift is
    worse than no drift check: it trains an operator to re-approve without
    reading, which is the exact habit the airlock exists to prevent.
    """
    epoch = parse_xero_date(value)
    return "" if epoch is None else str(epoch)


def today():
    return time.strftime("%Y-%m-%d", time.gmtime())


# ─────────────────────────────────────────────────────────── auth

def _token_path():
    return os.path.join(_h()["WS"], FILE_PREFIX + "token.json")


def _load_token_state():
    return _h()["jload"](_token_path(), {}) or {}


def _post_form(url, form, headers=None):
    """Raw urllib, deliberately NOT the injected http_post_form.

    http_post_form raises RuntimeError on any 4xx with the response body
    flattened into the message string and truncated to 400 bytes. `invalid_grant`
    — the single most important failure this module has — is a 400. Detecting it
    through the helper would mean substring-matching an exception message, which
    breaks the first time Xero rewords anything. Here we read the JSON error body
    and dispatch on the machine-readable `error` field.
    """
    data = urllib.parse.urlencode(form).encode()
    req = urllib.request.Request(url, data=data, method="POST")
    req.add_header("Content-Type", "application/x-www-form-urlencoded")
    for k, v in (headers or {}).items():
        req.add_header(k, v)
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            return r.getcode(), r.read().decode("utf-8")
    except urllib.error.HTTPError as e:
        return e.code, (e.read().decode("utf-8", "replace") or "")
    except urllib.error.URLError as e:
        raise RuntimeError("xero token endpoint unreachable: %s" % e.reason)


class XeroAuthError(RuntimeError):
    pass


def refresh_token(force=False):
    """Return a live access token, rotating and PERSISTING the refresh token.

    THE ORDERING BELOW IS THE WHOLE POINT. Do not reorder it.

    Xero's refresh tokens are single-use: every refresh returns a NEW one and
    invalidates the one just presented. The station's own oauth_refresh helper
    cannot be used here — it explicitly never overwrites refresh_token
    ("Never overwrite refresh_token or the seller-set static fields"), which is
    correct for Salesforce and HubSpot and fatal for Xero.

    So: write the new token to disk BEFORE returning it to the caller. If we
    returned first and the caller crashed, the token we just spent would be dead
    and its replacement lost with the process — recoverable only by redoing the
    browser consent flow.

    Probed 2026-09-03: Xero does honour a spent token for some grace window
    (re-use returned HTTP 200, not invalid_grant). We do not rely on that. The
    window is undocumented and unmeasured, and a design that leans on it fails
    silently the day it changes.
    """
    helpers = _h()
    vault = helpers["vault_get"]("xero-accounting")
    if not isinstance(vault, dict):
        raise XeroAuthError(
            "no xero-accounting credential saved. Add client_id, client_secret, "
            "refresh_token and tenant_id in Studio -> Integrations.")

    state = _load_token_state()
    now = time.time()
    if not force:
        tok = str(state.get("access_token") or "")
        exp = float(state.get("access_expires_at") or 0)
        if tok and now < (exp - SKEW_SECONDS):
            return tok

    # The rotating half lives in our own file once we have refreshed at least
    # once; the vault holds only the bootstrap credential the operator pasted.
    rt = str(state.get("refresh_token") or vault.get("refresh_token") or "").strip()
    cid = str(vault.get("client_id") or "").strip()
    csec = str(vault.get("client_secret") or "").strip()
    if not rt or not cid or not csec:
        raise XeroAuthError(
            "xero-accounting credential incomplete — need client_id, "
            "client_secret and refresh_token.")

    import base64
    basic = base64.b64encode(("%s:%s" % (cid, csec)).encode()).decode()
    status, body = _post_form(
        TOKEN_URL, {"grant_type": "refresh_token", "refresh_token": rt},
        {"Authorization": "Basic " + basic})
    try:
        parsed = json.loads(body or "{}")
    except ValueError:
        raise XeroAuthError("xero token endpoint returned non-JSON (HTTP %s)" % status)

    if status != 200 or not parsed.get("access_token"):
        err = str(parsed.get("error") or "unknown")
        if err == "invalid_grant":
            raise XeroAuthError(
                "Xero rejected the stored refresh token (invalid_grant). Refresh "
                "tokens are single-use and rotate on every refresh; this one has "
                "been spent or has expired. If a previous run was interrupted, the "
                "last token Xero issued is in %s. Otherwise re-authorise the app "
                "and re-save the credential." % _token_path())
        raise XeroAuthError("xero refresh failed (HTTP %s): %s %s"
                            % (status, err, parsed.get("error_description") or ""))

    # If Xero ever stops rotating, keeping the previous token is correct.
    # Writing "" would brick the next run.
    new_rt = str(parsed.get("refresh_token") or "").strip() or rt

    # ---- PERSIST BEFORE RETURNING ----
    helpers["jsave"](_token_path(), {
        "refresh_token": new_rt,
        "access_token": parsed["access_token"],
        "access_expires_at": now + int(parsed.get("expires_in") or 1800),
        "rotated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "rotations": int(state.get("rotations") or 0) + 1,
    })
    # ----------------------------------
    return parsed["access_token"]


def tenant_id():
    v = _h()["vault_get"]("xero-accounting")
    return str((v or {}).get("tenant_id") or "").strip()


# ─────────────────────────────────────────────────────────── http

class XeroApiError(RuntimeError):
    pass


def api(method, resource, token, body=None, params=None, extra_headers=None,
        base=API_BASE, tid=None):
    """One call. Returns (status, headers, parsed).

    Headers come back because the rate-limit counters must be readable from a
    NORMAL 200, not only from a 429 — verify_connection reports remaining quota
    so an operator knows before starting a batch whether it will complete.

    Deliberately does NOT retry. Retry policy is asymmetric and lives at the
    call site: reads may be retried freely, writes only through the idempotency
    ledger. A generic retry here would silently double-post.
    """
    url = base.rstrip("/") + "/" + resource.lstrip("/")
    if params:
        url += "?" + urllib.parse.urlencode(params)
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url, data=data, method=method)
    req.add_header("Authorization", "Bearer " + token)
    req.add_header("Accept", "application/json")
    if data is not None:
        req.add_header("Content-Type", "application/json")
    t = tid or tenant_id()
    if t:
        req.add_header("xero-tenant-id", t)
    for k, v in (extra_headers or {}).items():
        req.add_header(k, v)
    try:
        with urllib.request.urlopen(req, timeout=60) as r:
            status, headers, text = r.getcode(), dict(r.headers), r.read().decode("utf-8")
    except urllib.error.HTTPError as e:
        status, headers, text = e.code, dict(e.headers), e.read().decode("utf-8", "replace")
    except urllib.error.URLError as e:
        raise XeroApiError("xero unreachable: %s" % e.reason)
    try:
        parsed = json.loads(text) if text else {}
    except ValueError:
        parsed = {"_raw": text[:2000]}
    return status, headers, parsed


RATE_HEADERS = ("X-MinLimit-Remaining", "X-DayLimit-Remaining",
                "X-AppMinLimit-Remaining", "X-Rate-Limit-Problem", "Retry-After")


def rate_of(headers):
    low = {k.lower(): v for k, v in (headers or {}).items()}
    return {n: low[n.lower()] for n in RATE_HEADERS if n.lower() in low}


def get_all(resource, token, params=None, max_rows=1000, key=None):
    """Page to completion, or RAISE past the cap. Never truncate silently.

    A half-reported set is worse than an error when somebody is about to act on
    it: the operator sees 40 invoices, approves 40, and the other 187 were never
    shown. Refusing makes them narrow the selector, which is the correct move.
    """
    key = key or resource.split("/")[0]
    rows, page = [], 1
    last_headers = {}
    while True:
        p = dict(params or {})
        p["page"] = page
        st, hd, body = api("GET", resource, token, params=p)
        last_headers = hd
        if st == 401:
            raise XeroApiError(
                "%s refused (401) — this token does not hold the scope for it. "
                "Run verify_connection to see what it can read." % resource)
        if st != 200:
            raise XeroApiError("%s failed (HTTP %s): %s" % (resource, st, str(body)[:300]))
        got = (body or {}).get(key) or []
        rows.extend(got)
        if len(rows) > max_rows:
            raise XeroApiError(
                "%s returned more than max_rows=%d. Refusing rather than "
                "truncating — narrow the selector or raise the cap deliberately."
                % (resource, max_rows))
        if len(got) < 100:      # Xero pages at 100
            break
        page += 1
    return rows, last_headers


# ─────────────────────────────────────────────────────── fingerprints

def _sha(obj):
    return hashlib.sha256(
        json.dumps(obj, sort_keys=True, separators=(",", ":"), default=str).encode()
    ).hexdigest()


def line_fp(inv):
    """Fingerprint of an invoice's LINE ITEMS.

    Line items are inside the invoice fingerprint — not merely the total —
    because a total can stay identical while the account coding underneath it
    changes. Posting revenue to the wrong account is the error an accountant
    actually has to unpick later, and it is invisible to any check that only
    compares Total. Xero validates neither: the recoded invoice is a legal
    write, so nothing but this refuses it.
    """
    rows = []
    for li in (inv.get("LineItems") or []):
        rows.append([str(li.get("LineItemID") or ""), str(li.get("AccountCode") or ""),
                     str(li.get("TaxType") or ""), str(li.get("LineAmount") or "")])
    rows.sort()
    return _sha(rows)


def invoice_fp(inv):
    """The per-invoice fingerprint the approval is bound to.

    UpdatedDateUTC is included because an invoice can be edited in ways this
    command does not read — a field we never fetch, a note, a contact change —
    and a post that lands on an invoice somebody just touched is a post onto a
    record the approver never saw. That is a deliberate over-refusal: it will
    refuse on changes that would have been harmless, and it CANNOT say which
    field moved. Stated in the output rather than hidden.
    """
    return _sha([
        str(inv.get("InvoiceID") or ""),
        str(inv.get("Status") or ""),
        str(inv.get("Total") or ""),
        str(inv.get("AmountDue") or ""),
        str(inv.get("AmountPaid") or ""),
        normalise_date(inv.get("UpdatedDateUTC")),
        line_fp(inv),
    ])


def plan_fp_of(entries):
    """Fingerprint over a whole plan: sorted per-entry fingerprints.

    Sorted so that Xero returning the same set in a different order does not
    invalidate an approval — order is not something the operator reviewed.

    `action_fp` binds WHAT IS BEING DONE to each row, not just which row it is.
    Some plans carry a parameter the operator is really approving — which rung
    of a dunning ladder, which bank account — and plan-level fields are NOT
    hashed here, so a parameter stored beside the entries could be edited after
    approval while the seal still validated. Anything of that kind belongs in
    `action_fp`, inside the entry.

    Entries without an `action_fp` hash exactly as they did before the field
    existed, so a plan written by an earlier version still verifies rather than
    failing as "PLAN FILE ALTERED" after an upgrade.
    """
    parts = []
    for e in entries:
        fp = str(e.get("fp") or "")
        act = str(e.get("action_fp") or "")
        parts.append(fp + "|" + act if act else fp)
    return _sha(sorted(parts))


# ────────────────────────────────────────────────────────── ledger

def _ledger_path():
    return os.path.join(_h()["WS"], FILE_PREFIX + "ledger.json")


def ledger_append(op, outcome, detail):
    """Append to the local hash-chained write ledger.

    Each entry carries the previous entry's hash, so an in-place edit or a
    mid-chain deletion breaks the walk. Tamper-EVIDENT, not tamper-proof:
    whoever holds the file can truncate the tail and re-chain a shorter,
    internally-valid history. Detecting that needs an off-box witness, which
    does not exist here. The claim in verify_ledger's output says exactly this
    and must not be upgraded.
    """
    doc = _h()["jload"](_ledger_path(), {"entries": []}) or {"entries": []}
    entries = doc.get("entries") or []
    prev = entries[-1]["hash"] if entries else None
    body = {"seq": len(entries) + 1, "prev": prev,
            "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "op": op, "outcome": outcome, "detail": detail}
    body["hash"] = _sha(body)
    entries.append(body)
    _h()["jsave"](_ledger_path(), {"entries": entries})
    return body["hash"]


def ledger_verify():
    doc = _h()["jload"](_ledger_path(), {"entries": []}) or {"entries": []}
    entries = doc.get("entries") or []
    prev = None
    for e in entries:
        body = {k: v for k, v in e.items() if k != "hash"}
        if e.get("prev") != prev or _sha(body) != e.get("hash"):
            return len(entries), False, e.get("seq")
        prev = e["hash"]
    return len(entries), True, None


# ────────────────────────────────────────────────── dunning state
#
# WHY THIS FILE IS LOAD-BEARING AND THE LEDGER ABOVE IS NOT
#
# The write ledger records what happened, for an auditor. This records what was
# ALREADY SENT, and it is consulted BEFORE acting. Probed live 2026-09-04: Xero
# applies no deduplication to POST /Invoices/{id}/Email — five sends produced
# five deliveries and five 204s. There is no idempotency key on that endpoint
# (unlike invoice POST, where Xero's own Idempotency-Key genuinely dedupes), and
# `SentToContact` is a latch that says "emailed at least once" without saying
# which stage. So nothing upstream of this file prevents a duplicate delivery.
#
# Same chain construction as the write ledger, and the same honesty about it:
# tamper-EVIDENT, not tamper-proof. Whoever holds the file can truncate the tail
# and re-chain a shorter history. Detecting that needs an off-box witness, which
# does not exist here.
#
# Events are append-only. Current state is a FOLD over them rather than a
# mutable record, because "stage 21 was sent on the 3rd, then skipped on the
# 5th because of a part-payment" is the history an operator asks about, and a
# last-write-wins field cannot answer it.

DUNNING_SENT = "sent"
DUNNING_FAILED = "failed"
DUNNING_REFUSED = "refused"
DUNNING_HOLD = "part_payment_hold"
DUNNING_SKIPPED = "skipped"


def _dunning_path():
    return os.path.join(_h()["WS"], FILE_PREFIX + "dunning_state.json")


def dunning_append(invoice_id, stage, outcome, detail):
    """Append one dunning event, chained to the previous. Returns its hash."""
    doc = _h()["jload"](_dunning_path(), {"events": []}) or {"events": []}
    events = doc.get("events") or []
    prev = events[-1]["hash"] if events else None
    body = {"seq": len(events) + 1, "prev": prev,
            "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "invoice_id": invoice_id, "stage": int(stage),
            "outcome": outcome, "detail": detail}
    body["hash"] = _sha(body)
    events.append(body)
    _h()["jsave"](_dunning_path(), {"events": events})
    return body["hash"]


def dunning_verify():
    doc = _h()["jload"](_dunning_path(), {"events": []}) or {"events": []}
    events = doc.get("events") or []
    prev = None
    for e in events:
        body = {k: v for k, v in e.items() if k != "hash"}
        if e.get("prev") != prev or _sha(body) != e.get("hash"):
            return len(events), False, e.get("seq")
        prev = e["hash"]
    return len(events), True, None


def dunning_history():
    """invoice_id -> [events in order]. One read, folded once per run."""
    doc = _h()["jload"](_dunning_path(), {"events": []}) or {"events": []}
    out = {}
    for e in doc.get("events") or []:
        out.setdefault(e.get("invoice_id"), []).append(e)
    return out


def stages_sent(hist):
    return set(int(e["stage"]) for e in hist if e.get("outcome") == DUNNING_SENT)


def next_due_stage(ladder, hist):
    """The ONE stage this invoice is next owed, or None when the ladder is done.

    This is where "never skip a stage, and never send two in one run" is made
    mechanical rather than left to the caller. An invoice forty days overdue
    that has had nothing sent is owed stage 7 — not stage 21, and not both. A
    workflow that has not run for a fortnight therefore catches up one rung per
    run, which is the declared behaviour in the build spec: two emails in one
    day to somebody who heard nothing for two weeks reads as a malfunction.
    """
    sent = stages_sent(hist)
    for s in ladder:
        if int(s) not in sent:
            return int(s)
    return None


def last_observed_paid(hist):
    """AmountPaid as it stood at the most recent event carrying one."""
    for e in reversed(hist):
        v = (e.get("detail") or {}).get("amount_paid")
        if v is not None:
            try:
                return float(v)
            except (TypeError, ValueError):
                return 0.0
    return 0.0


def idem_key(plan_id, plan_fp, index, payload):
    """Idempotency key for one write.

    A pure function of the APPROVED plan plus this operation's position, never
    a uuid4. A fresh uuid per attempt offers no protection at all: every retry
    would present a new key and Xero would treat it as a new request. The key
    must be identical across retries of the same approved operation, which
    means it must be derived, not generated.

    Probed 2026-09-03: Xero's Idempotency-Key genuinely dedupes — replaying an
    identical POST returned the same InvoiceID. It is a real second layer, used
    IN ADDITION TO this module's ledger, not instead of it.
    """
    return "%s-%s-%d-%s" % (plan_id[:8], plan_fp[:8], index, _sha(payload)[:12])


# ──────────────────────────────────────────────────── plan binding

def _grouped(digest, size=8):
    """A hex digest in space-separated groups, for anything returned INLINE.

    spec-core section 4a: the airlock's identifier scrubber rewrites any run of
    13 or more digits to [account]. A bare 64-character hex digest carries such
    a run roughly one time in twenty, so `plan_fp` was being destroyed in the
    receipt at random — and it is precisely the value an operator copies into
    the apply command. Grouping in eights caps the longest possible digit run at
    eight, so it can never trip the threshold.

    The PLAN FILE keeps the ungrouped digest. Only the display copy is grouped,
    and load_plan accepts either.
    """
    s = str(digest or "")
    return " ".join(s[i:i + size] for i in range(0, len(s), size))


def _ungrouped(value):
    """Normalise a fingerprint that may carry the display grouping."""
    return "".join(str(value or "").split()).lower()


def _action_binding(payload):
    """Fingerprint of WHAT IS BEING DONE to one entry.

    plan_fp_of hashes each entry's `fp` (its ledger state) and its `action_fp`.
    Without the second half, an approval binds only WHICH rows are acted on,
    never WITH WHAT — so any parameter the operator actually reviewed, held
    beside the entries or in an unhashed entry field, could be edited between
    approval and apply while the seal still validated.

    Every apply that reads a parameter out of the plan must recompute this from
    the entry's declared fields and refuse on a mismatch. If a value is read at
    apply and is not inside this hash, it is unbound.
    """
    return _sha(payload)


def check_action_binding(entries, rebuild, what):
    """Refuse any entry whose declared action no longer matches what was sealed.

    Two tamper routes, both closed:
      - edit `action_fp`      -> plan_fp changes -> load_plan refuses upstream
      - edit the field itself -> action_fp no longer recomputes -> refused here

    A plan written before this binding existed has no `action_fp` at all. That
    is refused too, with its own message: such a plan genuinely does not bind
    %s, and silently honouring it would accept the very exposure this closes.
    It is not corruption, so it must not be reported as "PLAN FILE ALTERED".
    """
    out = []
    for e in entries:
        if not e.get("action_fp"):
            out.append({"invoice": e.get("number"),
                        "reason": "this plan predates %s being bound to the "
                                  "approval, so what was approved cannot be "
                                  "verified. Re-run the plan command and approve "
                                  "again." % what})
            continue
        if e["action_fp"] != _action_binding(rebuild(e)):
            out.append({"invoice": e.get("number"),
                        "reason": "%s does not match what was approved — the plan "
                                  "file has been edited since it was sealed" % what})
    return out


def write_plan(kind, entries, extra=None):
    helpers = _h()
    pid = _sha([kind, time.time(), [e.get("id") for e in entries]])[:16]
    fp = plan_fp_of(entries)
    plan = {"plan_id": pid, "plan_fp": fp, "kind": kind,
            "created_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "module_version": VERSION, "entries": entries}
    plan.update(extra or {})
    path = os.path.join(helpers["WS"],
                        "%splan_%s_%s.json" % (FILE_PREFIX, kind, pid))
    helpers["jsave"](path, plan)
    return plan, path


def load_plan(inputs, kind):
    """Load a plan and verify the approval actually binds its CONTENT.

    THIS IS THE LOAD-BEARING CHECK OF THE WHOLE MODULE.

    A RailCall approval binds payload_hash = sha256(command_id + inputs). If the
    apply command took only {"plan_path": ...}, the approval would bind a
    FILENAME — and two entirely different plan bodies at the same path are
    indistinguishable to an auditor reading the receipt. So plan_fp is a
    required input: it travels through the payload hash, and therefore through
    approved_payload_hash, and is re-checked here against the file on disk.

    An operator who approves plan_fp=abc123 has approved that content. If the
    file changed after they looked, this refuses before reading a single row.
    """
    helpers = _h()
    path = str(inputs.get("plan_path") or "")
    claimed = str(inputs.get("plan_fp") or "")
    if not path or not claimed:
        raise XeroApiError("plan_path and plan_fp are both required.")
    plan = helpers["jload"](path, None)
    if not plan:
        raise XeroApiError("no plan at %s" % path)
    if plan.get("kind") != kind:
        raise XeroApiError("plan at %s is a %r plan, not %r — wrong apply command."
                           % (path, plan.get("kind"), kind))
    actual = plan_fp_of(plan.get("entries") or [])
    if actual != plan.get("plan_fp"):
        raise XeroApiError(
            "PLAN FILE ALTERED. Its recorded fingerprint no longer matches its "
            "own contents (recorded %s, recomputed %s). Re-run the plan command."
            % (str(plan.get("plan_fp"))[:16], actual[:16]))
    # Accept the fingerprint with or without its display grouping. Plan commands
    # return it grouped in eights so the airlock's digit-run scrubber cannot
    # destroy it in the receipt; an operator copying from the plan FILE gets the
    # ungrouped form. Both must work, and both normalise to the same value, so
    # neither weakens the check.
    claimed = _ungrouped(claimed)
    if claimed != actual:
        raise XeroApiError(
            "APPROVAL DOES NOT MATCH THIS PLAN. You approved plan_fp=%s; the file "
            "now fingerprints as %s. The approval binds plan CONTENT, not the "
            "filename — re-plan and re-approve." % (claimed[:16], actual[:16]))
    return plan, path


# ─────────────────────────────────────────────────────── the limits
#
# House style: a limit belongs in the response body an operator reads, not
# buried in a README nobody opens at the moment of decision. Two of these admit
# that Xero already guards something — probed, not assumed. A module that
# claims to be the only guard when it is not is one API call from being caught.

_L_INFER = ("reports which reads this token can perform, inferred from what the "
            "API refused. Xero publishes no granted-scope set, so a scope that "
            "is held but unused is reported as unknown, never as granted.")
_L_SCOPED = ("lists what this token can see. Something excluded by scope is "
             "absent, not reported as zero.")
_L_CHAIN = ("tamper-evident, not tamper-proof: it detects edits and mid-chain "
            "deletion, not truncation of the tail by whoever holds the file.")
_L_DRIFT = ("refuses on any drift it can see. A change to a field this command "
            "does not read will still move UpdatedDateUTC and still refuse — "
            "deliberately, and it cannot tell you which field moved.")
_L_VOID = ("a void is a new permanent entry, never a deletion. Xero itself "
           "refuses a void on an invoice with payments; this refuses earlier, "
           "at plan time, and says what changed — it is not the only guard.")
_L_PAY = ("consistent with the payment having been recorded in the ledger, "
          "never a confirmation that funds cleared. Xero itself refuses an "
          "overpayment; this flags it at plan time so you never approve one. "
          "Unlike a posted invoice, a payment recorded here can be deleted "
          "afterwards — the one reversible write in this module.")
_L_POST = ("moving an invoice to AUTHORISED is the point of no return: it can "
           "no longer be deleted, only voided, and the void is permanent too.")
_L_SEND = ("Xero applies NO deduplication to invoice emails — probed live, five "
           "sends produced five deliveries. This module's dunning state is the "
           "only thing preventing a duplicate; if that file is lost the chain "
           "has no memory and will re-send. An email cannot be recalled.")
_L_SEND_BODY = ("the message body is Xero's own standard invoice template. This "
                "command governs WHEN a customer is chased and when the chase "
                "stops; it cannot change what the message says. Probed live: the "
                "endpoint accepts and discards any custom subject or body.")
_L_SEND_DELIV = ("Xero reports the send, not delivery. A recorded send is not a "
                 "received email, and a bounce is invisible here.")
_L_SEND_QUOTA = ("sending can start refusing with an opaque HTTP 500 while the "
                 "tenant rate counters are healthy and Xero reports no "
                 "incident. Measured on a real org: after roughly nine sends "
                 "in a day every further send failed for at least 7.5 minutes "
                 "with no Retry-After, and Xero recorded no send. Cause "
                 "unconfirmed — a daily send quota and an anti-abuse block look "
                 "identical from here. This command halts on the first such "
                 "failure rather than working through a batch that is no longer "
                 "sending.")
_L_REACH = ("the recipient address is never present on the invoice payload; it "
            "comes from a separate Contacts read. A contact with no address "
            "cannot be emailed at all, so the reachable count is reported rather "
            "than assumed.")
_L_GREETING = ("Xero's template greets by Contact.FirstName and does NOT fall "
               "back to the company name — confirmed by reading delivered mail: "
               "a contact with a first name got \"Hi Ayesha,\" and two without "
               "got \"Hi ,\". A contact person's name is NOT counted, because "
               "whether Xero falls back to one is unverified and accepting it "
               "would let a broken greeting through. By default a nameless "
               "contact is refused at plan time; allow_empty_greeting=true "
               "sends anyway, which puts that decision inside the approved "
               "inputs rather than leaving it to chance.")
_L_EMAIL_ABSENT = ("Xero is inconsistent about a missing address: some contacts "
                   "carry EmailAddress as an empty string and others omit the "
                   "key entirely. Both are counted as no address — a key-presence "
                   "test would call the empty ones reachable.")


def _contact_email(contact):
    """The address, or "" — treating BOTH absence shapes as no address.

    Measured on a live org: 25 of 53 contacts carried an `EmailAddress` key and
    only 7 held a non-empty value. So `"EmailAddress" in contact` is the wrong
    test — it would call eighteen unreachable contacts reachable, and each one
    of those becomes a plan promising a send that Xero refuses with HTTP 400.
    """
    return str((contact or {}).get("EmailAddress") or "").strip()


def _as_bool(v, default=False):
    """Coerce a flag the airlock cannot type-check for us.

    approval_airlock's validator (approval_airlock.py, _validate) knows exactly
    four type names — array, string, number, object — plus "no type declared".
    There is NO boolean branch, so a field declared "type": "boolean" is
    REFUSED with "wrong type" the moment anyone supplies a value. Declaring one
    makes the input permanently unusable.

    So a flag has to be declared with no type at all, which means the airlock
    performs no checking on it whatsoever — and a bare bool() would then read
    the string "false" as True, silently inverting the operator's intent on a
    field whose whole job is to gate a customer-facing send. Hence this.
    """
    if isinstance(v, bool):
        return v
    if v is None:
        return default
    if isinstance(v, str):
        return v.strip().lower() in ("true", "1", "yes", "on")
    if isinstance(v, (int, float)):
        return bool(v)
    return default


def _as_int(v, default):
    """Coerce a numeric input WITHOUT swallowing a legitimate zero.

    The obvious `int(inputs.get("x") or default)` treats 0 as absent, because 0
    is falsy — so an operator asking for `overdue_days: 0` ("everything due
    today or later") silently gets 1, and `max_findings: 0` silently gets 1000.
    The command does something other than what was asked and says nothing,
    which is the quiet half of the same family as the boolean bug: the input is
    accepted, and ignored.

    Only None and "" mean "not supplied".
    """
    if v is None or v == "":
        return int(default)
    return int(v)


def _contact_greeting_name(contact):
    """The name Xero's template greets by: `Contact.FirstName`, and ONLY that.

    Confirmed by reading delivered mail, not inferred. Three invoices were sent
    from one org on the same day:

        FirstName = "Ayesha"          -> "Hi Ayesha,"
        no personal name at all       -> "Hi ,"
        no personal name at all       -> "Hi ,"

    Xero renders the gap and does NOT fall back to the company `Name`. A dunning
    email opening "Hi ," undermines the request it is making, and like any send
    it cannot be recalled.

    A CONTACT PERSON'S first name is deliberately NOT accepted here. Whether
    Xero's template falls back to one is unverified — the probe that would have
    answered it collapsed because Xero silently dropped `ContactPersons` on a
    contact create, so that case was indistinguishable from the control.
    Accepting it would let a contact through this check and still send "Hi ,",
    which is the one outcome the rule exists to prevent. UNKNOWN is never a
    pass, so an unproven fallback does not count as a name.

    Absence has the same two shapes as EmailAddress — Xero omits the key on some
    records and returns "" on others — so this tests the VALUE, never presence.
    """
    return str((contact or {}).get("FirstName") or "").strip()


def _contact_person_name(contact):
    """A contact person's first name, if the contact carries one.

    Reported separately so an excluded row can say "there is a contact person,
    but Xero's use of it is unverified" rather than the blunter "no name" — the
    operator's fix differs between the two.
    """
    for p in ((contact or {}).get("ContactPersons") or []):
        pn = str((p or {}).get("FirstName") or "").strip()
        if pn:
            return pn
    return ""


def _iso_day(epoch):
    """Epoch -> YYYY-MM-DD, or "" — never a raw Xero /Date(...)/ string.

    Raw Xero dates carry a 13-digit millisecond run, which the airlock's
    identifier scrubber rewrites to [account]. These land in artifacts rather
    than inline, but an artifact an operator reads should still be legible.
    """
    if epoch is None:
        return ""
    return time.strftime("%Y-%m-%d", time.gmtime(epoch))


# ──────────────────────────────────────────────────────── 1. verify

def xero_accounting_verify_connection(inputs, stamp):
    token = refresh_token()
    st, hd, conns = api("GET", "", token, base=CONNECTIONS_URL)
    tenants = conns if isinstance(conns, list) else []
    configured = tenant_id()
    match = [c for c in tenants if c.get("tenantId") == configured]

    # One cheap read per scope group. Xero has no introspection endpoint, so
    # inference is the only route. 401 is the missing-scope shape; Attachments
    # answers 404 for the same condition (probed) — treat both as not granted.
    probes = [("accounting.settings", "Organisation"),
              ("accounting.settings", "Accounts"),
              ("accounting.contacts", "Contacts"),
              ("accounting.invoices", "Invoices"),
              ("accounting.payments", "Payments")]
    inferred, rate = {}, {}
    for scope, res in probes:
        s, h, _b = api("GET", res, token, params={"page": 1})
        rate = rate_of(h) or rate
        verdict = "granted" if s == 200 else ("not granted (HTTP %d)" % s)
        inferred.setdefault(scope, verdict)
        if s == 200:
            inferred[scope] = "granted"

    tstate = _load_token_state()
    ready = "yes" if (match and all(v == "granted" for v in inferred.values())) else "partial"

    out = {
        "ready": ready,
        "tenants": [{"name": c.get("tenantName"), "id": c.get("tenantId")} for c in tenants],
        # Surfaced because DELETE /connections/{id} returns 204 and silently
        # kills every token. An admin disconnecting the app looks IDENTICAL to
        # an expired token from the error alone, and the fixes differ.
        "connection_id": (match[0].get("id") if match else None),
        "configured_tenant": configured or "(none set)",
        "tenant_matches": bool(match),
        "inferred_scopes": inferred,
        "rate": rate,
        # NOT named "token": approval_airlock.redact() masks any field whose
        # NAME contains token/key/secret/password before sealing a receipt, so
        # a block called "token" is destroyed even though it holds no secret —
        # observed live 2026-09-03, the whole block came back as "••••••".
        # These are rotation diagnostics an operator needs when debugging an
        # invalid_grant; the field name is what has to change, not the content.
        "credential_state": {
            "rotations": tstate.get("rotations", 0),
            "last_rotated": tstate.get("rotated_at") or "never",
            "access_cached": bool(tstate.get("access_token"))},
        "limits": [_L_INFER],
    }
    if not tenants:
        # DELETE /connections/{id} returns 204 and silently kills every token;
        # resetting a Xero demo company does the same. From the error alone this
        # is indistinguishable from an expired token, and the fixes differ — so
        # name it.
        out["limits"].append(
            "this app holds NO connection to any organisation. Either it was "
            "disconnected in Xero (Settings -> Connected apps), or the org was "
            "reset. Re-authorise the app; re-saving the credential will not help, "
            "because the refresh token is valid and the connection is not.")
    elif not match:
        out["limits"].append(
            "the configured tenant_id is not in this token's connections — a write "
            "would land in the wrong organisation, so every command will refuse.")
    return out, None


# ────────────────────────────────────────────────────── 2. describe

def xero_accounting_describe_org(inputs, stamp):
    token = refresh_token()
    st, hd, org = api("GET", "Organisation", token)
    if st != 200:
        raise XeroApiError("Organisation failed (HTTP %s)" % st)
    o = ((org or {}).get("Organisations") or [{}])[0]
    accounts, _ = get_all("Accounts", token, key="Accounts")
    rates, _ = get_all("TaxRates", token, key="TaxRates")
    tracking, _ = get_all("TrackingCategories", token, key="TrackingCategories")

    lock_raw = o.get("PeriodLockDate")
    eoy_raw = o.get("EndOfYearLockDate")
    doc = {
        "organisation": {k: o.get(k) for k in
                         ("Name", "LegalName", "BaseCurrency", "CountryCode",
                          "Timezone", "FinancialYearEndDay", "FinancialYearEndMonth",
                          "OrganisationStatus", "IsDemoCompany")},
        "period_lock_date": lock_raw,
        "period_lock_epoch": parse_xero_date(lock_raw),
        "end_of_year_lock_date": eoy_raw,
        "accounts": [{k: a.get(k) for k in ("Code", "Name", "Type", "Class",
                                            "TaxType", "Status", "AccountID")}
                     for a in accounts],
        "tax_rates": [{k: t.get(k) for k in ("Name", "TaxType", "EffectiveRate",
                                             "Status")} for t in rates],
        "tracking_categories": [{k: t.get(k) for k in
                                 ("Name", "Status", "TrackingCategoryID")}
                                for t in tracking],
    }
    path = os.path.join(_h()["WS"], "%sdescribe_%s.json" % (FILE_PREFIX, stamp.replace(":", "")))
    _h()["jsave"](path, doc)

    limits = [_L_SCOPED,
              "dates are Microsoft JSON epoch (/Date(ms+offset)/), not ISO 8601. "
              "This module normalises them before hashing so a timezone change "
              "cannot look like ledger drift.",
              "period_lock reports only whether a lock is set. The date itself is "
              "in the artifact, not in this receipt: the airlock's identifier "
              "scrubber rewrites the epoch in /Date(...)/ to [account], so a date "
              "returned inline would be destroyed on the way into the receipt."]
    if eoy_raw is None:
        # Absent is ambiguous and must not be reported as "no lock".
        limits.append("EndOfYearLockDate is absent from this organisation's "
                      "response. That means either no year-end lock is set or "
                      "this org does not expose one — the API does not "
                      "distinguish them, and neither does this command.")
    # STATUS inline, VALUE in the file. The raw date cannot survive a receipt:
    # /Date(1222732800000+0000)/ carries a long digit run, and the airlock's
    # identifier scrubber rewrites it to /Date([account]+0000)/ before sealing —
    # so the field an operator reads is destroyed while the artifact keeps the
    # truth. Same class as the `token` field this module already renamed, but a
    # different scrubber: that one masks by field NAME, this one by value SHAPE,
    # so renaming does not help and only moving the value does.
    #
    # This follows the module's own file-vs-inline rule: anything an operator
    # must ACT on goes to a file; only counts, verdicts and labels go inline.
    # A lock date is acted on, so it goes to the file and the receipt carries
    # the verdict.
    return {"artifact": path,
            "counts": {"accounts": len(accounts), "tax_rates": len(rates),
                       "tracking_categories": len(tracking)},
            "period_lock": "set" if lock_raw else "(none)",
            "limits": limits}, {"path": path, "kind": "describe_org"}


# ─────────────────────────────────────────────────────── 3. hygiene

def xero_accounting_hygiene_scan(inputs, stamp):
    token = refresh_token()
    draft_days = _as_int(inputs.get("draft_days"), 14)
    overdue_days = _as_int(inputs.get("overdue_days"), 1)
    cap = _as_int(inputs.get("max_findings"), 1000)
    now = time.time()

    findings = []

    def add(kind, inv, detail, fixed_by, extra=None):
        row = {"finding": kind, "invoice_id": inv.get("InvoiceID"),
               "number": inv.get("InvoiceNumber"),
               "contact": (inv.get("Contact") or {}).get("Name"),
               "contact_id": (inv.get("Contact") or {}).get("ContactID"),
               "total": inv.get("Total"), "amount_due": inv.get("AmountDue"),
               "detail": detail, "fixed_by": fixed_by}
        row.update(extra or {})
        findings.append(row)

    invoices, hd = get_all("Invoices", token, params={"where": 'Type=="ACCREC"'},
                           max_rows=cap * 2, key="Invoices")
    for inv in invoices:
        status = inv.get("Status")
        d = parse_xero_date(inv.get("DateString") or inv.get("Date"))
        due = parse_xero_date(inv.get("DueDateString") or inv.get("DueDate"))
        age_days = int((now - d) / 86400) if d else 0
        if status == "DRAFT" and age_days >= draft_days:
            add("draft_ageing", inv, "%d days in DRAFT — revenue not recognised" % age_days,
                "xero_accounting.plan_invoice_post")
        elif status == "SUBMITTED" and age_days >= draft_days:
            add("submitted_ageing", inv, "%d days awaiting approval" % age_days,
                "xero_accounting.plan_invoice_post")
        elif status == "AUTHORISED" and due and (now - due) / 86400 >= overdue_days:
            od = int((now - due) / 86400)
            bucket = "1-30" if od <= 30 else ("31-60" if od <= 60 else ("61-90" if od <= 90 else "90+"))
            # days_overdue, due_date and contact_id are STRUCTURED fields, not
            # prose. v0.1.1 put the number only inside `detail` — "47 days
            # overdue (bucket 31-60)" — so anything downstream had to regex a
            # human-readable sentence to get the value that decides which stage
            # an invoice is owed. A sentence is not an interface: rewording the
            # message would silently change which reminder a customer receives.
            add("overdue", inv, "%d days overdue (bucket %s)" % (od, bucket),
                "xero_accounting.plan_send_reminder",
                {"days_overdue": od, "due_date": _iso_day(due), "bucket": bucket})
        try:
            if float(inv.get("AmountPaid") or 0) > float(inv.get("Total") or 0):
                add("overpaid", inv, "AmountPaid exceeds Total",
                    "xero_accounting.plan_payment_allocate")
        except (TypeError, ValueError):
            pass
        if len(findings) > cap:
            raise XeroApiError(
                "more than max_findings=%d. Refusing rather than truncating — a "
                "half-reported set is worse than an error when you are about to "
                "act on it. Narrow the window or raise the cap deliberately." % cap)

    doc = {"generated_at": stamp, "thresholds": {"draft_days": draft_days,
                                                 "overdue_days": overdue_days},
           "findings": findings}
    path = os.path.join(_h()["WS"], "%shygiene_%s.json" % (FILE_PREFIX, stamp.replace(":", "")))
    _h()["jsave"](path, doc)
    counts = {}
    for f in findings:
        counts[f["finding"]] = counts.get(f["finding"], 0) + 1
    return {"artifact": path, "counts": counts, "total_findings": len(findings),
            "limits": [_L_SCOPED,
                       "scans sales invoices (ACCREC) only. Bills, credit notes "
                       "and bank transactions are not covered by this version and "
                       "are not reported as clean."]}, {"path": path, "kind": "hygiene_scan"}


# ──────────────────────────────────────────────────────── 4. ledger

def xero_accounting_verify_ledger(inputs, stamp):
    n, intact, first_break = ledger_verify()
    # The dunning chain is verified here too rather than in a command of its own.
    # It is the same construction and the same claim, and an operator asking "is
    # my record intact" means both files — a separate command would let one be
    # checked while the other rots.
    dn, dintact, dbreak = dunning_verify()
    return {"entries": n,
            "chain_intact": "yes" if intact else "NO",
            "first_break": ("seq %s" % first_break) if first_break else "(none)",
            "dunning_events": dn,
            "dunning_chain_intact": "yes" if dintact else "NO",
            "dunning_first_break": ("seq %s" % dbreak) if dbreak else "(none)",
            "limits": [_L_CHAIN,
                       "covers two chains: the write ledger and the dunning "
                       "state. A break in the dunning chain means the duplicate-"
                       "send guard cannot be trusted, because that record is the "
                       "only thing preventing a repeat delivery."]}, None


# ──────────────────────────────────────────── 5/6. invoice post

def _fetch_invoices(token, ids=None, status=None, contact_id=None, cap=200):
    if ids:
        rows = []
        for iid in ids:
            st, hd, b = api("GET", "Invoices/%s" % iid, token)
            if st != 200:
                raise XeroApiError("invoice %s not readable (HTTP %s)" % (iid, st))
            rows.extend((b or {}).get("Invoices") or [])
        return rows
    where = ['Type=="ACCREC"']
    if status:
        where.append('Status=="%s"' % status)
    if contact_id:
        where.append('Contact.ContactID==GUID("%s")' % contact_id)
    rows, _ = get_all("Invoices", token, params={"where": "&&".join(where)},
                      max_rows=cap, key="Invoices")
    return rows


def _entry(inv):
    return {"id": inv.get("InvoiceID"), "number": inv.get("InvoiceNumber"),
            "contact": (inv.get("Contact") or {}).get("Name"),
            "status": inv.get("Status"), "total": inv.get("Total"),
            "amount_due": inv.get("AmountDue"), "amount_paid": inv.get("AmountPaid"),
            "updated": normalise_date(inv.get("UpdatedDateUTC")),
            "line_items": [{"account_code": li.get("AccountCode"),
                            "tax_type": li.get("TaxType"),
                            "amount": li.get("LineAmount"),
                            "description": li.get("Description")}
                           for li in (inv.get("LineItems") or [])],
            # Stored so _drift_check can compare like with like. The displayed
            # line_items above drop LineItemID (an operator does not read GUIDs),
            # so rebuilding a hash from them can never match line_fp(). The first
            # cut did exactly that and reported "line items recoded" on EVERY
            # drift — a fabricated reason on a command whose entire value is
            # naming what actually moved.
            "line_fp": line_fp(inv),
            "fp": invoice_fp(inv)}


def xero_accounting_plan_invoice_post(inputs, stamp):
    token = refresh_token()
    cap = _as_int(inputs.get("max_invoices"), 200)
    invs = _fetch_invoices(token, ids=inputs.get("invoice_ids"),
                           status=(inputs.get("status") or "DRAFT").upper(),
                           contact_id=inputs.get("contact_id"), cap=cap)
    if not invs:
        return {"artifact": None, "count": 0, "total": "0",
                "limits": ["nothing matched the selector; no plan was written."]}, None
    entries = [_entry(i) for i in invs]
    total = sum(float(e.get("total") or 0) for e in entries)
    plan, path = write_plan("invoice_post", entries, {"target_status": "AUTHORISED"})
    return {"artifact": path,
            "plan_id": _grouped(plan["plan_id"]),
            "plan_fp": _grouped(plan["plan_fp"]),
            "count": len(entries), "total": "%.2f" % total,
            "limits": [_L_POST, _L_DRIFT,
                       "reads only. Nothing is posted until apply_invoice_post "
                       "runs with this plan_fp and a human approval."]}, \
           {"path": path, "kind": "plan_invoice_post"}


def _drift_check(token, plan):
    """Re-read every entry and return (fresh_by_id, drift list). One read pass
    over everything BEFORE any write goes out — reads are cheap, and this
    collapses the drift window to the write phase alone."""
    ids = [e["id"] for e in plan["entries"]]
    fresh = {i.get("InvoiceID"): i for i in _fetch_invoices(token, ids=ids)}
    drift = []
    for e in plan["entries"]:
        cur = fresh.get(e["id"])
        if cur is None:
            drift.append({"invoice": e.get("number"), "reason": "no longer readable"})
            continue
        if invoice_fp(cur) != e["fp"]:
            why = []
            if str(cur.get("Status")) != str(e.get("status")):
                why.append("status %s -> %s" % (e.get("status"), cur.get("Status")))
            if str(cur.get("AmountPaid")) != str(e.get("amount_paid")):
                why.append("AmountPaid %s -> %s" % (e.get("amount_paid"), cur.get("AmountPaid")))
            if str(cur.get("AmountDue")) != str(e.get("amount_due")):
                why.append("AmountDue %s -> %s" % (e.get("amount_due"), cur.get("AmountDue")))
            if str(cur.get("Total")) != str(e.get("total")):
                why.append("Total %s -> %s" % (e.get("total"), cur.get("Total")))
            if e.get("line_fp") and line_fp(cur) != e["line_fp"]:
                why.append("line items recoded or amended")
            if not why:
                why.append("UpdatedDateUTC moved — a field this command does not "
                           "read was changed")
            drift.append({"invoice": e.get("number"), "reason": "; ".join(why)})
    return fresh, drift


def _post_batch(token, payload, plan, index_base=0):
    """POST with summarizeErrors=false and read the PER-ELEMENT verdict.

    Probed 2026-09-03: without the parameter, one bad element rejects the whole
    batch with HTTP 400. WITH it, Xero returns HTTP 200 and puts per-element
    failures inside the body. A handler that checks only the status code
    reports success while elements failed — the same class of bug as the Zoho
    merge endpoint that returned 200 while doing nothing. So: never trust the
    status code alone here.
    """
    key = idem_key(plan["plan_id"], plan["plan_fp"], index_base, payload)
    st, hd, body = api("POST", "Invoices", token, body=payload,
                       params={"summarizeErrors": "false"},
                       extra_headers={"Idempotency-Key": key})
    rows = (body or {}).get("Invoices") or [] if isinstance(body, dict) else []
    ok, failed = [], []
    for r in rows:
        errs = r.get("ValidationErrors") or []
        if str(r.get("StatusAttributeString") or "").upper() == "ERROR" or errs:
            failed.append({"number": r.get("InvoiceNumber") or r.get("Reference"),
                           "invoice_id": r.get("InvoiceID"),
                           "errors": [e.get("Message") for e in errs][:3]})
        else:
            ok.append({"number": r.get("InvoiceNumber"), "invoice_id": r.get("InvoiceID"),
                       "status": r.get("Status")})
    if st != 200 and not rows:
        raise XeroApiError("batch POST failed (HTTP %s): %s" % (st, str(body)[:400]))
    return ok, failed, rate_of(hd)


def _apply_invoice_status(inputs, stamp, kind, target_status, extra_guard=None,
                          limits=None, op_name=None):
    """Shared body for apply_invoice_post and apply_invoice_void.

    Both re-read, refuse the WHOLE batch on any drift, then write. Refusing
    rather than half-posting is deliberate: a partially posted batch leaves the
    operator working out which invoices went through, and each one that did is
    now non-deletable.
    """
    token = refresh_token()
    plan, path = load_plan(inputs, kind)
    fresh, drift = _drift_check(token, plan)

    if extra_guard:
        drift = drift + extra_guard(plan, fresh)

    if drift:
        ledger_append(op_name, "refused_drift",
                      {"plan_id": plan["plan_id"], "plan_fp": plan["plan_fp"],
                       "drift": drift[:20]})
        return {"committed": 0, "failed": 0, "refused": len(plan["entries"]),
                "drift": drift[:20], "artifact": path,
                "limits": (limits or []) + [
                    "REFUSED. The ledger moved between plan and approval, so this "
                    "is no longer the write you approved. Re-run the plan command, "
                    "review the change, and approve again."]}, None

    # Probed 2026-09-03: a partial POST (InvoiceID + Status only) does NOT blank
    # unsent fields — Reference, LineItems and Total all survived. So we send the
    # minimum rather than echoing the whole plan-time body.
    payload = {"Invoices": [{"InvoiceID": e["id"], "Status": target_status}
                            for e in plan["entries"]]}
    ok, failed, rate = _post_batch(token, payload, plan)

    ledger_append(op_name, "committed" if not failed else "partial",
                  {"plan_id": plan["plan_id"], "plan_fp": plan["plan_fp"],
                   "target": target_status, "ok": len(ok), "failed": len(failed),
                   "composite_fp": inputs.get("composite_fp"),
                   "ids": [o["invoice_id"] for o in ok][:50]})

    result = {"plan_id": plan["plan_id"], "target_status": target_status,
              "committed": ok, "failed": failed, "rate": rate}
    rpath = os.path.join(_h()["WS"], "%scustody_%s_%s.json"
                         % (FILE_PREFIX, kind, stamp.replace(":", "")))
    _h()["jsave"](rpath, result)

    out = {"committed": len(ok), "failed": len(failed), "refused": 0,
           "artifact": rpath, "limits": list(limits or [])}
    if failed:
        out["limits"].append(
            "%d element(s) were rejected by Xero inside an HTTP 200 response. "
            "They are named in the artifact. Nothing was rolled back: a rollback "
            "is itself a write that can fail, and a half-rolled-back batch is "
            "worse than a halted one that is fully accounted for." % len(failed))
    return out, {"path": rpath, "kind": kind}


def xero_accounting_apply_invoice_post(inputs, stamp):
    return _apply_invoice_status(inputs, stamp, "invoice_post", "AUTHORISED",
                                 limits=[_L_POST, _L_DRIFT],
                                 op_name="apply_invoice_post")


# ──────────────────────────────────────────── 7/8. invoice void

def xero_accounting_plan_invoice_void(inputs, stamp):
    token = refresh_token()
    ids = inputs.get("invoice_ids") or []
    if not ids:
        raise XeroApiError("invoice_ids is required.")
    cap = _as_int(inputs.get("max_invoices"), 200)
    if len(ids) > cap:
        raise XeroApiError("more than max_invoices=%d — refusing rather than truncating." % cap)

    st, hd, org = api("GET", "Organisation", token)
    lock_epoch = parse_xero_date(((org or {}).get("Organisations") or [{}])[0]
                                 .get("PeriodLockDate"))

    invs = _fetch_invoices(token, ids=ids)
    entries, voidable, blocked = [], 0, 0
    for inv in invs:
        e = _entry(inv)
        reasons = []
        try:
            if float(inv.get("AmountPaid") or 0) > 0:
                reasons.append("has payments totalling %s — Xero refuses a void "
                               "on a paid invoice" % inv.get("AmountPaid"))
        except (TypeError, ValueError):
            pass
        # Xero's status machine, verified live 2026-09-03: only an AUTHORISED
        # invoice is VOIDED. A DRAFT or SUBMITTED one is DELETED — posting
        # Status=VOIDED to a draft is refused with "Invoice not of valid status
        # for modification". The first cut of this treated all three as
        # voidable, so the plan told the operator "voidable: True" and the apply
        # then failed on every row. A plan that promises something the API will
        # refuse is worse than no plan: it spends a human approval on a write
        # that could never land.
        st = inv.get("Status")
        if st in ("DRAFT", "SUBMITTED"):
            reasons.append(
                "status is %s — Xero DELETES a draft, it does not void one. "
                "This command only voids AUTHORISED invoices; deleting a draft "
                "is not wired in v0.1." % st)
        elif st != "AUTHORISED":
            reasons.append("status is %s — only AUTHORISED invoices can be voided" % st)
        if (inv.get("CreditNotes") or []):
            reasons.append("has %d allocated credit note(s)" % len(inv["CreditNotes"]))
        d = parse_xero_date(inv.get("DateString") or inv.get("Date"))
        if lock_epoch and d and d <= lock_epoch:
            reasons.append("invoice date falls inside the locked period")
        e["payments"] = [{"id": p.get("PaymentID"), "amount": p.get("Amount"),
                          "date": normalise_date(p.get("Date"))}
                         for p in (inv.get("Payments") or [])]
        e["voidable"] = not reasons
        e["blocked_because"] = reasons
        # _void_guard REFUSES on blocked_because at apply time, so that list is
        # a control, not a display field — and it was not inside the
        # fingerprint. Emptying it on a sealed plan turned "this invoice cannot
        # be voided" into "go ahead" with the approval still valid. Xero backs
        # some of those reasons up (it refuses a void on a paid invoice) but not
        # all of them: a period-lock or credit-note block was ours alone.
        e["action_fp"] = _action_binding({"blocked_because": sorted(reasons)})
        entries.append(e)
        voidable += 1 if not reasons else 0
        blocked += 1 if reasons else 0

    plan, path = write_plan("invoice_void", entries,
                            {"target_status": "VOIDED",
                             "period_lock_epoch": lock_epoch})
    return {"artifact": path,
            "plan_id": _grouped(plan["plan_id"]),
            "plan_fp": _grouped(plan["plan_fp"]),
            "voidable": voidable, "blocked": blocked,
            "limits": [_L_VOID, _L_DRIFT]}, {"path": path, "kind": "plan_invoice_void"}


def _void_guard(plan, fresh):
    """Refuse anything the plan itself marked unvoidable, and anything that
    acquired a payment since. Checked separately from the fingerprint because
    an operator can approve a plan containing blocked rows — the plan is a
    report as well as a request."""
    out = check_action_binding(
        plan["entries"],
        lambda e: {"blocked_because": sorted(e.get("blocked_because") or [])},
        "the plan-time voidability verdict")
    for e in plan["entries"]:
        if e.get("blocked_because"):
            out.append({"invoice": e.get("number"),
                        "reason": "not voidable at plan time: " + "; ".join(e["blocked_because"])})
            continue
        cur = fresh.get(e["id"])
        if cur is not None:
            try:
                if float(cur.get("AmountPaid") or 0) > 0:
                    out.append({"invoice": e.get("number"),
                                "reason": "a payment landed since the plan was reviewed"})
            except (TypeError, ValueError):
                pass
    return out


def xero_accounting_apply_invoice_void(inputs, stamp):
    return _apply_invoice_status(inputs, stamp, "invoice_void", "VOIDED",
                                 extra_guard=_void_guard,
                                 limits=[_L_VOID, _L_DRIFT],
                                 op_name="apply_invoice_void")


# ────────────────────────────────────── 9/10. payment allocate

def xero_accounting_plan_payment_allocate(inputs, stamp):
    token = refresh_token()
    allocs = inputs.get("allocations") or []
    account_id = str(inputs.get("account_id") or "")
    if not allocs or not account_id:
        raise XeroApiError("allocations and account_id are both required.")

    ids = [str(a.get("invoice_id") or "") for a in allocs]
    invs = {i.get("InvoiceID"): i for i in _fetch_invoices(token, ids=ids)}
    entries, overpays, total = [], 0, 0.0
    for a in allocs:
        iid = str(a.get("invoice_id") or "")
        inv = invs.get(iid)
        if inv is None:
            raise XeroApiError("invoice %s not readable" % iid)
        amount = float(a.get("amount") or 0)
        due = float(inv.get("AmountDue") or 0)
        e = _entry(inv)
        e["allocate_amount"] = amount
        e["allocate_date"] = a.get("date") or today()
        e["resulting_due"] = round(due - amount, 2)
        e["overpays"] = amount > due
        # THE AMOUNT, THE DATE AND THE DESTINATION ACCOUNT ARE WHAT THE OPERATOR
        # APPROVED. None of them was inside the fingerprint before v0.1.2:
        # plan_fp hashes each entry's `fp`, which is the INVOICE's state, and
        # amount/date sat beside it while account_id sat at plan level. So a
        # sealed, validly-approved plan could be edited to move a different sum
        # to a different bank account and the receipt would still verify. That is
        # the module's own central claim failing on the one write that moves
        # money. account_id goes into every entry's binding rather than being
        # checked once, so the approval covers the destination per row.
        e["action_fp"] = _action_binding({"account_id": account_id,
                                          "amount": amount,
                                          "date": e["allocate_date"]})
        if e["overpays"]:
            overpays += 1
        total += amount
        entries.append(e)

    plan, path = write_plan("payment_allocate", entries, {"account_id": account_id})
    limits = [_L_PAY, _L_DRIFT]
    if overpays:
        limits.append("%d allocation(s) exceed the amount due. Xero will refuse "
                      "those writes; they are flagged here so you do not approve "
                      "a batch that cannot succeed." % overpays)
    return {"artifact": path,
            "plan_id": _grouped(plan["plan_id"]),
            "plan_fp": _grouped(plan["plan_fp"]),
            "count": len(entries), "total": "%.2f" % total, "overpays": overpays,
            "limits": limits}, {"path": path, "kind": "plan_payment_allocate"}


def xero_accounting_apply_payment_allocate(inputs, stamp):
    token = refresh_token()
    plan, path = load_plan(inputs, "payment_allocate")
    fresh, drift = _drift_check(token, plan)
    if drift:
        ledger_append("apply_payment_allocate", "refused_drift",
                      {"plan_id": plan["plan_id"], "plan_fp": plan["plan_fp"],
                       "drift": drift[:20]})
        return {"recorded": 0, "failed": 0, "refused": len(plan["entries"]),
                "drift": drift[:20], "artifact": path,
                "limits": [_L_PAY,
                           "REFUSED. A rising AmountPaid means a payment landed "
                           "while this allocation sat in review — applying the "
                           "reviewed amount now would overpay the invoice."]}, None

    account_id = plan.get("account_id")
    # Recompute every entry's binding from the fields this apply is about to
    # ACT on, including the plan-level account_id. A mismatch means the amount,
    # the date or the destination account moved after the human sealed it.
    unbound = check_action_binding(
        plan["entries"],
        lambda e: {"account_id": account_id,
                   "amount": e.get("allocate_amount"),
                   "date": e.get("allocate_date")},
        "the payment amount, date or destination account")
    if unbound:
        ledger_append("apply_payment_allocate", "refused_unbound",
                      {"plan_id": plan["plan_id"], "plan_fp": plan["plan_fp"],
                       "unbound": unbound[:20]})
        return {"recorded": 0, "failed": 0, "refused": len(plan["entries"]),
                "drift": unbound[:20], "artifact": path,
                "limits": [_L_PAY,
                           "REFUSED. What this plan would pay is not what was "
                           "approved. Nothing was recorded."]}, None

    recorded, failed = [], []
    for idx, e in enumerate(plan["entries"]):
        # Payments POST one at a time: Xero has no per-element verdict for this
        # endpoint, so a batch would be all-or-nothing on a 400 and we would
        # lose the account of which ones landed.
        payload = {"Payments": [{"Invoice": {"InvoiceID": e["id"]},
                                 "Account": {"AccountID": account_id},
                                 "Date": e.get("allocate_date") or today(),
                                 "Amount": e.get("allocate_amount")}]}
        key = idem_key(plan["plan_id"], plan["plan_fp"], idx, payload)
        st, hd, body = api("POST", "Payments", token, body=payload,
                           extra_headers={"Idempotency-Key": key})
        rows = (body or {}).get("Payments") or [] if isinstance(body, dict) else []
        if st == 200 and rows:
            recorded.append({"invoice": e.get("number"),
                             "payment_id": rows[0].get("PaymentID"),
                             "amount": e.get("allocate_amount")})
        else:
            msg = ""
            if isinstance(body, dict):
                els = body.get("Elements") or []
                errs = (els[0].get("ValidationErrors") if els else []) or []
                msg = "; ".join(x.get("Message", "") for x in errs[:2]) or \
                      str(body.get("Message") or "")[:160]
            failed.append({"invoice": e.get("number"), "error": msg or ("HTTP %s" % st)})
            # HALT on first failure. Continuing would keep spending an approval
            # against a ledger that has already behaved unexpectedly.
            break

    ledger_append("apply_payment_allocate",
                  "committed" if not failed else "partial",
                  {"plan_id": plan["plan_id"], "plan_fp": plan["plan_fp"],
                   "account_id": account_id, "recorded": len(recorded),
                   "failed": len(failed),
                   "composite_fp": inputs.get("composite_fp"),
                   "payment_ids": [r["payment_id"] for r in recorded][:50]})

    result = {"plan_id": plan["plan_id"], "recorded": recorded, "failed": failed}
    rpath = os.path.join(_h()["WS"], "%scustody_payment_%s.json"
                         % (FILE_PREFIX, stamp.replace(":", "")))
    _h()["jsave"](rpath, result)

    limits = [_L_PAY]
    if failed:
        limits.append("halted at the first failure. %d payment(s) were recorded "
                      "before it and are named in the artifact; nothing was "
                      "rolled back. Each recorded payment CAN be deleted in Xero "
                      "if you need to reverse it." % len(recorded))
    return {"recorded": len(recorded), "failed": len(failed), "refused": 0,
            "artifact": rpath, "limits": limits}, {"path": rpath, "kind": "payment_allocate"}


# ─────────────────────────────────────────── 11. list contacts

def _load_contacts(token, cap=2000):
    """Every contact, in ONE paged read. contact_id -> contact.

    Deliberately not a call per contact. The address is never on the invoice
    payload — measured: 0 of 10 authorised invoices carried EmailAddress, and
    the embedded Contact holds only ContactID, Name, Addresses, ContactPersons,
    Phones and HasValidationErrors. So it has to come from /Contacts, and the
    list endpoint returns it. Per-contact reads would burn one call each against
    a 1,000/day tenant budget to fetch what one paged read already has.
    """
    rows, _ = get_all("Contacts", token, max_rows=cap, key="Contacts")
    return {c.get("ContactID"): c for c in rows}


def xero_accounting_list_contacts(inputs, stamp):
    token = refresh_token()
    cap = _as_int(inputs.get("max_contacts"), 2000)
    rows, hd = get_all("Contacts", token, max_rows=cap, key="Contacts")

    only_reachable = _as_bool(inputs.get("only_reachable"))
    out_rows, reachable, greetable = [], 0, 0
    for c in rows:
        addr = _contact_email(c)
        if _contact_greeting_name(c):
            greetable += 1
        if addr:
            reachable += 1
        elif only_reachable:
            continue
        out_rows.append({
            "contact_id": c.get("ContactID"),
            "name": c.get("Name"),
            "email_address": addr,
            # A STATUS word inline-safe by construction, so a reader of the
            # artifact does not have to infer reachability from an empty string
            # that Xero may also have omitted entirely.
            "address_state": "set" if addr else "(none)",
            "greeting_name": _contact_greeting_name(c),
            "greeting_state": ("set" if _contact_greeting_name(c)
                               else ("(contact person only — unverified)"
                                     if _contact_person_name(c) else "(none)")),
            "contact_status": c.get("ContactStatus"),
            "is_customer": c.get("IsCustomer"),
            # Carried for the v0.2 work that wanted a per-contact describe:
            # hygiene_scan already flags these as missing but could not show them.
            "sales_default_account_code": c.get("SalesDefaultAccountCode"),
            "receivable_tax_type": c.get("AccountsReceivableTaxType"),
            "default_currency": c.get("DefaultCurrency"),
        })

    doc = {"generated_at": stamp, "total": len(rows), "reachable": reachable,
           "greetable": greetable, "contacts": out_rows}
    path = os.path.join(_h()["WS"], "%scontacts_%s.json"
                        % (FILE_PREFIX, stamp.replace(":", "")))
    _h()["jsave"](path, doc)
    return {"artifact": path,
            "counts": {"total": len(rows), "with_email": reachable,
                       "without_email": len(rows) - reachable,
                       "with_greeting_name": greetable},
            "rate": rate_of(hd),
            "limits": [_L_SCOPED, _L_EMAIL_ABSENT, _L_GREETING,
                       "one paged read of the whole contact book, not a call per "
                       "contact. Past max_contacts it refuses rather than "
                       "truncating."]}, {"path": path, "kind": "list_contacts"}


# ──────────────────────────────────── 12/13. send reminder

DEFAULT_LADDER = [7, 21, 45]


def _stage_binding(stage):
    """The approved rung, as a value plan_fp_of will hash.

    Without this the approval would bind only WHICH invoices get a reminder, not
    WHICH reminder they get. plan_fp hashes entries and nothing else, so a stage
    recorded beside the entries could be changed from 7 to 45 between approval
    and apply and the seal would still validate — the operator would have
    approved a gentle first nudge and a final notice would go out. Putting it in
    `action_fp` makes it part of what the human sealed, and apply recomputes it
    from the declared stage so the two cannot drift apart.
    """
    return _action_binding({"stage": int(stage)})


def _reminder_blockers(inv, addr, greeting, hist, stage, ladder, now,
                       allow_empty_greeting=False, person=""):
    """Every reason this invoice cannot be sent stage `stage`. Empty = eligible.

    All three of the probed refusal rules are checked HERE, at plan time, so an
    operator never approves a batch that Xero will reject or that would deliver
    a second copy. spec-core section 10: a plan promising a write the API will
    refuse spends a human approval on something that could never land — and the
    duplicate case is worse than that, because it CAN land.
    """
    reasons = []

    # RULE 1 — probed live: HTTP 400 "Draft, voided or deleted invoices cannot
    # be emailed". AUTHORISED is the only sendable status.
    status = inv.get("Status")
    if status != "AUTHORISED":
        reasons.append("status is %s — Xero refuses to email draft, voided or "
                       "deleted invoices" % status)

    # RULE 2 — probed live: HTTP 400 "Invoices for contacts with no email
    # address assigned cannot be emailed".
    if not addr:
        reasons.append("the contact has no email address on file")

    # RULE 2b — NOT an API refusal. Xero sends this one happily; it just sends
    # something embarrassing. A dunning email opening "Hi ," undercuts the
    # request it is making, and it is as unrecallable as any other send. So it
    # is refused by default and overridable in the INPUTS, which means the
    # decision to send a nameless greeting travels through the approval hash and
    # onto the receipt instead of happening by accident.
    if not allow_empty_greeting and not greeting:
        if person:
            reasons.append("the contact has no FirstName of its own — only a "
                           "contact person. Xero greets by Contact.FirstName "
                           "(confirmed from delivered mail); whether it ever "
                           "falls back to a contact person is unverified, so "
                           "this is not counted as a name. Set FirstName on the "
                           "contact, or allow_empty_greeting=true to send "
                           "anyway.")
        else:
            reasons.append("the contact has no personal first name, so Xero's "
                           "template would open \"Hi ,\" — it does not fall back "
                           "to the company name. Set allow_empty_greeting=true "
                           "to send anyway.")

    # RULE 3 — the load-bearing one. Xero does not dedupe; this record is the
    # only guard. Checked explicitly rather than left implied by the ladder
    # arithmetic below, because it is the check whose removal sends a real
    # customer a second copy, and it deserves to fail loudly on its own terms.
    if int(stage) in stages_sent(hist):
        when = next((e.get("ts") for e in reversed(hist)
                     if e.get("outcome") == DUNNING_SENT
                     and int(e.get("stage")) == int(stage)), "an earlier run")
        reasons.append("stage %d was already sent on %s — Xero applies no "
                       "deduplication, so sending again delivers a second copy"
                       % (int(stage), when))

    try:
        if float(inv.get("AmountDue") or 0) <= 0:
            reasons.append("nothing outstanding — the invoice is paid")
    except (TypeError, ValueError):
        reasons.append("AmountDue is unreadable — UNKNOWN is never a pass, so "
                       "this is not chased")

    due = parse_xero_date(inv.get("DueDateString") or inv.get("DueDate"))
    if due is None:
        reasons.append("no due date, so days overdue cannot be computed")
    else:
        od = int((now - due) / 86400)
        if od < int(stage):
            reasons.append("%d days overdue; stage %d is not due yet"
                           % (od, int(stage)))

    nxt = next_due_stage(ladder, hist)
    if nxt is None:
        reasons.append("every stage in the ladder has already been sent")
    elif nxt != int(stage):
        reasons.append("the next stage owed is %d, not %d — stages are never "
                       "skipped, and never two in one run" % (nxt, int(stage)))
    return reasons


def _part_payment_hold(inv, hist, stage):
    """(is_held, amount_paid). A part-payment pauses one cycle without resetting.

    Somebody paying part of an invoice is engaging with it, and chasing them the
    next day punishes exactly the behaviour the chain wants. So the stage holds
    for one cycle and then resumes where the ladder was — it does not reset.

    The hold has to be RECORDED to be released: without a record, "AmountPaid is
    higher than at the last send" stays true forever and the invoice would be
    held permanently. So the first run that sees the new amount writes a hold
    event and skips; the next run finds that event and proceeds. Recording is
    idempotent on (stage, amount_paid), so re-running the plan does not stack
    holds or extend one.

    This is a business judgement, not a technical one, which is why it is stated
    in the command's output rather than left for an operator to infer.
    """
    try:
        paid = float(inv.get("AmountPaid") or 0)
    except (TypeError, ValueError):
        return False, 0.0
    if paid <= 0 or paid <= last_observed_paid(hist):
        return False, paid
    served = any(e.get("outcome") == DUNNING_HOLD
                 and int(e.get("stage")) == int(stage)
                 and float((e.get("detail") or {}).get("amount_paid") or 0) == paid
                 for e in hist)
    return (not served), paid


def xero_accounting_plan_send_reminder(inputs, stamp):
    token = refresh_token()
    stage = _as_int(inputs.get("stage"), 0)
    ladder = [int(x) for x in (inputs.get("ladder") or DEFAULT_LADDER)]
    if stage not in ladder:
        raise XeroApiError(
            "stage %d is not in the ladder %s. A stage outside the ladder has no "
            "position in the sequence, so 'which stage is owed next' is "
            "undefined for it." % (stage, ladder))
    cap = _as_int(inputs.get("max_invoices"), 200)
    allow_empty_greeting = _as_bool(inputs.get("allow_empty_greeting"))

    invs = _fetch_invoices(token, ids=inputs.get("invoice_ids"),
                           status="AUTHORISED", cap=cap)
    contacts = _load_contacts(token)
    history = dunning_history()
    now = time.time()

    entries, excluded, held, nameless = [], [], 0, 0
    for inv in invs:
        iid = inv.get("InvoiceID")
        cid = (inv.get("Contact") or {}).get("ContactID")
        contact = contacts.get(cid)
        addr = _contact_email(contact)
        greeting = _contact_greeting_name(contact)
        person = _contact_person_name(contact)
        hist = history.get(iid, [])

        # PAID EXITS FIRST, before any stage arithmetic and before the
        # part-payment hold. A settled invoice is not a part-payment, and
        # ordering these the other way round classified a customer who had paid
        # in full as "engaging, hold one cycle" — which keeps them in the chain
        # instead of releasing them. Chasing somebody who has already paid is
        # the failure that destroys trust in the whole thing, so it is checked
        # before anything can reclassify it.
        #
        # Deliberately NOT recorded as an event: paid-ness is re-read from Xero
        # every run, so it needs no memory, and recording it would append a row
        # per settled invoice per run forever.
        try:
            if float(inv.get("AmountDue") or 0) <= 0:
                excluded.append({"number": inv.get("InvoiceNumber"), "invoice_id": iid,
                                 "reasons": ["nothing outstanding — the invoice is "
                                             "paid, so it leaves the chain"]})
                continue
        except (TypeError, ValueError):
            excluded.append({"number": inv.get("InvoiceNumber"), "invoice_id": iid,
                             "reasons": ["AmountDue is unreadable — UNKNOWN is "
                                         "never a pass, so this is not chased"]})
            continue

        is_held, paid = _part_payment_hold(inv, hist, stage)
        if is_held:
            dunning_append(iid, stage, DUNNING_HOLD,
                           {"amount_paid": paid, "number": inv.get("InvoiceNumber"),
                            "reason": "part-payment since the last contact"})
            excluded.append({"number": inv.get("InvoiceNumber"), "invoice_id": iid,
                             "reasons": ["a part-payment of %s landed since the "
                                         "last contact — holding this stage for "
                                         "one cycle, without resetting the ladder"
                                         % paid]})
            held += 1
            continue

        reasons = _reminder_blockers(inv, addr, greeting, hist, stage, ladder,
                                     now, allow_empty_greeting, person)
        if reasons:
            if any("allow_empty_greeting=true" in r for r in reasons):
                nameless += 1
            excluded.append({"number": inv.get("InvoiceNumber"), "invoice_id": iid,
                             "reasons": reasons})
            continue

        due = parse_xero_date(inv.get("DueDateString") or inv.get("DueDate"))
        e = _entry(inv)
        e["stage"] = int(stage)
        # The stage is sealed through action_fp, which plan_fp_of hashes. See
        # _stage_binding: `stage` on its own would be an unbound plan field.
        e["action_fp"] = _stage_binding(stage)
        e["contact_id"] = cid
        e["email_address"] = addr
        e["greeting_name"] = greeting
        e["days_overdue"] = int((now - due) / 86400) if due else None
        e["due_date"] = _iso_day(due)
        entries.append(e)

    total = sum(float(e.get("amount_due") or 0) for e in entries)
    considered = len(invs)
    plan, path = write_plan("send_reminder", entries,
                            {"stage": stage, "ladder": ladder,
                             "excluded": excluded})
    limits = [_L_SEND, _L_SEND_BODY, _L_REACH, _L_EMAIL_ABSENT, _L_GREETING,
              _L_SEND_QUOTA, _L_DRIFT,
              "reads only. Nothing is sent until apply_send_reminder runs with "
              "this plan_fp and a human approval.",
              "a part-payment holds the current stage for one cycle and does not "
              "reset the ladder. That is a policy choice, stated here so it is "
              "visible rather than inferred."]
    if not entries:
        limits.append("nothing is eligible for stage %d in this run. The "
                      "excluded list in the artifact names why for every "
                      "invoice considered." % stage)
    return {"artifact": path,
            "plan_id": _grouped(plan["plan_id"]),
            "plan_fp": _grouped(plan["plan_fp"]),
            "stage": stage,
            "counts": {"considered": considered, "eligible": len(entries),
                       "excluded": len(excluded), "held_for_part_payment": held,
                       "no_greeting_name": nameless},
            "greeting_policy": ("sending anyway (allow_empty_greeting=true)"
                                if allow_empty_greeting
                                else "refusing a nameless greeting"),
            "reachable_ratio": "%d of %d" % (len(entries), considered),
            "amount_due_total": "%.2f" % total,
            "limits": limits}, {"path": path, "kind": "plan_send_reminder"}


def xero_accounting_apply_send_reminder(inputs, stamp):
    token = refresh_token()
    plan, path = load_plan(inputs, "send_reminder")
    fresh, drift = _drift_check(token, plan)

    if drift:
        for e in plan["entries"]:
            dunning_append(e["id"], e.get("stage"), DUNNING_REFUSED,
                           {"number": e.get("number"), "reason": "batch refused on drift"})
        ledger_append("apply_send_reminder", "refused_drift",
                      {"plan_id": plan["plan_id"], "plan_fp": plan["plan_fp"],
                       "drift": drift[:20]})
        return {"sent": 0, "failed": 0, "refused": len(plan["entries"]),
                "drift": drift[:20], "artifact": path,
                "limits": [_L_SEND,
                           "REFUSED. Something moved between the plan and this "
                           "approval — most often a payment landing, which is "
                           "precisely the customer who must not be chased. "
                           "Re-plan, review, approve again."]}, None

    # RE-CHECK the duplicate guard against freshly-read state, not against the
    # plan. The plan checked it too, but an approval has no TTL and a sibling run
    # may have sent this exact stage in between. Reading the file again here is
    # one jload; the failure it prevents is a real customer receiving the same
    # reminder twice, which cannot be undone.
    history = dunning_history()
    contacts = _load_contacts(token)
    # The approved rung, re-derived from each entry. See check_action_binding.
    blocked = check_action_binding(
        plan["entries"],
        lambda e: {"stage": int(e.get("stage"))},
        "the reminder stage")
    for e in plan["entries"]:
        hist = history.get(e["id"], [])
        stage = int(e.get("stage"))
        # The stage must still match the value that was sealed. plan_fp covers
        # action_fp, so editing action_fp breaks the plan fingerprint upstream in
        # load_plan; editing `stage` alone is caught here. Between them the rung
        # the human approved is the rung that goes out.
        if stage in stages_sent(hist):
            blocked.append({"invoice": e.get("number"),
                            "reason": "stage %d has been sent since this plan was "
                                      "written — refusing rather than delivering a "
                                      "second copy" % stage})
            continue
        cur = fresh.get(e["id"])
        if cur is not None and cur.get("Status") != "AUTHORISED":
            blocked.append({"invoice": e.get("number"),
                            "reason": "status is now %s — Xero refuses to email "
                                      "draft, voided or deleted invoices"
                                      % cur.get("Status")})
            continue
        # Fresh read first: the plan's copy is a convenience, and trusting it
        # would check one contact's address while Xero mails another's.
        cid = ((cur or {}).get("Contact") or {}).get("ContactID") or e.get("contact_id")
        if not _contact_email(contacts.get(cid)):
            blocked.append({"invoice": e.get("number"),
                            "reason": "the contact's email address has been "
                                      "removed since the plan was written"})

    if blocked:
        for e in plan["entries"]:
            dunning_append(e["id"], e.get("stage"), DUNNING_REFUSED,
                           {"number": e.get("number"),
                            "reason": "batch refused: %d entry(s) no longer sendable"
                                      % len(blocked)})
        ledger_append("apply_send_reminder", "refused_ineligible",
                      {"plan_id": plan["plan_id"], "plan_fp": plan["plan_fp"],
                       "blocked": blocked[:20]})
        return {"sent": 0, "failed": 0, "refused": len(plan["entries"]),
                "drift": blocked[:20], "artifact": path,
                "limits": [_L_SEND,
                           "REFUSED THE WHOLE BATCH. At least one invoice is no "
                           "longer sendable. A partly-sent batch would leave you "
                           "working out who received what, and an email cannot "
                           "be recalled — so nothing was sent."]}, None

    sent, failed = [], []
    for e in plan["entries"]:
        stage = int(e.get("stage"))
        # No Idempotency-Key here, deliberately. Xero honours that header on
        # invoice POST but NOT on this endpoint — probed live, five identical
        # sends produced five deliveries. Sending one would be decoration that
        # reads like protection, which is worse than none.
        st, hd, body = api("POST", "Invoices/%s/Email" % e["id"], token, body={})
        if st in (200, 204):
            sent.append({"number": e.get("number"), "invoice_id": e["id"],
                         "stage": stage})
            dunning_append(e["id"], stage, DUNNING_SENT,
                           {"number": e.get("number"),
                            "amount_paid": e.get("amount_paid"),
                            "amount_due": e.get("amount_due"),
                            "days_overdue": e.get("days_overdue"),
                            "plan_id": plan["plan_id"], "plan_fp": plan["plan_fp"]})
        else:
            msg = ""
            if isinstance(body, dict):
                els = body.get("Elements") or []
                errs = (els[0].get("ValidationErrors") if els else []) or []
                msg = "; ".join(x.get("Message", "") for x in errs[:2]) or \
                      str(body.get("Message") or body.get("Detail") or "")[:160]
            if st >= 500:
                # Xero's 500 body is a generic "an error occurred, check the
                # status page" blob that tells an operator nothing. Measured on
                # a healthy org: sends began failing this way after ~9 in a day
                # while the minute and day counters were fine and the status
                # page was green, and did not recover in 7.5 minutes. Naming it
                # here turns a dead end into something actionable — the handoff's
                # rule that the production failure must produce a named error,
                # not a generic one.
                msg = ("Xero refused the send with HTTP %s and a generic error. "
                       "The tenant rate counters and the status page are not the "
                       "explanation: this has been measured on a healthy org "
                       "after roughly nine sends in one day, persisting for at "
                       "least 7.5 minutes with no Retry-After. Treat it as a "
                       "send quota or an anti-abuse block and retry later — not "
                       "as a fault in this batch. Xero recorded no send, so "
                       "nothing was delivered." % st)
            failed.append({"number": e.get("number"), "error": msg or ("HTTP %s" % st)})
            dunning_append(e["id"], stage, DUNNING_FAILED,
                           {"number": e.get("number"), "error": msg or ("HTTP %s" % st)})
            # HALT. Continuing would keep sending real email against an endpoint
            # that has already behaved unexpectedly, and every send after this
            # point is unrecallable.
            break

    ledger_append("apply_send_reminder", "committed" if not failed else "partial",
                  {"plan_id": plan["plan_id"], "plan_fp": plan["plan_fp"],
                   "stage": sorted({int(e.get("stage")) for e in plan["entries"]}),
                   "sent": len(sent),
                   "failed": len(failed),
                   "composite_fp": inputs.get("composite_fp"),
                   "ids": [s["invoice_id"] for s in sent][:50]})

    result = {"plan_id": plan["plan_id"],
              "stage": sorted({int(e.get("stage")) for e in plan["entries"]}),
              "sent": sent, "failed": failed}
    rpath = os.path.join(_h()["WS"], "%scustody_send_%s.json"
                         % (FILE_PREFIX, stamp.replace(":", "")))
    _h()["jsave"](rpath, result)

    limits = [_L_SEND, _L_SEND_BODY, _L_SEND_DELIV, _L_SEND_QUOTA]
    if failed:
        limits.append("halted at the first failure. %d reminder(s) went out "
                      "before it and are named in the artifact. Nothing was "
                      "rolled back because nothing can be: an email is not "
                      "recallable." % len(sent))
    return {"sent": len(sent), "failed": len(failed), "refused": 0,
            "artifact": rpath, "limits": limits}, {"path": rpath, "kind": "send_reminder"}
