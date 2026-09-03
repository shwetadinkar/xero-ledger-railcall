#!/usr/bin/env python3
"""Xero Ledger Airlock — governed Xero invoices and payments. v0.1.1

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

VERSION = "0.1.1"

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
    """
    return _sha(sorted(str(e.get("fp") or "") for e in entries))


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
    draft_days = int(inputs.get("draft_days") or 14)
    overdue_days = int(inputs.get("overdue_days") or 1)
    cap = int(inputs.get("max_findings") or 1000)
    now = time.time()

    findings = []

    def add(kind, inv, detail, fixed_by):
        findings.append({"finding": kind, "invoice_id": inv.get("InvoiceID"),
                         "number": inv.get("InvoiceNumber"),
                         "contact": (inv.get("Contact") or {}).get("Name"),
                         "total": inv.get("Total"), "amount_due": inv.get("AmountDue"),
                         "detail": detail, "fixed_by": fixed_by})

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
            add("overdue", inv, "%d days overdue (bucket %s)" % (od, bucket),
                "collections / dunning")
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
    return {"entries": n,
            "chain_intact": "yes" if intact else "NO",
            "first_break": ("seq %s" % first_break) if first_break else "(none)",
            "limits": [_L_CHAIN]}, None


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
    cap = int(inputs.get("max_invoices") or 200)
    invs = _fetch_invoices(token, ids=inputs.get("invoice_ids"),
                           status=(inputs.get("status") or "DRAFT").upper(),
                           contact_id=inputs.get("contact_id"), cap=cap)
    if not invs:
        return {"artifact": None, "count": 0, "total": "0",
                "limits": ["nothing matched the selector; no plan was written."]}, None
    entries = [_entry(i) for i in invs]
    total = sum(float(e.get("total") or 0) for e in entries)
    plan, path = write_plan("invoice_post", entries, {"target_status": "AUTHORISED"})
    return {"artifact": path, "plan_id": plan["plan_id"], "plan_fp": plan["plan_fp"],
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
    cap = int(inputs.get("max_invoices") or 200)
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
        entries.append(e)
        voidable += 1 if not reasons else 0
        blocked += 1 if reasons else 0

    plan, path = write_plan("invoice_void", entries,
                            {"target_status": "VOIDED",
                             "period_lock_epoch": lock_epoch})
    return {"artifact": path, "plan_id": plan["plan_id"], "plan_fp": plan["plan_fp"],
            "voidable": voidable, "blocked": blocked,
            "limits": [_L_VOID, _L_DRIFT]}, {"path": path, "kind": "plan_invoice_void"}


def _void_guard(plan, fresh):
    """Refuse anything the plan itself marked unvoidable, and anything that
    acquired a payment since. Checked separately from the fingerprint because
    an operator can approve a plan containing blocked rows — the plan is a
    report as well as a request."""
    out = []
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
    return {"artifact": path, "plan_id": plan["plan_id"], "plan_fp": plan["plan_fp"],
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
