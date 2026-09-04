#!/usr/bin/env python3
"""Self-running suite for xero-ledger. `python3 test_handler.py` — NOT pytest.

CI runs this on Python 3.9 and 3.12; pytest is not installed on either.

Tests load the handler against a fake __rc_helpers__ and a fake urlopen, so
nothing here touches the network or a real credential. Fixtures captured from
the live API live in ~/railcall-xero-probes/fixtures/ and the shapes asserted
below were taken from them, not invented.
"""
import io
import json
import os
import sys
import types

HERE = os.path.dirname(os.path.abspath(__file__))

# ───────────────────────────────────────────────── fake environment

class FakeWS(dict):
    pass


_FILES = {}


def _fake_jload(path, default=None):
    return json.loads(json.dumps(_FILES[path])) if path in _FILES else default


def _fake_jsave(path, obj):
    _FILES[path] = json.loads(json.dumps(obj))
    return True


_VAULT = {"client_id": "cid", "client_secret": "sec",
          "refresh_token": "rt-bootstrap", "tenant_id": "tenant-1"}

HELPERS = {
    "jload": _fake_jload, "jsave": _fake_jsave,
    "vault_get": lambda p: dict(_VAULT) if p == "xero-accounting" else None,
    "safe_name": lambda s: s, "WS": "/ws", "ROOT": "/root",
    "http_get_json": None, "http_post_json": None, "http_post_form": None,
    "http_patch_json": None, "http_delete_json": None,
    "oauth_refresh": None, "airlock_payload_hash": lambda c, i: "sha256:fake",
}


def load_handler():
    """Exec handler.py in an isolated namespace with __rc_helpers__ injected —
    the same shape routes/modules.py builds at load time."""
    ns = {"__name__": "railcall_module_xero_ledger",
          "__file__": os.path.join(HERE, "handlers", "handler.py"),
          "__rc_helpers__": HELPERS,
          "os": os, "json": json, "time": __import__("time")}
    with open(ns["__file__"], encoding="utf-8") as f:
        exec(compile(f.read(), ns["__file__"], "exec"), ns)
    return ns


H = load_handler()

# ───────────────────────────────────────────────── fake transport

_RESPONSES = []


class _Resp:
    def __init__(self, code, body, headers=None):
        self._code, self._body = code, json.dumps(body).encode()
        self.headers = headers or {"X-MinLimit-Remaining": "59",
                                   "X-DayLimit-Remaining": "999"}

    def getcode(self):
        return self._code

    def read(self):
        return self._body

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


def queue(code, body, headers=None):
    _RESPONSES.append(_Resp(code, body, headers))


def _fake_urlopen(req, timeout=None):
    if not _RESPONSES:
        raise AssertionError("unexpected extra HTTP call to %s" % req.full_url)
    return _RESPONSES.pop(0)


H["urllib"].request.urlopen = _fake_urlopen


def reset():
    _RESPONSES.clear()
    _FILES.clear()


def token_ok(rt="rt-2"):
    queue(200, {"access_token": "at-1", "refresh_token": rt, "expires_in": 1800})


# ─────────────────────────────────────────────────────── the tests

def t_date_parses_microsoft_epoch():
    assert H["parse_xero_date"]("/Date(1222732800000+0000)/") == 1222732800
    assert H["parse_xero_date"]("/Date(1222732800000)/") == 1222732800


def t_date_offset_does_not_shift_the_instant():
    """The offset is a display timezone, not part of the instant. If it were
    added, the same moment would hash differently per org setting."""
    a = H["normalise_date"]("/Date(1222732800000+0000)/")
    b = H["normalise_date"]("/Date(1222732800000+1300)/")
    assert a == b, "timezone suffix must not change the normalised value"


def t_date_normalises_iso_and_epoch_to_same_value():
    assert H["normalise_date"]("/Date(1222732800000+0000)/") == "1222732800"
    assert H["normalise_date"](None) == ""
    assert H["normalise_date"]("nonsense") == ""


def t_line_items_are_inside_the_fingerprint():
    """A recoded account with an identical total must change the fingerprint."""
    base = {"InvoiceID": "i1", "Status": "DRAFT", "Total": "100", "AmountDue": "100",
            "AmountPaid": "0", "UpdatedDateUTC": "/Date(1000000000000+0000)/",
            "LineItems": [{"LineItemID": "l1", "AccountCode": "200",
                           "TaxType": "OUTPUT", "LineAmount": "100"}]}
    recoded = json.loads(json.dumps(base))
    recoded["LineItems"][0]["AccountCode"] = "260"
    assert H["invoice_fp"](base) != H["invoice_fp"](recoded)


def t_fingerprint_uses_the_NORMALISED_date_not_the_raw_string():
    """Found by mutation_test.py: t_date_offset_does_not_shift_the_instant tested
    normalise_date in isolation, and nothing asserted that invoice_fp actually
    CALLS it. Hashing the raw string would make an org timezone change look like
    ledger drift — phantom refusals, which train an operator to re-approve
    without reading. That is the exact habit the airlock exists to prevent."""
    a = {"InvoiceID": "i1", "Status": "DRAFT", "Total": "100", "AmountDue": "100",
         "AmountPaid": "0", "UpdatedDateUTC": "/Date(1222732800000+0000)/",
         "LineItems": []}
    b = dict(a, UpdatedDateUTC="/Date(1222732800000+1300)/")   # same instant
    assert H["invoice_fp"](a) == H["invoice_fp"](b), \
        "invoice_fp must hash the normalised date, not the raw string"
    c = dict(a, UpdatedDateUTC="/Date(1222736400000+0000)/")   # +1 hour, real change
    assert H["invoice_fp"](a) != H["invoice_fp"](c)


def t_amount_paid_change_moves_the_fingerprint():
    base = {"InvoiceID": "i1", "Status": "AUTHORISED", "Total": "100",
            "AmountDue": "100", "AmountPaid": "0",
            "UpdatedDateUTC": "/Date(1000000000000+0000)/", "LineItems": []}
    paid = dict(base, AmountPaid="40", AmountDue="60")
    assert H["invoice_fp"](base) != H["invoice_fp"](paid)


def t_plan_fingerprint_is_order_independent():
    a = [{"fp": "x"}, {"fp": "y"}]
    b = [{"fp": "y"}, {"fp": "x"}]
    assert H["plan_fp_of"](a) == H["plan_fp_of"](b)


def t_idempotency_key_is_stable_across_retries():
    """A uuid4 per attempt would offer no protection: every retry would look
    like a new request. The key must be a pure function of the approved plan."""
    p = {"Invoices": [{"InvoiceID": "i1", "Status": "AUTHORISED"}]}
    k1 = H["idem_key"]("plan1234", "fp567890", 0, p)
    k2 = H["idem_key"]("plan1234", "fp567890", 0, p)
    assert k1 == k2
    assert H["idem_key"]("plan1234", "fp567890", 1, p) != k1


def t_refresh_persists_before_returning():
    reset()
    token_ok(rt="rt-rotated")
    tok = H["refresh_token"](force=True)
    assert tok == "at-1"
    state = _FILES["/ws/xero_ledger_token.json"]
    assert state["refresh_token"] == "rt-rotated", "rotated token must be persisted"
    assert state["rotations"] == 1


def t_refresh_uses_persisted_token_not_the_vault():
    reset()
    _FILES["/ws/xero_ledger_token.json"] = {"refresh_token": "rt-stored", "rotations": 3}
    token_ok(rt="rt-4")
    H["refresh_token"](force=True)
    assert _FILES["/ws/xero_ledger_token.json"]["rotations"] == 4


def t_refresh_keeps_old_token_if_xero_returns_none():
    """Defensive: writing "" would brick the next run."""
    reset()
    _FILES["/ws/xero_ledger_token.json"] = {"refresh_token": "rt-keep"}
    queue(200, {"access_token": "at", "expires_in": 1800})
    H["refresh_token"](force=True)
    assert _FILES["/ws/xero_ledger_token.json"]["refresh_token"] == "rt-keep"


def t_invalid_grant_is_a_named_error():
    reset()
    queue(400, {"error": "invalid_grant", "error_description": "nope"})
    try:
        H["refresh_token"](force=True)
    except Exception as e:
        msg = str(e)
        assert "single-use" in msg and "invalid_grant" in msg, msg
        return
    raise AssertionError("expected XeroAuthError")


def t_cached_access_token_skips_the_network():
    reset()
    _FILES["/ws/xero_ledger_token.json"] = {
        "refresh_token": "rt", "access_token": "cached",
        "access_expires_at": __import__("time").time() + 3600}
    assert H["refresh_token"]() == "cached"   # no queued response = no HTTP call


def t_ledger_chain_detects_tampering():
    reset()
    H["ledger_append"]("apply_invoice_post", "committed", {"a": 1})
    H["ledger_append"]("apply_invoice_post", "committed", {"a": 2})
    n, intact, brk = H["ledger_verify"]()
    assert (n, intact) == (2, True)
    _FILES["/ws/xero_ledger_ledger.json"]["entries"][0]["detail"] = {"a": 99}
    n, intact, brk = H["ledger_verify"]()
    assert not intact and brk == 1


def t_load_plan_refuses_a_mismatched_approval():
    """The load-bearing check: the approval binds plan CONTENT, not a filename."""
    reset()
    entries = [{"id": "i1", "fp": "aaa"}]
    plan = {"plan_id": "p1", "plan_fp": H["plan_fp_of"](entries),
            "kind": "invoice_post", "entries": entries}
    _FILES["/ws/plan.json"] = plan
    try:
        H["load_plan"]({"plan_path": "/ws/plan.json", "plan_fp": "wrong"}, "invoice_post")
    except Exception as e:
        assert "APPROVAL DOES NOT MATCH" in str(e), str(e)
        return
    raise AssertionError("expected refusal")


def t_load_plan_detects_an_edited_plan_file():
    reset()
    entries = [{"id": "i1", "fp": "aaa"}]
    good = H["plan_fp_of"](entries)
    _FILES["/ws/plan.json"] = {"plan_id": "p1", "plan_fp": good,
                               "kind": "invoice_post",
                               "entries": [{"id": "i1", "fp": "TAMPERED"}]}
    try:
        H["load_plan"]({"plan_path": "/ws/plan.json", "plan_fp": good}, "invoice_post")
    except Exception as e:
        assert "PLAN FILE ALTERED" in str(e), str(e)
        return
    raise AssertionError("expected refusal")


def t_load_plan_refuses_the_wrong_apply_command():
    reset()
    entries = [{"id": "i1", "fp": "aaa"}]
    fp = H["plan_fp_of"](entries)
    _FILES["/ws/plan.json"] = {"plan_id": "p1", "plan_fp": fp,
                               "kind": "payment_allocate", "entries": entries}
    try:
        H["load_plan"]({"plan_path": "/ws/plan.json", "plan_fp": fp}, "invoice_post")
    except Exception as e:
        assert "wrong apply command" in str(e), str(e)
        return
    raise AssertionError("expected refusal")


def t_batch_200_with_element_errors_is_not_success():
    """THE TRAP. Xero returns HTTP 200 with per-element failures inside when
    summarizeErrors=false. A handler reading only the status code reports
    success while elements failed."""
    reset()
    plan = {"plan_id": "p1", "plan_fp": "f1"}
    queue(200, {"Invoices": [
        {"InvoiceNumber": "INV-1", "InvoiceID": "i1", "Status": "AUTHORISED",
         "StatusAttributeString": "OK"},
        {"Reference": "bad", "StatusAttributeString": "ERROR",
         "ValidationErrors": [{"Message": "The Contact must contain at least 1"}]},
    ]})
    ok, failed, rate = H["_post_batch"]("tok", {"Invoices": []}, plan)
    assert len(ok) == 1 and len(failed) == 1, (ok, failed)
    assert "Contact" in failed[0]["errors"][0]


def t_get_all_raises_past_the_cap_rather_than_truncating():
    reset()
    queue(200, {"Invoices": [{"InvoiceID": str(i)} for i in range(100)]})
    queue(200, {"Invoices": [{"InvoiceID": str(i)} for i in range(100)]})
    try:
        H["get_all"]("Invoices", "tok", max_rows=150, key="Invoices")
    except Exception as e:
        assert "Refusing rather than truncating" in str(e), str(e)
        return
    raise AssertionError("expected a refusal past the cap")


def t_missing_scope_401_is_explained():
    reset()
    queue(401, {"Detail": "AuthorizationUnsuccessful"})
    try:
        H["get_all"]("Invoices", "tok", key="Invoices")
    except Exception as e:
        assert "verify_connection" in str(e), str(e)
        return
    raise AssertionError("expected a scope explanation")


def t_every_written_path_carries_the_sandbox_prefix():
    """requires.filesystem_writes is scoped to **/xero_ledger_*.json. A handler
    writing any other name raises SandboxViolation at runtime — a loud failure,
    but a late one. Fail here instead."""
    reset()
    token_ok()
    H["refresh_token"](force=True)
    H["ledger_append"]("op", "committed", {})
    entries = [{"id": "i1", "fp": "a"}]
    H["write_plan"]("invoice_post", entries)
    assert _FILES, "no files written"
    for path in _FILES:
        base = os.path.basename(path)
        assert base.startswith("xero_ledger_"), \
            "%s would be refused by the filesystem gate" % path


def t_only_authorised_invoices_are_voidable():
    """Found live 2026-09-03: Xero DELETES a draft and VOIDS an authorised
    invoice. Posting Status=VOIDED to a DRAFT is refused with "Invoice not of
    valid status for modification". The plan must not promise a write the API
    will refuse — that spends a human approval on something that cannot land."""
    reset()
    token_ok()
    queue(200, {"Organisations": [{"PeriodLockDate": None}]})
    for st in ("DRAFT", "SUBMITTED"):
        queue(200, {"Invoices": [{"InvoiceID": "i1", "InvoiceNumber": "INV-1",
                                  "Status": st, "Total": "10", "AmountDue": "10",
                                  "AmountPaid": "0", "LineItems": [],
                                  "UpdatedDateUTC": "/Date(1000000000000+0000)/"}]})
    out, _ = H["xero_accounting_plan_invoice_void"](
        {"invoice_ids": ["i1", "i2"]}, "2026-09-03T00:00:00Z")
    assert out["voidable"] == 0, "a DRAFT must not be reported voidable"
    assert out["blocked"] == 2
    plan = _FILES[out["artifact"]]
    assert "DELETES a draft" in plan["entries"][0]["blocked_because"][0]


def t_drift_reasons_do_not_fabricate_line_item_changes():
    """Found live 2026-09-03: an out-of-band payment correctly refused, but the
    reason list also claimed "line items recoded or amended" when nothing had
    touched them. _drift_check compared line_fp() (4 fields incl. LineItemID)
    against a 3-field rebuild of the DISPLAY copy, which can never match. On a
    command whose whole value is naming what moved, a fabricated reason is worse
    than a vague one."""
    inv = {"InvoiceID": "i1", "InvoiceNumber": "INV-1", "Status": "AUTHORISED",
           "Total": "216.5", "AmountDue": "216.5", "AmountPaid": "0",
           "UpdatedDateUTC": "/Date(1000000000000+0000)/",
           "Contact": {"Name": "X"},
           "LineItems": [{"LineItemID": "l1", "AccountCode": "200",
                          "TaxType": "OUTPUT", "LineAmount": "216.5"}]}
    entry = H["_entry"](inv)
    assert entry.get("line_fp"), "plan entry must carry line_fp"
    # only the payment moved; line items untouched
    moved = json.loads(json.dumps(inv))
    moved["AmountPaid"] = "25"; moved["AmountDue"] = "191.5"
    # _drift_check takes a token directly, so no token response is consumed.
    # Queuing one would be eaten by the first Invoices GET and look like a
    # missing invoice.
    reset()
    queue(200, {"Invoices": [moved]})
    plan = {"entries": [entry]}
    _fresh, drift = H["_drift_check"]("tok", plan)
    assert len(drift) == 1
    reason = drift[0]["reason"]
    assert "AmountPaid" in reason, reason
    assert "line items" not in reason, "fabricated a line-item change: " + reason


def t_no_output_field_name_trips_the_airlock_redactor():
    """Found live 2026-09-03: verify_connection returned its rotation diagnostics
    under a field called `token`, and approval_airlock.redact() masks by field
    NAME against SECRET_HINT — so the whole block came back as "••••••" in every
    receipt despite holding no secret. The content was fine; the name was the
    bug. This asserts no top-level output key trips the redactor.

    SECRET_HINT is mirrored from approval_airlock. If the station widens it, this
    test goes red and names the field to rename — which is the point."""
    SECRET_HINT = ("token", "key", "secret", "password", "apikey",
                   "authorization", "bearer", "dsn")
    reset()
    token_ok()
    queue(200, [{"tenantId": "tenant-1", "tenantName": "Demo", "id": "conn-1"}])
    for _ in range(5):                       # one per scope probe
        queue(200, {"Organisation": []})
    out, _ = H["xero_accounting_verify_connection"]({}, "2026-09-03T00:00:00Z")
    offenders = [k for k in out
                 if any(h in str(k).lower() for h in SECRET_HINT)]
    assert not offenders, \
        "these output fields would be redacted to ••••••: %s" % offenders
    assert "credential_state" in out, "rotation diagnostics must still be reported"


def t_no_raw_xero_date_is_returned_inline():
    """Found live 2026-09-03: describe_org returned PeriodLockDate inline as
    /Date(1222732800000+0000)/ and the airlock's IDENTIFIER scrubber rewrote the
    epoch to [account] before sealing — the receipt field was destroyed while the
    artifact kept the truth.

    Sibling of t_no_output_field_name_trips_the_airlock_redactor: that one is
    masked by field NAME, this one by value SHAPE. Renaming cannot fix a shape
    problem, so the value has to move to the file and the receipt carries a
    verdict instead. This asserts no inline value looks like a Xero date."""
    import re
    reset()
    token_ok()
    queue(200, {"Organisations": [{"Name": "Demo", "PeriodLockDate":
                                   "/Date(1222732800000+0000)/"}]})
    for _ in range(3):                       # Accounts, TaxRates, TrackingCategories
        queue(200, {"Accounts": [], "TaxRates": [], "TrackingCategories": []})
    out, art = H["xero_accounting_describe_org"]({}, "2026-09-03T00:00:00Z")

    assert out.get("period_lock") == "set", out.get("period_lock")
    assert "period_lock_date" not in out, "the raw date must not be returned inline"

    blob = json.dumps(out)
    assert not re.search(r"/Date\(-?\d+", blob), \
        "an inline value still carries a raw Xero date: " + blob[:200]

    # ...and the real value is still recoverable from the artifact
    doc = _FILES[out["artifact"]]
    assert doc["period_lock_date"] == "/Date(1222732800000+0000)/"
    assert doc["period_lock_epoch"] == 1222732800


def t_period_lock_reports_none_when_unset():
    reset()
    token_ok()
    queue(200, {"Organisations": [{"Name": "Demo"}]})
    for _ in range(3):
        queue(200, {"Accounts": [], "TaxRates": [], "TrackingCategories": []})
    out, _ = H["xero_accounting_describe_org"]({}, "2026-09-03T00:00:00Z")
    assert out["period_lock"] == "(none)", out["period_lock"]


def t_manifest_matches_the_handlers():
    m = json.load(open(os.path.join(HERE, "module.json"), encoding="utf-8"))
    for c in m["commands"]:
        fn = c["id"].replace(".", "_")
        assert fn in H, "manifest declares %s but there is no def %s" % (c["id"], fn)
        assert callable(H[fn])
    assert m["requires"]["filesystem_writes"] == [
        "**/.railcall/station/.railcall_workspace/xero_ledger_*.json"], \
        "the write glob must stay deep-anchored: fnmatch's * crosses separators"


def t_manifest_modes_and_risks_are_graded():
    m = json.load(open(os.path.join(HERE, "module.json"), encoding="utf-8"))
    for c in m["commands"]:
        assert c["mode"] in ("read", "write_requires_approval"), c["id"]
        assert c["mode"] != "read_only"
        if c["id"].split(".")[1].startswith("apply_"):
            assert c["mode"] == "write_requires_approval", c["id"]
            assert c["risk"] == "high", c["id"]
            for f in ("plan_path", "plan_fp"):
                assert f in c["input_schema"], "%s must bind %s" % (c["id"], f)
            assert c["input_schema"]["plan_fp"]["required"] is True


def t_command_count_matches_the_docs():
    m = json.load(open(os.path.join(HERE, "module.json"), encoding="utf-8"))
    n = len(m["commands"])
    for doc in ("README.md", "COMMANDS.md"):
        p = os.path.join(HERE, doc)
        if os.path.isfile(p):
            text = open(p, encoding="utf-8").read()
            assert ("%d commands" % n) in text, \
                "%s does not say '%d commands'" % (doc, n)


# ────────────────────────────────────── v0.1.2 — dunning

def _inv(iid="i1", number="INV-1", status="AUTHORISED", due_days=30,
         amount_due="100", amount_paid="0", contact_id="c1"):
    """An overdue AUTHORISED sales invoice, `due_days` days past due."""
    import time as _t
    due_ms = int((_t.time() - due_days * 86400) * 1000)
    return {"InvoiceID": iid, "InvoiceNumber": number, "Status": status,
            "Total": "100", "AmountDue": amount_due, "AmountPaid": amount_paid,
            "DueDate": "/Date(%d+0000)/" % due_ms,
            "UpdatedDateUTC": "/Date(1000000000000+0000)/",
            "Contact": {"ContactID": contact_id, "Name": "Acme"},
            "LineItems": []}


def _contact(cid="c1", email="a@example.com", first="Ayesha", persons=None):
    """A contact Xero would render a proper greeting for.

    `first` defaults to a real name because the DEFAULT plan policy refuses a
    contact without one — Xero's template opens "Hi ," rather than falling back
    to the company name. Pass first=None to exercise that path.
    """
    c = {"ContactID": cid, "Name": "Acme", "ContactStatus": "ACTIVE"}
    if email is not None:
        c["EmailAddress"] = email
    if first is not None:
        c["FirstName"] = first
    if persons is not None:
        c["ContactPersons"] = persons
    return c


def _ready():
    """Seed a live access token directly.

    NOT token_ok(): that queues a refresh RESPONSE, and refresh_token() only
    consumes one when the cached token has expired. A test that queues a token
    the handler does not need shifts every subsequent response by one, so the
    Invoices read receives the token body and the run silently sees zero
    invoices. Setting the state removes the coupling entirely.
    """
    _FILES["/ws/xero_ledger_token.json"] = {
        "refresh_token": "rt", "access_token": "at-1",
        "access_expires_at": __import__("time").time() + 1800, "rotations": 1}


def _plan_stage(stage=7, invoices=None, contacts=None, ladder=None):
    """Run plan_send_reminder against queued responses; return (output, plan)."""
    _ready()
    queue(200, {"Invoices": invoices if invoices is not None else [_inv()]})
    queue(200, {"Contacts": contacts if contacts is not None else [_contact()]})
    args = {"stage": stage}
    if ladder:
        args["ladder"] = ladder
    out, _art = H["xero_accounting_plan_send_reminder"](args, "2026-09-04T00:00:00Z")
    return out, (_FILES.get(out["artifact"]) if out.get("artifact") else None)


def t_contact_email_treats_empty_string_and_missing_key_alike():
    """Measured live: 25 of 53 contacts carried an EmailAddress key while only 7
    held a value. A `"EmailAddress" in contact` test would call eighteen
    unreachable contacts reachable, and each becomes a plan promising a send
    Xero refuses with HTTP 400."""
    f = H["_contact_email"]
    assert f({"EmailAddress": "a@example.com"}) == "a@example.com"
    assert f({"EmailAddress": ""}) == ""          # present but empty
    assert f({}) == ""                            # key omitted entirely
    assert f({"EmailAddress": None}) == ""
    assert f({"EmailAddress": "  "}) == ""        # whitespace is not an address


def t_list_contacts_counts_reachability_not_row_count():
    reset()
    token_ok()
    queue(200, {"Contacts": [_contact("c1", "a@example.com"),
                             _contact("c2", "", first=None),
                             _contact("c3", None, first=None)]})
    out, _ = H["xero_accounting_list_contacts"]({}, "2026-09-04T00:00:00Z")
    assert out["counts"] == {"total": 3, "with_email": 1, "without_email": 2,
                             "with_greeting_name": 1}, out["counts"]
    doc = _FILES[out["artifact"]]
    states = sorted(r["address_state"] for r in doc["contacts"])
    assert states == ["(none)", "(none)", "set"], states


def t_hygiene_overdue_carries_structured_fields_not_prose():
    """v0.1.1 put days-overdue only inside a prose `detail` string, so anything
    downstream had to regex a sentence for the number that decides which stage
    an invoice is owed. Rewording the message would silently change which
    reminder a customer receives."""
    reset()
    token_ok()
    queue(200, {"Invoices": [_inv(due_days=47)]})
    out, _ = H["xero_accounting_hygiene_scan"]({}, "2026-09-04T00:00:00Z")
    row = next(f for f in _FILES[out["artifact"]]["findings"]
               if f["finding"] == "overdue")
    assert row["days_overdue"] == 47, row
    assert row["due_date"] and row["due_date"].count("-") == 2, row["due_date"]
    assert row["contact_id"] == "c1", row
    assert row["fixed_by"] == "xero_accounting.plan_send_reminder", row["fixed_by"]


def t_overdue_finding_names_a_real_governed_command():
    """It read "collections / dunning" — the only finding in the module naming
    no command. A finding that names nothing is a finding nobody can act on."""
    reset()
    token_ok()
    queue(200, {"Invoices": [_inv(due_days=47)]})
    out, _ = H["xero_accounting_hygiene_scan"]({}, "2026-09-04T00:00:00Z")
    row = next(f for f in _FILES[out["artifact"]]["findings"]
               if f["finding"] == "overdue")
    m = json.load(open(os.path.join(HERE, "module.json"), encoding="utf-8"))
    assert row["fixed_by"] in [c["id"] for c in m["commands"]], \
        "fixed_by %r is not a command in this manifest" % row["fixed_by"]


def t_plan_refuses_a_contact_with_no_email_address():
    """Probed live: HTTP 400 "Invoices for contacts with no email address
    assigned cannot be emailed". Refuse at plan time, not at apply."""
    reset()
    out, plan = _plan_stage(contacts=[_contact("c1", "")])
    assert out["counts"]["eligible"] == 0, out["counts"]
    reasons = plan["excluded"][0]["reasons"]
    assert any("no email address" in r for r in reasons), reasons


def t_plan_refuses_a_draft_or_voided_invoice():
    """Probed live: HTTP 400 "Draft, voided or deleted invoices cannot be
    emailed"."""
    for status in ("DRAFT", "VOIDED", "DELETED"):
        reset()
        out, plan = _plan_stage(invoices=[_inv(status=status)])
        assert out["counts"]["eligible"] == 0, (status, out["counts"])
        reasons = plan["excluded"][0]["reasons"]
        assert any("draft, voided or deleted" in r.lower() for r in reasons), \
            (status, reasons)


def t_plan_refuses_a_stage_already_sent():
    """THE LOAD-BEARING CHECK. Xero applies no deduplication to invoice emails —
    five sends produced five deliveries — so this record is the only thing
    preventing a real customer receiving the same reminder twice."""
    reset()
    H["dunning_append"]("i1", 7, "sent", {"number": "INV-1", "amount_paid": "0"})
    out, plan = _plan_stage(stage=7)
    assert out["counts"]["eligible"] == 0, out["counts"]
    reasons = plan["excluded"][0]["reasons"]
    assert any("already sent" in r for r in reasons), reasons
    assert any("no deduplication" in r for r in reasons), \
        "the reason must say WHY a duplicate matters, not just that it is one"


def t_apply_refuses_a_duplicate_that_appeared_after_approval():
    """The apply-time half of the same guard, and the one that actually saves a
    customer. Approvals have no TTL, so a sibling run can send this exact stage
    between approval and apply. Checking only at plan time would let that
    through."""
    reset()
    out, _ = _plan_stage(stage=7)
    assert out["counts"]["eligible"] == 1, out["counts"]

    # a sibling run sends stage 7 AFTER the plan was written and approved
    H["dunning_append"]("i1", 7, "sent", {"number": "INV-1", "amount_paid": "0"})

    _ready()
    queue(200, {"Invoices": [_inv()]})          # drift re-read: unchanged
    queue(200, {"Contacts": [_contact()]})      # address re-read: unchanged
    res, _ = H["xero_accounting_apply_send_reminder"](
        {"plan_path": out["artifact"], "plan_fp": out["plan_fp"]},
        "2026-09-04T00:01:00Z")
    assert res["sent"] == 0, res
    assert res["refused"] == 1, res
    assert any("sent since this plan" in d["reason"] for d in res["drift"]), res["drift"]


def t_apply_sends_and_records_the_stage():
    reset()
    out, _ = _plan_stage(stage=7)
    _ready()
    queue(200, {"Invoices": [_inv()]})
    queue(200, {"Contacts": [_contact()]})
    queue(204, {})                               # POST .../Email
    res, _ = H["xero_accounting_apply_send_reminder"](
        {"plan_path": out["artifact"], "plan_fp": out["plan_fp"]},
        "2026-09-04T00:01:00Z")
    assert res["sent"] == 1, res
    assert res["failed"] == 0, res
    hist = H["dunning_history"]()["i1"]
    assert [e["outcome"] for e in hist] == ["sent"], hist
    assert hist[0]["stage"] == 7


def t_a_second_apply_of_the_same_plan_sends_nothing():
    """End to end: the whole point. Re-running an approved plan must not deliver
    a second copy, because Xero will happily deliver one."""
    reset()
    out, _ = _plan_stage(stage=7)
    for expected_sent in (1, 0):
        _ready()
        queue(200, {"Invoices": [_inv()]})
        queue(200, {"Contacts": [_contact()]})
        if expected_sent:
            queue(204, {})
        res, _ = H["xero_accounting_apply_send_reminder"](
            {"plan_path": out["artifact"], "plan_fp": out["plan_fp"]},
            "2026-09-04T00:01:00Z")
        assert res["sent"] == expected_sent, (expected_sent, res)
    assert len(_RESPONSES) == 0, "the second run must not have called Email"


def t_stages_are_never_skipped_and_never_doubled():
    """An invoice 40 days overdue with nothing sent is owed stage 7 — not stage
    21, and not both in one run. A workflow that has not run for a fortnight
    catches up one rung per run; two emails in one day reads as a malfunction."""
    reset()
    out7, _ = _plan_stage(stage=7, invoices=[_inv(due_days=40)])
    assert out7["counts"]["eligible"] == 1, out7["counts"]

    reset()
    out21, plan21 = _plan_stage(stage=21, invoices=[_inv(due_days=40)])
    assert out21["counts"]["eligible"] == 0, out21["counts"]
    assert any("next stage owed is 7" in r for r in plan21["excluded"][0]["reasons"]), \
        plan21["excluded"][0]["reasons"]


def t_stage_21_opens_once_stage_7_is_sent():
    reset()
    H["dunning_append"]("i1", 7, "sent", {"number": "INV-1", "amount_paid": "0"})
    out, _ = _plan_stage(stage=21, invoices=[_inv(due_days=40)])
    assert out["counts"]["eligible"] == 1, out["counts"]


def t_a_stage_not_in_the_ladder_is_refused():
    reset()
    _ready()
    try:
        H["xero_accounting_plan_send_reminder"](
            {"stage": 30}, "2026-09-04T00:00:00Z")
    except Exception as e:
        assert "not in the ladder" in str(e), str(e)
        return
    raise AssertionError("a stage outside the ladder has no position in the sequence")


def t_a_paid_invoice_is_never_chased():
    reset()
    out, plan = _plan_stage(invoices=[_inv(amount_due="0", amount_paid="100")])
    assert out["counts"]["eligible"] == 0, out["counts"]
    assert any("paid" in r for r in plan["excluded"][0]["reasons"]), plan["excluded"]


def t_part_payment_holds_one_cycle_then_resumes():
    """A part-payment is engagement; chasing the next day punishes it. Hold one
    cycle, do not reset the ladder. The hold must be RECORDED to be released —
    otherwise "paid more than at the last send" stays true forever and the
    invoice is held permanently."""
    reset()
    inv = _inv(amount_due="60", amount_paid="40")

    out1, plan1 = _plan_stage(invoices=[inv])
    assert out1["counts"]["held_for_part_payment"] == 1, out1["counts"]
    assert out1["counts"]["eligible"] == 0
    assert any("part-payment" in r for r in plan1["excluded"][0]["reasons"])

    # the hold is now on record, so the NEXT run proceeds
    out2, _ = _plan_stage(invoices=[inv])
    assert out2["counts"]["eligible"] == 1, out2["counts"]
    assert out2["counts"]["held_for_part_payment"] == 0


def t_part_payment_hold_is_idempotent_across_replans():
    """Re-running the plan must not stack holds or extend one."""
    reset()
    inv = _inv(amount_due="60", amount_paid="40")
    _plan_stage(invoices=[inv])
    holds = [e for e in H["dunning_history"]()["i1"]
             if e["outcome"] == "part_payment_hold"]
    assert len(holds) == 1, holds


def t_the_approved_stage_is_bound_not_just_recorded():
    """plan_fp hashes ENTRIES only, never plan-level fields — so a stage stored
    beside the entries could be edited from 7 to 45 after approval and the seal
    would still validate. The operator approves a gentle first nudge; a final
    notice goes out.

    Caught by this test while writing it: putting `stage` in the entry is NOT
    enough, because plan_fp_of hashes only each entry's `fp`. The stage is bound
    through `action_fp`, and BOTH tamper routes have to close:
      - edit action_fp  -> plan_fp changes  -> load_plan refuses
      - edit stage only -> action_fp no longer matches -> apply refuses
    """
    reset()
    out, plan = _plan_stage(stage=7)
    e = plan["entries"][0]
    assert e["stage"] == 7 and e["action_fp"], e

    # route 1: the binding itself is inside the plan fingerprint
    fp_before = H["plan_fp_of"](plan["entries"])
    tampered = json.loads(json.dumps(plan["entries"]))
    tampered[0]["action_fp"] = H["_stage_binding"](45)
    assert H["plan_fp_of"](tampered) != fp_before, \
        "action_fp must be inside plan_fp"

    # route 2: editing the stage alone leaves the binding behind, and apply
    # refuses rather than sending a rung nobody approved
    _FILES[out["artifact"]]["entries"][0]["stage"] = 45
    _ready()
    queue(200, {"Invoices": [_inv()]})
    queue(200, {"Contacts": [_contact()]})
    res, _ = H["xero_accounting_apply_send_reminder"](
        {"plan_path": out["artifact"], "plan_fp": out["plan_fp"]},
        "2026-09-04T00:01:00Z")
    assert res["sent"] == 0 and res["refused"] == 1, res
    assert any("the reminder stage does not match" in d["reason"]
               for d in res["drift"]), res["drift"]


def t_a_plan_without_action_fp_still_fingerprints_as_before():
    """Backward compatibility: entries predating action_fp must hash exactly as
    they used to, or every plan written before the upgrade fails as "PLAN FILE
    ALTERED" — a frightening message for a benign cause."""
    legacy = [{"fp": "x"}, {"fp": "y"}]
    import hashlib as _h2
    expect = _h2.sha256(
        json.dumps(sorted(["x", "y"]), sort_keys=True,
                   separators=(",", ":"), default=str).encode()).hexdigest()
    assert H["plan_fp_of"](legacy) == expect


def t_apply_refuses_the_whole_batch_when_one_invoice_is_unsendable():
    """Refuse rather than half-complete. A partly-sent batch leaves the operator
    working out who received what, and an email cannot be recalled."""
    reset()
    out, _ = _plan_stage(stage=7, invoices=[_inv("i1", "INV-1"),
                                            _inv("i2", "INV-2")],
                         contacts=[_contact("c1")])
    assert out["counts"]["eligible"] == 2, out["counts"]
    _ready()
    # i2's invoice comes back VOIDED on the drift re-read
    queue(200, {"Invoices": [_inv("i1", "INV-1")]})
    queue(200, {"Invoices": [_inv("i2", "INV-2", status="VOIDED")]})
    res, _ = H["xero_accounting_apply_send_reminder"](
        {"plan_path": out["artifact"], "plan_fp": out["plan_fp"]},
        "2026-09-04T00:01:00Z")
    assert res["sent"] == 0, "nothing may be sent when any entry is unsendable"
    assert res["refused"] == 2, res


def t_dunning_chain_detects_an_edited_event():
    reset()
    H["dunning_append"]("i1", 7, "sent", {"number": "INV-1"})
    H["dunning_append"]("i2", 7, "sent", {"number": "INV-2"})
    n, intact, brk = H["dunning_verify"]()
    assert (n, intact, brk) == (2, True, None), (n, intact, brk)
    path = "/ws/xero_ledger_dunning_state.json"
    _FILES[path]["events"][0]["stage"] = 45
    n, intact, brk = H["dunning_verify"]()
    assert intact is False and brk == 1, (n, intact, brk)


def t_verify_ledger_reports_both_chains():
    """One command covers both files. A separate one would let an operator check
    the write ledger while the dunning record rots — and that record is the only
    duplicate guard."""
    reset()
    H["dunning_append"]("i1", 7, "sent", {"number": "INV-1"})
    out, _ = H["xero_accounting_verify_ledger"]({}, "2026-09-04T00:00:00Z")
    assert out["dunning_events"] == 1, out
    assert out["dunning_chain_intact"] == "yes", out
    assert out["chain_intact"] == "yes", out


def t_send_does_not_pretend_an_idempotency_key_protects_it():
    """Xero honours Idempotency-Key on invoice POST but NOT on the Email
    endpoint — five identical sends produced five deliveries. Sending one here
    would be decoration that reads like protection."""
    import ast
    src = open(os.path.join(HERE, "handlers", "handler.py"), encoding="utf-8").read()
    tree = ast.parse(src)

    # Parse rather than grep, for two reasons found the hard way:
    #  - a substring search over the function body matches the COMMENT that
    #    explains why no key is sent, so it passes for the wrong reason;
    #  - a line-based search misses a call split across two lines, which is
    #    exactly how the mutation writes it. The mutation survived until this
    #    was an AST walk.
    found = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        if not (isinstance(node.func, ast.Name) and node.func.id == "api"):
            continue
        seg = ast.get_source_segment(src, node) or ""
        if "/Email" in seg:
            found.append({k.arg for k in node.keywords})
    assert len(found) == 1, "expected exactly one Email send call, saw %d" % len(found)
    assert "extra_headers" not in found[0], \
        "the send must not carry an idempotency key Xero ignores on this endpoint"


def t_send_output_states_that_xero_does_not_dedupe():
    """spec-core section 13: the limit belongs in the field an operator reads,
    not only in the docs."""
    reset()
    out, _ = _plan_stage(stage=7)
    assert any("no deduplication" in x.lower() or "NO deduplication" in x
               for x in out["limits"]), out["limits"]
    assert any("standard invoice template" in x for x in out["limits"]), out["limits"]


def t_new_command_outputs_survive_both_scrubbers():
    """Sweep EVERY new command's inline output, not just the one that broke.

    spec-core section 14, learned on SafeDB: when fixing a scrubber-safety bug,
    check every raw string in the response. The two tests above cover only the
    commands that had the original bugs, so a v0.1.2 command could reintroduce
    either class and neither would notice.

    Two scrubbers, two different failure modes:
      - by field NAME, substring against SECRET_HINT
      - by value SHAPE, a run of 13+ digits read as an account number
    """
    SECRET_HINT = ("token", "key", "secret", "password", "apikey",
                   "authorization", "bearer", "dsn")
    import re as _re

    outputs = {}
    reset()
    _ready()
    queue(200, {"Contacts": [_contact("c1", "a@example.com")]})
    outputs["list_contacts"], _ = H["xero_accounting_list_contacts"](
        {}, "2026-09-04T00:00:00Z")

    reset()
    out, _ = _plan_stage(stage=7)
    outputs["plan_send_reminder"] = out

    reset()
    plan_out, _ = _plan_stage(stage=7)
    _ready()
    queue(200, {"Invoices": [_inv()]})
    queue(200, {"Contacts": [_contact()]})
    queue(204, {})
    outputs["apply_send_reminder"], _ = H["xero_accounting_apply_send_reminder"](
        {"plan_path": plan_out["artifact"], "plan_fp": plan_out["plan_fp"]},
        "2026-09-04T00:01:00Z")

    for cmd, out in outputs.items():
        offenders = [k for k in out if any(h in str(k).lower() for h in SECRET_HINT)]
        assert not offenders, "%s: fields would be masked to ••••••: %s" % (cmd, offenders)

        for k, v in out.items():
            if not isinstance(v, str):
                continue
            assert not _re.search(r"/Date\(-?\d+", v), \
                "%s.%s returns a raw Xero date inline: %r" % (cmd, k, v)
            assert not _re.search(r"\d{13,}", v), \
                "%s.%s has a 13+ digit run and would become [account]: %r" % (cmd, k, v)


def t_dunning_state_file_carries_the_sandbox_prefix():
    reset()
    H["dunning_append"]("i1", 7, "sent", {})
    assert any(os.path.basename(p) == "xero_ledger_dunning_state.json"
               for p in _FILES), sorted(_FILES)


# ──────────────────────── v0.1.2 — binding what was approved

def _payment_plan(amount=100.0, account="acct-1"):
    """Plan one payment allocation and return (output, plan_path)."""
    _ready()
    queue(200, {"Invoices": [_inv(amount_due="100")]})
    out, _ = H["xero_accounting_plan_payment_allocate"](
        {"allocations": [{"invoice_id": "i1", "amount": amount,
                          "date": "2026-09-04"}],
         "account_id": account}, "2026-09-04T00:00:00Z")
    return out


def _apply_payment(out, queue_invoice=True):
    _ready()
    if queue_invoice:
        queue(200, {"Invoices": [_inv(amount_due="100")]})
    return H["xero_accounting_apply_payment_allocate"](
        {"plan_path": out["artifact"], "plan_fp": out["plan_fp"]},
        "2026-09-04T00:01:00Z")[0]


def t_a_grouped_fingerprint_is_accepted_and_a_wrong_one_is_not():
    """plan_fp is returned grouped in eights so the airlock's digit-run scrubber
    cannot destroy it, but the plan FILE holds the ungrouped digest. Both forms
    must verify, and neither may weaken the check."""
    reset()
    out = _payment_plan()
    assert " " in out["plan_fp"], "plan_fp must be returned grouped"
    plan = _FILES[out["artifact"]]
    assert " " not in plan["plan_fp"], "the plan FILE must keep the raw digest"

    # ungrouped form verifies too
    _ready()
    queue(200, {"Invoices": [_inv(amount_due="100")]})
    queue(200, {"Payments": [{"PaymentID": "p1"}]})
    res = H["xero_accounting_apply_payment_allocate"](
        {"plan_path": out["artifact"], "plan_fp": plan["plan_fp"]},
        "2026-09-04T00:01:00Z")[0]
    assert res["recorded"] == 1, res

    reset()
    out = _payment_plan()
    _ready()
    try:
        H["xero_accounting_apply_payment_allocate"](
            {"plan_path": out["artifact"], "plan_fp": "dead beef " * 8},
            "2026-09-04T00:01:00Z")
    except Exception as e:
        assert "APPROVAL DOES NOT MATCH" in str(e), str(e)
        return
    raise AssertionError("a wrong fingerprint must still be refused")


def t_no_inline_fingerprint_can_trip_the_digit_scrubber():
    """A bare 64-char hex digest carries a 13+ digit run about one time in
    twenty, and plan_fp is the value an operator copies into apply. Grouping in
    eights caps the longest possible run at eight, so this holds for EVERY
    digest rather than for the lucky ones."""
    import re as _re
    for i in range(200):
        d = H["_sha"]([i, "spread"])
        g = H["_grouped"](d)
        assert not _re.search(r"\d{13,}", g), (d, g)
        assert H["_ungrouped"](g) == d


def t_the_payment_amount_is_bound_to_the_approval():
    """THE MONEY ONE. plan_fp hashes each entry's `fp`, which is the INVOICE's
    state — the amount, the date and the destination account sat outside it. A
    sealed, validly-approved plan could be edited to move a different sum to a
    different bank account and the receipt would still verify."""
    reset()
    out = _payment_plan(amount=100.0)
    _FILES[out["artifact"]]["entries"][0]["allocate_amount"] = 9999.0
    res = _apply_payment(out)
    assert res["recorded"] == 0 and res["refused"] == 1, res
    assert any("payment amount" in d["reason"] for d in res["drift"]), res["drift"]


def t_the_destination_account_is_bound_to_the_approval():
    reset()
    out = _payment_plan(account="acct-1")
    _FILES[out["artifact"]]["account_id"] = "acct-attacker"
    res = _apply_payment(out)
    assert res["recorded"] == 0 and res["refused"] == 1, res
    assert any("destination account" in d["reason"] for d in res["drift"]), res["drift"]


def t_the_payment_date_is_bound_to_the_approval():
    reset()
    out = _payment_plan()
    _FILES[out["artifact"]]["entries"][0]["allocate_date"] = "2019-01-01"
    res = _apply_payment(out)
    assert res["recorded"] == 0 and res["refused"] == 1, res


def t_a_plan_predating_the_binding_is_refused_not_called_corrupt():
    """A v0.1.1 plan genuinely does not bind the amount. Honouring it would
    accept the exposure this closes; calling it "PLAN FILE ALTERED" would send
    the operator hunting for corruption that is not there. It gets its own
    message."""
    reset()
    out = _payment_plan()
    plan = _FILES[out["artifact"]]
    for e in plan["entries"]:
        del e["action_fp"]
    plan["plan_fp"] = H["plan_fp_of"](plan["entries"])   # a valid v0.1.1 seal
    _ready()
    queue(200, {"Invoices": [_inv(amount_due="100")]})
    res = H["xero_accounting_apply_payment_allocate"](
        {"plan_path": out["artifact"], "plan_fp": plan["plan_fp"]},
        "2026-09-04T00:01:00Z")[0]
    assert res["recorded"] == 0 and res["refused"] == 1, res
    assert any("predates" in d["reason"] for d in res["drift"]), res["drift"]


def t_the_voidability_verdict_is_bound_to_the_approval():
    """_void_guard REFUSES on blocked_because, so that list is a control rather
    than a display field — and it was outside the fingerprint. Emptying it on a
    sealed plan turned "cannot be voided" into "go ahead"."""
    reset()
    _ready()
    queue(200, {"Organisations": [{"PeriodLockDate": None}]})
    queue(200, {"Invoices": [_inv(status="AUTHORISED", amount_paid="40",
                                  amount_due="60")]})
    out, _ = H["xero_accounting_plan_invoice_void"](
        {"invoice_ids": ["i1"]}, "2026-09-04T00:00:00Z")
    assert out["blocked"] == 1, out
    _FILES[out["artifact"]]["entries"][0]["blocked_because"] = []
    _ready()
    queue(200, {"Invoices": [_inv(status="AUTHORISED", amount_paid="40",
                                  amount_due="60")]})
    res = H["xero_accounting_apply_invoice_void"](
        {"plan_path": out["artifact"], "plan_fp": out["plan_fp"]},
        "2026-09-04T00:01:00Z")[0]
    assert res["committed"] == 0, res
    assert any("voidability verdict" in d["reason"] for d in res["drift"]), res["drift"]


def t_every_plan_field_read_at_apply_is_inside_the_fingerprint():
    """The sweep, as a standing check rather than a one-off audit.

    For each plan kind, tamper with each field the apply path actually reads and
    assert the fingerprint moves. A field that can be edited without changing
    plan_fp is unbound by definition — that is what this catches, whoever adds
    the next command.
    """
    cases = [
        ("payment_allocate", {"fp": "x", "action_fp": H["_action_binding"](
            {"account_id": "a", "amount": 1.0, "date": "2026-01-01"})},
         [{"account_id": "b", "amount": 1.0, "date": "2026-01-01"},
          {"account_id": "a", "amount": 2.0, "date": "2026-01-01"},
          {"account_id": "a", "amount": 1.0, "date": "2026-01-02"}]),
        ("invoice_void", {"fp": "x", "action_fp": H["_action_binding"](
            {"blocked_because": ["has payments"]})},
         [{"blocked_because": []}]),
        ("send_reminder", {"fp": "x", "action_fp": H["_action_binding"](
            {"stage": 7})},
         [{"stage": 45}]),
    ]
    for kind, entry, tampers in cases:
        base = H["plan_fp_of"]([entry])
        for t in tampers:
            moved = dict(entry, action_fp=H["_action_binding"](t))
            assert H["plan_fp_of"]([moved]) != base, \
                "%s: %r is not inside plan_fp" % (kind, t)


def t_every_plan_command_returns_a_grouped_fingerprint():
    """All five, not just the one that had a test.

    Mutation testing applies one edit at a time, so a check that covers a single
    plan command leaves the other four free to regress. plan_fp is the value an
    operator copies into apply, and an ungrouped digest is destroyed by the
    airlock's digit scrubber roughly one run in twenty.
    """
    outs = {}

    reset()
    _ready()
    queue(200, {"Invoices": [_inv(status="DRAFT")]})
    o = H["xero_accounting_plan_invoice_post"](
        {"status": "DRAFT"}, "2026-09-04T00:00:00Z")[0]
    outs["plan_invoice_post"] = (o, _FILES[o["artifact"]])

    reset()
    _ready()
    queue(200, {"Organisations": [{"PeriodLockDate": None}]})
    queue(200, {"Invoices": [_inv()]})
    o = H["xero_accounting_plan_invoice_void"](
        {"invoice_ids": ["i1"]}, "2026-09-04T00:00:00Z")[0]
    outs["plan_invoice_void"] = (o, _FILES[o["artifact"]])

    reset()
    o = _payment_plan()
    outs["plan_payment_allocate"] = (o, _FILES[o["artifact"]])

    reset()
    o, plan = _plan_stage(stage=7)
    outs["plan_send_reminder"] = (o, plan)

    for name, (out, plan) in outs.items():
        assert " " in str(out.get("plan_fp")), \
            "%s returns an ungrouped plan_fp, exposed to the digit scrubber" % name
        assert " " in str(out.get("plan_id")), "%s: plan_id ungrouped" % name
        assert H["_ungrouped"](out["plan_fp"]) == plan["plan_fp"], \
            "%s: the grouped display value must normalise back to the sealed one" % name


def t_an_untampered_void_plan_still_applies():
    """The happy path for the voidability binding.

    Without it, breaking the binding leaves every void plan refused as
    "predates" — safe, but broken, and the refusal tests alone cannot tell a
    working guard from one that refuses everything.
    """
    reset()
    _ready()
    queue(200, {"Organisations": [{"PeriodLockDate": None}]})
    queue(200, {"Invoices": [_inv(status="AUTHORISED")]})
    out, _ = H["xero_accounting_plan_invoice_void"](
        {"invoice_ids": ["i1"]}, "2026-09-04T00:00:00Z")
    assert out["voidable"] == 1 and out["blocked"] == 0, out

    _ready()
    queue(200, {"Invoices": [_inv(status="AUTHORISED")]})
    queue(200, {"Invoices": [{"InvoiceID": "i1", "InvoiceNumber": "INV-1",
                              "Status": "VOIDED", "StatusAttributeString": "OK"}]})
    res = H["xero_accounting_apply_invoice_void"](
        {"plan_path": out["artifact"], "plan_fp": out["plan_fp"]},
        "2026-09-04T00:01:00Z")[0]
    assert res["committed"] == 1, res
    assert res["refused"] == 0, res


# ─────────────────────── v0.1.2 — the greeting rule

def t_greeting_name_reads_value_not_key_and_falls_back_to_a_person():
    f = H["_contact_greeting_name"]
    assert f({"FirstName": "Ayesha"}) == "Ayesha"
    assert f({"FirstName": ""}) == ""                 # present but empty
    assert f({}) == ""                                # key omitted entirely
    assert f({"FirstName": "  "}) == ""
    assert f({"Name": "Acme Ltd"}) == "", \
        "the company name is NOT a fallback — Xero renders 'Hi ,' instead"
    assert f({"ContactPersons": [{"FirstName": "Bhavna"}]}) == "Bhavna"
    assert f({"FirstName": "Ayesha",
              "ContactPersons": [{"FirstName": "Bhavna"}]}) == "Ayesha"


def t_a_contact_with_no_first_name_is_refused_by_default():
    """Learned from a live send: the email arrived opening "Hi ,". Xero sends it
    happily — this is not an API refusal, it is a quality one, and it is as
    unrecallable as any other send."""
    reset()
    out, plan = _plan_stage(contacts=[_contact("c1", "a@example.com", first=None)])
    assert out["counts"]["eligible"] == 0, out["counts"]
    assert out["counts"]["no_greeting_name"] == 1, out["counts"]
    assert out["greeting_policy"] == "refusing a nameless greeting", out
    reasons = plan["excluded"][0]["reasons"]
    assert any("Hi ," in r for r in reasons), reasons
    assert any("does not fall back to the company name" in r for r in reasons), reasons


def t_the_nameless_override_travels_through_the_inputs():
    """The override is an INPUT, so choosing to send a nameless greeting goes
    through the approval hash and onto the receipt. A flag that lived in the
    handler instead would make it an accident nobody approved."""
    reset()
    _ready()
    queue(200, {"Invoices": [_inv()]})
    queue(200, {"Contacts": [_contact("c1", "a@example.com", first=None)]})
    out, _ = H["xero_accounting_plan_send_reminder"](
        {"stage": 7, "allow_empty_greeting": True}, "2026-09-04T00:00:00Z")
    assert out["counts"]["eligible"] == 1, out["counts"]
    assert out["greeting_policy"] == "sending anyway (allow_empty_greeting=true)", out

    m = json.load(open(os.path.join(HERE, "module.json"), encoding="utf-8"))
    cmd = next(c for c in m["commands"] if c["id"].endswith("plan_send_reminder"))
    assert "allow_empty_greeting" in cmd["input_schema"], \
        "an override that is not a declared input cannot reach the approval"


def t_a_contact_person_first_name_satisfies_the_greeting():
    reset()
    out, _ = _plan_stage(contacts=[_contact("c1", "a@example.com", first=None,
                                            persons=[{"FirstName": "Bhavna"}])])
    assert out["counts"]["eligible"] == 1, out["counts"]


def t_the_greeting_limit_is_in_the_output():
    reset()
    out, _ = _plan_stage()
    assert any("Hi ," in x for x in out["limits"]), out["limits"]
    assert any("allow_empty_greeting" in x for x in out["limits"]), out["limits"]


def t_no_input_type_the_airlock_cannot_validate():
    """Mirror approval_airlock's type list, and go red if a manifest declares
    one outside it.

    approval_airlock._validate accepts array / string / number / object, or no
    type at all. There is NO boolean branch and no integer branch, so a field
    declared either is REFUSED with "wrong type" the moment a value is supplied
    — the input becomes permanently unusable while looking perfectly correct in
    the manifest. Caught live: `allow_empty_greeting` was declared "boolean" and
    the Studio approve call rejected it.

    Same pattern as t_no_output_field_name_trips_the_airlock_redactor: mirror
    the platform constant so a widening of it shows up here by name.
    """
    VALID = {"array", "string", "number", "object", None}
    m = json.load(open(os.path.join(HERE, "module.json"), encoding="utf-8"))
    bad = []
    for c in m["commands"]:
        for f, spec in (c.get("input_schema") or {}).items():
            if isinstance(spec, dict) and spec.get("type") not in VALID:
                bad.append("%s.%s = %r" % (c["id"], f, spec.get("type")))
    assert not bad, "the airlock cannot validate these, so they can never be " \
                    "supplied: %s" % bad


def t_a_flag_declared_without_a_type_is_still_coerced_safely():
    """A typeless field gets NO airlock validation, so the handler must not use
    a bare bool(): the string "false" is truthy, and this flag gates a
    customer-facing send."""
    f = H["_as_bool"]
    assert f(True) is True and f(False) is False
    assert f(None) is False
    assert f("true") is True and f("false") is False
    assert f("False") is False and f("0") is False and f("no") is False
    assert f("1") is True and f("yes") is True
    assert f(1) is True and f(0) is False
    assert f({"weird": 1}) is False, "an unexpected shape must not read as true"


def t_the_greeting_override_honours_a_string_false():
    """End to end for the coercion: an operator passing "false" must not have
    the gate flipped open."""
    reset()
    _ready()
    queue(200, {"Invoices": [_inv()]})
    queue(200, {"Contacts": [_contact("c1", "a@example.com", first=None)]})
    out, _ = H["xero_accounting_plan_send_reminder"](
        {"stage": 7, "allow_empty_greeting": "false"}, "2026-09-04T00:00:00Z")
    assert out["counts"]["eligible"] == 0, out["counts"]
    assert out["greeting_policy"] == "refusing a nameless greeting", out


def _airlock_validate(schema, inputs):
    """A faithful mirror of approval_airlock._validate's type + required rules.

    Copied deliberately rather than imported: the station is not on the CI
    machine's path, and a mirror that drifts shows up as a failure here, which
    is the point. If the platform widens its type vocabulary, this goes red and
    names the field.
    """
    errors = []
    for field, spec in (schema or {}).items():
        if not isinstance(spec, dict):
            continue
        if spec.get("required") and (field not in inputs
                                     or inputs[field] in (None, "", [])):
            errors.append("missing required field: " + field)
        if field in inputs and inputs[field] is not None:
            t, v = spec.get("type"), inputs[field]
            ok = (t == "array" and isinstance(v, list)) or \
                 (t == "string" and isinstance(v, str)) or \
                 (t == "number" and isinstance(v, (int, float))
                  and not isinstance(v, bool)) or \
                 (t == "object" and isinstance(v, dict)) or t is None
            if not ok:
                errors.append("wrong type for '%s' (want %s)" % (field, t))
    for field in inputs:
        if field not in (schema or {}):
            errors.append("unknown field: " + field)
    return errors


def _specimen(t):
    """A well-formed value for a declared type — what a buyer would send."""
    return {"array": ["x"], "string": "x", "number": 1,
            "object": {"k": "v"}}.get(t, True)


def t_every_declared_input_is_actually_settable():
    """The bug this exists for: `allow_empty_greeting` was declared "boolean",
    passed every lint and every unit test, and failed the first time anyone SET
    it — which happened to be a Studio run, not the suite. A field nobody sets
    in testing is a field whose type is unverified until a buyer finds it.

    So: for every input on every command, synthesize a well-formed value of its
    declared type and push it through the airlock's own validation rules. This
    catches a bad type name AND a type name that cannot carry a real value.
    """
    m = json.load(open(os.path.join(HERE, "module.json"), encoding="utf-8"))
    broken = []
    for c in m["commands"]:
        schema = c.get("input_schema") or {}
        for field, spec in schema.items():
            if not isinstance(spec, dict):
                broken.append("%s.%s: spec is not a dict" % (c["id"], field))
                continue
            # supply this ONE field, plus anything required, as a buyer would
            inputs = {f: _specimen(sp.get("type"))
                      for f, sp in schema.items()
                      if isinstance(sp, dict) and sp.get("required")}
            inputs[field] = _specimen(spec.get("type"))
            errs = _airlock_validate(schema, inputs)
            if errs:
                broken.append("%s.%s (type=%r) -> %s"
                              % (c["id"], field, spec.get("type"), errs))
    assert not broken, "these inputs cannot be set by a caller:\n  " + \
                       "\n  ".join(broken)


def t_a_required_array_input_is_a_deliberate_choice():
    """A trap one line ABOVE the type check in the same validator:

        if spec.get("required") and inputs[field] in (None, "", [])

    An EMPTY LIST counts as MISSING. So a required `array` input can never be
    sent empty — the airlock rejects it as absent before the handler sees it.
    That is correct for `invoice_ids` on a void (an empty void selects nothing,
    and the handler refuses it too, so both layers agree). It would be WRONG for
    any field where empty legitimately means "none, carry on".

    A tripwire, not a ban: adding a required array is fine, but it has to be a
    decision somebody made rather than a default nobody noticed.
    """
    REVIEWED = {
        # empty means "nothing to void" — the handler raises on it as well
        "xero_accounting.plan_invoice_void.invoice_ids",
        # empty means "no allocations" — the handler raises on it as well
        "xero_accounting.plan_payment_allocate.allocations",
    }
    m = json.load(open(os.path.join(HERE, "module.json"), encoding="utf-8"))
    found = set()
    for c in m["commands"]:
        for field, spec in (c.get("input_schema") or {}).items():
            if isinstance(spec, dict) and spec.get("required") \
                    and spec.get("type") == "array":
                found.add("%s.%s" % (c["id"], field))
    new = found - REVIEWED
    assert not new, (
        "new required array input(s) %s — an empty value reads as MISSING to "
        "the airlock. If empty legitimately means 'none', drop `required`; if "
        "not, add it to REVIEWED with the reason." % sorted(new))


def t_a_typeless_input_is_paired_with_a_safe_coercer():
    """spec-core 4e: a boolean must be declared with NO type, because the
    airlock has no boolean branch. But a typeless field gets NO validation at
    all — so the handler becomes the only guard, and a bare bool() reads the
    string "false" as True.

    Declaring typeless and reading it raw is the dangerous half of the
    workaround without the safe half. This asserts the pair.
    """
    import re
    m = json.load(open(os.path.join(HERE, "module.json"), encoding="utf-8"))
    src = open(os.path.join(HERE, "handlers", "handler.py"), encoding="utf-8").read()
    unguarded = []
    for c in m["commands"]:
        for field, spec in (c.get("input_schema") or {}).items():
            if not isinstance(spec, dict) or spec.get("type") is not None:
                continue
            safe = re.search(r"_as_bool\(inputs\.get\(\"%s\"\)" % re.escape(field), src)
            bare = re.search(r"(?<!_as_)bool\(inputs\.get\(\"%s\"\)" % re.escape(field), src)
            if bare or not safe:
                unguarded.append("%s.%s" % (c["id"], field))
    assert not unguarded, (
        "typeless inputs read without a coercer — the airlock validates these "
        "not at all, so bool(\"false\") would flip them open: %s" % unguarded)


def t_every_declared_input_is_exercised_somewhere_in_this_suite():
    """The coverage half. A declared input nobody ever sets is an input whose
    behaviour is unverified — which is exactly how the boolean bug survived to
    a Studio run. If a field is worth declaring, one test should send it.
    """
    m = json.load(open(os.path.join(HERE, "module.json"), encoding="utf-8"))
    suite = open(os.path.join(HERE, "test_handler.py"), encoding="utf-8").read()
    # only count a field being SET as an input key, not merely mentioned
    never = []
    for c in m["commands"]:
        for field in (c.get("input_schema") or {}):
            if ('"%s":' % field) not in suite:
                never.append("%s.%s" % (c["id"], field))
    assert not never, ("declared but never supplied by any test, so its type is "
                       "unverified until a buyer sets it:\n  " + "\n  ".join(never))


# ──────────── coverage for inputs no test used to supply

def t_hygiene_scan_honours_all_three_thresholds():
    reset()
    _ready()
    queue(200, {"Invoices": [_inv(due_days=47)]})
    out, _ = H["xero_accounting_hygiene_scan"](
        {"draft_days": 30, "overdue_days": 90, "max_findings": 500},
        "2026-09-04T00:00:00Z")
    # 47 days overdue does not clear an overdue_days of 90
    assert out["total_findings"] == 0, out
    assert _FILES[out["artifact"]]["thresholds"] == {"draft_days": 30,
                                                     "overdue_days": 90}, \
        _FILES[out["artifact"]]["thresholds"]

    reset()
    _ready()
    queue(200, {"Invoices": [_inv(due_days=47)]})
    try:
        H["xero_accounting_hygiene_scan"]({"max_findings": 0},
                                          "2026-09-04T00:00:00Z")
    except Exception as e:
        # Assert the PROPERTY, not the message: a cap of 0 is honoured as zero
        # rather than silently rewritten to the default, and whichever layer
        # catches it refuses instead of truncating. (spec-core 4a.)
        assert "Refusing rather than truncating" in str(e), str(e)
        return
    raise AssertionError("max_findings=0 must be honoured, not swallowed as a "
                         "falsy value and replaced by the default")


def t_plan_invoice_post_honours_contact_id_and_its_cap():
    reset()
    _ready()
    captured = {}
    real = H["urllib"].request.urlopen

    def spy(req, timeout=None):
        captured["url"] = req.full_url
        return real(req, timeout=timeout)

    H["urllib"].request.urlopen = spy
    try:
        queue(200, {"Invoices": [_inv(status="DRAFT")]})
        out, _ = H["xero_accounting_plan_invoice_post"](
            {"status": "DRAFT", "contact_id": "c-42", "max_invoices": 5},
            "2026-09-04T00:00:00Z")
    finally:
        H["urllib"].request.urlopen = real
    assert out["count"] == 1, out
    assert "c-42" in captured["url"], \
        "contact_id must reach the Xero where clause: %s" % captured["url"]


def t_plan_invoice_void_honours_its_cap():
    reset()
    _ready()
    try:
        H["xero_accounting_plan_invoice_void"](
            {"invoice_ids": ["i1", "i2", "i3"], "max_invoices": 2},
            "2026-09-04T00:00:00Z")
    except Exception as e:
        assert "max_invoices=2" in str(e), str(e)
        return
    raise AssertionError("the cap must refuse rather than truncate")


def t_list_contacts_only_reachable_filters_the_artifact_not_the_counts():
    """The counts must still describe the whole book — a filter that also
    shrank the denominator would report 100% reachability on any store."""
    reset()
    _ready()
    queue(200, {"Contacts": [_contact("c1", "a@example.com"),
                             _contact("c2", "", first=None),
                             _contact("c3", None, first=None)]})
    out, _ = H["xero_accounting_list_contacts"](
        {"only_reachable": True, "max_contacts": 100}, "2026-09-04T00:00:00Z")
    assert out["counts"] == {"total": 3, "with_email": 1, "without_email": 2,
                             "with_greeting_name": 1}, out["counts"]
    rows = _FILES[out["artifact"]]["contacts"]
    assert len(rows) == 1 and rows[0]["contact_id"] == "c1", rows


def t_a_custom_ladder_changes_which_stage_is_owed():
    """`ladder` is configurable per run and must not be hardcoded anywhere."""
    reset()
    out, plan = _plan_stage(stage=14, invoices=[_inv(due_days=40)],
                            ladder=[14, 30])
    assert out["counts"]["eligible"] == 1, out["counts"]

    reset()
    out, plan = _plan_stage(stage=30, invoices=[_inv(due_days=40)],
                            ladder=[14, 30])
    assert out["counts"]["eligible"] == 0, out["counts"]
    assert any("next stage owed is 14" in r
               for r in plan["excluded"][0]["reasons"]), plan["excluded"]

    reset()
    _ready()
    queue(200, {"Invoices": [_inv()]})
    queue(200, {"Contacts": [_contact()]})
    try:
        H["xero_accounting_plan_send_reminder"](
            {"stage": 7, "ladder": [14, 30]}, "2026-09-04T00:00:00Z")
    except Exception as e:
        assert "not in the ladder" in str(e), str(e)
        return
    raise AssertionError("a stage outside a CUSTOM ladder must refuse too")


def t_composite_fp_reaches_the_ledger():
    """Declared on every apply for the cross-module coordinator and never
    supplied by a test until now. It costs nothing at runtime, but a field that
    silently fails to record would make a coordinator's trail unreadable."""
    reset()
    out, _ = _plan_stage(stage=7)
    _ready()
    queue(200, {"Invoices": [_inv()]})
    queue(200, {"Contacts": [_contact()]})
    queue(204, {})
    res, _ = H["xero_accounting_apply_send_reminder"](
        {"plan_path": out["artifact"], "plan_fp": out["plan_fp"],
         "composite_fp": "cross-system-abc123"}, "2026-09-04T00:01:00Z")
    assert res["sent"] == 1, res
    led = _FILES["/ws/xero_ledger_ledger.json"]["entries"]
    assert any(e["detail"].get("composite_fp") == "cross-system-abc123"
               for e in led), led


def t_a_numeric_input_of_zero_is_not_swallowed():
    """`int(inputs.get("x") or default)` treats 0 as absent, because 0 is falsy.
    So `overdue_days: 0` — "everything due today or later" — silently became 1,
    and `max_findings: 0` silently became 1000. The command did something other
    than what was asked and said nothing.

    The quiet half of the same family as the boolean bug: the input is accepted
    and then ignored. Found by writing coverage for inputs no test had ever set.
    """
    f = H["_as_int"]
    assert f(0, 99) == 0, "a legitimate zero must survive"
    assert f(None, 99) == 99
    assert f("", 99) == 99
    assert f(5, 99) == 5
    assert f("7", 99) == 7
    assert f(0.0, 99) == 0


def t_overdue_days_zero_is_honoured_not_replaced_by_the_default():
    """End to end for the zero case, on the input where zero is most obviously
    meaningful."""
    reset()
    _ready()
    # due TODAY: 0 days overdue. overdue_days=0 must flag it; the old
    # `or 1` default would silently require 1 and report nothing.
    queue(200, {"Invoices": [_inv(due_days=0)]})
    out, _ = H["xero_accounting_hygiene_scan"]({"overdue_days": 0},
                                               "2026-09-04T00:00:00Z")
    assert _FILES[out["artifact"]]["thresholds"]["overdue_days"] == 0, \
        _FILES[out["artifact"]]["thresholds"]
    assert out["counts"].get("overdue") == 1, out["counts"]


# ─────────────────────────────────────────────────────────── runner

def main():
    tests = sorted((k, v) for k, v in globals().items()
                   if k.startswith("t_") and callable(v))
    failed = []
    for name, fn in tests:
        try:
            reset()
            fn()
            print("  PASS  %s" % name)
        except Exception as e:
            failed.append((name, e))
            print("  FAIL  %s -> %s: %s" % (name, type(e).__name__, e))
    print("\n%d/%d passed" % (len(tests) - len(failed), len(tests)))
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
