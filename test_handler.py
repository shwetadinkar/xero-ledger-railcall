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
