"""The decision function, one rule at a time. No processes, no I/O."""

from pathlib import Path

import pytest

from mcpgate.config import Controls, Policy, ToolPolicy
from mcpgate.policy import Session, ToolInfo, decide, derive, record

ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture
def policy() -> Policy:
    return Policy.load(ROOT / "gateway.toml")


def info(name="mail.send_email", labels=(), effect="communication", **kw) -> ToolInfo:
    server, tool = name.split(".")
    return ToolInfo(qualified=name, server=server, name=tool, labels=set(labels), effect=effect, **kw)


SEND = dict(recipient_args=["to", "cc"], owner_reply_ok=True)


def test_least_privilege_blocks_tools_outside_the_profile(policy):
    d = decide(info("files.read_file", {"D"}, "none"), {"path": "x"}, Session(), policy, "inbox_summary")
    assert (d.verdict, d.control) == ("deny", "least_privilege")


def test_egress_checks_recipients_not_addresses_in_the_body(policy):
    s = Session()
    ok = decide(info(**SEND), {"to": "tim@yourcompany.example", "body": "from j.weber@customer.example"}, s, policy, "inbox_summary")
    bad = decide(info(**SEND), {"to": "tim@yourcompany.example", "cc": "x@attacker.example", "body": ""}, s, policy, "inbox_summary")
    assert ok.verdict == "allow"
    assert (bad.verdict, bad.control) == ("deny", "egress_allowlist")


def test_tools_without_recipient_fields_are_scanned_completely(policy):
    t = info("weather.get_forecast", {"U"}, "communication")
    policy.profiles["p"] = {"weather.get_forecast"}
    d = decide(t, {"city": "Berlin", "notes": "see https://attacker.example/x?d=1"}, Session(), policy, "p")
    assert d.control == "egress_allowlist"


def test_rule_of_two_asks_before_data_leaves(policy):
    policy.controls.egress = False
    s = Session(labels={"U", "D"})
    d = decide(info(**SEND), {"to": "someone@partner.example"}, s, policy, "inbox_summary")
    assert (d.verdict, d.control) == ("approve", "rule_of_two")


def test_reply_to_the_owner_is_not_an_external_effect(policy):
    s = Session(labels={"U", "D"})
    d = decide(info(**SEND), {"to": "tim@yourcompany.example", "body": "summary"}, s, policy, "inbox_summary")
    assert d.verdict == "allow"


def test_integrity_rule_untrusted_input_plus_state_change(policy):
    policy.profiles["p"] = {"crm.update"}
    d = decide(info("crm.update", (), "state"), {}, Session(labels={"U"}), policy, "p")
    assert (d.verdict, d.control) == ("approve", "integrity")


def test_destructive_always_needs_a_human(policy):
    policy.profiles["p"] = {"mail.delete_emails"}
    d = decide(info("mail.delete_emails", (), "destructive"), {"scope": "all"}, Session(), policy, "p")
    assert (d.verdict, d.control) == ("approve", "destructive")


def test_changed_tool_is_quarantined(policy):
    t = info(**SEND)
    t.status = "changed"
    assert decide(t, {"to": "tim@yourcompany.example"}, Session(), policy, "inbox_summary").control == "pinning"


def test_circuit_breaker(policy):
    s = Session(calls=policy.max_calls)
    assert decide(info(**SEND), {"to": "tim@yourcompany.example"}, s, policy, "inbox_summary").control == "circuit_breaker"


def test_taint_is_monotone():
    s = Session()
    record(info("mail.read_inbox", {"U", "D"}, "none"), s)
    record(info("files.read_file", {"D"}, "none"), s)
    assert s.labels == {"U", "D"} and s.calls == 2


def test_annotations_count_only_for_internal_servers():
    tool = {"name": "wipe", "annotations": {"readOnlyHint": True, "openWorldHint": False}}
    trusted = derive("internal", tool, None, "a.wipe")
    stranger = derive("third_party", tool, None, "b.wipe")
    assert (trusted.effect, trusted.labels) == ("none", set())
    assert (stranger.effect, stranger.labels) == ("communication", {"U"})   # a liar gets the worst case


def test_policy_overrides_annotations():
    tool = {"name": "read_inbox", "annotations": {"readOnlyHint": True, "openWorldHint": False}}
    t = derive("internal", tool, ToolPolicy(labels={"U", "D"}), "mail.read_inbox")
    assert t.labels == {"U", "D"} and t.effect == "none"


def test_a_read_only_tool_that_reaches_the_open_world_still_communicates():
    fetch = {"name": "fetch", "annotations": {"readOnlyHint": True, "openWorldHint": True}}
    assert derive("internal", fetch, None, "web.fetch").effect == "communication"   # its URL leaves


def test_prose_with_addresses_and_links_is_not_refused(policy):
    t = info("calendar.create_event", (), "communication", arg_names={"title", "description"})
    policy.profiles["p"] = {"calendar.create_event"}
    text = "Agenda: see https://yourcompany.example/wiki (page 2). Questions to tim@yourcompany.example, thanks."
    assert decide(t, {"title": "Sync", "description": text}, Session(), policy, "p").verdict == "allow"


def test_words_a_relay_would_route_elsewhere_are_refused(policy):
    t = info("calendar.create_event", (), "communication", arg_names={"title", "description"})
    policy.profiles["p"] = {"calendar.create_event"}
    for word in ["x%attacker.example@yourcompany.example", "x@[203.0.113.5]",
                 "https://yourcompany.example\t.attacker.example/c", "https://attacker.example\\@yourcompany.example/c"]:
        d = decide(t, {"title": "Sync", "description": f"see {word}"}, Session(), policy, "p")
        assert (d.verdict, d.control) == ("deny", "egress_allowlist"), word


def test_controls_can_be_switched_off_for_the_ablation(policy):
    policy.controls = Controls(least_privilege=False)
    d = decide(info("files.read_file", {"D"}, "none"), {"path": "x"}, Session(), policy, "inbox_summary")
    assert d.verdict == "allow"


MAIL_SCHEMA = {"to", "cc", "bcc", "subject", "body"}


def test_an_unlisted_bcc_field_is_still_a_recipient(policy):
    t = info(arg_names=MAIL_SCHEMA, **SEND)
    s = Session(labels={"U", "D"})
    leak = decide(t, {"to": "tim@yourcompany.example", "bcc": "x@attacker.example", "body": "secret"}, s, policy, "inbox_summary")
    reply = decide(t, {"to": "tim@yourcompany.example", "body": "summary"}, s, policy, "inbox_summary")
    assert (leak.verdict, leak.control) == ("deny", "egress_allowlist")
    assert reply.verdict == "allow"


def test_recipients_the_gateway_cannot_read_count_as_foreign(policy):
    t = info(**SEND)
    for to in ["x@[203.0.113.5]", "x@attacker", "tim@yourcompany.example x@[203.0.113.5]"]:
        d = decide(t, {"to": to, "body": ""}, Session(), policy, "inbox_summary")
        assert (d.verdict, d.control) == ("deny", "egress_allowlist"), to
    named = decide(t, {"to": "Tim <tim@yourcompany.example>", "body": ""}, Session(), policy, "inbox_summary")
    assert named.verdict == "allow"


def test_arguments_outside_the_reviewed_schema_are_refused(policy):
    t = info(arg_names={"to", "subject", "body"}, **SEND)
    d = decide(t, {"to": "tim@yourcompany.example", "body": "", "forward_copy": "yes"}, Session(), policy, "inbox_summary")
    assert (d.verdict, d.control) == ("deny", "egress_allowlist") and "forward_copy" in d.reason


def test_schema_fields_come_from_the_reviewed_definition():
    tool = {"name": "send_email", "inputSchema": {"type": "object", "properties": {"to": {}, "body": {}}}}
    assert derive("internal", tool, None, "mail.send_email").arg_names == {"to", "body"}
    assert derive("internal", {"name": "x"}, None, "mail.x").arg_names is None
