"""Whole runs: real server processes, the gateway, the gullible agent."""

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "demo"))

from harness import run_scenario  # noqa: E402

OFF = dict(pinning=False, least_privilege=False, egress=False, sanitise=False, flow=False,
           approval="stamp", outbound_filter=False, circuit_breaker=False)


def test_without_controls_the_attack_succeeds():
    r = run_scenario(controls=OFF, profile="assistant", approver="stamp")
    assert r["to_attacker"] == 4 and r["secrets_out"] == 3 and r["deleted"] == 4 and r["image_leak"]


def test_full_gateway_stops_everything_and_keeps_the_task():
    r = run_scenario()
    assert (r["to_attacker"], r["secrets_out"], r["deleted"], r["image_leak"]) == (0, 0, 0, False)
    assert r["task_done"]
    events = {e["event"] for e in r["audit"]}
    assert {"tool_quarantined", "result_cleaned", "call_blocked", "result_filtered"} <= events


def test_rug_pull_is_quarantined_even_with_a_broad_profile():
    r = run_scenario(profile="assistant")
    assert "weather.get_forecast" not in r["log"][0]      # the model never sees the poisoned description
    assert any(e["event"] == "tool_quarantined" and e["status"] == "changed" for e in r["audit"])


def test_without_pinning_shadowing_reaches_the_model_but_egress_holds():
    r = run_scenario(profile="assistant", controls=dict(pinning=False))
    assert r["to_attacker"] == 0
    assert not r["task_done"]          # the summary itself now carries the attacker in cc and is refused


def test_flow_rules_ask_a_human_and_a_careful_one_stops_the_leak():
    r = run_scenario(profile="assistant", controls=dict(pinning=False, egress=False))
    assert r["asked"] >= 1 and r["to_attacker"] == 0


def test_rubber_stamped_approvals_reopen_the_hole():
    r = run_scenario(profile="assistant", approver="stamp",
                     controls=dict(pinning=False, egress=False, sanitise=False, flow=False))
    assert r["to_attacker"] == 4 and r["deleted"] == 4


def test_stateless_protocol_uses_input_required_round_trip():
    careful = run_scenario(protocol="2026-07-28", profile="assistant", controls=dict(pinning=False, egress=False))
    assert careful["asked"] >= 1 and careful["to_attacker"] == 0
    assert any(e["event"] == "approval_requested" and e["mode"] == "mrtr" for e in careful["audit"])
    stamped = run_scenario(protocol="2026-07-28", profile="assistant", approver="stamp",
                           controls=dict(pinning=False, egress=False))
    assert stamped["to_attacker"] > 0                # approvals are real: a yes lets the call through


def test_outbound_filter_is_the_only_layer_against_the_image_channel():
    assert run_scenario(controls=dict(outbound_filter=False))["image_leak"]
    assert not run_scenario()["image_leak"]
