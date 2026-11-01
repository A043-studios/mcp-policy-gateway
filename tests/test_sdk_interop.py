"""Interoperability with the official MCP Python SDK, as a real client over stdio.

Skipped when the SDK is not installed (pip install "mcp>=2").
"""

import asyncio
import os
import shutil
import sys
import tempfile
from pathlib import Path

import pytest

mcp = pytest.importorskip("mcp")
from mcp import ClientSession, StdioServerParameters, types  # noqa: E402
from mcp.client.stdio import stdio_client  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]


def _is_error(res) -> bool:   # SDK 1.x: isError, SDK 2.x: is_error
    return bool(getattr(res, "is_error", None) if hasattr(res, "is_error") else res.isError)


def _params(ws: str, policy: str = "gateway.toml", profile: str = "inbox_summary") -> StdioServerParameters:
    return StdioServerParameters(
        command=sys.executable, args=["-m", "mcpgate", "run", "--policy", policy, "--profile", profile],
        env={**os.environ, "PYTHONPATH": str(ROOT / "src"), "WORKSPACE": ws}, cwd=str(ROOT))


def _workspace() -> str:
    ws = tempfile.mkdtemp()
    shutil.copytree(ROOT / "demo" / "workspace", ws, dirs_exist_ok=True)
    return ws


def test_sdk_client_lists_and_calls_through_the_gateway():
    async def go():
        async with stdio_client(_params(_workspace())) as (r, w):
            async with ClientSession(r, w) as s:
                await s.initialize()
                names = [t.name for t in (await s.list_tools()).tools]
                ok = await s.call_tool("mail.read_inbox", {})
                blocked = await s.call_tool("files.read_file", {"path": "secrets/api_keys.env"})
                return names, ok, blocked
    names, ok, blocked = asyncio.run(go())
    assert names == ["mail.read_inbox", "mail.send_email"]
    assert not _is_error(ok) and "untrusted_data" in ok.content[0].text
    assert _is_error(blocked) and "least_privilege" in blocked.content[0].text


def test_sdk_elicitation_approval_round_trip(tmp_path):
    # a policy where a call needs approval: egress open, so the Rule of Two decides
    policy = tmp_path / "p.toml"
    text = (ROOT / "gateway.toml").read_text().replace("egress = true", "egress = false")
    text = text.replace('[gateway]\n', f'[gateway]\nroot = "{ROOT.as_posix()}"\n', 1)
    policy.write_text(text)
    shutil.copy(ROOT / "mcp.lock.json", tmp_path / "mcp.lock.json")
    answers = []

    async def on_elicit(context, params):
        answers.append(params.message)
        return types.ElicitResult(action="accept", content={"approve": False})

    async def go():
        async with stdio_client(_params(_workspace(), str(policy))) as (r, w):
            async with ClientSession(r, w, elicitation_callback=on_elicit) as s:
                await s.initialize()
                await s.call_tool("mail.read_inbox", {})
                return await s.call_tool("mail.send_email", {"to": "x@partner.example", "subject": "s", "body": "b"})
    res = asyncio.run(go())
    assert len(answers) == 1 and "mail.send_email" in answers[0]
    assert _is_error(res) and "rule_of_two" in res.content[0].text


async def _never(context, params):   # pragma: no cover
    raise AssertionError("the 2026 path must not use server-initiated elicitation")


def test_sdk_stateless_2026_protocol_with_input_required(tmp_path):
    """2026-07-28: no handshake; approval comes back as an input_required result (MRTR)."""
    policy = tmp_path / "p.toml"
    text = (ROOT / "gateway.toml").read_text().replace("egress = true", "egress = false")
    policy.write_text(text.replace('[gateway]\n', f'[gateway]\nroot = "{ROOT.as_posix()}"\n', 1))
    shutil.copy(ROOT / "mcp.lock.json", tmp_path / "mcp.lock.json")
    args = {"to": "x@partner.example", "subject": "s", "body": "b"}

    async def go():
        async with stdio_client(_params(_workspace(), str(policy))) as (r, w):
            # declaring an elicitation callback advertises the capability; the round trip is driven by hand
            async with ClientSession(r, w, elicitation_callback=_never) as s:
                found = await s.discover()
                await s.call_tool("mail.read_inbox", {})
                first = await s.call_tool("mail.send_email", args, allow_input_required=True)
                key, request = next(iter(first.input_requests.items()))
                yes = types.ElicitResult(action="accept", content={"approve": True})
                forged = await s.call_tool("mail.send_email", {**args, "to": "evil@attacker.example"},
                                           input_responses={key: yes}, request_state=first.request_state)
                second = await s.call_tool("mail.send_email", args, input_responses={key: yes},
                                           request_state=first.request_state)
                return found, s.protocol_version, first, request, forged, second
    found, version, first, request, forged, second = asyncio.run(go())
    assert version == "2026-07-28" and "2026-07-28" in found.supported_versions
    assert first.result_type == "input_required"
    assert "mail.send_email" in request.params.message
    assert _is_error(forged)                      # a state token for one call cannot approve another
    assert not _is_error(second) and "Sent to x@partner.example" in second.content[0].text
