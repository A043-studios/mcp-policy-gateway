# MCP threats and what the gateway does about them

| Threat | Example | Gateway control | Residual risk |
|---|---|---|---|
| Indirect prompt injection in tool results | Hidden HTML in an email, a GitHub issue (Invariant Labs, May 2025), a support ticket (Supabase, July 2025) | Flow rules (U and D tracking), egress allowlist, least privilege; sanitising and spotlighting as helpers | Visible injections reach the model; the gateway limits what they can make it do |
| Tool poisoning | Instructions in a tool description (Invariant Labs, April 2025; MCPTox, 2025) | Pinning: only reviewed descriptions are shown. `review` screens descriptions | A description that was malicious at review time and passed review |
| Rug pull | A reviewed tool changes its description later | Pinning: changed definitions are quarantined | None for descriptions; behaviour changes inside the server are not visible |
| Tool shadowing | One server's description changes how the model uses another server's tool | Pinning; egress allowlist on the other tool's recipients | Shadowing that stays inside allowed destinations |
| Config or command swap | Approved config replaced later (MCPoison, CVE-2025-54136) | Start commands are pinned; a changed command is not started, neither by the gateway nor by `review` | Unpinned package versions behind an unchanged command |
| Malicious server code | postmark-mcp 1.0.16 BCC'd every email (September 2025) | Not covered | Sandbox the server, restrict its network egress, pin versions |
| Untrusted annotations | A server claims `readOnlyHint` for a destructive tool | Annotations are believed only from `trust = "internal"` servers | Lying internal servers |
| Confused deputy, token passthrough | Proxies reusing consent or forwarding tokens | Out of scope (stdio, no OAuth) | Follow the MCP authorization spec |
| Exfiltration through rendering | Markdown image with data in the URL | Outbound filter on results (text, embedded resources, structured content) and arguments | Channels the filter does not parse, such as HTML images in results from tools without U |
| Unclassified or unreadable recipients | A `bcc` field the policy does not list; `x@[203.0.113.5]` | Recipient-like schema fields are checked as recipients; recipients must parse completely; arguments outside the reviewed schema are refused | Recipient fields with unusual names (`review` flags the common ones) |
| Runaway agents | Loops, cost blow-ups | Circuit breaker per session and per tool | Long, slow abuse below the limits |
| Approval fatigue | Users clicking yes | Approvals only where flow rules demand them; the prompt names recipients and hosts first, then the call and the reason | A user who approves everything (see the ablation) |
