"""Take the gateway apart one control at a time and see what each one was holding back.

    python demo/ablation.py
"""

from __future__ import annotations

from harness import run_scenario

OFF = dict(pinning=False, least_privilege=False, egress=False, sanitise=False, flow=False,
           approval="stamp", outbound_filter=False, circuit_breaker=False)

ROWS = [
    ("No gateway (pass-through)", dict(controls=OFF, profile="assistant", approver="stamp")),
    ("Full gateway", dict()),
    ("Full gateway, 2026-07-28 protocol", dict(protocol="2026-07-28")),
    ("Over-broad profile", dict(profile="assistant")),
    ("... and pinning off", dict(profile="assistant", controls=dict(pinning=False))),
    ("... and egress open", dict(profile="assistant", controls=dict(pinning=False, egress=False))),
    ("... and sanitising off", dict(profile="assistant", controls=dict(pinning=False, egress=False, sanitise=False))),
    ("... and flow rules off", dict(profile="assistant", controls=dict(pinning=False, egress=False, sanitise=False, flow=False))),
    ("... and approvals stamped", dict(profile="assistant", approver="stamp",
                                       controls=dict(pinning=False, egress=False, sanitise=False, flow=False))),
    ("Full gateway, outbound filter off", dict(controls=dict(outbound_filter=False))),
]


def main() -> list[tuple[str, dict]]:
    results = [(name, run_scenario(**kw)) for name, kw in ROWS]
    head = f"{'Configuration':36} {'Out':>4} {'Secr':>5} {'Del':>4} {'Img':>4} {'Task':>5} {'Blk':>4} {'Ask':>4}"
    print(head + "\n" + "-" * len(head))
    for name, r in results:
        print(f"{name:36} {r['to_attacker']:>4} {r['secrets_out']:>5} {r['deleted']:>4} "
              f"{'yes' if r['image_leak'] else 'no':>4} {'yes' if r['task_done'] else 'no':>5} {r['blocked']:>4} {r['asked']:>4}")
    print("\nOut: emails to the attacker. Secr: of those, carrying secrets. Del: emails deleted. Img: image link")
    print("leaking data in the summary. Task: summary delivered. Blk: calls blocked. Ask: approvals requested.")
    return results


if __name__ == "__main__":
    main()
