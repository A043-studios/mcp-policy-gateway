# Reproducing "Who Decides" (Working Paper No. 2026-02)

Every number in Section 7 of the paper comes from this repository at tag `paper-2026-02`.

| Paper | Command | What you should see |
|---|---|---|
| Section 7.3, demo | `python demo/run_demo.py` | 4 emails to the attacker without the gateway, 0 behind it |
| Table 7, ablation | `python demo/ablation.py` | The ten rows of the ablation table |
| Section 7.5, overhead | `python demo/bench.py` | About 0.2 ms per call through the gateway |
| Section 7.1, tests | `pip install pytest "mcp>=2"` then `pytest` | 44 passed, including the SDK interop tests |

Python 3.11 or newer. No API key and no network are needed, except to install the MCP SDK for the interop tests.
