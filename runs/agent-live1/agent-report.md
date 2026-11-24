# Guardian report (PARTIAL: no model-written analysis was accepted)

The run stopped: token budget spent (623221/600000). Below is only what the deterministic tools recorded.

## Plan at stop
- P-01 [pending] Non-CVE supply-chain forensics: typosquats, install scripts, odd sources, lockfile integrity
- P-02 [pending] Inventory nodegoat: files, manifests, lockfiles, SBOM, dependency graph
- P-03 [pending] Verify hypotheses and citations independently

---
## Run facts (deterministic, written by code, not by the model)

- Goal: Assess the software supply-chain risk of the target application and produce an evidence-backed report of what matters most, what was and was not checked, and what to do next.
- Target: nodegoat; stored run `runs/agent-live1`
- Model: deepinfra:deepseek-ai/DeepSeek-V4.1-Flash-1017
- Sandbox: no usable sandbox: docker daemon is not reachable (failed to connect to the docker API at unix:///var/run/docker.sock; check if the path is correct and if the daemon is running: dial unix /var/run/docker.sock: connect: no such file or directory)
- Budget used: steps 55/60, tool calls 144/150, time 126s/540s, tokens 623221/600000
- No findings were built in this run.
