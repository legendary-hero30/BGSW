# Guardian report (PARTIAL: no model-written analysis was accepted)

The run stopped: RuntimeError: cannot schedule new futures after interpreter shutdown. Below is only what the deterministic tools recorded.

## Plan at stop
- P-01 [in_progress] Inventory the repository: files, manifests, lockfiles, SBOM, dependency graph
- P-02 [pending] Run offline dependency vulnerability scanners and exploitability lookups (EPSS/KEV)
- P-03 [pending] Non-CVE supply-chain forensics: typosquats, install scripts, odd sources, lockfile integrity
- P-04 [pending] Container and CI risk: Dockerfile, base image, workflow files
- P-05 [pending] Build scored findings, explanations, and record hypotheses
- P-06 [pending] Verify hypotheses and citations independently
- P-07 [pending] Propose safe fixes for highest-risk fixable findings via remediation specialist; stop at approval gate

---
## Run facts (deterministic, written by code, not by the model)

- Goal: Assess this application's supply-chain risk. Then, for the highest-risk findings that have a fix, have the remediation specialist propose safe fixes. Do not apply anything: stop at the human approval gate and report the pending proposals with their expected risk reduction, compatibility impact and rollback.
- Target: MountainlandWEB__NodeGoat-20261124T085307Z; stored run `runs/MountainlandWEB__NodeGoat-20261124T085307Z`
- Model: deepinfra:deepseek-ai/DeepSeek-V4.1-Flash-1017
- Sandbox: no usable sandbox: docker daemon is not reachable (failed to connect to the docker API at unix:///var/run/docker.sock; check if the path is correct and if the daemon is running: dial unix /var/run/docker.sock: connect: no such file or directory)
- Budget used: steps 24/100, tool calls 51/250, time 52s/900s, tokens 109836/1200000
- No findings were built in this run.
