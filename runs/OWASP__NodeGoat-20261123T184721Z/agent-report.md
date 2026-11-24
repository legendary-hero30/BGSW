# Guardian report (PARTIAL: no model-written analysis was accepted)

The run stopped: tool-call budget spent (250/250). Below is only what the deterministic tools recorded.

## Plan at stop
- P-01 [done] Inventory the repository: files, manifests, lockfiles, SBOM, dependency graph
- P-02 [done] Run offline dependency vulnerability scanners and exploitability lookups
- P-03 [done] Non-CVE supply-chain forensics: typosquats, install scripts, odd sources, lockfile integrity
- P-04 [done] Container and CI risk: Dockerfile, base image, workflow files
- P-05 [pending] Build scored findings, record hypotheses, verify, then submit report
- P-06 [pending] Resolve the identity of osv-scanner advisory MAL-2023-462 (malicious package) — which package@version, and is it real or a scanner artifact
- P-07 [pending] Build scored findings from all scanner output and record hypotheses for the non-CVE supply-chain risks

## Top findings by risk

| ID | Risk | Type | Package |
|---|---|---|---|
| F-001 | 57.0 Critical | malicious_package | fsevents@1.2.9 |
| F-002 | 57.24 Medium | vulnerable_direct | underscore@1.9.1 |
| F-003 | 56.82 Medium | vulnerable_transitive | y18n@3.2.1 |
| F-004 | 54.0 Medium | vulnerable_direct | mongodb@2.2.36 |
| F-005 | 54.0 Medium | vulnerable_direct | marked@0.3.5 |
| F-006 | 53.29 Medium | vulnerable_direct | body-parser@1.18.3 |
| F-007 | 51.81 Medium | vulnerable_direct | underscore@1.9.1 |
| F-008 | 50.1 Medium | vulnerable_direct | marked@0.3.5 |
| F-009 | 50.08 Medium | vulnerable_direct | marked@0.3.5 |
| F-010 | 50.0 Medium | misconfiguration | targets/dynamic/OWASP__NodeGoat-20261123T184721Z/Dockerfile@None |

---
## Run facts (deterministic, written by code, not by the model)

- Goal: Assess the software supply-chain risk of this repository. Find what is in it, what is vulnerable, and what looks suspicious beyond known CVEs. Report the few things that matter most, with evidence, what was not checked, and what to do next.
- Target: OWASP__NodeGoat-20261123T184721Z; stored run `runs/OWASP__NodeGoat-20261123T184721Z`
- Model: deepinfra:deepseek-ai/DeepSeek-V4.1-Flash-1017
- Sandbox: no usable sandbox: docker daemon is not reachable (failed to connect to the docker API at unix:///var/run/docker.sock; check if the path is correct and if the daemon is running: dial unix /var/run/docker.sock: connect: no such file or directory)
- Budget used: steps 97/100, tool calls 250/250, time 424s/900s, tokens 975999/1200000
- Findings: 344 (by risk level {'Critical': 1, 'Medium': 39, 'Low': 304})
- Scanners run: ['grype', 'trivy', 'osv-scanner']; NOT run: none
- Dockerfile scanned: True; workflows scanned: True; base image scanned: False; anomaly rules run: True
- Findings were built 1 time(s); explanations accepted by the gate (current build): 5; gate rejections logged this run: 3

| Hypothesis | Status | Confidence | Claim |
|---|---|---|---|
| H-01 | verified | medium | grunt-if is resolved in package-lock.json from the mutable git branch tarball URL https://github.com/binarymist/grunt-if/tarball/master (finding F-267, evidence |
| H-02 | verified | high | The Dockerfile base image is referenced as the mutable tag node:12-alpine (evidence E-1279 line 1 and E-1280 line 7) with no digest pin, so the base image conte |
| H-03 | verified | high | GitHub Actions workflows reference third-party actions by mutable tags rather than commit SHAs: actions/checkout@v2 (E-1265, E-1266), actions/setup-node@v1 (E-1 |
| H-04 | rejected | medium | fsevents@1.2.9 is flagged as malicious by both grype (GHSA-xv2f-5jw4-v95m, E-0305) and osv-scanner (MAL-2023-462, E-0306) and declares a lifecycle install scrip |
