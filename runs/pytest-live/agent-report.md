# Guardian report (PARTIAL: no model-written analysis was accepted)

The run stopped: step budget spent (100/100 model calls). Below is only what the deterministic tools recorded.

## Plan at stop
- P-01 [done] Inventory nodegoat: files, manifests, lockfiles, SBOM, dependency graph
- P-02 [done] Run offline dependency vulnerability scanners (grype, trivy, osv-scanner) and exploitability lookups
- P-03 [done] Non-CVE supply-chain forensics: typosquats, install scripts, odd sources, lockfile integrity
- P-04 [done] Container and CI risk: Dockerfile, base image, GitHub Actions workflows
- P-05 [done] Build scored findings, rank, explain, record hypotheses
- P-06 [in_progress] Verify hypotheses and citations, then submit accepted report
- P-07 [done] Resolve MAL-2023-462: identify which package@version osv-scanner flagged as malicious
- P-08 [done] Confirm grunt-if lockfile entry: resolved URL, integrity hash, and whether it is a mutable ref

## Top findings by risk

| ID | Risk | Type | Package |
|---|---|---|---|
| F-001 | 57.0 Critical | malicious_package | fsevents@1.2.9 |
| F-002 | 64.73 Medium | vulnerable_image_package | libcrypto1.1@1.1.1n-r0 |
| F-003 | 64.73 Medium | vulnerable_image_package | libssl1.1@1.1.1n-r0 |
| F-004 | 64.69 Medium | vulnerable_image_package | libcrypto1.1@1.1.1n-r0 |
| F-005 | 64.69 Medium | vulnerable_image_package | libssl1.1@1.1.1n-r0 |
| F-006 | 62.69 Medium | vulnerable_image_package | zlib@1.2.12-r0 |
| F-007 | 59.32 Medium | vulnerable_image_package | ip@1.1.5 |
| F-008 | 58.18 Medium | vulnerable_image_package | minimist@1.2.5 |
| F-009 | 57.58 Medium | vulnerable_image_package | tough-cookie@2.4.3 |
| F-010 | 57.27 Medium | vulnerable_image_package | ip@1.1.5 |

---
## Run facts (deterministic, written by code, not by the model)

- Goal: Assess the software supply-chain risk of the target application and produce an evidence-backed report of what matters most, what was and was not checked, and what to do next.
- Target: nodegoat; stored run `runs/pytest-live`
- Model: deepinfra:deepseek-ai/DeepSeek-V4.1-Flash-1017
- Sandbox: sandboxing disabled by the caller (exec-tier tools will refuse)
- Budget used: steps 100/100, tool calls 192/250, time 395s/900s, tokens 1078953/1200000
- Findings: 415 (by risk level {'Critical': 1, 'Medium': 97, 'Low': 317})
- Scanners run: ['grype', 'trivy', 'osv-scanner']; NOT run: none
- Dockerfile scanned: True; workflows scanned: True; base image scanned: True; anomaly rules run: True
- Findings were built 1 time(s); explanations accepted by the gate (current build): 3; gate rejections logged this run: 5

| Hypothesis | Status | Confidence | Claim |
|---|---|---|---|
| H-01 | needs_more_evidence | medium | grunt-if@0.2.0 (F-338) is the highest-priority non-CVE supply-chain risk in this repo: its lockfile entry resolves to the mutable ref https://github.com/binarym |
| H-02 | verified | medium | The EOL base image node:12-alpine (F-031, alpine 3.15.4 end-of-service-life) is a material risk independent of the npm dependency CVEs: it is a separate layer w |
| H-03 | rejected | low | Testable claim: the bulk of the 300+ dependency CVEs sit in dev/transitive packages and are not on the production runtime path. Falsifier: count findings whose  |
| H-04 | needs_more_evidence | medium | MAL-2023-462 on fsevents@1.2.9 (F-001) is an unresolved gap, not a clean result: the advisory is reported by osv-scanner and corroborated by grype GHSA-xv2f-5jw |
| H-05 | verified | medium | MAL-2023-462 is reported by osv-scanner against fsevents@1.2.9 (E-0306, package-lock.json line 3286) and GHSA-xv2f-5jw4-v95m by grype (E-0305, same line), but t |
| H-06 | verified | high | grunt-if@0.2.0 (F-338) is a direct devDependency resolved from the mutable GitHub branch tarball https://github.com/binarymist/grunt-if/tarball/master (package- |
| H-07 | needs_more_evidence | medium | A substantial share of the transitive vulnerability findings are runtime-reachable, not confined to dev tooling: the top 10 of 303 vulnerable_transitive finding |
| H-08 | verified | medium | The top 50 of 303 vulnerable_transitive findings, ranked by risk score, are all reachability present_only with exposure runtime_internal (F-012, F-045, F-080-F- |
