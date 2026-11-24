# AI explanations: runs/agent-live2

Generator: **language model** (deepinfra:deepseek-ai/DeepSeek-V4.1-Flash-1017). Each explanation passed the deterministic gate; rejected ones are listed, never shown as explanations.

## F-001 fsevents@1.2.9: Malicious code in fsevents (npm)

- Risk: 57.0 Critical (coverage 0.5)
- Why it matters: fsevents@1.2.9 is flagged as malicious by two independent scanners (grype GHSA-xv2f-5jw4-v95m and osv-scanner MAL-2023-462) and carries a hasInstallScript hook, so a confirmed-malicious package with an install-time execution surface sits on the runtime dependency path owasp-nodejs-goat@1.3.0 > forever@2.0.0 > forever-monitor@2.0.0 > chokidar@2.1.8 > fsevents@1.2.9 and both scanners give fixed_in 1.2.11
- Reachability: present
- Confidence: medium (Two independent scanners agree on the malicious flag and the same lockfile entry, and the install hook is confirmed in that block; but the package is optional and darwin-only, and cvss/epss_kev are unknown (weight_coverage 0.5).)
- Evidence: E-0305, E-0306, E-0303, E-1288

