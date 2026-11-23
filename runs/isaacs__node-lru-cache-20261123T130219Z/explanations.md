# AI explanations: runs/isaacs__node-lru-cache-20261123T130219Z

Generator: **language model** (deepinfra:deepseek-ai/DeepSeek-V4.1-Flash-1017). Each explanation passed the deterministic gate; rejected ones are listed, never shown as explanations.

## F-001 actions/checkout@v6: action is referenced by tag or branch, not a full commit SHA

- Risk: 35.0 Low (coverage 0.3)
- Path: n/a
- Why it matters: The benchmark workflow invokes actions/checkout@v6 by mutable tag, so a compromised or retagged upstream action could execute arbitrary code in CI with the workflow's token and repository access.
- Reachability: unknown
- Confidence: high (Both guardian-rules (GR-CI-001) and zizmor (unpinned-uses) independently flag the same line 26 reference in benchmark.yml, and the excerpt shows a tag rather than a commit SHA.)
- Evidence: E-0246, E-0247

## F-002 actions/setup-node@v6: action is referenced by tag or branch, not a full commit SHA

- Risk: 35.0 Low (coverage 0.3)
- Path: n/a
- Why it matters: actions/setup-node@v6 is pinned only to a tag in the benchmark workflow, allowing a mutable upstream reference to run unreviewed code during CI setup.
- Reachability: unknown
- Confidence: high (guardian-rules GR-CI-001 and zizmor unpinned-uses agree on the same line 29 reference in benchmark.yml.)
- Evidence: E-0248, E-0249

## F-003 actions/checkout@v6: action is referenced by tag or branch, not a full commit SHA

- Risk: 35.0 Low (coverage 0.3)
- Path: n/a
- Why it matters: The main CI workflow checks out the repository via actions/checkout@v6 by tag, so a hijacked action tag could tamper with build and test results or exfiltrate secrets.
- Reachability: unknown
- Confidence: high (Two independent scanners (guardian-rules GR-CI-001 and zizmor unpinned-uses) report the identical line 45 reference in ci.yml.)
- Evidence: E-0251, E-0252

## F-004 actions/setup-node@v6: action is referenced by tag or branch, not a full commit SHA

- Risk: 35.0 Low (coverage 0.3)
- Path: n/a
- Why it matters: actions/setup-node@v6 is referenced by tag in the primary CI workflow, leaving the Node toolchain setup step open to supply-chain substitution.
- Reachability: unknown
- Confidence: high (guardian-rules GR-CI-001 and zizmor unpinned-uses both identify the same line 48 reference in ci.yml.)
- Evidence: E-0253, E-0254

## F-005 actions/checkout@v6: action is referenced by tag or branch, not a full commit SHA

- Risk: 35.0 Low (coverage 0.3)
- Path: n/a
- Why it matters: The typedoc workflow uses actions/checkout@v6 by tag, so a mutable action reference could inject code into the documentation build pipeline.
- Reachability: unknown
- Confidence: high (guardian-rules GR-CI-001 and zizmor unpinned-uses both flag line 25 of typedoc.yml.)
- Evidence: E-0256, E-0257

## F-006 actions/setup-node@v6: action is referenced by tag or branch, not a full commit SHA

- Risk: 35.0 Low (coverage 0.3)
- Path: n/a
- Why it matters: actions/setup-node@v6 is tag-pinned in the typedoc workflow, permitting an altered upstream action to run in the docs build.
- Reachability: unknown
- Confidence: high (guardian-rules GR-CI-001 and zizmor unpinned-uses agree on line 27 of typedoc.yml.)
- Evidence: E-0258, E-0259

## F-007 actions/configure-pages@v5: action is referenced by tag or branch, not a full commit SHA

- Risk: 35.0 Low (coverage 0.3)
- Path: n/a
- Why it matters: actions/configure-pages@v5 is referenced by tag in the typedoc workflow, so a mutable reference could alter GitHub Pages configuration during the build.
- Reachability: unknown
- Confidence: high (guardian-rules GR-CI-001 and zizmor unpinned-uses both report line 36 of typedoc.yml.)
- Evidence: E-0260, E-0261

## F-008 actions/upload-pages-artifact@v4: action is referenced by tag or branch, not a full commit SHA

- Risk: 35.0 Low (coverage 0.3)
- Path: n/a
- Why it matters: actions/upload-pages-artifact@v4 is tag-pinned, allowing a substituted action to tamper with the artifact published to GitHub Pages.
- Reachability: unknown
- Confidence: high (guardian-rules GR-CI-001 and zizmor unpinned-uses both flag line 38 of typedoc.yml.)
- Evidence: E-0262, E-0263

## F-009 actions/deploy-pages@v4: action is referenced by tag or branch, not a full commit SHA

- Risk: 35.0 Low (coverage 0.3)
- Path: n/a
- Why it matters: actions/deploy-pages@v4 is referenced by tag, so a mutable upstream reference could control what gets deployed to the published Pages site.
- Reachability: unknown
- Confidence: high (guardian-rules GR-CI-001 and zizmor unpinned-uses agree on line 43 of typedoc.yml.)
- Evidence: E-0264, E-0265

## F-010 tar@7.5.15: node-tar: Decompression/parse DoS via unlimited input

- Risk: 30.72 Low (coverage 1.0)
- Path: lru-cache@11.5.3 > tap@21.7.4 > @tapjs/run@4.5.8 > pacote@21.5.0 > tar@7.5.15
- Why it matters: tar@7.5.15 carries a critical-severity decompression/parse DoS (CVE-2026-59873 / GHSA-23hp-3jrh-7fpw, CVSS 9.2) reachable through the dev-only test toolchain, so a crafted archive processed during test or install tooling could exhaust resources.
- Reachability: dev_only_unused
- Confidence: high (Three scanners (grype, osv-scanner, trivy) agree on the advisory and the 7.5.19 fix, the dependency graph confirms the path lru-cache@11.5.3 > tap@21.7.4 > @tapjs/run@4.5.8 > pacote@21.5.0 > tar@7.5.15, and the finding records reachability as dev_only_unused with EPSS 0.00582 and no KEV listing.)
- Evidence: E-0162, E-0163, E-0164, E-0156, E-0165

## Rejected by the gate

- F-010 attempt 1: schema: ('reachability',): String should have at least 5 characters
