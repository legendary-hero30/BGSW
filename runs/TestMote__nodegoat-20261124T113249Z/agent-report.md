# Supply-Chain Risk Assessment — TestMote__nodegoat-20261124T113249Z

## Overall picture

This is `owasp-nodejs-goat@1.3.0`, a **deliberately vulnerable training application**. That framing matters: the app-level weaknesses (A1–A10) are intentional and are not supply-chain defects. The supply-chain picture is nonetheless poor, and it is dominated by **age, not by compromise**.

The SBOM holds **424 components** across a graph of 1480 nodes and 2295 edges, max depth 13, with 36 direct dependencies (16 runtime, 20 dev). Three independent scanners ran and substantially agreed: grype (340 matches / 196 advisories), trivy (325 / 206), osv-scanner (313 / 196). `build_findings` produced **418 stored findings**.

The single most important structural fact: **the runtime surface is small (16 direct deps) but the dev/build tree dominates the graph** (790 unique dev packages vs 380 runtime). Raw CVE counts therefore overstate production exposure.

**No CVE in the top-20 set is in CISA KEV.** Highest EPSS is CVE-2020-7774 (y18n) at 0.69589 — an outlier well above its peers.

## What matters most

**1. Runtime-path criticals — the real priority.**
- **F-089 `bson@1.0.9`**, CVE-2020-7610, CVSS 9.8, fix 1.1.4. Path: `owasp-nodejs-goat@1.3.0 > mongodb@2.2.36 > mongodb-core@2.1.20 > bson@1.0.9`. Scored 43.36 (Medium) with reachability `present_only`. It is **not** the only critical on a runtime path — see F-011 and F-001 below.
- **F-011 `underscore@1.9.1`**, CVE-2021-23358, critical, fix 1.12.1. Direct, `imported`, `runtime_network`, score 57.24 — the highest-scoring runtime finding.
- **F-019 `body-parser@1.18.3`**, CVE-2024-45590, high, fix 1.20.3. Direct, `imported`, `runtime_network`.
- **F-017 `mongodb@2.2.36`**, GHSA-mh5c-679w-hh4r, high, fix 3.1.13. Direct, `imported` at `server.js` line 11.

**2. A confirmed-malicious package flag.**
**F-001 `fsevents@1.2.9`** is scored Critical (57.0) as `malicious_package`, `confirmed_malicious: true`, with `MAL-2023-462` and `GHSA-xv2f-5jw4-v95m`. **Two independent scanners agree** (grype E-0305, osv-scanner E-0306) — this is not a single-scanner signal. The scanners split on the advisory id: grype and osv-scanner report GHSA-8r6j-v8pm-fqw3, trivy reports CVE-2023-45311. Fix 1.2.11. **No remediation proposal was produced for this finding** — it needs a human decision.

**3. Container base image.**
`node:12-alpine` is referenced **unpinned by digest** at `Dockerfile:1` and `Dockerfile:7`, and trivy reports the base OS **alpine 3.15.4 as end-of-service-life**. The image scan found **145 matches (11 critical, 74 high, 56 medium, 4 low)**. **70 `vulnerable_image_package` findings** are attributed to that image — Alpine OS packages *and* npm packages bundled in it — not to application source. This is inherited risk; it is not the highest-scoring container finding (F-002 at 64.73 and F-006 at 62.69 score above F-031 at 50.0 and F-075 at 45.0).

**4. CI/CD.**
Seven unpinned GitHub Actions across three workflows: `ci.yml:14` `actions/checkout@v4`; `e2e-test.yml:16` `actions/checkout@v2`, `:21` `actions/setup-node@v1`, `:26` `actions/cache@v2`, `:58` `actions/upload-artifact@v2`; `lint.yml:16` `actions/checkout@v2`, `:21` `actions/setup-node@v1`. Three `excessive-permissions` hits. **No `pull_request_target`, `workflow_run` or `issue_comment` triggers**, and no untrusted event data interpolated into `run:` blocks — so no script-injection path was found.

**5. One genuine non-CVE supply-chain risk.**
`grunt-if@0.2.0` is declared at `package.json:51` as `https://github.com/binarymist/grunt-if/tarball/master` — a **mutable branch ref**, sha1 integrity, dev-only, direct. The bytes fetched can change with no lockfile change. Rule GR-LOCK-001, high. The four typosquat hits (`director`, `node-eta`, `pad-stream`, `lodash.rest`) were assessed as **false positives**.

## Pending remediation proposals — HUMAN APPROVAL REQUIRED

Six proposals are recorded. **Nothing has been applied, merged or pushed.** Main is untouched.

| Proposal | Package | Change | Clears | Compatibility | Human decision |
|---|---|---|---|---|---|
| **R-001** | underscore | 1.9.1 → 1.13.8 (direct) | F-011, F-025 | **low** — minor within major 1 | No |
| **R-003** | body-parser | 1.18.3 → 1.20.9 (direct) | F-019, F-037, F-078 | **low** — minor within major 1 | No |
| **R-002** | bson | 1.0.9 → 1.1.4 (override) | F-089, F-208 | **medium** — patch within major 1, but an override forces every consumer | Yes — override |
| **R-005** | y18n | 3.2.1 → 3.2.2 (override) | F-012 | **medium** — patch, but an override | Yes — override |
| **R-006** | mongodb | 2.2.36 → 3.1.13 (direct) | F-017 | **high** — major 2 → 3, driver API changes | **Yes — needs build/test validation** |
| **R-004** | marked | 0.3.5 → 4.0.10 (direct) | F-018, F-028, F-029, F-034, F-036, F-072, F-073 | **high** — major 0 → 4 | **Yes — needs validation** |

**Rollback for all six:** delete branch `guardian/fix-F-###` or `git revert` the commit, and restore `package.json` / `package-lock.json` from the base commit.

**Recommended order (INFERENCE, medium confidence):** approve **R-001** and **R-003** first — lowest compatibility risk, both clear runtime-path findings. Then choose between **R-006** (root fix for the bson chain, but a major driver migration) and **R-002** (smaller override, but forces a version on consumers). Do not approve both blindly. **R-004** jumps far beyond the reported `>=0.3.6` fix for a medium finding — a narrower 0.3.6 bump may be preferable.

## Not scanned, not verified, or left out

- **No sandbox** — the Docker daemon is unreachable, so no untrusted content was executed and no build or test was run. All compatibility ratings are semver estimates only.
- **`babel-traverse@6.11.4` CVE-2023-45133** — scanners disagree on whether a fix exists (trivy says 7.23.2; grype and osv-scanner say none). Unresolved.
- **`extract-zip@1.6.7` CVE-2026-56876** and **`ip@1.1.5` CVE-2024-29415** have **no fix version** — no proposal possible.
- **Install-script bodies** for `cypress@3.3.1`, `fsevents@1.2.9`, `nodemon@1.19.1` were not inspected (packages not installed).
- **Lockfile integrity** was sampled (5 entries), not swept across all ~12k lines. One bundled entry under `nyc` has no integrity hash, which `bundled: true` explains.
- **No reachability analysis** — "runtime" vs "dev" comes from the lockfile graph, not call paths.
- **Deliberately excluded:** the intentional app-level vulnerabilities (A1–A10) and the hardcoded secrets at `config/env/all.js:8` and `server.js:82` (values redacted). These are by-design training weaknesses, not supply-chain defects.
- **No prompt injection** was found in the repository.
- **Two recorded hypotheses remain `needs_more_evidence`** and are therefore not asserted here; no tool exists to edit hypothesis claim text, so the narrowed wording could not be applied. This report states only tool-confirmed facts.

## Next steps

1. **A named human** reviews and approves R-001 and R-003 (low risk), then decides R-006 vs R-002 and validates R-004. *Human decision required.*
2. **A named human** decides on **F-001 `fsevents@1.2.9`** — a confirmed-malicious flag with no proposal. *Human decision required.*
3. **Repo owner** pins `node:12-alpine` to a digest and moves off Node 12 (EOL), and pins the seven GitHub Actions to commit SHAs with least-privilege `permissions:`. *Human decision required.*
4. **Repo owner** pins or removes `grunt-if` (`package.json:51`) and regenerates the lockfile.
5. **Someone with a hypothesis-edit tool** applies the verifier-approved narrowed wording to the two open hypotheses so they can be verified.
6. Run a full integrity audit (`npm ci --dry-run`, `npm audit signatures`) in a networked environment.

---
## Run facts (deterministic, written by code, not by the model)

- Goal: Assess this application's supply-chain risk. Then, for the highest-risk findings that have a fix, have the remediation specialist propose safe fixes. Do not apply anything: stop at the human approval gate and report the pending proposals with their expected risk reduction, compatibility impact and rollback.
- Target: TestMote__nodegoat-20261124T113249Z; stored run `runs/TestMote__nodegoat-20261124T113249Z`
- Model: deepinfra:deepseek-ai/DeepSeek-V4.1-Flash-1017
- Sandbox: no usable sandbox: docker daemon is not reachable (failed to connect to the docker API at unix:///var/run/docker.sock; check if the path is correct and if the daemon is running: dial unix /var/run/docker.sock: connect: no such file or directory)
- Budget used: steps 96/100, tool calls 195/250, time 286s/900s, tokens 1114648/1200000
- Findings: 418 (by risk level {'Critical': 1, 'Medium': 97, 'Low': 320})
- Scanners run: ['grype', 'trivy', 'osv-scanner']; NOT run: none
- Dockerfile scanned: True; workflows scanned: True; base image scanned: True; anomaly rules run: True
- Findings were built 1 time(s); explanations accepted by the gate (current build): 0; gate rejections logged this run: 3

| Hypothesis | Status | Confidence | Claim |
|---|---|---|---|
| H-01 | needs_more_evidence | medium | bson@1.0.9 (CVE-2020-7610, CVSS 9.8, fix 1.1.4) is the highest-consequence finding in this repo because it is the only critical-severity advisory sitting on the |
| H-02 | verified | medium | The bulk of the raw CVE count overstates production exposure: the critical-severity advisories in handlebars@4.0.5, json-schema@0.2.3, getobject@0.1.0, growl@1. |
| H-03 | needs_more_evidence | medium | The node:12-alpine base image is the dominant container risk and is inherited rather than app-specific: trivy reports the base OS alpine 3.15.4 as end-of-servic |
| H-04 | rejected | medium | fsevents@1.2.9 (F-001) is flagged as a malicious_package via MAL-2023-462 by osv-scanner only, while grype and trivy report it as CVE-2023-45311 with fix 1.2.11 |
