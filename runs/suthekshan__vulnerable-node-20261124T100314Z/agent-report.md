# Supply-Chain Risk Assessment — `suthekshan__vulnerable-node-20261124T100314Z`

## Overall picture

This is a small Node.js service (`guardian-demo-app` 1.0.0, entry `src/index.js`) with **7 direct runtime dependencies, all of them vulnerable, and no transitive-only vulnerable packages**. Three independent scanners (grype, trivy, osv-scanner) agree on the shape of the result: 39–40 advisories across those 7 packages, including **3 critical and 17–18 high** severity advisories. Every advisory has a published fix. **None of the advisories is in CISA KEV**, so there is no evidence of active exploitation in the wild.

The dependency problem is broad but shallow and mechanically fixable. The two things that matter most are not the CVE count:

1. **The CI workflow is the highest-impact defect.** It combines `pull_request_target` with a checkout of the PR head SHA, `permissions: write-all`, an unpinned third-party action, and a deploy token handed to that action. This is a privileged-context code-execution path, and it is **verified** (H-01).
2. **The Dockerfile bakes a secret into the image and runs as root.** `ENV API_TOKEN` is a literal ENV instruction, so the value is committed to image config and readable by anyone who can pull the image; there is no `USER` instruction. **Verified** (H-02).

Note on scoring: the composite risk model rates all 59 findings **Medium** (50 Medium, 9 Low) even though the underlying severities include 3 critical and 17 high. The weighted score caps exposure and reachability contributions. Treat the severity column, not the composite level, as the driver for prioritisation.

## What matters most

### 1. CI privileged-context code execution and secret exposure — verified inference (H-01)
Facts: `.github/workflows/ci.yml` uses `pull_request_target` (F-057, F-058, E-0165, E-0166), checks out `${{ github.event.pull_request.head.sha }}` via `actions/checkout@main` (F-052, E-0167, E-0168), sets `permissions: write-all`, interpolates the PR title into a `run` step (F-056, E-0172), and passes `secrets.DEPLOY_TOKEN` to `some-org/deploy-action@master` (F-054, E-0173, E-0174). Checkout also persists credentials (F-059, E-0169).

Verified inference: because the job runs `npm install` and `npm test` on attacker-controlled PR code in the same job that later receives the token, a malicious PR can execute code with the token in its environment. The verifier confirmed this by reading the file directly and judged the path real, not theoretical. The PR-title template injection is a second, independent path.

### 2. Secret in image layer plus root runtime — verified inference (H-02)
Facts: Dockerfile line 4 is `ENV API_TOKEN=[REDACTED]`, flagged by trivy DS-0031 (F-024, E-0180) and hadolint DL3064 (F-029, E-0179). No `USER` instruction exists; trivy DS-0002 (F-025, E-0175) and GR-IMG-003 (F-028, E-0178) both report root. Base is `FROM node:14`, unpinned (F-046, E-0177). The Dockerfile also fetches remote content at build time via `ADD https://example.com/install.sh` and exposes port 22 (F-027).

Verified inference: the ENV form commits the secret to image config, so it is readable by anyone who can pull the image and persists at runtime; any code execution in the container starts as root. **Not established:** whether the token is live — the record shows `[REDACTED]`.

### 3. Three critical dependency advisories
- **F-001** `ejs@3.1.6` — CVE-2022-29078 / GHSA-phwq-j96m-2c2q — fix 3.1.7 — **EPSS 0.328, the highest in the repo** (E-0098, E-0099, E-0100, E-0101, E-0102).
- **F-002** `minimist@1.2.5` — CVE-2021-44906 / GHSA-xvch-5gv4-984h — fix 1.2.6 (E-0142, E-0143, E-0144, E-0145, E-0146).
- **F-003** `underscore@1.9.2` — CVE-2021-23358 / GHSA-cf4h-3jhx-xvhq — fix 1.12.1 (E-0156, E-0157, E-0158, E-0159, E-0160).

### 4. High-severity dependency clusters
- **axios@0.21.1** — 24 findings (F-004, F-006, F-007, F-013–F-016, F-018–F-021, F-023, F-035–F-040, F-042, F-043, F-045, F-049–F-051). Highest-profile: F-004 CVE-2026-42043 / GHSA-pmwg-cvhr-8vh7 fix 0.31.1 (E-0062–E-0065); F-021 CVE-2025-27152 / GHSA-jr5f-v2jv-69x6 fix 0.30.0 (E-0010–E-0013); F-018 CVE-2021-3749 / GHSA-cph5-m8f7-6c5x fix 0.21.2 (E-0001–E-0005).
- **lodash@4.17.15** — 6 findings (F-005, F-008, F-010, F-011, F-022, F-047). F-010 CVE-2021-23337 / GHSA-35jh-r3h4-6jhm fix 4.17.21 (E-0129–E-0132); F-022 CVE-2020-8203 / GHSA-p6mc-m468-83gw fix 4.17.19 (E-0125–E-0128); F-005 CVE-2026-4800 / GHSA-r5fr-rjxr-66jc fix 4.18.0 (E-0137–E-0140).
- **node-fetch@2.6.0** — F-009 CVE-2022-0235 / GHSA-r683-j2x4-v87g fix 2.6.7 (E-0152–E-0155); F-048 CVE-2020-15168 fix 2.6.1.
- **jsonwebtoken@8.5.1** — F-017 CVE-2022-23539 / GHSA-8cf7-32gw-wr33 fix 9.0.0 (E-0107–E-0111); also F-034, F-044.
- **underscore@1.9.2** — F-012 CVE-2026-27601 / GHSA-qpx9-hpmf-5gmw fix 1.13.8 (E-0161–E-0164).

### 5. Scanner disagreement worth noting
trivy reports one extra high, **NSWG-ECO-516** on lodash (F-008, E-0141), which grype and osv-scanner do not. CVSS also differs between scanners: CVE-2026-42043 is 10.0 in grype/trivy but 7.2 in osv-scanner; CVE-2026-4800 is 9.8 vs 8.1. I did not resolve which is correct; the fix versions agree, so remediation is unaffected.

## Not a finding: the vendored package
`vendor/colour-utils@0.0.1` is a `file:` dependency with a `postinstall` script. The verifier **rejected** the hypothesis that this is a meaningful risk: `setup.js` is 3 lines and its only executable statement is a `console.log`. No typosquat near-miss was found for any of the 8 dependency names, no non-registry sources exist beyond the local `file:` link, and the lockfile (v3) carries `sha512` integrity for every registry entry. F-055's stored rationale is stale and its sole evidence (E-0186) is a bare graph edge that does not support the install-script claim — it is the one citation failure in 1365 checked. Treat F-055 as low-severity hygiene only.

## Pending remediation proposals — awaiting human approval, nothing applied

Six proposals have concrete edits. All are on branches; `main` is untouched.

| Proposal | Findings | Change | Expected risk reduction | Compatibility | Rollback |
|---|---|---|---|---|---|
| R-012 | F-001, F-041 | ejs 3.1.6 → 3.1.10 | closes 2 findings incl. the highest-EPSS critical (CVE-2022-29078) | low — patch within major 3 | revert branch / restore `package.json` + `package-lock.json` |
| R-001 | F-002 | minimist 1.2.5 → 1.2.6 | closes 1 critical (CVE-2021-44906) | low — patch | as above |
| R-003 | F-003, F-012 | underscore 1.9.2 → 1.13.8, and the declared floating range must be tightened to match | closes 2 findings (CVE-2021-23358, CVE-2026-27601) | low — minor within major 1 | as above |
| R-002 | F-004 + 23 others | axios 0.21.1 → 0.33.0 | closes **24 findings** | **medium** — 0.x line, may break on any minor | as above |
| R-004 | F-005, F-008, F-010, F-011, F-022, F-047 | lodash 4.17.15 → 4.18.0 | closes 6 findings | low — minor within major 4 | as above |
| R-005 | F-009, F-048 | node-fetch 2.6.0 → 2.6.7 | closes 2 findings | low — patch | as above |
| R-006 | F-017, F-034, F-044 | jsonwebtoken 8.5.1 → 9.0.0 | closes 3 findings | **high — major bump 8→9** | as above |

Eight further proposals are escalations with no automated edit possible: R-007 (F-024, Dockerfile secret), R-008 (F-025, root user), R-009 (F-056, ci.yml template injection), R-010 (F-046, node@14 base image — needs a supported tag and digest), R-011 (F-052, pin `actions/checkout`), R-013 (F-055, vendored package review), R-014 (F-057, ci.yml trigger). These need commit SHAs or image digests that cannot be resolved offline, or a human decision.

**Do not approve R-002 or R-006 without a build and test run.** All compatibility ratings are estimated from semantic versioning alone, because no sandbox was available to test.

## What was NOT scanned or verified
- **The container image was never scanned.** `scan_image` returned `scanned: false` — base image `node:14` is not in the local cache and the docker daemon is unreachable. OS-package CVEs in the base image are unknown.
- **No sandbox:** nothing was built, installed, executed or rescanned. `npm install` was never run, so install-time behaviour is unverified.
- **Medium and low advisory ids were not individually enumerated** by the vulnerability specialist, and no EPSS/KEV lookup was done for them.
- **SBOM and lockfile disagree** on component count (37 vs 31); the cause was not determined.
- **`src/` and `test/` file contents were not read**, so actual usage of each dependency (and therefore real reachability) is unverified.
- **No registry access:** download counts, publish dates and deprecation status are unknown.
- Whether the CI workflow and Dockerfile are actually deployed is unknown; the repository self-describes as a demo fixture. That text is untrusted data and was not acted on.

## Recommended next steps
1. **Fix CI first** — it is the highest-impact item and costs nothing in dependency risk: drop `pull_request_target` or the head-SHA checkout, scope `permissions` off `write-all`, pin all three actions to commit SHAs, and pass the PR title via `env:` instead of inline interpolation.
2. **Rotate `API_TOKEN` and `DEPLOY_TOKEN`** if either is or was live, then remove the `ENV` secret from the Dockerfile and inject it at runtime; add a non-root `USER`.
3. **Approve R-012, R-001, R-003, R-004, R-005** — low-compatibility-risk patches that close 13 findings including all three criticals.
4. **Test before approving R-002 (axios) and R-006 (jsonwebtoken)** — 24 and 3 findings respectively, but with real breaking-change exposure.
5. **Scan the built image** once a sandbox is available, and pin the base image by digest off EOL Node 14.
6. **Restate F-055** with `package.json` and `setup.js` as evidence, or drop it.

---
## Run facts (deterministic, written by code, not by the model)

- Goal: Assess this application's supply-chain risk. Then, for the highest-risk findings that have a fix, have the remediation specialist propose safe fixes. Do not apply anything: stop at the human approval gate and report the pending proposals with their expected risk reduction, compatibility impact and rollback.
- Target: suthekshan__vulnerable-node-20261124T100314Z; stored run `runs/suthekshan__vulnerable-node-20261124T100314Z`
- Model: deepinfra:deepseek-ai/DeepSeek-V4.1-Flash-1017
- Sandbox: no usable sandbox: docker daemon is not reachable (failed to connect to the docker API at unix:///var/run/docker.sock; check if the path is correct and if the daemon is running: dial unix /var/run/docker.sock: connect: no such file or directory)
- Budget used: steps 67/100, tool calls 180/250, time 293s/900s, tokens 896111/1200000
- Findings: 59 (by risk level {'Medium': 50, 'Low': 9})
- Scanners run: ['grype', 'trivy', 'osv-scanner']; NOT run: none
- Dockerfile scanned: True; workflows scanned: True; base image scanned: False; anomaly rules run: True
- Findings were built 1 time(s); explanations accepted by the gate (current build): 27; gate rejections logged this run: 1

| Hypothesis | Status | Confidence | Claim |
|---|---|---|---|
| H-01 | verified | medium | The CI workflow combines the pull_request_target trigger (F-057, F-058) with actions/checkout of the PR head (F-052, F-059), write-all permissions, an unpinned  |
| H-02 | verified | medium | The Dockerfile findings share one root cause: a secret is placed in an ENV/ARG instruction (F-024 DS-0031, F-029 DL3064) and the image runs as root with no non- |
| H-03 | rejected | low | The vendored file: dependency vendor/colour-utils@0.0.1 (F-055) declares an install lifecycle script, so npm install executes code from a package that is not fe |
