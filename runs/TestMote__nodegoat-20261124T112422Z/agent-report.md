# Supply-Chain Risk Assessment — TestMote__nodegoat-20261124T112422Z

## Overall picture

This is a deliberately vulnerable Node.js training application (OWASP NodeGoat) with a **broad but mostly low-urgency dependency risk profile**. 418 findings were built from three independent scanners (grype, trivy, osv-scanner) plus Dockerfile, workflow, image and anomaly rules: **1 Critical, 97 Medium, 320 Low**. No advisory in this run is in CISA KEV, and the highest EPSS observed is 0.0707 (CVE-2019-19919), so nothing here is under known active exploitation.

The things that matter most, in order:

1. **F-001 (Critical, fsevents@1.2.9)** — the only Critical. Two independent scanners flag a malicious-package advisory: grype reports GHSA-xv2f-5jw4-v95m (E-0305) and osv-scanner reports MAL-2023-462 (E-0306). The dependency path is real: `owasp-nodejs-goat@1.3.0 > forever@2.0.0 > forever-monitor@2.0.0 > chokidar@2.1.8 > fsevents@1.2.9` (E-0303), and the package has an install script (E-1292). **Important caveat:** the lockfile shows fsevents resolved from registry.npmjs.org with a sha512 integrity hash, `"optional": true` and `"os": ["darwin"]`, so on the Linux container it is not installed at all. Treat the 57.0 score as an upper bound for macOS installs, not Linux runtime exposure. The malicious attribution is well supported; the practical exposure is conditional.
2. **F-011 (Medium, underscore@1.9.1, CVE-2021-23358)** — the highest-value *fixable* finding. It is a **direct runtime dependency** (E-1217) that is actually imported (`config/config.js:1`, E-1474), with a fix at 1.12.1 (E-1214–E-1216).
3. **F-019 (Medium, body-parser@1.18.3, CVE-2024-45590)** — direct runtime, fix 1.20.3, required by `server.js` (E-1461).
4. **F-017 (Medium, mongodb@2.2.36)** — direct runtime, fix 3.1.13, but a major-version jump with real driver-API risk.
5. **F-031 / F-075 / F-076 (Medium)** — the Dockerfile base image `node:12-alpine` is end-of-life (alpine 3.15.4, E-1285) and is not digest-pinned at either stage (E-1283, E-1284). This is a base-image hygiene and staleness risk, not a demonstrated root cause of the individual image CVEs.
6. **F-339 (Low, grunt-if@0.2.0)** — resolved from the mutable ref `https://github.com/binarymist/grunt-if/tarball/master` (E-1293), path confirmed (E-1294). Low score because it is dev-only, but a mutable branch ref is a genuine integrity gap.

## Verified inference vs tool fact

**Tool fact:** all scanner counts, advisory ids, versions, fix versions, dependency paths, EPSS/KEV lookups, the image scan (145 matches: 11 critical, 74 high), the 7 unpinned GitHub Actions, and the lockfile entries are direct tool output.

**Verified inference (ruled on by the verifier):**
- **H-01 (verified):** the grunt-if mutable `tarball/master` ref means the installed bytes can change with no lockfile diff — a real integrity risk despite the Low score (F-339; E-1293, E-1294). Caveat: no evidence the bytes *did* change.
- **H-03 (verified):** the handlebars@4.0.5 criticals (F-161, F-162, F-164, F-181, F-182) are all `dev_only_unused` / `build_or_dev` on a shared dev path (E-0343), so real-world exposure is lower than CVSS 9.8 suggests. `dev_only_unused` is a heuristic, not proof of non-reachability.
- **H-04 (verified):** the node:12-alpine base image is EOL and not digest-pinned, so its OS packages are stale and the build is not reproducible (F-031, F-075, F-076; E-1285, E-1283, E-1284).

**Rejected / withdrawn:** an earlier hypothesis claiming the EOL base image was the *root cause* of the ~70 image findings was returned `needs_more_evidence` by the verifier — no evidence links those findings to EOSL, and several image findings do carry fix versions (e.g. F-002 fixed_in 1.1.1u-r0, F-006 fixed_in 1.2.12-r2). It was superseded by H-04 and is **not** asserted here.

## Remediation proposals — PENDING HUMAN APPROVAL, NOTHING APPLIED

No change has been made to the repository. All proposals below are `proposed` only and require a named human approver. No build, install or test was run (no sandbox: docker daemon unreachable), so **no compatibility claim is test-verified** — compatibility is semver inference only.

| Proposal | Finding | Change | Expected risk reduction | Compatibility impact | Rollback |
|---|---|---|---|---|---|
| **R-002** | F-011 | underscore `^1.8.3` → `^1.13.8` in package.json, regenerate lockfile | Closes F-011 and F-025 (highest score 57.24); removes the only imported direct-runtime critical | **Low** — minor within major 1; template-function API expected unchanged; untested | Revert commit / delete branch `guardian/fix-F-011`, restore package.json + package-lock.json |
| **R-003** | F-019 | body-parser → `^1.20.9` in package.json, regenerate lockfile | Closes F-019, F-037, F-078 (highest 53.29) | **Low** — minor within major 1; untested | Revert commit / delete branch `guardian/fix-F-019` |
| **R-001** | F-001 | **Escalate — no automated target.** The tool refuses to auto-bump a confirmed-malicious package | Requires a human decision: remove, replace, or block fsevents | Unknown until a decision is made; parents forever@2.0.0 / nodemon@1.19.1 unchanged | N/A — no change proposed |

**Not yet proposed (gap):** F-017 (mongodb 2.2.36 → 3.1.13, major bump, driver-API risk in `server.js`), F-089 (bson@1.0.9 — whether bumping mongodb actually removes it is unverified), F-339 (pin grunt-if to a commit SHA), F-031 (base-image migration), and the CI findings. The remediation specialist hit its call limit before covering these; a first attempt at F-017 was rejected for citing packages not on its path. These need a follow-up pass.

## What was NOT scanned or verified

- **No OS/container scan of a built image** — the image result is from a cached scan; no build was possible.
- **Install scripts in cypress@3.3.1, fsevents@1.2.9 and nodemon@1.19.1 were never inspected** — packages are not installed and there is no sandbox.
- **The grunt-if tarball contents were never inspected.**
- **No registry metadata** (maintainers, download counts, publish dates) — offline.
- **Trivy's 10 extra advisories vs grype were not itemised.**
- **babel-traverse@6.11.4 (CVE-2023-45133) has no fix version** in either scanner.
- **No runtime reachability testing** — reachability labels are heuristics.
- **No full repo tree listing** was available, so unread files (e.g. `server.js`, `app/`, `config/`) were not audited beyond the specific lines cited.
- **No prompt injection was found** in the repository; a `comments` field in package.json reading "a9 insecure components" is quoted data, not an instruction.

## Recommended next steps

1. **Approve R-002 and R-003 first** — lowest disruption, closes the only imported direct-runtime critical and two more direct-runtime findings.
2. **Have a human decide F-001** (R-001): confirm whether macOS developer installs are in scope; if not, document the accepted risk rather than bumping blindly.
3. **Re-run proposal generation** for F-017, F-089, F-339, F-031 and the CI findings with path-correct justifications.
4. **Migrate the base image** off `node:12-alpine` to a supported Node LTS alpine image pinned by digest, and pin `mongo:4.4` / `mongo:4.0` in compose and CI.
5. **Pin all GitHub Actions to commit SHAs** and add least-privilege `permissions:` blocks.
6. **Regenerate the lockfile with sha512 integrity** — several entries are sha1-only and at least one bundled entry carries no integrity hash at all.

---
## Run facts (deterministic, written by code, not by the model)

- Goal: Assess this application's supply-chain risk. Then, for the highest-risk findings that have a fix, have the remediation specialist propose safe fixes. Do not apply anything: stop at the human approval gate and report the pending proposals with their expected risk reduction, compatibility impact and rollback.
- Target: TestMote__nodegoat-20261124T112422Z; stored run `runs/TestMote__nodegoat-20261124T112422Z`
- Model: deepinfra:deepseek-ai/DeepSeek-V4.1-Flash-1017
- Sandbox: no usable sandbox: docker daemon is not reachable (failed to connect to the docker API at unix:///var/run/docker.sock; check if the path is correct and if the daemon is running: dial unix /var/run/docker.sock: connect: no such file or directory)
- Budget used: steps 81/100, tool calls 188/250, time 282s/900s, tokens 832042/1200000
- Findings: 418 (by risk level {'Critical': 1, 'Medium': 97, 'Low': 320})
- Scanners run: ['grype', 'trivy', 'osv-scanner']; NOT run: none
- Dockerfile scanned: True; workflows scanned: True; base image scanned: True; anomaly rules run: True
- Findings were built 1 time(s); explanations accepted by the gate (current build): 6; gate rejections logged this run: 6

| Hypothesis | Status | Confidence | Claim |
|---|---|---|---|
| H-01 | verified | medium | grunt-if@0.2.0 is resolved from the mutable ref https://github.com/binarymist/grunt-if/tarball/master (E-1293), so the installed bytes can change without any pa |
| H-02 | needs_more_evidence | medium | The node:12-alpine base image (alpine 3.15.4, end-of-service-life per E-1285) is the dominant container risk: it is the root cause of the 70 vulnerable_image_pa |
| H-03 | verified | medium | The handlebars@4.0.5 critical advisories (CVE-2019-19919, CVE-2021-23369, CVE-2021-23383, CVE-2026-33937, CVE-2026-106446) are all scored dev_only_unused / buil |
| H-04 | verified | medium | The node:12-alpine base image is end-of-life (alpine 3.15.4, EOSL per E-1285) and is not digest-pinned (E-1283, E-1284), so its OS packages are stale and the im |
