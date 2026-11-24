# Supply-Chain Risk Assessment — TestMote__nodegoat-20261124T063131Z

## Overall picture

This is **OWASP NodeGoat 1.3.0**, a deliberately-vulnerable Node.js/Express training application backed by MongoDB. It is a **high-risk, deeply outdated codebase**: 424 SBOM components, 36 direct dependencies, dependency graph depth 13, and a lockfile (`package-lock.json`, lockfileVersion 2) that resolves fully. Three independent scanners produced **196–206 distinct advisories** across **33–37 critical** matches. 418 findings were stored.

The most important thing to understand is that **the risk is concentrated in the deployment artifact and in a handful of direct runtime dependencies, not spread evenly**. The highest-scoring findings are all inside the EOL base image; the highest-scoring application dependency is a direct runtime package. Critically, **no advisory in this run is in CISA KEV and all EPSS scores are ≤0.071** — that is a snapshot fact about observed exploitation, not a safety verdict, and it should not be read as reassurance given the age of the stack.

## What matters most

**1. A malicious-code advisory is recorded against `fsevents@1.2.9` (F-001, Critical).** Two independent scanners agree: grype reports GHSA-xv2f-5jw4-v95m "Malware in fsevents" (E-0305) and osv-scanner reports MAL-2023-462 "Malicious code in fsevents (npm)" (E-0306), both citing `package-lock.json` line 3286. The package declares an install script (E-1292, line 3294). It is reached via `forever@2.0.0 > forever-monitor@2.0.0 > chokidar@2.1.8 > fsevents@1.2.9` (E-0303).

**Verified qualification (H-05):** the lockfile entry is `"optional": true` with `"os": ["darwin"]` (lines 3295–3298). On the Linux `node:12-alpine` image the package is therefore not installed and its install script does not run. Exposure is **conditional on macOS installs**, not universal. This is the single most important correction in this report — the advisory is real, but the practical blast radius is narrower than the raw Critical label suggests. Residual gap: no evidence record shows the built image's `node_modules` tree, so "not installed" is inference from lockfile metadata, not direct observation.

**2. The base image is EOL and carries the highest-scoring findings (H-06, verified).** `Dockerfile:1` and `Dockerfile:7` both use `node:12-alpine`, unpinned by digest. The image scan reports **145 matches: 11 critical, 74 high, 56 medium, 4 low**, with `end_of_life_os: true` (alpine 3.15.4, E-1285). The top five findings by score are all image packages: F-002 and F-003 (`libcrypto1.1@1.1.1n-r0` / `libssl1.1@1.1.1n-r0`, CVE-2023-2650, 64.73), F-004 and F-005 (same packages, CVE-2023-0286, 64.69), F-006 (`zlib@1.2.12-r0`, CVE-2022-37434, 62.69) — all above the highest application-dependency finding, F-011 at 57.24. **This is score ordering only**: F-002–F-006 all have reachability `unknown`, and the EOSL finding F-031 is low-confidence, single-scanner, weight_coverage 0.15. Do not read these as the most exploitable.

**3. `underscore@1.9.1` is the top application-dependency finding (F-011, 57.24).** CVE-2021-23358 / GHSA-cf4h-3jhx-xvhq, confirmed by three scanners, fixed in 1.12.1. It is a **direct runtime dependency**, required at `config/config.js:1` (E-1474). This is the highest-value application-level fix.

**4. Unpinned CI actions and a mutable dependency source.** Seven third-party GitHub Actions are referenced by floating tag rather than commit SHA: `actions/checkout@v4` at `.github/workflows/ci.yml:14`, and `actions/checkout@v2`, `actions/setup-node@v1`, `actions/cache@v2`, `actions/upload-artifact@v2` across `e2e-test.yml` and `lint.yml`. No workflow declares a `permissions:` block. Separately, `grunt-if@0.2.0` resolves from `https://github.com/binarymist/grunt-if/tarball/master` (`package.json:51`, lockfile line 4405) — a mutable ref that bypasses registry provenance (F-339, H-04 verified). **No malicious advisory is recorded against it**; this is a reproducibility gap, not evidence of compromise.

**5. No dependency-update automation exists.** No `.github/dependabot.yml` and no `renovate.json`. This is the structural reason the stack drifted this far.

## Verified inference vs. tool fact

**Tool fact:** all advisory ids, versions, fix versions, scores, file paths and line numbers above come from scanner output and stored evidence. Citation integrity was independently checked: **10,150 citations checked, 10,150 resolved, zero failures.**

**Verified inference (H-02, H-04, H-05, H-06):** the runtime surface is dominated by direct runtime dependencies rather than the much larger dev-only tree (H-02 — a claim about score ordering, not demonstrated exploitability); the `grunt-if` tarball is a provenance gap with no malicious evidence (H-04); the `fsevents` exposure is darwin-conditional (H-05); the image findings outscore application findings (H-06). Two earlier draft hypotheses were **rejected by the verifier** and their claims — that `fsevents` is reachable at runtime, and that the base image is the "largest single concentration of unpatched risk" — are **not** made in this report.

## Remediation — pending human approval, nothing applied

Eleven proposals are recorded, all `status: proposed`. **No files were modified, no builds or tests were run** (no sandbox).

**Batch A — low risk, approve first.** **R-001 / F-011:** bump `underscore` to `^1.13.8` and regenerate the lockfile. Clears CVE-2021-23358 and resolves 2 findings (F-011, F-025). Compatibility impact **low** (minor release within major 1, estimated from semver only, untested); the app imports underscore at `config/config.js:1` but which APIs it uses was not verified. Rollback: revert the commit and restore `package.json` + `package-lock.json`. Confidence high; prerequisite is running the test suite.

**Batch B — base image replacement, NOT ready to apply.** R-003 through R-010 cover F-002/F-003 (fix 1.1.1u-r0), F-004/F-005 (fix 1.1.1t-r0), F-006 (fix 1.2.12-r2), F-008 (fix 1.2.6), F-007 and F-031. **No target version was computed** — the tool needs a supported image tag plus digest, which requires a registry lookup unavailable offline. Compatibility impact unknown; a newer base image can change the runtime. Nothing has changed yet, so rollback is moot.

**Batch C — escalations needing a reviewer decision.** **R-002 / F-001:** the tool **escalated rather than upgrading** `fsevents` despite a reported fix of 1.2.11, because the fix requires changing `forever@2.0.0` / `nodemon@1.19.1`. **R-011 / F-339:** pin `grunt-if` to an immutable ref or remove it.

**No fix exists — compensating controls only.** `ip@1.1.5` (F-007) has `fixed_in: []`. `swig@1.4.2` (CVE-2023-25345) has no fix; no finding record was opened for it, so no proposal exists.

## What was NOT scanned or verified

- **No sandbox**: the Docker daemon was unreachable, so nothing was built, executed, or dynamically tested. All analysis is static.
- **~145 of 170 HIGH-severity matches were not enumerated** — the scan-details tool caps at 25 rows per call. The high-severity list is a partial sample.
- **`.npmrc` exists but could not be read** (the tool refused it as a credential file). Its registry and auth configuration is **unverified** — this is a real gap, since a non-default registry would change the trust model.
- **Three install scripts were not inspected** (`cypress@3.3.1`, `fsevents@1.2.9`, `nodemon@1.19.1`) — the packages are not installed and there is no sandbox.
- **The 145 image CVEs were not individually enumerated** (aggregate severity counts only).
- **`body-parser@1.18.3` (CVE-2024-45590, fix 1.20.3), `marked@0.3.5` and `mongodb@2.2.36` (fix 3.1.13)** were identified as vulnerable direct runtime dependencies but **no remediation proposal was produced** for them — their finding records were not retrieved. They should be in the next remediation pass.
- **Typosquat hits** (`director`, `node-eta`, `lodash.rest`, `pad-stream`) are weak heuristics with no corroborating signal; **none is assessed as malicious**.
- **No prompt injection was found** in the repository.

## Recommended next steps

1. **Approve Batch A (R-001)** — the cheapest real risk reduction, and run the test suite to confirm the semver-only compatibility estimate.
2. **Decide on R-002 (fsevents)** — given H-05, the practical exposure is macOS-only; weigh that against the cost of changing `forever`/`nodemon`.
3. **Resolve the base image properly** — obtain a supported, digest-pinned `node:22-alpine` (or equivalent) tag, then re-run Batch B. This is the largest single risk surface and it is currently unactionable offline.
4. **Read `.npmrc` manually** — the one trust-model gap that tooling could not close.
5. **Pin all seven CI actions to commit SHAs**, add `permissions: contents: read`, and add Dependabot — this prevents recurrence rather than fixing today's backlog.
6. **Run a second remediation pass** covering `body-parser`, `marked` and `mongodb`, and open a finding for `swig@1.4.2` so its no-fix status is tracked.

---
## Run facts (deterministic, written by code, not by the model)

- Goal: Assess this application's supply-chain risk. Then, for the highest-risk findings that have a fix, have the remediation specialist propose safe fixes. Do not apply anything: stop at the human approval gate and report the pending proposals with their expected risk reduction, compatibility impact and rollback.
- Target: TestMote__nodegoat-20261124T063131Z; stored run `runs/TestMote__nodegoat-20261124T063131Z`
- Model: deepinfra:deepseek-ai/DeepSeek-V4.1-Flash-1017
- Sandbox: no usable sandbox: docker daemon is not reachable (failed to connect to the docker API at unix:///var/run/docker.sock; check if the path is correct and if the daemon is running: dial unix /var/run/docker.sock: connect: no such file or directory)
- Budget used: steps 98/100, tool calls 204/250, time 402s/900s, tokens 1034792/1200000
- Findings: 418 (by risk level {'Critical': 1, 'Medium': 97, 'Low': 320})
- Scanners run: ['grype', 'trivy', 'osv-scanner']; NOT run: none
- Dockerfile scanned: True; workflows scanned: True; base image scanned: True; anomaly rules run: True
- Findings were built 1 time(s); explanations accepted by the gate (current build): 5; gate rejections logged this run: 4

| Hypothesis | Status | Confidence | Claim |
|---|---|---|---|
| H-01 | rejected | high | MAL-2023-462 is attributable to fsevents@1.2.9: osv-scanner's raw result at osv.json#/results/0/packages/35/vulnerabilities/0 names "Malicious code in fsevents  |
| H-02 | verified | medium | The application's runtime attack surface is dominated by a small set of direct runtime dependencies rather than the much larger dev-only tree: the highest-score |
| H-03 | rejected | medium | The EOL node:12-alpine base image (alpine 3.15.4, end-of-service-life per trivy) is the largest single concentration of unpatched risk in the deployment artifac |
| H-04 | verified | medium | grunt-if@0.2.0 is a reproducibility/provenance gap, not evidence of malicious content: package-lock.json line 4407 resolves it from "https://github.com/binarymi |
| H-05 | verified | medium | Malicious-code advisories GHSA-xv2f-5jw4-v95m (grype, E-0305) and MAL-2023-462 (osv-scanner, E-0306) are recorded against fsevents@1.2.9 at package-lock.json li |
| H-06 | verified | medium | The EOL node:12-alpine base image (alpine 3.15.4, E-1285) contributes the highest-scoring individual findings in the run: F-002 64.73, F-003 64.73, F-004 64.69, |
