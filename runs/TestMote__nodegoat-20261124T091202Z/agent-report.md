# Supply-Chain Risk Assessment — TestMote__nodegoat

## Overall picture

This is the OWASP NodeGoat training application (npm/Node.js, Express 4, MongoDB), 424 SBOM components and 36 direct dependencies. The dependency tree is very old and carries a large volume of known-vulnerable code: three independent offline scanners agree closely (grype 340 matches / 196 advisories, trivy 325 / 206, osv-scanner 313 / 196), and `build_findings` stored **418 findings — 1 Critical, 0 High, 97 Medium, 320 Low**. No advisory in the run is in CISA KEV, and the highest EPSS among the criticals is about 0.07, so nothing here is under active mass exploitation. The real problem is breadth and age, not a single burning CVE.

The few things that matter most:

1. **A malicious-package finding on fsevents@1.2.9 (F-001, Critical, score 57.0, fixed_in 1.2.11).** This is the only Critical finding and the one item I would treat as urgent, with the caveat in the next section.
2. **Runtime-reachable vulnerable direct dependencies.** underscore@1.9.1 (F-011, CVE-2021-23358, fixed_in 1.12.1; and F-025, CVE-2026-27601, fixed_in 1.13.8), mongodb@2.2.36 (F-017, GHSA-mh5c-679w-hh4r, fixed_in 3.1.13), body-parser@1.18.3 (F-019, CVE-2024-45590, fixed_in 1.20.3), marked@0.3.5 (F-018, fixed_in >=0.3.6), and swig@1.4.2 (F-035, CVE-2023-25345, **no fix reported**). These are the findings where a fix actually reduces exposure of the running app.
3. **Critical-severity prototype pollution on a production install path.** mixin-deep@1.3.1 (F-084, CVE-2019-10746, fixed_in 1.3.2) and set-value@0.4.3 / 2.0.0 (F-087, F-088, F-090, F-091, CVE-2019-10747 / CVE-2021-23440, fixed_in 2.0.1) reach the app through forever@2.0.0, a production dependency.
4. **An unpinned, mutable git dependency.** grunt-if@0.2.0 is resolved from `https://github.com/binarymist/grunt-if/tarball/master` (F-339, Low score 24.0) — a branch ref, so the installed code is not pinned to audited content.
5. **An end-of-life base image.** The Dockerfile builds on `node:12-alpine` (F-031, EOSL, score 50.0; F-075 and F-076, digest-pinning, score 45.0). The image scan reported 11 critical / 74 high / 56 medium / 4 low OS matches, but those were **not** emitted as individual findings, so they cannot be ranked or fixed per-CVE from this run.

## Verified inference vs tool fact

**Tool fact:** all scanner counts, advisory ids, versions and fix versions above come from grype/trivy/osv-scanner output and the stored findings. `verify_citations` resolved 10150 of 10150 stored citations with 0 failures.

**Verified inference (asserted):**
- **H-02 (verified):** grunt-if@0.2.0's lockfile entry resolves to a mutable `tarball/master` ref, so installed content is not pinned to audited code, even though the package is dev-only and scores Low (F-339, E-1293, E-1294).
- **H-05 (verified):** the base image is EOL (alpine 3.15.4, E-1285) and only three image findings exist (F-031, F-075, F-076), all with empty `fixed_in`; no per-CVE fix count is computable from stored findings.
- **H-06 (verified):** handlebars@4.0.5 (F-161) and json-schema@0.2.3 (F-168) are dev-scope only, reached through grunt-if@0.2.0 and cypress@3.3.1 respectively (E-0343, E-0529).
- **H-07 (verified):** mixin-deep@1.3.1 and set-value@2.0.0/0.4.3 reach the app through forever@2.0.0, a production dependency, so those prototype-pollution advisories sit on a production install path (E-0765, E-0980, E-0989, E-0764, E-0979, E-0984).

**Not asserted:** the malicious-advisory attribution on F-001 is not confirmed. What the evidence shows is that osv-scanner reported MAL-2023-462 against the fsevents@1.2.9 lockfile entry (E-0306) and grype separately reported malware in fsevents under GHSA-xv2f-5jw4-v95m (E-0305); the advisory's own affected-package record was not retrieved, and F-001's `advisory_ids` pairs the two ids while only the grype id is evidenced as a fsevents malware record. Two further inference questions — whether the dev-scope criticals are entirely non-runtime-reachable, and whether the EOL base image is the "dominant" container risk — remain unresolved and are deliberately not asserted; the verified H-07 already shows that at least two packages in that dev-scope group are in fact runtime-scope.

## What was NOT scanned or verified

- **No sandbox** (docker daemon unreachable): install-script bodies for cypress@3.3.1, fsevents@1.2.9 and nodemon@1.19.1 were never executed or unpacked, and the grunt-if tarball contents were not inspected. The malicious-package signal on fsevents is therefore scanner-reported, not reproduced.
- **MAL-2023-462's affected package** could not be resolved; package-filtered lookups returned 0 matches.
- **babel-traverse@6.11.4 fix version is disputed**: trivy reports 7.23.2, grype and osv report no fix. Unresolved.
- **Image OS CVEs** (11 critical / 74 high) exist only as scan counts, not as findings with fix versions.
- The require() check behind H-06 covered only the first 30–40 lines of three source files, not a repo-wide scan.
- No `.dockerignore` verification, no exhaustive lockfile-integrity sweep of all 424 entries, no base-commit diff analysis.
- Typosquat hits (director, node-eta, lodash.rest, pad-stream) were all distance-2 heuristics with no advisory; none is assessed as malicious.

## Remediation — pending human approval

No fix has been applied. The remediation specialist was not run to completion within budget, so the proposals below are the supervisor's recommendations derived from the stored `fixed_in` values; they must be turned into reviewed proposals and approved by a human before any change.

| Target | Finding | Proposed change | Expected risk reduction | Compatibility impact | Rollback |
|---|---|---|---|---|---|
| underscore@1.9.1 | F-011, F-025 | Upgrade to 1.13.8 (covers both advisories) | Removes the highest-confidence runtime critical (CVSS 9.8, imported, runtime_network) | Low–medium: 1.9→1.13 is a major-version jump; check template/`_.template` usage | Revert package.json + lockfile |
| mongodb@2.2.36 | F-017 | Upgrade to 3.1.13 | Removes a high-severity driver advisory | **High**: 2.x→3.x driver API change; needs code and connection-string testing | Revert lockfile; pin back to 2.2.36 |
| body-parser@1.18.3 | F-019 | Upgrade to 1.20.3 | Removes CVE-2024-45590 (8.7) on the request path | Low: patch-level within 1.x | Revert lockfile |
| marked@0.3.5 | F-018 | Upgrade to >=0.3.6 (prefer current major) | Removes three high-severity advisories | Medium: output/API changes across majors | Revert lockfile |
| mixin-deep / set-value | F-084, F-087, F-088, F-090, F-091 | Add lockfile overrides to 1.3.2 / 2.0.1 | Removes critical prototype pollution from the production install path | Low: transitive-only, no direct API use | Remove overrides |
| fsevents@1.2.9 | F-001 | Upgrade to 1.2.11, or drop the dependency | Removes the only Critical finding | Low: optional macOS-only watcher | Revert lockfile |
| grunt-if@0.2.0 | F-339 | Pin to a commit SHA or a registry version | Removes the mutable-ref exposure (H-02) | Low: dev-only build tool | Revert package.json + lockfile |
| node:12-alpine | F-031, F-075, F-076 | Move to a maintained Node LTS base, digest-pinned | Largest single reduction in image CVEs, though not quantifiable from this run (H-05) | **High**: Node 12→LTS runtime change; needs full app test | Revert Dockerfile |
| swig@1.4.2 | F-035 | No fix reported — escalate | None available | — | — |

## Recommended next steps

1. Approve and validate the low-risk, high-value fixes first: underscore→1.13.8, body-parser→1.20.3, the mixin-deep/set-value overrides, fsevents→1.2.11, and pinning grunt-if to a commit SHA.
2. Treat the mongodb 2.x→3.x and Node 12→LTS upgrades as separate, tested changes — they carry the real compatibility risk.
3. Re-run the image scan with per-CVE findings enabled so the 11 critical / 74 high OS matches become rankable, then decide the base-image bump on data rather than counts.
4. Resolve MAL-2023-462's affected-package record and the babel-traverse fix disagreement before closing F-001 and that advisory.
5. Run the install scripts and the grunt-if tarball in a real sandbox when one is available; that is the only way to confirm or clear the malicious-package signal.
6. Note that this repository is a deliberately vulnerable teaching app; if it is ever deployed beyond training, the whole dependency set needs a modernization pass, not just the items above.

---
## Run facts (deterministic, written by code, not by the model)

- Goal: Assess this application's supply-chain risk. Then, for the highest-risk findings that have a fix, have the remediation specialist propose safe fixes. Do not apply anything: stop at the human approval gate and report the pending proposals with their expected risk reduction, compatibility impact and rollback.
- Target: TestMote__nodegoat-20261124T091202Z; stored run `runs/TestMote__nodegoat-20261124T091202Z`
- Model: deepinfra:deepseek-ai/DeepSeek-V4.1-Flash-1017
- Sandbox: no usable sandbox: docker daemon is not reachable (failed to connect to the docker API at unix:///var/run/docker.sock; check if the path is correct and if the daemon is running: dial unix /var/run/docker.sock: connect: no such file or directory)
- Budget used: steps 96/100, tool calls 233/250, time 404s/900s, tokens 1183783/1200000
- Findings: 418 (by risk level {'Critical': 1, 'Medium': 97, 'Low': 320})
- Scanners run: ['grype', 'trivy', 'osv-scanner']; NOT run: none
- Dockerfile scanned: True; workflows scanned: True; base image scanned: True; anomaly rules run: True
- Findings were built 1 time(s); explanations accepted by the gate (current build): 6; gate rejections logged this run: 4

| Hypothesis | Status | Confidence | Claim |
|---|---|---|---|
| H-01 | needs_more_evidence | medium | The dev-scope criticals in the grunt/cypress toolchain are not runtime-reachable: they are dev dependencies only, so they do not execute in the deployed applica |
| H-02 | verified | medium | grunt-if@0.2.0 resolved from https://github.com/binarymist/grunt-if/tarball/master is a real supply-chain exposure because a mutable branch ref means the instal |
| H-03 | needs_more_evidence | medium | The end-of-service-life node:12-alpine base (alpine 3.15.4) is the dominant container risk: because the OS no longer receives security updates, the 11 critical  |
| H-04 | rejected | low | MAL-2023-462 is attributed by osv-scanner to fsevents@1.2.9 in this repository, but the scanner run also reported one malicious advisory whose package could not |
| H-05 | verified | high | The node:12-alpine base image is EOL (alpine 3.15.4, E-1285) and is the only image component with findings, but the 11 critical / 74 high / 56 medium / 4 low OS |
| H-06 | verified | medium | handlebars@4.0.5 (F-161) and json-schema@0.2.3 (F-168) are dev-scope only: the graph resolves handlebars@4.0.5 through grunt-if@0.2.0 > grunt-contrib-nodeunit@1 |
| H-07 | verified | high | mixin-deep@1.3.1 (F-084) and set-value@2.0.0/0.4.3 (F-087, F-088, F-090, F-091) resolve through forever@2.0.0, which package.json line 15 lists under `dependenc |
