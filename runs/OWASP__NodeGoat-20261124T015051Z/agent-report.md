# Supply-Chain Risk Assessment — OWASP NodeGoat

## Overall picture

This is a deliberately insecure teaching application (OWASP NodeGoat, `owasp-nodejs-goat@1.3.0`), and its dependency tree reflects that: **415 findings** were built from three independent scanners, with **1 Critical, 97 Medium and 317 Low**. The single most serious item is a **malicious-package advisory on `fsevents@1.2.9` (F-001)**. Beyond that, the risk is dominated by a very old, unpinned dependency and build stack rather than by any one exploitable CVE.

The most important caveat up front: **no advisory in this run is in CISA KEV, and every EPSS score seen was below 0.08.** That is a snapshot fact, not a safety verdict.

## What matters most

**1. Malicious package: `fsevents@1.2.9` — F-001 (Critical)**
Two independent scanners attribute malware to this package: osv-scanner reports `MAL-2023-462` with the excerpt "Malicious code in fsevents (npm)" (E-0306), and grype independently flags the same package (E-0305). The lockfile entry is confirmed at `package-lock.json:3286` (E-1288).
*Caveats that materially reduce urgency:* the lockfile marks it `"optional": true` with `"os": ["darwin"]` (E-1288), so it is a **macOS-only optional dependency** and does not install in the Linux container. Its reachability is `present_only`. **The advisory's affected-version range was never retrieved**, so I cannot confirm that 1.2.9 specifically falls inside it. Treat as: real, but not executing in the deployed image.

**2. Two direct runtime dependencies carry advisories — F-011, F-017 (Medium)**
`underscore@1.9.1` (CVE-2021-23358, E-1214/E-1215/E-1216) is a direct runtime dependency imported at `config/config.js:1` (E-1470); `mongodb@2.2.36` (GHSA-mh5c-679w-hh4r, E-0776/E-0777/E-0778) is imported at `server.js:11` (E-1466). Both are single-install-path direct dependencies (E-1217, E-0779).
*Important limit:* these are **imported, not demonstrated exploitable**. The underscore advisory is a `_.template` code-injection issue, and `_.template` is never called in `config/config.js` — the file only requires the module. Both findings are scored Medium, not Critical.

**3. Non-registry dependency on a mutable git ref — F-338 (Low)**
`grunt-if@0.2.0` resolves from `https://github.com/binarymist/grunt-if/tarball/master` (`package-lock.json:4407`, E-1289) — a branch name, not an immutable commit. An integrity hash is present (E-1290), so npm would reject a *changed* tarball; the real risk is that **the lockfile cannot be reproduced to the same code**. It is dev-only (`"dev": true`).

**4. End-of-life, unpinned base image — F-031, F-075 (Medium)**
The Dockerfile uses `node:12-alpine` on lines 1 and 7, not pinned by digest (E-1279). The image scan reports the OS as **end-of-service-life: alpine 3.15.4, no more security updates** (E-1281). The image scan returned **145 matches (11 critical, 74 high, 56 medium, 4 low)** — but see the gap below.

**5. Unpinned CI actions — F-151 to F-156 (Low)**
Six GitHub Actions are referenced by mutable tag rather than commit SHA: `actions/checkout@v2`, `actions/setup-node@v1`, `actions/cache@v2`, `actions/upload-artifact@v2` (E-1265–E-1277). Both workflows also declare no `permissions:` block (F-369, F-370). Mitigating: triggers are `push`/`pull_request` only — no `pull_request_target` — and checkouts set `persist-credentials: false`.

**6. Dev-only critical advisory cluster — F-160 (Low)**
`handlebars@4.0.5` carries critical-severity advisories, but the chain is depth-7 dev-only: `grunt-if@0.2.0 > grunt-contrib-nodeunit@1.0.0 > nodeunit@0.9.5 > tap@7.1.2 > nyc@7.1.0 > istanbul-reports@1.0.0-alpha.8 > handlebars@4.0.5` (E-0343). The Dockerfile installs with `npm install --production`, excluding it. **The advisory is critical; the finding is Low.**

## Verified inference vs tool fact

**Tool fact:** all scanner counts, advisory ids, package versions, dependency paths, file contents, EOSL metadata, and the 10,127/10,127 citation check.

**Verified inference (H-02, H-05, H-06, H-07):** that `grunt-if` is installed from a mutable ref; that the handlebars cluster is dev-only; that the two direct runtime deps are imported by non-dev code; that the base OS is EOSL.

**Explicitly not asserted:** I make no claim that any runtime dependency is *exploitable* in this application, and no claim that the EOL base image currently contains specific unpatched OS vulnerabilities. Neither is supported by the evidence gathered.

## What was NOT checked

- **No CVE identifiers exist for the 145 image matches.** `scan_image` returns counts only, with no per-finding records. The 11 critical image matches are real but unnamed; I cannot say which component drives them.
- **The `MAL-2023-462` affected-version range** was never retrieved.
- **No sandbox** (docker daemon unreachable): nothing was built or executed. Install-script bodies for `cypress@3.3.1`, `fsevents@1.2.9` and `nodemon@1.19.1` were not inspected.
- **No EPSS/KEV lookup** was completed for the high/medium set; only the 16 critical CVEs were checked.
- **No finding exists** for three confirmed hygiene facts: `grunt-env` declared as `"latest"` (`package.json:50`), `npm install` instead of `npm ci` in the Dockerfile, and hardcoded `cryptoKey`/`cookieSecret` in `config/env/all.js`. The tooling produced no rule hit, so no finding was invented.
- Typosquat heuristics returned four hits, **all false positives** (all resolve to `registry.npmjs.org` from legitimate parents). No prompt injection was found in the repository.

## Recommended next steps

1. **Remove or replace `fsevents@1.2.9`** and confirm the advisory's version range; it is macOS-only, so this is cheap.
2. **Upgrade the base image** to a supported Node LTS pinned by digest, and re-scan with a mode that emits per-CVE records so the 11 critical image matches can be triaged.
3. **Replace `grunt-if`** with a registry-pinned version or vendor it; pin `grunt-env` to an exact version.
4. **Pin all six CI actions to commit SHAs** and add `permissions: contents: read`.
5. **Switch the Dockerfile to `npm ci`** and move the hardcoded secrets to environment variables.
6. Upgrade `underscore` and `mongodb`; note that neither is currently demonstrated exploitable, so this is hygiene rather than an emergency.

---
## Run facts (deterministic, written by code, not by the model)

- Goal: Assess the software supply-chain risk of this repository. Find what is in it, what is vulnerable, and what looks suspicious beyond known CVEs. Report the few things that matter most, with evidence, what was not checked, and what to do next.
- Target: OWASP__NodeGoat-20261124T015051Z; stored run `runs/OWASP__NodeGoat-20261124T015051Z`
- Model: deepinfra:deepseek-ai/DeepSeek-V4.1-Flash-1017
- Sandbox: no usable sandbox: docker daemon is not reachable (failed to connect to the docker API at unix:///var/run/docker.sock; check if the path is correct and if the daemon is running: dial unix /var/run/docker.sock: connect: no such file or directory)
- Budget used: steps 83/100, tool calls 197/250, time 408s/900s, tokens 876552/1200000
- Findings: 415 (by risk level {'Critical': 1, 'Medium': 97, 'Low': 317})
- Scanners run: ['grype', 'trivy', 'osv-scanner']; NOT run: none
- Dockerfile scanned: True; workflows scanned: True; base image scanned: True; anomaly rules run: True
- Findings were built 1 time(s); explanations accepted by the gate (current build): 7; gate rejections logged this run: 2

| Hypothesis | Status | Confidence | Claim |
|---|---|---|---|
| H-01 | rejected | high | The runtime (non-dev) dependency tree contains at least one critical-severity vulnerability reachable in production: underscore@1.9.1 (CVE-2021-23358) is a dire |
| H-02 | verified | high | grunt-if@0.2.0 is installed from a mutable git branch ref (https://github.com/binarymist/grunt-if/tarball/master), so the audited code is not guaranteed to be t |
| H-03 | needs_more_evidence | medium | The node:12-alpine base image is end-of-life (alpine 3.15.4 EOSL) and therefore accumulates unpatched OS-level vulnerabilities. |
| H-04 | rejected | medium | MAL-2023-462 cannot be attributed to any package in this tree with the available tools; the only package-level attribution seen is fsevents@1.2.9 from grype/osv |
| H-05 | verified | high | The handlebars@4.0.5 critical cluster is dev-only: the graph path is owasp-nodejs-goat@1.3.0 > grunt-if@0.2.0 > grunt-contrib-nodeunit@1.0.0 > nodeunit@0.9.5 >  |
| H-06 | verified | medium | underscore@1.9.1 and mongodb@2.2.36 are direct runtime dependencies (each with 1 install path) that are imported by non-dev application code and each carries a  |
| H-07 | verified | medium | The node:12-alpine base image runs an end-of-service-life OS (alpine 3.15.4) that will receive no further security updates. |
