# NodeGoat — Software Supply-Chain Risk Assessment

## Overall picture

NodeGoat is a deliberately-vulnerable OWASP training application, and its dependency tree reflects that: **415 findings** were built from a 422-component SBOM (1480-node graph, max depth 13, 36 direct dependencies). The distribution is **1 Critical, 97 Medium, 317 Low**.

The single most important item is **F-001 (Critical, score 57.0)**: `fsevents@1.2.9` is flagged as a **malicious package** by two independent scanners — grype reports GHSA-xv2f-5jw4-v95m and osv-scanner reports MAL-2023-462 — and it carries an install hook (`hasInstallScript: true`). It is not a direct dependency; it arrives transitively via `owasp-nodejs-goat@1.3.0 > forever@2.0.0 > forever-monitor@2.0.0 > chokidar@2.1.8 > fsevents@1.2.9` (E-0303, E-0305, E-0306, E-1288). Fix version is 1.2.11.

Two structural issues matter next: an **end-of-life, unpinned base image** and a **mutable-tarball dev dependency**. Everything else is a long tail of old transitive packages.

## What matters most

**1. Malicious package in the tree — F-001 (Critical).** This is the only Critical finding and the only malicious-package advisory in the run. Notably, **only osv-scanner reported MAL-2023-462**; grype and trivy reported zero malicious advisories. The cross-scanner disagreement is why this needed a second look rather than a pick — but grype independently flags the same package with GHSA-xv2f-5jw4-v95m, so the two flags attach to one package instance (verified, H-05). Exposure is bounded: the lockfile marks the entry `optional: true` with `os: ["darwin"]`, so it is macOS-only and install-time exposure on Linux/CI is limited. That qualifier is a limiting factor, not a clearance — the package is still in the resolved tree.

**2. EOL, unpinned base image — F-031, F-075, F-076 (Medium).** Both `FROM` lines use the floating tag `node:12-alpine` with no digest pin (E-1279, E-1280), and trivy reports the base OS as end-of-service-life with no further security updates (E-1281). The image scan returned 145 matches: 11 critical, 74 high, 56 medium, 4 low. The build is not reproducible and the runtime receives no further patches. This is a verified inference (H-04) — deliberately narrower than an earlier claim that this was the "dominant" risk, which the verifier rejected as unsupported.

**3. Mutable-tarball dev dependency — F-338 (Low).** `grunt-if@0.2.0` resolves from `https://github.com/binarymist/grunt-if/tarball/master` — a mutable branch ref, not the npm registry — pinned only by a weak sha1 hash (E-1289, E-1290). Content can change without any lockfile diff. Dev-only, hence Low, but it is a genuine integrity gap (verified, H-06).

**4. Old direct runtime dependencies.** `underscore@1.9.1` (F-011, Medium 57.24, reachability `imported`, exposure `runtime_network`), `mongodb@2.2.36` (F-017), `marked@0.3.5` (F-018), `body-parser@1.18.3` (F-019). These are the findings most likely to be reachable from application code.

**5. CI and container hygiene.** Four GitHub Actions pinned to mutable major tags rather than commit SHAs — `actions/checkout@v2`, `actions/setup-node@v1`, `actions/cache@v2`, `actions/upload-artifact@v2` (F-151–F-156); no explicit `permissions:` block in either workflow (F-369, F-370); `mongo:4.4` and CI's `mongo:4.0` unpinned; Dockerfile uses `npm install` rather than `npm ci`, has its hardening line commented out, and has no HEALTHCHECK (F-032, F-033).

## Verified inference vs tool fact

**Tool fact:** all finding ids, scores, package versions, advisory ids, evidence ids and the image scan counts above come from scanner and `build_findings` output. Citation integrity was independently checked: **10127 citations checked, 10127 resolved, zero failures.**

**Verified inference (ruled on by the verifier):** H-04 (EOL/unpinned base image), H-05 (the malicious flag and install hook are one package instance, with the macOS-only caveat), H-06 (mutable tarball ref as an integrity risk). An earlier hypothesis that the base image was the "dominant structural risk" and that image findings "cannot be fixed by rebuilding" was **rejected as overreach** and replaced with the narrower H-04.

**Exploitability:** EPSS/KEV was obtained for only two findings. `underscore@1.9.1` / CVE-2021-23358: EPSS 0.042, 91st percentile, not in KEV. `body-parser@1.18.3` / CVE-2024-45590: EPSS 0.00956, not in KEV. F-017 and F-018 carry no CVE id in stored output, so no EPSS/KEV coverage exists for them. `kev_findings` is 0, which may reflect missing feed data rather than absence of KEV entries.

## What was NOT checked or verified

- **Per-advisory detail for the long tail.** No CVE/GHSA ids are exposed for the 303 transitive and 70 image findings beyond F-001. They cannot be ranked by advisory, only by score.
- **Raw scan artifacts were unreadable.** All three scanners report output paths (`runs/agent-live2/*.json`) that `read_file` cannot open. Per-advisory data was only recoverable through `build_findings`. This is a tooling gap, not evidence of absence.
- **No sandbox.** The docker daemon was unreachable, so no package was installed, unpacked or executed. Install-script bodies for `cypress@3.3.1`, `fsevents@1.2.9` and `nodemon@1.19.1` were **not inspected**.
- **Image scan provenance.** The `node:12-alpine` scan ran against a locally cached layout; I could not confirm it matches the upstream registry digest.
- **Not checked:** vendored/bundled third-party JS, maintainer metadata, registry age data, transitive paths for sub-dependencies below the direct level.
- **F-001 explanation** was initially blocked by an exhausted attempt counter; it was reset and the explanation was accepted. The finding is explained.
- **Prompt injection:** searched for and found none. `package.json` contains a `"//": "a9 insecure components"` comment — that is the project's own teaching label, treated as data.

## Recommended next steps

1. **Resolve F-001 first.** Upgrade or remove `fsevents@1.2.9` (fix 1.2.11) and confirm with a second scanner that MAL-2023-462 no longer matches. Treat the macOS-only qualifier as a scoping fact, not a reason to defer.
2. **Move off `node:12-alpine`** to a supported, digest-pinned Node LTS; pin `mongo:4.4` and CI's `mongo:4.0` the same way. Switch the Dockerfile to `npm ci --omit=dev`, uncomment the hardening line, add a HEALTHCHECK.
3. **Replace `grunt-if`** with a registry-pinned version or vendor it; pin `grunt-env` (currently `"latest"`).
4. **Pin all four CI actions to commit SHAs** and add least-privilege `permissions:` blocks; drop EOL Node 10/12 from the CI matrix.
5. **Upgrade the direct runtime dependencies** — `underscore`, `mongodb`, `marked`, `body-parser` — and re-scan.
6. **Fix the tooling gap** so per-advisory JSON is readable, then re-run `build_findings` to rank the 303 transitive findings by advisory and complete EPSS/KEV coverage.

---
## Run facts (deterministic, written by code, not by the model)

- Goal: Assess the software supply-chain risk of the target application and produce an evidence-backed report of what matters most, what was and was not checked, and what to do next.
- Target: nodegoat; stored run `runs/agent-live2`
- Model: deepinfra:deepseek-ai/DeepSeek-V4.1-Flash-1017
- Sandbox: no usable sandbox: docker daemon is not reachable (failed to connect to the docker API at unix:///var/run/docker.sock; check if the path is correct and if the daemon is running: dial unix /var/run/docker.sock: connect: no such file or directory)
- Budget used: steps 84/100, tool calls 182/250, time 364s/900s, tokens 732799/1200000
- Findings: 415 (by risk level {'Critical': 1, 'Medium': 97, 'Low': 317})
- Scanners run: ['grype', 'trivy', 'osv-scanner']; NOT run: none
- Dockerfile scanned: True; workflows scanned: True; base image scanned: True; anomaly rules run: True
- Explanations accepted by the gate: 1; rejected: 0

| Hypothesis | Status | Confidence | Claim |
|---|---|---|---|
| H-01 | verified | medium | fsevents@1.2.9 is flagged by both grype (GHSA-xv2f-5jw4-v95m) and osv-scanner (MAL-2023-462) as malicious, and it also carries a hasInstallScript install hook,  |
| H-02 | rejected | medium | The node:12-alpine base image is end-of-service-life (no more security updates) and is referenced by a floating tag rather than a digest, so the EOL runtime plu |
| H-03 | verified | medium | grunt-if@0.2.0 is resolved from a mutable GitHub tarball branch ref rather than registry.npmjs.org, so the installed content is not cryptographically pinned and |
| H-04 | verified | medium | Both FROM lines in the Dockerfile use the floating tag node:12-alpine with no digest pin, and trivy reports the base OS as end-of-service-life, so the runtime r |
| H-05 | verified | medium | fsevents@1.2.9 is flagged by both grype (GHSA-xv2f-5jw4-v95m) and osv-scanner (MAL-2023-462) as malicious, and it also carries a hasInstallScript install hook,  |
| H-06 | verified | medium | grunt-if@0.2.0 is resolved from a mutable GitHub tarball branch ref rather than registry.npmjs.org, so the installed content is pinned only by a weak sha1 over  |
