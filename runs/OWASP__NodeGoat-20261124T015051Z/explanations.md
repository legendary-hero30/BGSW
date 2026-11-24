# AI explanations: runs/OWASP__NodeGoat-20261124T015051Z

Generator: **language model** (deepinfra:deepseek-ai/DeepSeek-V4.1-Flash-1017). Each explanation passed the deterministic gate; rejected ones are listed, never shown as explanations.

## F-001 fsevents@1.2.9: Malicious code in fsevents (npm)

- Risk: 57.0 Critical (coverage 0.5)
- Why it matters: fsevents@1.2.9 is flagged as malicious by both grype (GHSA-xv2f-5jw4-v95m) and osv-scanner (MAL-2023-462) and carries a hasInstallScript entry, so installing the tree executes attacker-controlled code at install time. The risk score is an override to Critical on confirmed_malicious, with cvss and epss_kev unknown (weight coverage 0.5).
- Reachability: present
- Confidence: medium (Two independent scanners agree on the malicious advisory and the install-script flag is present, but the package is only present in the tree (not imported by application code) and the malicious advisory's package attribution is not independently confirmed by a third source.)
- Evidence: E-0305, E-0306, E-0303, E-1288

## F-011 underscore@1.9.1: Arbitrary Code Execution in underscore

- Risk: 57.24 Medium (coverage 1.0)
- Why it matters: underscore@1.9.1 is a direct runtime dependency with CVSS 9.8 arbitrary code execution via the template function (CVE-2021-23358 / GHSA-cf4h-3jhx-xvhq), fixed in 1.12.1. It is required by config/config.js and the app listens on a network port, so the vulnerable code sits on the production request path.
- Reachability: imported
- Confidence: high (All three scanners report the same advisory and fix version, the dependency graph shows a direct root-to-package path, and a require() of the package was located in application source.)
- Evidence: E-1214, E-1215, E-1216, E-1217, E-1209, E-1470, E-1459

## F-017 mongodb@2.2.36: Denial of Service in mongodb

- Risk: 54.0 Medium (coverage 0.5)
- Why it matters: mongodb@2.2.36 is a direct runtime dependency with a high-severity denial-of-service advisory (GHSA-mh5c-679w-hh4r), fixed in 3.1.13. server.js requires the driver and the app exposes HTTP/HTTPS listeners, so the driver is on the production path; cvss and epss are unknown, so the score rests on reachability and exposure only (weight coverage 0.5).
- Reachability: imported
- Confidence: high (Three scanners agree on the advisory and fix version, the graph shows a direct dependency, and a require() of mongodb was located in server.js.)
- Evidence: E-0776, E-0777, E-0778, E-0779, E-1466, E-1459

## F-031 node@12-alpine: base image OS alpine 3.15.4 is end-of-service-life (no more security updates)

- Risk: 50.0 Medium (coverage 0.15)
- Why it matters: The node:12-alpine base image runs alpine 3.15.4, which trivy reports as end-of-service-life, so OS packages in the image will not receive further security updates. Reachability and provenance are unknown and exposure is the only scored factor (weight coverage 0.15), so the Medium score is weakly supported.
- Reachability: unknown
- Confidence: medium (The EOSL determination comes from a single scanner (trivy image metadata) and no per-CVE identifiers were available for the image scan, so the downstream vulnerability impact is inferred rather than measured.)
- Evidence: E-1281

## F-075 node@12-alpine: base image is not pinned by digest

- Risk: 45.0 Medium (coverage 0.3)
- Why it matters: The Dockerfile pulls node:12-alpine by tag rather than by digest, so the same build can resolve to different image content over time and the audited image is not the image that runs. Reachability is unknown and the score rests on exposure and provenance only (weight coverage 0.3).
- Reachability: unknown
- Confidence: high (The FROM line is quoted directly from the Dockerfile and shows a tag reference with no digest.)
- Evidence: E-1279

## F-151 actions/checkout@v2: action is referenced by tag or branch, not a full commit SHA

- Risk: 35.0 Low (coverage 0.3)
- Why it matters: actions/checkout@v2 is referenced by a mutable tag instead of a full commit SHA, so a compromised or retargeted tag would execute unreviewed code in CI with the workflow's token. Reachability is unknown and the score is Low because only exposure and provenance are scored (weight coverage 0.3).
- Reachability: unknown
- Confidence: high (Both the guardian rule and zizmor independently flag the same line as an unpinned action reference.)
- Evidence: E-1265, E-1266

## F-338 grunt-if@0.2.0: resolved from 'github.com', not registry.npmjs.org (mutable branch ref)

- Risk: 24.0 Low (coverage 0.5)
- Why it matters: grunt-if@0.2.0 is resolved from https://github.com/binarymist/grunt-if/tarball/master, a mutable branch ref rather than a registry tarball, so the code that installs is not guaranteed to be the code that was audited. It is a dev-only dependency, which is why the score is Low despite the high severity of the provenance rule.
- Reachability: dev_only_unused
- Confidence: high (The lockfile resolved URL is directly quoted in the evidence and the dependency graph confirms grunt-if is a direct dev dependency.)
- Evidence: E-1289, E-1290

