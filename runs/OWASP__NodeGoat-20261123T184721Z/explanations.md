# AI explanations: runs/OWASP__NodeGoat-20261123T184721Z

Generator: **language model** (deepinfra:deepseek-ai/DeepSeek-V4.1-Flash-1017). Each explanation passed the deterministic gate; rejected ones are listed, never shown as explanations.

## F-001 fsevents@1.2.9: Malicious code in fsevents (npm)

- Risk: 57.0 Critical (coverage 0.5)
- Why it matters: fsevents@1.2.9 is flagged as malicious by two independent scanners (grype GHSA-xv2f-5jw4-v95m and osv-scanner MAL-2023-462) and declares a lifecycle install script, so the malicious code would run at npm install time. It is the only Critical finding in the build.
- Reachability: present
- Confidence: medium (Two scanners agree on maliciousness and the install script is recorded, but the package is only present transitively (forever > forever-monitor > chokidar) and is not imported by application code; the script body was not inspected.)
- Evidence: E-0305, E-0306, E-0303, E-1287

## F-002 underscore@1.9.1: Arbitrary Code Execution in underscore

- Risk: 57.24 Medium (coverage 1.0)
- Why it matters: underscore@1.9.1 is a direct runtime dependency with CVSS 9.8 arbitrary code execution via the template function (CVE-2021-23358), required in config/config.js and served by an HTTP/HTTPS listener, so the vulnerable code is on a reachable runtime path; fixed in 1.12.1.
- Reachability: imported
- Confidence: high (All three scanners agree, the require() call site and the listening server are recorded, and every scoring factor is known (weight coverage 1.0).)
- Evidence: E-1214, E-1215, E-1216, E-1217, E-1209, E-1314, E-1315, E-1303, E-1304, E-1305

## F-020 node@12-alpine: base image is not pinned by digest

- Risk: 45.0 Medium (coverage 0.3)
- Why it matters: The Dockerfile base image node:12-alpine is referenced by mutable tag with no digest pin, so the base image content can change between builds; this is a duplicate of F-021 (same rule, same file).
- Reachability: unknown
- Confidence: high (The FROM line is recorded verbatim; reachability of the image is not modelled.)
- Evidence: E-1279

## F-081 actions/checkout@v2: action is referenced by tag or branch, not a full commit SHA

- Risk: 35.0 Low (coverage 0.3)
- Why it matters: actions/checkout@v2 is referenced by mutable tag rather than a full commit SHA, so a retagged or compromised action would execute in CI.
- Reachability: unknown
- Confidence: high (Both the guardian rule and zizmor report the unpinned reference at the same workflow line.)
- Evidence: E-1265, E-1266

## F-267 grunt-if@0.2.0: resolved from 'github.com', not registry.npmjs.org (mutable branch ref)

- Risk: 24.0 Low (coverage 0.5)
- Why it matters: grunt-if is resolved from the mutable git branch tarball https://github.com/binarymist/grunt-if/tarball/master rather than a registry version, so its content can change without a version change and builds are not reproducible.
- Reachability: dev only
- Confidence: medium (The lockfile resolved URL is recorded directly, but the package is a dev-only dependency and its use in Gruntfile.js could not be read by this agent.)
- Evidence: E-1288, E-1289

