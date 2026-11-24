# AI explanations: runs/TestMote__nodegoat-20261124T112422Z

Generator: **language model** (deepinfra:deepseek-ai/DeepSeek-V4.1-Flash-1017). Each explanation passed the deterministic gate; rejected ones are listed, never shown as explanations.

## F-001 fsevents@1.2.9: Malicious code in fsevents (npm)

- Risk: 57.0 Critical (coverage 0.5)
- Why it matters: fsevents@1.2.9 carries a malicious-package advisory (MAL-2023-462 / GHSA-xv2f-5jw4-v95m) from two independent scanners, grype (E-0305) and osv-scanner (E-0306), so the malicious attribution is well supported. Exposure is conditional: package-lock.json 3286-3298 shows a sha512 integrity hash, "optional": true and "os": ["darwin"], so on the Linux container it is not installed at all.
- Reachability: present
- Confidence: medium (Two scanners agree on the malicious advisory (E-0305, E-0306) and the path is confirmed (E-0303), but only 50% of risk factors are known and the lockfile shows the package is optional and darwin-only, so exposure is conditional.)
- Evidence: E-0305, E-0306, E-0303, E-1292

## F-011 underscore@1.9.1: Arbitrary Code Execution in underscore

- Risk: 57.24 Medium (coverage 1.0)
- Why it matters: underscore@1.9.1 is a DIRECT runtime dependency reachable from network-facing code; CVE-2021-23358 (CVSS 9.8) is arbitrary code execution via the template function, fixed in 1.12.1. This is the highest-exposure application-level vulnerability in the build.
- Reachability: The computed reachability is imported: underscore@1.9.1 is a direct dependency required in config/config.js and the app listens on a network port (server.js), giving runtime_network exposure.
- Confidence: high (Three scanners agree, the score rests on 100% of risk factors, and a fix version (1.12.1) is published.)
- Evidence: E-1214, E-1215, E-1216, E-1217, E-1474, E-1463

## F-031 node@12-alpine: base image OS alpine 3.15.4 is end-of-service-life (no more security updates)

- Risk: 50.0 Medium (coverage 0.15)
- Why it matters: The node:12-alpine base image runs alpine 3.15.4, which is end-of-service-life, so no further security updates will be published for its OS packages; this is the root cause behind the 70 vulnerable_image_package findings.
- Reachability: The computed reachability is unknown: this is a base-image lifecycle finding, not a code path.
- Confidence: low (Only one scanner (trivy) reported it and the score rests on only 15% of risk factors.)
- Evidence: E-1285

## F-089 bson@1.0.9: Deserialization of Untrusted Data in bson

- Risk: 43.36 Medium (coverage 1.0)
- Why it matters: bson@1.0.9 has CVE-2020-7610 (CVSS 9.8), deserialization of untrusted data leading to code injection or excessive CPU load, fixed in 1.1.4; it sits on the runtime path of a database-backed application.
- Reachability: The computed reachability is present: bson@1.0.9 is present in the graph via owasp-nodejs-goat@1.3.0 > mongodb@2.2.36 > mongodb-core@2.1.20 > bson@1.0.9, but it is not directly imported by application code.
- Confidence: high (Three scanners agree, the score rests on 100% of risk factors, and a fix version (1.1.4) is published.)
- Evidence: E-0157, E-0158, E-0159, E-0155, E-0160

## F-161 handlebars@4.0.5: Prototype Pollution in handlebars

- Risk: 33.81 Low (coverage 1.0)
- Why it matters: CVE-2019-19919 (CVSS 9.8) is prototype pollution leading to RCE, fixed in 4.3.0, but the package is only on the dev/test toolchain path, so real-world exposure is lower than the critical severity suggests.
- Reachability: The computed reachability is dev: handlebars@4.0.5 is reached only through grunt-if@0.2.0 > grunt-contrib-nodeunit@1.0.0 > nodeunit@0.9.5 > tap@7.1.2 > nyc@7.1.0 > istanbul-reports@1.0.0-alpha.8, a build/test path.
- Confidence: high (Three scanners agree and the score rests on 100% of risk factors; the low score reflects dev-only reachability, not weak evidence.)
- Evidence: E-0340, E-0341, E-0342, E-0343, E-0344

## F-339 grunt-if@0.2.0: resolved from 'github.com', not registry.npmjs.org (mutable branch ref)

- Risk: 24.0 Low (coverage 0.5)
- Why it matters: grunt-if@0.2.0 is resolved from a mutable GitHub branch tarball rather than the npm registry, so the installed bytes can change without any lockfile diff; this is a supply-chain integrity gap that no CVE database covers.
- Reachability: The computed reachability is dev: grunt-if@0.2.0 is a direct dev dependency that is not used by application code.
- Confidence: low (A deterministic rule reported it and no CVE database is involved; the score rests on only 50% of risk factors.)
- Evidence: E-1293, E-1294

