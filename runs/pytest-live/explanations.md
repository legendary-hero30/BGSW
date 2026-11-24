# AI explanations: runs/pytest-live

Generator: **language model** (deepinfra:deepseek-ai/DeepSeek-V4.1-Flash-1017). Each explanation passed the deterministic gate; rejected ones are listed, never shown as explanations.

## F-001 fsevents@1.2.9: Malicious code in fsevents (npm)

- Risk: 57.0 Critical (coverage 0.5)
- Why it matters: osv-scanner reports MAL-2023-462, a malicious-code advisory, on fsevents@1.2.9; grype independently reports GHSA-xv2f-5jw4-v95m for the same package. Malicious-code packages can run attacker-chosen code at install or import time. It arrives transitively via forever@2.0.0 > forever-monitor@2.0.0 > chokidar@2.1.8, and the lockfile entry has hasInstallScript true. Both scanners give fix 1.2.11.
- Reachability: present
- Confidence: medium (Two scanners agree on package and version; path and install-script flag are in evidence. Not high: advisory text unread, install script not inspectable, score rests on 0.5 weight coverage with cvss and epss/kev unknown.)
- Evidence: E-0305, E-0306, E-0303, E-1288

## F-031 node@12-alpine: base image OS alpine 3.15.4 is end-of-service-life (no more security updates)

- Risk: 50.0 Medium (coverage 0.15)
- Why it matters: The container base image node:12-alpine is built on alpine 3.15.4, which trivy reports as end-of-service-life, meaning no further security updates are published for its OS packages. Every OS-level vulnerability in that image therefore has no upstream fix path, and the image scan separately reported 11 critical and 74 high package matches. This risk is independent of the npm dependency CVEs because it lives in the base image layer.
- Reachability: unknown
- Confidence: medium (The EOSL determination comes directly from trivy image metadata. Reachability and provenance are unknown and the score rests on only 0.15 weight coverage, so the numeric score understates the structural problem; the EOSL fact itself is solid.)
- Evidence: E-1281

## F-338 grunt-if@0.2.0: resolved from 'github.com', not registry.npmjs.org (mutable branch ref)

- Risk: 24.0 Low (coverage 0.5)
- Why it matters: grunt-if@0.2.0 is a direct devDependency whose lockfile entry resolves to https://github.com/binarymist/grunt-if/tarball/master, a mutable branch ref rather than an immutable commit SHA. The tarball behind that URL can change without any package-lock.json change, so reviewed and installed artifacts can diverge silently. As a build-time dependency, substituted content would run in CI or on a developer machine.
- Reachability: dev_only_unused
- Confidence: high (The resolved URL is recorded verbatim in lockfile evidence and the package is a direct dependency in the graph. The engine scores it Low (24.0) because reachability is dev_only_unused and cvss/epss are unknown, but the mutable-reference fact is directly observed.)
- Evidence: E-1289, E-1290

