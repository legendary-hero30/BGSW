# AI explanations: runs/cr0hn__vulnerable-node-20261123T132127Z

Generator: **language model** (deepinfra:deepseek-ai/DeepSeek-V4.1-Flash-1017). Each explanation passed the deterministic gate; rejected ones are listed, never shown as explanations.

## F-001 targets/dynamic/cr0hn__vulnerable-node-20261123T132127Z/mocks/imds/Dockerfile: Image user should not be 'root'

- Risk: 50.0 Medium (coverage 0.15)
- Path: n/a
- Why it matters: The mock IMDS container image runs as root, so any process compromise inside it gains full container privileges against a service that emulates cloud instance metadata.
- Reachability: Reachability is unknown: the scanner recorded no reachability signal for this configuration finding.
- Confidence: medium (Trivy config rule DS-0002 is a deterministic hit on the Dockerfile, but no CVSS, EPSS, or reachability data exists to refine impact.)
- Evidence: E-0052

## F-002 targets/dynamic/cr0hn__vulnerable-node-20261123T132127Z/mocks/vault/Dockerfile: Image user should not be 'root'

- Risk: 50.0 Medium (coverage 0.15)
- Path: n/a
- Why it matters: The mock vault container image runs as root, giving any compromise of that secrets-emulating service full container privileges.
- Reachability: Reachability is unknown: the scanner recorded no reachability signal for this configuration finding.
- Confidence: medium (Trivy config rule DS-0002 is a deterministic hit on the Dockerfile, but no CVSS, EPSS, or reachability data exists to refine impact.)
- Evidence: E-0054

## F-003 targets/dynamic/cr0hn__vulnerable-node-20261123T132127Z/Dockerfile: No HEALTHCHECK defined

- Risk: 50.0 Medium (coverage 0.15)
- Path: n/a
- Why it matters: The application Dockerfile defines no HEALTHCHECK, so orchestrators cannot detect a hung or unhealthy container and route traffic to it.
- Reachability: Reachability is unknown: the scanner recorded no reachability signal for this configuration finding.
- Confidence: medium (Trivy rule DS-0026 is a deterministic hit, but the finding is rated low severity and lacks CVSS/EPSS/reachability context.)
- Evidence: E-0049

## F-004 targets/dynamic/cr0hn__vulnerable-node-20261123T132127Z/Dockerfile: Non-numeric user-id may not be resolvable by host system

- Risk: 50.0 Medium (coverage 0.15)
- Path: n/a
- Why it matters: A non-numeric USER in the Dockerfile may not resolve on the host, potentially causing the container to run with unintended or root-equivalent identity.
- Reachability: Reachability is unknown: the scanner recorded no reachability signal for this configuration finding.
- Confidence: medium (Hadolint rule DL3066 is a deterministic hit at Dockerfile line 21, but the finding is low severity with no exploitability data.)
- Evidence: E-0051

## F-005 targets/dynamic/cr0hn__vulnerable-node-20261123T132127Z/mocks/imds/Dockerfile: No HEALTHCHECK defined

- Risk: 50.0 Medium (coverage 0.15)
- Path: n/a
- Why it matters: The mock IMDS Dockerfile defines no HEALTHCHECK, so a failed metadata-emulation service may go undetected while still receiving traffic.
- Reachability: Reachability is unknown: the scanner recorded no reachability signal for this configuration finding.
- Confidence: medium (Trivy rule DS-0026 is a deterministic hit, but the finding is low severity and lacks CVSS/EPSS/reachability context.)
- Evidence: E-0053

## F-006 targets/dynamic/cr0hn__vulnerable-node-20261123T132127Z/mocks/vault/Dockerfile: No HEALTHCHECK defined

- Risk: 50.0 Medium (coverage 0.15)
- Path: n/a
- Why it matters: The mock vault Dockerfile defines no HEALTHCHECK, so a failed secrets-emulation service may go undetected while still receiving traffic.
- Reachability: Reachability is unknown: the scanner recorded no reachability signal for this configuration finding.
- Confidence: medium (Trivy rule DS-0026 is a deterministic hit, but the finding is low severity and lacks CVSS/EPSS/reachability context.)
- Evidence: E-0055

## F-007 node@22-slim: base image is not pinned by digest

- Risk: 45.0 Medium (coverage 0.3)
- Path: n/a
- Why it matters: The base image node:22-slim is referenced by tag rather than digest, so builds can silently pull different, unverified image content over time.
- Reachability: Reachability is unknown: the scanner recorded no reachability signal for this image-provenance finding.
- Confidence: high (The unpinned FROM line is directly visible in the Dockerfile at line 2 and confirmed by guardian-rules GR-IMG-001.)
- Evidence: E-0050

## F-008 morgan@1.12.0: morgan vulnerable to Log Injection via unescaped double quote in quoted log fields

- Risk: 42.98 Medium (coverage 1.0)
- Path: vulnerable-nodejs@2.1.0 > morgan@1.12.0
- Why it matters: morgan 1.12.0 is vulnerable to log injection via an unescaped double quote in quoted log fields, allowing forged log entries that can mislead monitoring and audit trails.
- Reachability: Reachability is imported: server.js line 9 requires morgan, and the dependency graph records morgan@1.12.0 as an installed dependency.
- Confidence: high (Three independent scanners (grype, osv-scanner, trivy) agree on the advisory, the import is confirmed in source, and a fixed version 1.12.1 is published.)
- Evidence: E-0019, E-0020, E-0021, E-0022, E-0023, E-0056, E-0057

## F-009 proxy-addr@2.0.7: proxy-addr vulnerable to IP spoofing via IPv4-mapped IPv6 trust subnet

- Risk: 40.85 Medium (coverage 1.0)
- Path: vulnerable-nodejs@2.1.0 > express@4.22.2 > proxy-addr@2.0.7
- Why it matters: proxy-addr 2.0.7 is vulnerable to IP spoofing via an IPv4-mapped IPv6 trust subnet, which can let attackers bypass IP-based trust and rate-limit controls in Express.
- Reachability: Reachability is present_only: the package is installed transitively through express@4.22.2 but no direct import of it was observed in the scanned source.
- Confidence: high (Three scanners agree on the advisory, the transitive path is confirmed by the dependency graph, and a fixed version 2.0.8 exists; only the reachability signal is weaker.)
- Evidence: E-0024, E-0025, E-0026, E-0027, E-0028

## F-010 brace-expansion@2.1.4: brace-expansion: DoS via uncontrolled recursion in parseCommaParts causing stack exhaustion

- Risk: 36.1 Low (coverage 1.0)
- Path: vulnerable-nodejs@2.1.0 > ejs@3.1.10 > jake@10.9.4 > filelist@1.0.6 > minimatch@5.1.9 > brace-expansion@2.1.4
- Why it matters: brace-expansion 2.1.4 can be driven into uncontrolled recursion in parseCommaParts, causing stack exhaustion and denial of service.
- Reachability: Reachability is present_only: the package is installed deep in the transitive chain via ejs@3.1.10, jake, filelist and minimatch, with no direct import observed.
- Confidence: high (Three scanners agree on the advisory and the full transitive path is confirmed by the dependency graph, though the deep transitive position lowers practical exposure.)
- Evidence: E-0006, E-0007, E-0008, E-0009, E-0010

## Rejected by the gate

- F-008 attempt 1: mentions vulnerable-nodejs@2.1.0., which is not on F-008's path
