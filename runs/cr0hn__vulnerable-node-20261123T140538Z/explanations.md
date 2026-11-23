# AI explanations: runs/cr0hn__vulnerable-node-20261123T140538Z

Generator: **language model** (deepinfra:deepseek-ai/DeepSeek-V4.1-Flash-1017). Each explanation passed the deterministic gate; rejected ones are listed, never shown as explanations.

## F-001 targets/dynamic/cr0hn__vulnerable-node-20261123T140538Z/mocks/imds/Dockerfile: Image user should not be 'root'

- Risk: 50.0 Medium (coverage 0.15)
- Path: n/a
- Why it matters: The mock IMDS container image runs as root, so any process compromise inside it gains full container privileges and eases escape or lateral movement against the simulated metadata service.
- Reachability: unknown
- Confidence: medium (Trivy config scan reports DS-0002 directly on the Dockerfile, but no reachability analysis was computed for this OCI misconfiguration.)
- Evidence: E-0052

## F-002 targets/dynamic/cr0hn__vulnerable-node-20261123T140538Z/mocks/vault/Dockerfile: Image user should not be 'root'

- Risk: 50.0 Medium (coverage 0.15)
- Path: n/a
- Why it matters: The mock vault container image runs as root, giving any compromised process full container privileges against a service that simulates secret storage.
- Reachability: unknown
- Confidence: medium (Trivy config scan reports DS-0002 directly on the Dockerfile, but no reachability analysis was computed for this OCI misconfiguration.)
- Evidence: E-0054

## F-003 targets/dynamic/cr0hn__vulnerable-node-20261123T140538Z/Dockerfile: No HEALTHCHECK defined

- Risk: 50.0 Medium (coverage 0.15)
- Path: n/a
- Why it matters: Without a HEALTHCHECK the orchestrator cannot detect a wedged application container, so failures go unnoticed and traffic keeps hitting an unhealthy instance.
- Reachability: unknown
- Confidence: medium (Trivy config scan reports DS-0026 on the Dockerfile; severity is low and no reachability was computed.)
- Evidence: E-0049

## F-004 targets/dynamic/cr0hn__vulnerable-node-20261123T140538Z/Dockerfile: Non-numeric user-id may not be resolvable by host system

- Risk: 50.0 Medium (coverage 0.15)
- Path: n/a
- Why it matters: A non-numeric USER in the image may not resolve on the host, which can cause the container to run with unintended or fallback privileges.
- Reachability: unknown
- Confidence: medium (Hadolint reports DL3066 at Dockerfile line 21; severity is low and no reachability was computed.)
- Evidence: E-0051

## F-005 targets/dynamic/cr0hn__vulnerable-node-20261123T140538Z/mocks/imds/Dockerfile: No HEALTHCHECK defined

- Risk: 50.0 Medium (coverage 0.15)
- Path: n/a
- Why it matters: The mock IMDS image lacks a HEALTHCHECK, so a hung metadata mock is not detected and dependent tests or services may silently fail.
- Reachability: unknown
- Confidence: medium (Trivy config scan reports DS-0026 on the Dockerfile; severity is low and no reachability was computed.)
- Evidence: E-0053

## F-006 targets/dynamic/cr0hn__vulnerable-node-20261123T140538Z/mocks/vault/Dockerfile: No HEALTHCHECK defined

- Risk: 50.0 Medium (coverage 0.15)
- Path: n/a
- Why it matters: The mock vault image lacks a HEALTHCHECK, so an unhealthy secret-store mock is not detected by the orchestrator.
- Reachability: unknown
- Confidence: medium (Trivy config scan reports DS-0026 on the Dockerfile; severity is low and no reachability was computed.)
- Evidence: E-0055

## F-007 node@22-slim: base image is not pinned by digest

- Risk: 45.0 Medium (coverage 0.3)
- Path: n/a
- Why it matters: The base image node:22-slim is referenced by tag rather than digest, so a rebuilt or tampered upstream tag silently changes what code runs in the container.
- Reachability: unknown
- Confidence: medium (Guardian rule GR-IMG-001 flags the FROM line directly, but no reachability analysis was computed for this image provenance finding.)
- Evidence: E-0050

## F-008 morgan@1.12.0: morgan vulnerable to Log Injection via unescaped double quote in quoted log fields

- Risk: 42.98 Medium (coverage 1.0)
- Path: vulnerable-nodejs@2.1.0 > morgan@1.12.0
- Why it matters: morgan 1.12.0 is vulnerable to log injection via an unescaped double quote in quoted log fields, letting attacker-controlled input forge or corrupt log records.
- Reachability: imported
- Confidence: high (Three scanners agree on the advisory and the fix version, and the dependency graph plus a require() call in server.js confirm the package is imported by the application.)
- Evidence: E-0019, E-0020, E-0021, E-0022, E-0023, E-0056, E-0057

## F-009 proxy-addr@2.0.7: proxy-addr vulnerable to IP spoofing via IPv4-mapped IPv6 trust subnet

- Risk: 40.85 Medium (coverage 1.0)
- Path: vulnerable-nodejs@2.1.0 > express@4.22.2 > proxy-addr@2.0.7
- Why it matters: proxy-addr 2.0.7 mishandles IPv4-mapped IPv6 addresses in the trust subnet, allowing a client to spoof its source IP and defeat IP-based trust decisions such as rate limiting or access control.
- Reachability: present
- Confidence: high (Three scanners agree on the advisory and fix version and the dependency graph places it under express, but it is only present in the tree with no import or call site evidenced.)
- Evidence: E-0024, E-0025, E-0026, E-0027, E-0028

## F-010 brace-expansion@2.1.4: brace-expansion: DoS via uncontrolled recursion in parseCommaParts causing stack exhaustion

- Risk: 36.1 Low (coverage 1.0)
- Path: vulnerable-nodejs@2.1.0 > ejs@3.1.10 > jake@10.9.4 > filelist@1.0.6 > minimatch@5.1.9 > brace-expansion@2.1.4
- Why it matters: brace-expansion 2.1.4 can be driven into uncontrolled recursion by crafted brace patterns, exhausting the stack and crashing the process that parses them.
- Reachability: present
- Confidence: high (Three scanners agree on the advisory and fix versions and the dependency graph shows a full path from ejs, but it is only present in the tree with no import or call site evidenced.)
- Evidence: E-0006, E-0007, E-0008, E-0009, E-0010

