# AI explanations: runs/demo

Generator: **language model** (deepinfra:deepseek-ai/DeepSeek-V4.1-Flash-1017). Each explanation passed the deterministic gate; rejected ones are listed, never shown as explanations.

## F-001 fsevents@1.2.9: Malicious code in fsevents (npm)

- Risk: 57.0 Critical (coverage 0.5)
- Path: owasp-nodejs-goat@1.3.0 > forever@2.0.0 > forever-monitor@2.0.0 > chokidar@2.1.8 > fsevents@1.2.9
- Why it matters: fsevents@1.2.9 is flagged by both grype (GHSA-xv2f-5jw4-v95m) and osv-scanner (MAL-2023-462) as containing malicious code, and the finding carries a confirmed_malicious override, so this is a supply-chain compromise rather than a mere vulnerability.
- Reachability: present
- Confidence: high (Two independent scanners agree on malicious code, and the graph shows a concrete install path with hasInstallScript true, though no runtime call path was proven (reachability factor is present_only).)
- Evidence: E-0305, E-0306, E-0303, E-1288

## F-002 libcrypto1.1@1.1.1n-r0 in node:12-alpine: openssl: Possible DoS translating ASN.1 object identifiers

- Risk: 64.73 Medium (coverage 0.65)
- Path: docker.io/library/node:12-alpine@sha256:4517380049fc3c9aacceae7764fcf3500354b0ac8a47e4afb35b5bbeb75b9498 > libcrypto1.1@1.1.1n-r0
- Why it matters: libcrypto1.1@1.1.1n-r0 in the node:12-alpine base image is affected by CVE-2023-2650, an OpenSSL DoS when translating ASN.1 object identifiers, with a high EPSS of 0.75358.
- Reachability: unknown
- Confidence: medium (grype and trivy both report the CVE and agree on the 1.1.1u-r0 fix, but no call-graph evidence ties the vulnerable OpenSSL code to application usage, so reachability is unresolved.)
- Evidence: E-1302, E-1369, E-1370, E-1371

## F-003 libssl1.1@1.1.1n-r0 in node:12-alpine: openssl: Possible DoS translating ASN.1 object identifiers

- Risk: 64.73 Medium (coverage 0.65)
- Path: docker.io/library/node:12-alpine@sha256:4517380049fc3c9aacceae7764fcf3500354b0ac8a47e4afb35b5bbeb75b9498 > libssl1.1@1.1.1n-r0
- Why it matters: libssl1.1@1.1.1n-r0 in the node:12-alpine base image carries the same CVE-2023-2650 OpenSSL DoS, so the vulnerable OpenSSL code is present in both the crypto and TLS libraries of the runtime image.
- Reachability: unknown
- Confidence: medium (grype and trivy agree on CVE-2023-2650 with fix 1.1.1u-r0 and the EPSS advisory is shared with F-002, but reachability is recorded as unknown and no call-path evidence for OBJ_obj2txt() or the affected OpenSSL subsystems was produced.)
- Evidence: E-1302, E-1395, E-1396, E-1371

## F-004 libcrypto1.1@1.1.1n-r0 in node:12-alpine: openssl: X.400 address type confusion in X.509 GeneralName

- Risk: 64.69 Medium (coverage 0.65)
- Path: docker.io/library/node:12-alpine@sha256:4517380049fc3c9aacceae7764fcf3500354b0ac8a47e4afb35b5bbeb75b9498 > libcrypto1.1@1.1.1n-r0
- Why it matters: libcrypto1.1@1.1.1n-r0 is affected by CVE-2023-0286, an X.400 address type confusion in X.509 GeneralName rated high severity with CVSS 7.4 and EPSS 0.61757, which can lead to memory disclosure or crash when parsing crafted certificates.
- Reachability: unknown
- Confidence: medium (grype and trivy both report CVE-2023-0286 with fix 1.1.1t-r0 and the EPSS advisory corroborates exploitation likelihood, but reachability is an unknown factor in the risk model and no evidence shows the image actually parses untrusted X.509 certificates.)
- Evidence: E-1302, E-1360, E-1361, E-1362

## F-005 libssl1.1@1.1.1n-r0 in node:12-alpine: openssl: X.400 address type confusion in X.509 GeneralName

- Risk: 64.69 Medium (coverage 0.65)
- Path: docker.io/library/node:12-alpine@sha256:4517380049fc3c9aacceae7764fcf3500354b0ac8a47e4afb35b5bbeb75b9498 > libssl1.1@1.1.1n-r0
- Why it matters: libssl1.1@1.1.1n-r0 carries the same CVE-2023-0286 X.400 type confusion, so the high-severity OpenSSL parsing flaw is present in the TLS library of the node:12-alpine image.
- Reachability: unknown
- Confidence: medium (grype and trivy agree on CVE-2023-0286 with fix 1.1.1t-r0 and share the EPSS advisory with F-004, but reachability is recorded as unknown and no certificate-parsing call path was evidenced.)
- Evidence: E-1302, E-1389, E-1390, E-1362

## F-006 zlib@1.2.12-r0 in node:12-alpine: zlib: heap-based buffer over-read and overflow in inflate() in inflate.c via a large gzip header extra field

- Risk: 62.69 Medium (coverage 0.65)
- Path: docker.io/library/node:12-alpine@sha256:4517380049fc3c9aacceae7764fcf3500354b0ac8a47e4afb35b5bbeb75b9498 > zlib@1.2.12-r0
- Why it matters: zlib@1.2.12-r0 in the node:12-alpine image is affected by CVE-2022-37434, a heap-based buffer over-read/overflow in inflate() with CVSS 9.8, which is a memory-safety issue in a library used pervasively for decompression.
- Reachability: unknown
- Confidence: medium (grype and trivy both report CVE-2022-37434 with fix 1.2.12-r2, but the advisory states only applications calling inflateGetHeader are affected and no evidence establishes that call path, so reachability remains an unknown factor in the risk model.)
- Evidence: E-1302, E-1454, E-1455, E-1456

## F-007 ip@1.1.5 in node:12-alpine: node-ip: Incomplete fix for CVE-2023-42282

- Risk: 59.32 Medium (coverage 0.65)
- Path: docker.io/library/node:12-alpine@sha256:4517380049fc3c9aacceae7764fcf3500354b0ac8a47e4afb35b5bbeb75b9498 > ip@1.1.5
- Why it matters: ip@1.1.5 in the node:12-alpine image is affected by CVE-2024-29415 / GHSA-2p57-rm9w-gvfp, an incomplete fix that still mis-categorizes private addresses as public, and no fixed version is listed.
- Reachability: unknown
- Confidence: medium (grype and trivy agree on the package and advisory, but fixed_in is empty so no remediation version is available, and reachability is unknown.)
- Evidence: E-1302, E-1345, E-1346, E-1347

## F-008 minimist@1.2.5 in node:12-alpine: minimist: prototype pollution

- Risk: 58.18 Medium (coverage 0.65)
- Path: docker.io/library/node:12-alpine@sha256:4517380049fc3c9aacceae7764fcf3500354b0ac8a47e4afb35b5bbeb75b9498 > minimist@1.2.5
- Why it matters: minimist@1.2.5 in the node:12-alpine image is affected by CVE-2021-44906 / GHSA-xvch-5gv4-984h prototype pollution (CVSS 9.8), which can corrupt object prototypes and alter application behaviour when untrusted arguments are parsed.
- Reachability: unknown
- Confidence: medium (grype and trivy agree on the advisory and on fix versions 1.2.6 (trivy also lists 0.2.4), but reachability is an unknown factor and no evidence shows the image passes untrusted input to minimist.)
- Evidence: E-1302, E-1411, E-1412, E-0743

## F-009 tough-cookie@2.4.3 in node:12-alpine: tough-cookie: prototype pollution in cookie memstore

- Risk: 57.58 Medium (coverage 0.65)
- Path: docker.io/library/node:12-alpine@sha256:4517380049fc3c9aacceae7764fcf3500354b0ac8a47e4afb35b5bbeb75b9498 > tough-cookie@2.4.3
- Why it matters: tough-cookie@2.4.3 in the node:12-alpine image is affected by CVE-2023-26136 / GHSA-72xf-g2v4-qvf3, prototype pollution in the cookie memstore, which can be abused to tamper with cookie handling logic.
- Reachability: unknown
- Confidence: medium (grype and trivy both report the advisory with a common fix version 4.1.3, but reachability is an unknown factor and no evidence shows the memstore is used with attacker-controlled cookie data.)
- Evidence: E-1302, E-1450, E-1451, E-1169

## F-010 ip@1.1.5 in node:12-alpine: nodejs-ip: arbitrary code execution via the isPublic() function

- Risk: 57.27 Medium (coverage 0.65)
- Path: docker.io/library/node:12-alpine@sha256:4517380049fc3c9aacceae7764fcf3500354b0ac8a47e4afb35b5bbeb75b9498 > ip@1.1.5
- Why it matters: ip@1.1.5 in the node:12-alpine image is affected by CVE-2023-42282 / GHSA-78xj-cgh5-2h22, where isPublic() misidentifies private addresses as public, which can enable SSRF and is described by trivy as arbitrary code execution via isPublic().
- Reachability: unknown
- Confidence: medium (grype and trivy both report the advisory with fix versions 1.1.9 (trivy also lists 2.0.1), but the finding is rated low severity by the scanners, reachability is an unknown factor, and no evidence shows isPublic() is called on untrusted input.)
- Evidence: E-1302, E-1342, E-1343, E-1344

## Rejected by the gate

- F-001 attempt 1: schema: ('confidence_reason',): String should have at most 300 characters
- F-001 attempt 3: mentions owasp-nodejs-goat@1.3.0., which is not on F-001's path
- F-002 attempt 3: schema: ('confidence_reason',): String should have at most 300 characters
- F-007 attempt 1: mentions CVE-2023-42282, which is not an advisory of F-007
- F-007 attempt 3: mentions CVE-2023-42282, which is not an advisory of F-007
