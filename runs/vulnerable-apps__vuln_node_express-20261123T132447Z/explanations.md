# AI explanations: runs/vulnerable-apps__vuln_node_express-20261123T132447Z

Generator: **language model** (deepinfra:deepseek-ai/DeepSeek-V4.1-Flash-1017). Each explanation passed the deterministic gate; rejected ones are listed, never shown as explanations.

## F-001 targets/dynamic/vulnerable-apps__vuln_node_express-20261123T132447Z/Dockerfile: Image user should not be 'root'

- Risk: 50.0 Medium (coverage 0.15)
- Path: n/a
- Why it matters: The container image is configured to run as root, so any process compromise inside the container gains root privileges and eases container escape or lateral movement.
- Reachability: unknown
- Confidence: medium (Trivy config scan (DS-0002) directly reports the root-user misconfiguration, but no CVSS/EPSS/reachability factors were available so the risk score rests only on exposure.)
- Evidence: E-0321

## F-002 node@14.16.1-buster: final stage runs as root (no non-root USER)

- Risk: 50.0 Medium (coverage 0.15)
- Path: n/a
- Why it matters: The final stage of the image has no non-root USER directive, so the Node.js application runs with root privileges at runtime.
- Reachability: unknown
- Confidence: medium (Guardian rule GR-IMG-003 points at the FROM line of the Dockerfile, but the finding carries no CVSS/EPSS/reachability data and the rule evidence is a single file location.)
- Evidence: E-0324

## F-003 targets/dynamic/vulnerable-apps__vuln_node_express-20261123T132447Z/Dockerfile: No HEALTHCHECK defined

- Risk: 50.0 Medium (coverage 0.15)
- Path: n/a
- Why it matters: Without a HEALTHCHECK the orchestrator cannot detect a hung or compromised container, delaying restarts and incident response.
- Reachability: unknown
- Confidence: medium (Trivy config scan (DS-0026) reports the missing HEALTHCHECK, but this is a low-severity hygiene issue with no exploitability factors recorded.)
- Evidence: E-0322

## F-004 express@4.16.4: Express.js Open Redirect in malformed URLs

- Risk: 45.46 Medium (coverage 1.0)
- Path: nodeexpressvulny@0.0.0 > express@4.16.4
- Why it matters: Express 4.16.4 is vulnerable to an open redirect in malformed URLs (CVE-2024-29041 / GHSA-rv95-896h-c2vc), which can be abused for phishing or OAuth token leakage from a network-exposed service.
- Reachability: imported
- Confidence: high (Three independent scanners (grype, osv-scanner, trivy) agree on the advisory, the dependency graph confirms a direct install path, and guardian-rules shows express is required in app.js with port 3000 exposed.)
- Evidence: E-0066, E-0067, E-0068, E-0069, E-0070, E-0325, E-0326, E-0327

## F-005 node@14.16.1-buster: base image is not pinned by digest

- Risk: 45.0 Medium (coverage 0.3)
- Path: n/a
- Why it matters: The base image node:14.16.1-buster is referenced by tag rather than digest, so builds can silently pull different, potentially tampered content.
- Reachability: unknown
- Confidence: medium (Guardian rule GR-IMG-001 flags the unpinned FROM line and a provenance factor of 40.0 was recorded, but no CVSS/EPSS/reachability data exists for this supply-chain hygiene finding.)
- Evidence: E-0323

## F-006 minimist@0.0.8: Prototype Pollution in minimist

- Risk: 43.82 Medium (coverage 1.0)
- Path: nodeexpressvulny@0.0.0 > sqlite@3.0.3 > sqlite3@4.1.0 > node-pre-gyp@0.11.0 > mkdirp@0.5.1 > minimist@0.0.8
- Why it matters: minimist 0.0.8 is vulnerable to prototype pollution (CVE-2021-44906 / GHSA-xvch-5gv4-984h, CVSS 9.8), which can corrupt object prototypes and lead to logic bypass or RCE in dependent code.
- Reachability: present_only
- Confidence: high (grype, osv-scanner and trivy all report the advisory and the dependency graph gives a single install path, but the package is only present in the tree (not shown as imported by application code).)
- Evidence: E-0138, E-0139, E-0140, E-0136, E-0141

## F-007 minimist@1.2.0: Prototype Pollution in minimist

- Risk: 43.82 Medium (coverage 1.0)
- Path: nodeexpressvulny@0.0.0 > sqlite@3.0.3 > sqlite3@4.1.0 > node-pre-gyp@0.11.0 > rc@1.2.8 > minimist@1.2.0
- Why it matters: minimist 1.2.0 is also affected by prototype pollution (CVE-2021-44906 / GHSA-xvch-5gv4-984h, CVSS 9.8), giving a second exploitable copy of the same flaw in the dependency tree.
- Reachability: present_only
- Confidence: high (All three scanners agree on the advisory and the dependency graph shows one install path via rc@1.2.8, but reachability is limited to presence in the tree.)
- Evidence: E-0146, E-0147, E-0148, E-0145, E-0141

## F-008 json-schema@0.2.3: json-schema is vulnerable to Prototype Pollution

- Risk: 43.67 Medium (coverage 1.0)
- Path: nodeexpressvulny@0.0.0 > sqlite@3.0.3 > sqlite3@4.1.0 > request@2.88.0 > http-signature@1.2.0 > jsprim@1.4.1 > json-schema@0.2.3
- Why it matters: json-schema 0.2.3 is vulnerable to prototype pollution (CVE-2021-3918 / GHSA-896r-f27r-55mw, CVSS 9.8), which can be triggered through schema validation of attacker-controlled input.
- Reachability: present_only
- Confidence: high (grype, osv-scanner and trivy concur on the advisory and the dependency graph confirms a single install path, but the package is only present rather than shown as imported.)
- Evidence: E-0089, E-0090, E-0091, E-0092, E-0093

## F-009 ini@1.3.5: ini before 1.3.6 vulnerable to Prototype Pollution via ini.parse

- Risk: 43.63 Medium (coverage 1.0)
- Path: nodeexpressvulny@0.0.0 > sqlite@3.0.3 > sqlite3@4.1.0 > node-pre-gyp@0.11.0 > rc@1.2.8 > ini@1.3.5
- Why it matters: ini 1.3.5 is vulnerable to prototype pollution via ini.parse (CVE-2020-7788 / GHSA-qqgx-2p2h-9c37), which can be exploited by parsing a malicious INI file.
- Reachability: present_only
- Confidence: high (Three scanners agree on the advisory and the dependency graph shows one install path via rc@1.2.8, but reachability is limited to presence in the tree.)
- Evidence: E-0084, E-0085, E-0086, E-0087, E-0088

## F-010 lodash@4.17.15: lodash vulnerable to Code Injection via `_.template` imports key names

- Risk: 43.47 Medium (coverage 1.0)
- Path: nodeexpressvulny@0.0.0 > pug@2.0.4 > pug-code-gen@2.0.2 > constantinople@3.1.2 > babel-types@6.26.0 > lodash@4.17.15
- Why it matters: lodash 4.17.15 is vulnerable to code injection via _.template key names (CVE-2026-4800 / GHSA-r5fr-rjxr-66jc, CVSS 9.8), potentially allowing arbitrary code execution when templates process untrusted input.
- Reachability: present_only
- Confidence: high (grype, osv-scanner and trivy all report the advisory and the dependency graph gives a single install path via pug, but the package is only present rather than shown as imported.)
- Evidence: E-0111, E-0112, E-0113, E-0097, E-0114

