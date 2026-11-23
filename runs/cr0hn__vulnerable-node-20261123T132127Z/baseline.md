# Scanner-only baseline: cr0hn__vulnerable-node-20261123T132127Z @ d68f2a3c9277

Generated 2026-11-23T13:22:21+00:00. Scanners ran offline (empty network namespace).
Every value below comes from tool output or the cached EPSS and KEV feeds.
Findings are ranked by risk score v1 (PDF formula; unknown factors are left out and the
rest re-weighted, shown as coverage). Dependency counts cover the app's npm packages.

| Metric | Value |
|---|---|
| Findings | 26 total |
| Dependency findings | 7 (7 runtime, 0 dev-only) |
| Vulnerable packages | 5 |
| By type | {'misconfiguration': 6, 'untrusted_image': 1, 'vulnerable_direct': 1, 'vulnerable_transitive': 6, 'unpinned_ci': 12} |
| By severity | {'high': 9, 'low': 4, 'medium': 12, 'critical': 1} |
| In CISA KEV | 0 |
| Fix version available | 7 |
| Raw matches per tool | {'grype': 7, 'trivy': 7, 'osv-scanner': 7} |
| Advisory groups found by 1/2/3 tools | {'3_tools': 7} |
| Unmapped to graph | 0 |
| Image inspected | none |
| CI/Dockerfile rule hits | {'guardian-rules:GR-IMG-001': 1, 'guardian-rules:GR-CI-001': 2, 'hadolint:DL3066': 1, 'trivy:DS-0026': 3, 'trivy:DS-0002': 2, 'zizmor:artipacked': 7, 'zizmor:excessive-permissions': 1, 'zizmor:template-injection': 3, 'zizmor:unpinned-uses': 2} |
| Anomaly rule hits | {} |
| By risk level | {'Medium': 9, 'Low': 17} |
| Reachability | {'unknown': 19, 'imported': 1, 'present_only': 6} |
| Exposure | {'runtime_internal': 13, 'runtime_network': 1, 'build_or_dev': 12} |

| ID | Risk | Coverage | Type | Severity | CVSS | EPSS | KEV | Reach | Exposure | Provenance | Package | Dependency path | Fixed in | Tools | Evidence |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| F-001 | 50.0 Medium | 0.15 | misconfiguration | high |  |  | unknown | unknown | runtime_internal |  | targets/dynamic/cr0hn__vulnerable-node-20261123T132127Z/mocks/imds/Dockerfile@None |  | none | trivy | E-0052 |
| F-002 | 50.0 Medium | 0.15 | misconfiguration | high |  |  | unknown | unknown | runtime_internal |  | targets/dynamic/cr0hn__vulnerable-node-20261123T132127Z/mocks/vault/Dockerfile@None |  | none | trivy | E-0054 |
| F-003 | 50.0 Medium | 0.15 | misconfiguration | low |  |  | unknown | unknown | runtime_internal |  | targets/dynamic/cr0hn__vulnerable-node-20261123T132127Z/Dockerfile@None |  | none | trivy | E-0049 |
| F-004 | 50.0 Medium | 0.15 | misconfiguration | low |  |  | unknown | unknown | runtime_internal |  | targets/dynamic/cr0hn__vulnerable-node-20261123T132127Z/Dockerfile@None |  | none | hadolint | E-0051 |
| F-005 | 50.0 Medium | 0.15 | misconfiguration | low |  |  | unknown | unknown | runtime_internal |  | targets/dynamic/cr0hn__vulnerable-node-20261123T132127Z/mocks/imds/Dockerfile@None |  | none | trivy | E-0053 |
| F-006 | 50.0 Medium | 0.15 | misconfiguration | low |  |  | unknown | unknown | runtime_internal |  | targets/dynamic/cr0hn__vulnerable-node-20261123T132127Z/mocks/vault/Dockerfile@None |  | none | trivy | E-0055 |
| F-007 | 45.0 Medium | 0.3 | untrusted_image | medium |  |  | unknown | unknown | runtime_internal | 40.0 | node@22-slim |  | none | guardian-rules | E-0050 |
| F-008 | 42.98 Medium | 1.0 | vulnerable_direct | medium | 5.3 | 0.0041 | no | imported | runtime_network | 0.0 | morgan@1.12.0 | vulnerable-nodejs@2.1.0 > morgan@1.12.0 | grype: 1.12.1; osv-scanner: 1.12.1; trivy: 1.12.1 | grype, guardian-rules, osv-scanner, trivy | E-0019, E-0020, E-0021, E-0022, E-0023, E-0056, E-0057, E-0058, E-0059, E-0060, E-0061, E-0062, E-0063, E-0064, E-0065, E-0066, E-0067 |
| F-009 | 40.85 Medium | 1.0 | vulnerable_transitive | critical | 9.1 | 0.0026 | no | present_only | runtime_internal | 0.0 | proxy-addr@2.0.7 | vulnerable-nodejs@2.1.0 > express@4.22.2 > proxy-addr@2.0.7 | grype: 2.0.8; osv-scanner: 2.0.8; trivy: 2.0.8 | grype, osv-scanner, trivy | E-0024, E-0025, E-0026, E-0027, E-0028 |
| F-010 | 36.1 Low | 1.0 | vulnerable_transitive | high | 7.5 | 0.00491 | no | present_only | runtime_internal | 0.0 | brace-expansion@2.1.4 | vulnerable-nodejs@2.1.0 > ejs@3.1.10 > … > minimatch@5.1.9 > brace-expansion@2.1.4 | grype: 2.1.5; osv-scanner: 1.1.19, 2.1.5, 3.0.7, 5.0.10; trivy: 1.1.19, 2.1.5, 3.0.7, 5.0.10 | grype, osv-scanner, trivy | E-0006, E-0007, E-0008, E-0009, E-0010 |
| F-011 | 36.1 Low | 1.0 | vulnerable_transitive | high | 7.5 | 0.00491 | no | present_only | runtime_internal | 0.0 | brace-expansion@2.1.4 | vulnerable-nodejs@2.1.0 > ejs@3.1.10 > … > minimatch@5.1.9 > brace-expansion@2.1.4 | grype: 2.1.6; osv-scanner: 1.1.20, 2.1.6, 3.0.8, 5.0.11; trivy: 1.1.20, 2.1.6, 3.0.8, 5.0.11 | grype, osv-scanner, trivy | E-0015, E-0016, E-0017, E-0009, E-0018 |
| F-012 | 36.08 Low | 1.0 | vulnerable_transitive | high | 7.5 | 0.00388 | no | present_only | runtime_internal | 0.0 | body-parser@1.20.6 | vulnerable-nodejs@2.1.0 > express@4.22.2 > body-parser@1.20.6 | grype: 1.20.9; osv-scanner: 1.20.9, 2.4.0; trivy: 1.20.9, 2.4.0 | grype, osv-scanner, trivy | E-0001, E-0002, E-0003, E-0004, E-0005 |
| F-013 | 35.0 Low | 0.3 | unpinned_ci | high |  |  | unknown | unknown | build_or_dev | 50.0 | actions/checkout@v4 |  | none | guardian-rules, zizmor | E-0039, E-0040 |
| F-014 | 35.0 Low | 0.3 | unpinned_ci | high |  |  | unknown | unknown | build_or_dev | 50.0 | actions/setup-node@v4 |  | none | guardian-rules, zizmor | E-0041, E-0042 |
| F-015 | 32.47 Low | 1.0 | vulnerable_transitive | medium | 6.3 | 0.00368 | no | present_only | runtime_internal | 0.0 | qs@6.16.0 | vulnerable-nodejs@2.1.0 > express@4.22.2 > qs@6.16.0 | grype: 6.16.1; osv-scanner: 6.16.1; trivy: 6.16.1 | grype, osv-scanner, trivy | E-0029, E-0030, E-0031, E-0032, E-0033 |
| F-016 | 29.49 Low | 1.0 | vulnerable_transitive | medium | 5.3 | 0.00428 | no | present_only | runtime_internal | 0.0 | brace-expansion@2.1.4 | vulnerable-nodejs@2.1.0 > ejs@3.1.10 > … > minimatch@5.1.9 > brace-expansion@2.1.4 | grype: 2.1.7; osv-scanner: 1.1.21, 2.1.7, 3.0.9, 5.0.12; trivy: 1.1.21, 2.1.7, 3.0.9, 5.0.12 | grype, osv-scanner, trivy | E-0011, E-0012, E-0013, E-0009, E-0014 |
| F-017 | 20.0 Low | 0.15 | unpinned_ci | high |  |  | unknown | unknown | build_or_dev |  | targets/dynamic/cr0hn__vulnerable-node-20261123T132127Z/.github/workflows/ci.yml@None |  | none | zizmor | E-0043, E-0044 |
| F-018 | 20.0 Low | 0.15 | unpinned_ci | high |  |  | unknown | unknown | build_or_dev |  | targets/dynamic/cr0hn__vulnerable-node-20261123T132127Z/.github/workflows/ci.yml@None |  | none | zizmor | E-0045 |
| F-019 | 20.0 Low | 0.15 | unpinned_ci | medium |  |  | unknown | unknown | build_or_dev |  | targets/dynamic/cr0hn__vulnerable-node-20261123T132127Z/.github/workflows/ci-hardened.yml@None |  | none | zizmor | E-0034 |
| F-020 | 20.0 Low | 0.15 | unpinned_ci | medium |  |  | unknown | unknown | build_or_dev |  | targets/dynamic/cr0hn__vulnerable-node-20261123T132127Z/.github/workflows/ci-hardened.yml@None |  | none | zizmor | E-0035 |
| F-021 | 20.0 Low | 0.15 | unpinned_ci | medium |  |  | unknown | unknown | build_or_dev |  | targets/dynamic/cr0hn__vulnerable-node-20261123T132127Z/.github/workflows/ci-hardened.yml@None |  | none | zizmor | E-0036 |
| F-022 | 20.0 Low | 0.15 | unpinned_ci | medium |  |  | unknown | unknown | build_or_dev |  | targets/dynamic/cr0hn__vulnerable-node-20261123T132127Z/.github/workflows/ci.yml@None |  | none | zizmor | E-0037 |
| F-023 | 20.0 Low | 0.15 | unpinned_ci | medium |  |  | unknown | unknown | build_or_dev |  | targets/dynamic/cr0hn__vulnerable-node-20261123T132127Z/.github/workflows/ci.yml@None |  | none | zizmor | E-0038 |
| F-024 | 20.0 Low | 0.15 | unpinned_ci | medium |  |  | unknown | unknown | build_or_dev |  | targets/dynamic/cr0hn__vulnerable-node-20261123T132127Z/.github/workflows/sast-benchmark.yml@None |  | none | zizmor | E-0048 |
| F-025 | 20.0 Low | 0.15 | unpinned_ci | medium |  |  | unknown | unknown | build_or_dev |  | targets/dynamic/cr0hn__vulnerable-node-20261123T132127Z/.github/workflows/sast-benchmark.yml@None |  | none | zizmor | E-0046 |
| F-026 | 20.0 Low | 0.15 | unpinned_ci | medium |  |  | unknown | unknown | build_or_dev |  | targets/dynamic/cr0hn__vulnerable-node-20261123T132127Z/.github/workflows/sast-benchmark.yml@None |  | none | zizmor | E-0047 |
