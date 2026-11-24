# Scanner-only baseline: work-suthekshan__vulnerable-node-20261124t100314z-r-002 @ c35fa32337e5

Generated 2026-11-24T10:22:18+00:00. Scanners ran offline (empty network namespace).
Every value below comes from tool output or the cached EPSS and KEV feeds.
Findings are ranked by risk score v1 (PDF formula; unknown factors are left out and the
rest re-weighted, shown as coverage). Dependency counts cover the app's npm packages.

| Metric | Value |
|---|---|
| Findings | 37 total |
| Dependency findings | 18 (18 runtime, 0 dev-only) |
| Vulnerable packages | 7 |
| By type | {'vulnerable_direct': 18, 'misconfiguration': 10, 'untrusted_image': 1, 'unpinned_ci': 7, 'install_script': 1} |
| By severity | {'critical': 4, 'high': 16, 'medium': 12, 'low': 5} |
| In CISA KEV | 0 |
| Fix version available | 18 |
| Raw matches per tool | {'grype': 17, 'trivy': 18, 'osv-scanner': 17} |
| Advisory groups found by 1/2/3 tools | {'1_tools': 1, '3_tools': 17} |
| Unmapped to graph | 0 |
| Image inspected | none |
| CI/Dockerfile rule hits | {'guardian-rules:GR-IMG-001': 1, 'guardian-rules:GR-IMG-003': 1, 'hadolint:DL3064': 1, 'hadolint:DL3008': 1, 'hadolint:DL3009': 1, 'hadolint:DL3015': 1, 'trivy:DS-0002': 1, 'trivy:DS-0004': 1, 'trivy:DS-0026': 1, 'trivy:DS-0029': 1, 'trivy:DS-0031': 1, 'guardian-rules:GR-CI-001': 3, 'guardian-rules:GR-CI-002': 1, 'zizmor:artipacked': 1, 'zizmor:dangerous-triggers': 1, 'zizmor:template-injection': 1, 'zizmor:unpinned-uses': 3} |
| Anomaly rule hits | {'GR-INST-001': 1} |
| By risk level | {'Medium': 29, 'Low': 8} |
| Reachability | {'imported': 18, 'unknown': 18, 'present_only': 1} |
| Exposure | {'runtime_network': 18, 'runtime_internal': 12, 'build_or_dev': 7} |

| ID | Risk | Coverage | Type | Severity | CVSS | EPSS | KEV | Reach | Exposure | Provenance | Package | Dependency path | Fixed in | Tools | Evidence |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| F-001 | 62.96 Medium | 1.0 | vulnerable_direct | critical | 9.8 | 0.32808 | no | imported | runtime_network | 0.0 | ejs@3.1.6 | guardian-demo-app@1.0.0 > ejs@3.1.6 | grype: 3.1.7; osv-scanner: 3.1.7; trivy: 3.1.7 | grype, guardian-rules, osv-scanner, trivy | E-0010, E-0011, E-0012, E-0013, E-0014, E-0102, E-0103, E-0101 |
| F-002 | 57.32 Medium | 1.0 | vulnerable_direct | critical | 9.8 | 0.04581 | no | imported | runtime_network | 0.0 | minimist@1.2.5 | guardian-demo-app@1.0.0 > minimist@1.2.5 | grype: 1.2.6; osv-scanner: 0.2.4, 1.2.6; trivy: 0.2.4, 1.2.6 | grype, guardian-rules, osv-scanner, trivy | E-0054, E-0055, E-0056, E-0057, E-0058, E-0108, E-0109, E-0101 |
| F-003 | 57.24 Medium | 1.0 | vulnerable_direct | critical | 9.8 | 0.042 | no | imported | runtime_network | 0.0 | underscore@1.9.2 | guardian-demo-app@1.0.0 > underscore@1.9.2 | grype: 1.12.1; osv-scanner: 1.12.1; trivy: 1.12.1 | grype, guardian-rules, osv-scanner, trivy | E-0068, E-0069, E-0070, E-0071, E-0072, E-0112, E-0113, E-0101 |
| F-004 | 56.97 Medium | 1.0 | vulnerable_direct | high | 9.8 | 0.0287 | no | imported | runtime_network | 0.0 | lodash@4.17.15 | guardian-demo-app@1.0.0 > lodash@4.17.15 | grype: 4.18.0; osv-scanner: 4.18.0; trivy: 4.18.0 | grype, guardian-rules, osv-scanner, trivy | E-0049, E-0050, E-0051, E-0035, E-0052, E-0106, E-0107, E-0101 |
| F-005 | 54.0 Medium | 0.5 | vulnerable_direct | high |  |  | unknown | imported | runtime_network | 0.0 | lodash@4.17.15 | guardian-demo-app@1.0.0 > lodash@4.17.15 | trivy: >=4.17.19 | guardian-rules, trivy | E-0053, E-0035, E-0106, E-0107, E-0101 |
| F-006 | 53.76 Medium | 1.0 | vulnerable_direct | high | 8.8 | 0.01778 | no | imported | runtime_network | 0.0 | node-fetch@2.6.0 | guardian-demo-app@1.0.0 > node-fetch@2.6.0 | grype: 2.6.7; osv-scanner: 2.6.7, 3.1.1; trivy: 2.6.7, 3.1.1 | grype, guardian-rules, osv-scanner, trivy | E-0064, E-0065, E-0066, E-0062, E-0067, E-0110, E-0111, E-0101 |
| F-007 | 52.63 Medium | 1.0 | vulnerable_direct | high | 7.2 | 0.20158 | no | imported | runtime_network | 0.0 | lodash@4.17.15 | guardian-demo-app@1.0.0 > lodash@4.17.15 | grype: 4.17.21; osv-scanner: 4.17.21; trivy: 4.17.21 | grype, guardian-rules, osv-scanner, trivy | E-0041, E-0042, E-0043, E-0035, E-0044, E-0106, E-0107, E-0101 |
| F-008 | 52.0 Medium | 1.0 | vulnerable_direct | high | 8.3 | 0.00497 | no | imported | runtime_network | 0.0 | axios@0.33.0 | guardian-demo-app@1.0.0 > axios@0.33.0 | grype: 0.34.0; osv-scanner: 0.34.0, 1.20.0; trivy: 0.34.0, 1.20.0 | grype, guardian-rules, osv-scanner, trivy | E-0006, E-0007, E-0008, E-0004, E-0009, E-0099, E-0100, E-0101 |
| F-009 | 51.96 Medium | 1.0 | vulnerable_direct | medium | 8.2 | 0.01823 | no | imported | runtime_network | 0.0 | lodash@4.17.15 | guardian-demo-app@1.0.0 > lodash@4.17.15 | grype: 4.17.23; osv-scanner: 4.17.23; trivy: 4.17.23 | grype, guardian-rules, osv-scanner, trivy | E-0045, E-0046, E-0047, E-0035, E-0048, E-0106, E-0107, E-0101 |
| F-010 | 51.81 Medium | 1.0 | vulnerable_direct | high | 8.2 | 0.01063 | no | imported | runtime_network | 0.0 | underscore@1.9.2 | guardian-demo-app@1.0.0 > underscore@1.9.2 | grype: 1.13.8; osv-scanner: 1.13.8; trivy: 1.13.8 | grype, guardian-rules, osv-scanner, trivy | E-0073, E-0074, E-0075, E-0071, E-0076, E-0112, E-0113, E-0101 |
| F-011 | 51.4 Medium | 1.0 | vulnerable_direct | high | 8.1 | 0.00524 | no | imported | runtime_network | 0.0 | jsonwebtoken@8.5.1 | guardian-demo-app@1.0.0 > jsonwebtoken@8.5.1 | grype: 9.0.0; osv-scanner: 9.0.0; trivy: 9.0.0 | grype, guardian-rules, osv-scanner, trivy | E-0019, E-0020, E-0021, E-0022, E-0023, E-0104, E-0105, E-0101 |
| F-012 | 50.24 Medium | 1.0 | vulnerable_direct | high | 7.4 | 0.05213 | no | imported | runtime_network | 0.0 | lodash@4.17.15 | guardian-demo-app@1.0.0 > lodash@4.17.15 | grype: 4.17.19; osv-scanner: 4.17.19; trivy: 4.17.19 | grype, guardian-rules, osv-scanner, trivy | E-0037, E-0038, E-0039, E-0035, E-0040, E-0106, E-0107, E-0101 |
| F-013 | 50.0 Medium | 0.15 | misconfiguration | critical |  |  | unknown | unknown | runtime_internal |  | targets/work/suthekshan__vulnerable-node-20261124t100314z-r-002/Dockerfile@None |  | none | trivy | E-0092 |
| F-014 | 50.0 Medium | 0.15 | misconfiguration | high |  |  | unknown | unknown | runtime_internal |  | targets/work/suthekshan__vulnerable-node-20261124t100314z-r-002/Dockerfile@None |  | none | trivy | E-0087 |
| F-015 | 50.0 Medium | 0.15 | misconfiguration | high |  |  | unknown | unknown | runtime_internal |  | targets/work/suthekshan__vulnerable-node-20261124t100314z-r-002/Dockerfile@None |  | none | trivy | E-0096 |
| F-016 | 50.0 Medium | 0.15 | misconfiguration | medium |  |  | unknown | unknown | runtime_internal |  | targets/work/suthekshan__vulnerable-node-20261124t100314z-r-002/Dockerfile@None |  | none | trivy | E-0097 |
| F-017 | 50.0 Medium | 0.15 | misconfiguration | medium |  |  | unknown | unknown | runtime_internal |  | node@14 |  | none | guardian-rules | E-0090 |
| F-018 | 50.0 Medium | 0.15 | misconfiguration | medium |  |  | unknown | unknown | runtime_internal |  | targets/work/suthekshan__vulnerable-node-20261124t100314z-r-002/Dockerfile@None |  | none | hadolint | E-0091 |
| F-019 | 50.0 Medium | 0.15 | misconfiguration | medium |  |  | unknown | unknown | runtime_internal |  | targets/work/suthekshan__vulnerable-node-20261124t100314z-r-002/Dockerfile@None |  | none | hadolint | E-0093 |
| F-020 | 50.0 Medium | 0.15 | misconfiguration | low |  |  | unknown | unknown | runtime_internal |  | targets/work/suthekshan__vulnerable-node-20261124t100314z-r-002/Dockerfile@None |  | none | trivy | E-0088 |
| F-021 | 50.0 Medium | 0.15 | misconfiguration | low |  |  | unknown | unknown | runtime_internal |  | targets/work/suthekshan__vulnerable-node-20261124t100314z-r-002/Dockerfile@None |  | none | hadolint | E-0094 |
| F-022 | 50.0 Medium | 0.15 | misconfiguration | low |  |  | unknown | unknown | runtime_internal |  | targets/work/suthekshan__vulnerable-node-20261124t100314z-r-002/Dockerfile@None |  | none | hadolint | E-0095 |
| F-023 | 49.91 Medium | 1.0 | vulnerable_direct | medium | 7.6 | 0.00572 | no | imported | runtime_network | 0.0 | jsonwebtoken@8.5.1 | guardian-demo-app@1.0.0 > jsonwebtoken@8.5.1 | grype: 9.0.0; osv-scanner: 9.0.0; trivy: 9.0.0 | grype, guardian-rules, osv-scanner, trivy | E-0024, E-0025, E-0026, E-0022, E-0027, E-0104, E-0105, E-0101 |
| F-024 | 47.82 Medium | 1.0 | vulnerable_direct | medium | 6.9 | 0.00614 | no | imported | runtime_network | 0.0 | ejs@3.1.6 | guardian-demo-app@1.0.0 > ejs@3.1.6 | grype: 3.1.10; osv-scanner: 3.1.10; trivy: 3.1.10 | grype, guardian-rules, osv-scanner, trivy | E-0015, E-0016, E-0017, E-0013, E-0018, E-0102, E-0103, E-0101 |
| F-025 | 47.78 Medium | 1.0 | vulnerable_direct | medium | 6.9 | 0.00414 | no | imported | runtime_network | 0.0 | axios@0.33.0 | guardian-demo-app@1.0.0 > axios@0.33.0 | grype: 0.34.0; osv-scanner: 0.34.0, 1.20.0; trivy: 0.34.0, 1.20.0 | grype, guardian-rules, osv-scanner, trivy | E-0001, E-0002, E-0003, E-0004, E-0005, E-0099, E-0100, E-0101 |
| F-026 | 46.06 Medium | 1.0 | vulnerable_direct | medium | 6.3 | 0.0081 | no | imported | runtime_network | 0.0 | jsonwebtoken@8.5.1 | guardian-demo-app@1.0.0 > jsonwebtoken@8.5.1 | grype: 9.0.0; osv-scanner: 9.0.0; trivy: 9.0.0 | grype, guardian-rules, osv-scanner, trivy | E-0028, E-0029, E-0030, E-0022, E-0031, E-0104, E-0105, E-0101 |
| F-027 | 45.0 Medium | 0.3 | untrusted_image | medium |  |  | unknown | unknown | runtime_internal | 40.0 | node@14 |  | none | guardian-rules | E-0089 |
| F-028 | 44.38 Medium | 1.0 | vulnerable_direct | medium | 5.3 | 0.07424 | no | imported | runtime_network | 0.0 | lodash@4.17.15 | guardian-demo-app@1.0.0 > lodash@4.17.15 | grype: 4.17.21; osv-scanner: 4.17.21; trivy: 4.17.21 | grype, guardian-rules, osv-scanner, trivy | E-0032, E-0033, E-0034, E-0035, E-0036, E-0106, E-0107, E-0101 |
| F-029 | 43.24 Medium | 1.0 | vulnerable_direct | low | 5.3 | 0.01692 | no | imported | runtime_network | 0.0 | node-fetch@2.6.0 | guardian-demo-app@1.0.0 > node-fetch@2.6.0 | grype: 2.6.1; osv-scanner: 2.6.1, 3.0.0-beta.9; trivy: 2.6.1, 3.0.0-beta.9 | grype, guardian-rules, osv-scanner, trivy | E-0059, E-0060, E-0061, E-0062, E-0063, E-0110, E-0111, E-0101 |
| F-030 | 35.0 Low | 0.3 | unpinned_ci | high |  |  | unknown | unknown | build_or_dev | 50.0 | actions/checkout@main |  | none | guardian-rules, zizmor | E-0079, E-0080 |
| F-031 | 35.0 Low | 0.3 | unpinned_ci | high |  |  | unknown | unknown | build_or_dev | 50.0 | actions/setup-node@v3 |  | none | guardian-rules, zizmor | E-0082, E-0083 |
| F-032 | 35.0 Low | 0.3 | unpinned_ci | high |  |  | unknown | unknown | build_or_dev | 50.0 | some-org/deploy-action@master |  | none | guardian-rules, zizmor | E-0085, E-0086 |
| F-033 | 27.0 Low | 0.5 | install_script | low |  |  | unknown | present_only | runtime_internal | 0.0 | vendor/colour-utils@0.0.1 | guardian-demo-app@1.0.0 > vendor/colour-utils@0.0.1 | none |  | E-0098 |
| F-034 | 20.0 Low | 0.15 | unpinned_ci | high |  |  | unknown | unknown | build_or_dev |  | targets/work/suthekshan__vulnerable-node-20261124t100314z-r-002/.github/workflows/ci.yml@None |  | none | zizmor | E-0084 |
| F-035 | 20.0 Low | 0.15 | unpinned_ci | high |  |  | unknown | unknown | build_or_dev |  | targets/work/suthekshan__vulnerable-node-20261124t100314z-r-002/.github/workflows/ci.yml@None |  | none | guardian-rules | E-0077 |
| F-036 | 20.0 Low | 0.15 | unpinned_ci | high |  |  | unknown | unknown | build_or_dev |  | targets/work/suthekshan__vulnerable-node-20261124t100314z-r-002/.github/workflows/ci.yml@None |  | none | zizmor | E-0078 |
| F-037 | 20.0 Low | 0.15 | unpinned_ci | medium |  |  | unknown | unknown | build_or_dev |  | actions/checkout@main |  | none | zizmor | E-0081 |
