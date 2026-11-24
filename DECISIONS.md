# Decisions

Each entry records the decision, its source, and its approval.

## D1-01 Orchestration framework: LangChain Deep Agents

- **Decision:** Use `deepagents` (LangChain Deep Agents) rather than DeepSeek Harness.
- **Why:**
  - It compiles to a LangGraph graph, which is the PDF's primary agent framework.
  - It is a Python library, matching the FastAPI/Pydantic backend.
  - It supports per-tool human approval (`interrupt_on`, which requires a checkpointer).
  - It supports specialist subagents, each with its own prompt, tools and model.
  - It has a tool allow-list, path permission rules, and `response_format` for structured output.
  - It supports multiple providers through `provider:model` strings.
- **Why not DeepSeek Harness:**
  - Its README calls it a "developer preview" and promises breaking changes.
  - Its safety notes say it has had no security audit and is not production-ready.
  - It is a TypeScript/Node plugin runtime, and its Python SDK only launches the CLI.
  - The pages read document no API for structured output.
- **Constraints carried forward:**
  - Disable the built-in write and shell tools.
  - Never use the local shell backend on the host.
  - Scanners run as plain Python outside the agent, so the scanner-only baseline works without a model.
- **Open checks before D1.S8:**
  - The Subagents and Backends doc pages failed to load; verify them then.
  - Pin and verify the package versions then.
- **Approval:** recommended to the user; the user replied "start execution of Day 1, Step 1"
  on 2026-11-23. Adding the dependency still requires approval in D1.S8.

## D1-02 Unknown risk factors are renormalized, not zeroed

- **Decision:** A factor with no data is marked unknown and left out. The remaining PDF weights
  are rescaled to sum to 1.
- **Reported fields:** `unknown_factors` and `weight_coverage`, which is the sum of the known
  weights.
- **No data at all:** the score is `None` and the level is `Unknown`.
- **Special cases:**
  - `kev=False` with no EPSS value is still unknown.
  - `kev=True` sets the exploit factor to 100.
- **Known trade-off:** with low coverage, one strong factor dominates. For example, CVSS 9.8 alone
  scores 98. The UI must show `weight_coverage` beside the score.
- **Approval:** proposed in the D1.S1 plan, approved with the step.

## D1-03 Fractional band boundaries

- **Decision:** Round the score to 2 decimals, then band it:
  - Critical: 85 and above
  - High: 65 and above
  - Medium: 40 and above
  - Low: below 40
- **Why:** rounding first keeps the shown score and band consistent (84.996 shows as 85.00 and is
  Critical). Bands are half-open, so 84.6 is High.
- **Approval:** proposed in the D1.S1 plan, approved with the step.

## D1-04 Malicious override only on confirmation

- **Decision:**
  - `confirmed_malicious` forces Critical and records `override="confirmed_malicious"`.
  - It is valid only on `malicious_package` findings, from confirmed evidence.
  - A typosquat heuristic match uses the `typosquat` type and raises only the provenance factor.
- **Why:** the PDF says "confirmed malicious or typosquatted". `AGENTS.md` forbids equating a
  typosquat heuristic with confirmation.
- **Approval:** proposed in the D1.S1 plan, approved with the step.

## D1-05 Contract shape

- **Finding schema:** follows PDF section 5, with two groupings:
  - `cvss`, `epss`, `kev`, `reachable` and `exposure` are in `factors`.
  - `risk_level` and `risk_score` are in `risk`. A model never supplies them.
- **Dependency paths:** they start at the root. `vulnerable_direct` needs `[root, package]`.
  `vulnerable_transitive` needs 3 or more entries.
- **Rationale:** it must cite at least one `E-###`. Every citation must be attached to that
  finding.
- **FindingSet:** checks that every citation resolves to a stored `EvidenceRecord` with the same
  tool.
- **Evidence file paths:** must be workspace-relative, with no absolute paths, `..` or `\`.
- **All contracts:** frozen and reject unknown fields.
- **Not yet done:**
  - Redacting excerpts is the producer's job. It is implemented with the scanners (D1.S4).
  - The graph store choice (NetworkX or otherwise) is deferred. The contract has a
    dependency-free BFS path query.

## D1-06 Environment

- Python 3.12.16, a uv-managed interpreter (the system has only 3.14).
- `uv` project with the `uv_build` backend; `src/guardian`.
- No Git repository was created in this step. The `.guardian-git` setup that `AGENTS.md` describes
  is not present in this workspace.

## D2-01 Scanner pinning: 7-day minimum release age plus cross-checked SHA-256

- **Decision:** pin the newest release of each tool that is at least 7 days old on 2026-11-23:

  | Tool | Version |
  |---|---|
  | Syft | 1.57.2 |
  | Grype | 0.121.3 (0.122.x was too new) |
  | OSV-Scanner | 2.7.1 |
  | Trivy | 0.76.2 |
  | Hadolint | 2.15.1 |
  | zizmor | 1.32.0 (1.33.x was published the day before) |

- **Hash pinning:** each binary's SHA-256 is recorded in `tools/manifest.json`.
  - For five tools, the hash was confirmed by both the project's checksum file and the GitHub
    API asset digest.
  - zizmor publishes no checksum file, so its hash has a single source (the GitHub API digest).
    This is a weaker guarantee.
- **Not verified:** Sigstore signatures. Syft, Grype and Trivy publish them, but verifying
  needs cosign, which is not installed.
- **Installer:** `scripts/install_tools.py` is stdlib only.
  - It accepts only `https://github.com/` URLs.
  - It deletes any download whose hash does not match.
  - It extracts only the named regular-file member, and needs no root.
- **Why:** freshly published releases are where compromised builds usually show up. Trivy had a
  compromised release in early 2026.
- **Approval:** within D1.S2 ("pinned release binaries ... checked against published checksums").
  The 7-day rule is a choice made within that step.

## D2-02 Sample app: OWASP NodeGoat (default, swappable)

- **Selection:** checked against the PDF's section 8 criteria using the GitHub API. NodeGoat is
  the only candidate that met all of them:
  - Apache-2.0 licence
  - Dockerfile and docker-compose file
  - committed `package-lock.json` (v2)
  - two CI workflows
  - 380 unique runtime packages, within the PDF's 150 to 600
- **Rejected candidates:**
  - Juice Shop: no lockfile.
  - Spring PetClinic: no lockfile, no Dockerfile.
  - DVNA: no CI.
  - RealWorld Express: no licence.
- **Caveats:**
  - NodeGoat is an intentionally vulnerable training app. The PDF says such apps "may look too
    contrived" and suggests pairing them with a seeded fork.
  - The last commit is from 2023, so it is stable but unmaintained.
- **Approval:** the user had not chosen. It was selected as the default so D1.S3 could proceed.
  To swap, re-clone and update `targets/targets.json`.

## D3-01 Graph source: the lockfile, cross-checked against the Syft SBOM

- **Deliverable:** the SBOM is Syft's CycloneDX 1.5 output.
- **Why Syft alone is not enough for the graph:**
  - It has no root-to-direct edges.
  - It drops dev dependencies by default.
  - It records no line numbers.
  - It merges duplicate installs ambiguously.
- **Graph source:** the graph is built from `package-lock.json`, following npm's resolution
  algorithm (nearest `node_modules` ancestor).
  - Node IDs are lockfile install paths.
  - Each node carries `SourceLocation(file, line)`, used as evidence.
- **Trust check:** the production package set must match the SBOM exactly. The build exits with
  an error if it does not, or if a required dependency is unresolved.
- **Contract change:** `SbomComponent.source_files` became `locations: tuple[SourceLocation]`,
  and an `optional` flag was added.
- **Graph features added:**
  - new edge kinds: optional, peer and dev
  - `depths()`, `introduced_by()`, `path_labels()`
  - `shortest_path(exclude_dev=True)`
  - an O(1) node index
- **Still no new dependency:** NetworkX was not added.

## D3-02 Dev dependencies stay in the graph, flagged by scope

- **Decision:** dev packages stay in the graph with `scope=dev` (790 unique), so the exposure
  factor can use them. The SBOM cross-check compares runtime packages only.
- **Path shown:** a runtime package's dependency path is searched over runtime nodes only.
  - The plain shortest path for `minimist@0.0.8` under `fsevents` ran through the dev-only
    `nodemon`. A production install reaches it through `forever`.
- **Platform caveat:** packages like `fsevents` are macOS-only optional packages and are absent on
  Linux. They are flagged `optional`; their exposure is decided in D1.S7.

## D3-03 Execution safety for tools

- **Runner:** `guardian.tools.run_tool` runs only allow-listed binaries from `tools/bin`.
  - Argument lists only, never a shell.
  - Fixed environment: `PATH=/usr/bin:/bin`, `HOME=cache/tool-home`, update checks off.
  - stdin closed, a timeout, and output caps.
  - Any path passed through `jail()` is resolved, including symlinks, and must stay inside the
    workspace.
- **Targets:** only targets registered in `targets/targets.json` can be built, and only while
  `.git/HEAD` equals the pinned commit.
- **Config isolation:** Syft runs with the workspace as its working directory and a controlled
  `HOME`, so a target repo cannot supply a Syft config file.

## D4-01 Scan scope includes dev dependencies

- **Decision:** Grype scans a second Syft SBOM made with
  `SYFT_JAVASCRIPT_INCLUDE_DEV_DEPENDENCIES=true`, Trivy runs with `--include-dev-deps`, and
  OSV-Scanner includes dev by default. All three therefore see the same package set, which keeps
  the cross-check fair.
- **Scope on findings:** a finding is `exposure=build_or_dev` only if every install path is dev.
- **The deliverable SBOM** stays the D1.S3 runtime SBOM.

## D4-02 Scanners must run offline, enforced by the kernel

- **Decision:** `run_tool(offline=True)` prefixes `/usr/bin/unshare -rn`, which gives the tool an
  empty network namespace. This does not rely on each tool's "offline" flag.
- **Database freshness:** Grype's default 120-hour age check stays on. A stale database fails
  loudly rather than silently giving old results, so refresh within 5 days of a demo.

## D4-03 Correlation and the facts on each finding

- **Grouping:** for each name@version, union-find over the advisory ID plus aliases (Grype
  related vulnerabilities, OSV aliases, Trivy VendorIDs).
  - Repeated matches with the same tool, advisory and package are collapsed. Grype reports one
    per install path.
  - IDs with no alias, such as Trivy's NSWG-ECO-*, stay as separate single-tool findings and
    are never merged by guesswork. They may duplicate other findings.
- **Facts on each finding:**
  - **CVSS:** the highest v3/v4 base score any tool reports. This is conservative, and the
    source records keep each value.
  - **EPSS:** the highest score across the group's CVE aliases, from the cached feed.
  - **KEV:** `True` if any CVE alias is listed. `False` if the group has CVEs but none are
    listed. `None` if there is no CVE alias, because KEV is keyed by CVE.
  - **Severity:** the highest normalized scanner label.
  - **Fix versions:** kept per tool, as reported (for example, Trivy gives `>=0.4.9` while OSV
    gives `0.4.11`).
- **Type:**
  - A `MAL-` advisory gives `malicious_package` with `confirmed_malicious=True`, per D1-04.
  - Otherwise, the type is `vulnerable_direct` when the representative install path is a direct
    dependency, and `vulnerable_transitive` when it is not.
- **Representative install path:** runtime before dev, direct first, then the shortest path.
- **Deferred to D1.S7:** reachability, network exposure and the risk score.

## D4-04 Evidence and citation verification

- **Evidence records for each finding:**
  - **Scanner results:** tool, version, advisory ID, `package-lock.json:<line>`, and a JSON
    pointer into the raw output. This matches the PDF's evidence example.
  - **Graph node:** the path, from the dependency graph.
  - **EPSS and KEV:** advisory records from the cached feeds.
- **Deduplication:** identical facts share one record.
- **Verifier:** `guardian.scan.verify` independently re-reads the raw files. It checks every
  advisory ID, package version, pointer, lockfile line, graph path, fix version and
  `introduced_by`. The baseline command exits non-zero below 100%.
- **Tested:** the tests confirm it catches invented CVEs, wrong versions, wrong fixes, wrong paths
  and unknown parents.

## D5-01 Image source without Docker: a digest-verified base image as an OCI layout

- **Situation:** the Docker daemon is not running, and the user did not choose an option.
- **What was done:** option (b). `scripts/fetch_image.py` pulls the Dockerfile's base image
  through the registry API, using `curl --proto =https`.
  - Initial requests go only to auth.docker.io and registry-1.docker.io. Blob redirects to
    Docker's CDN are followed.
  - It verifies every manifest and blob against its sha256 digest and writes an OCI layout.
  - Trivy and Grype then scan the layout offline.
- **Pinning:** the scan is pinned by manifest digest even though the Dockerfile is not.
- **Limitation:** NodeGoat's own built image, which includes `npm install --production`, is not
  scanned. The app's packages are covered by the D1.S4 lockfile scan instead.

## D5-02 Guardian rules and their severities

- **Approach:** deterministic, line-based rules, each with a fixed severity chosen here.
- **Dockerfile rules:**

  | Rule | What it flags | Severity | Type |
  |---|---|---|---|
  | GR-IMG-001 | `FROM` without `@sha256:` | medium | untrusted_image |
  | GR-IMG-002 | `latest` tag or no tag | high | untrusted_image |
  | GR-IMG-003 | final stage runs as root | medium | misconfiguration |

- **Workflow rules:**

  | Rule | What it flags | Severity | Type |
  |---|---|---|---|
  | GR-CI-001 | action not pinned to a 40-hex commit SHA | high | unpinned_ci |
  | GR-CI-002 | `pull_request_target` together with `actions/checkout` | high | unpinned_ci |
  | GR-CI-003 | `docker://` action without a digest | medium | unpinned_ci |

- **End-of-life:** Trivy's own `Metadata.OS.EOSL=true` becomes an untrusted_image finding at the
  final `FROM` line, with severity high (our choice; Trivy gives none).
- **Mapping tool severities:**
  - Hadolint: error → high, warning → medium, info and style → low.
  - zizmor: "Informational" → low.
- **Type label:** `unpinned_ci` stands for the slide's "unpinned or unsafe CI/CD component", so
  zizmor's excessive-permissions results use it too.
- **Line-based caveat:** the workflow rules don't parse YAML; zizmor, a real YAML parser,
  cross-checks GR-CI-001.

## D5-03 Grype CPE-only image matches are excluded from findings

- **Data:** on the image, 144 of Grype's 217 matches are `cpe-match` only. CPE matching is a loose
  name-based method and a well-known source of false positives; the PDF lists "false positives
  swamp the list" as a risk.
- **Decision:** CPE-only matches don't become findings. Their count is reported
  (`grype_cpe_only_excluded`) and they stay in `grype-image.json`.
- **Cost:** CVEs in the Node 12 binary are therefore not listed, because only Grype's CPE matching
  covers them.

## D5-04 Merging tool results and rules

- **Merge rule:** configuration hits merge when they share (file, line, concern).
- **Concern map:** `zizmor:unpinned-uses` and `GR-CI-001` both mean "action-not-sha-pinned".
  Every other rule is its own concern.
- **Finding IDs:** a merged finding lists every rule ID in `advisory_ids`.
- **Components:**
  - a `uses:` line gives `pkg:github/<owner>/<repo>@<ref>`
  - a `FROM` line gives `pkg:docker/<path>@<tag>`
  - otherwise, the file path
- **Image packages:** type `vulnerable_image_package`, with path `[image@digest, package@version]`
  and `introduced_by` set to the image.
- **Contract additions:** finding types `vulnerable_image_package` and `misconfiguration`.

## D5-05 The target cannot suppress its own findings

- zizmor runs with `--no-config`, so the repo's `zizmor.yml` is ignored.
- Hadolint runs with `--disable-ignore-pragma`, so `# hadolint ignore=` comments are ignored.
- **Not covered:** Trivy's inline `#trivy:ignore` comments. Trivy has no equivalent flag in the
  version used.

## D5-06 Verifier covers every evidence kind

- **Format detection:** `verify()` identifies each raw record's format from its content (Grype,
  Trivy vuln, OSV, Hadolint, zizmor, Trivy misconfig, Trivy EOSL), not from the tool name the
  evidence claims.
- **What it checks:**
  - **Tool results:** rule IDs, lines and files for Hadolint, zizmor and Trivy config.
  - **Guardian rules:** the exact source line text.
  - **Image findings:** the manifest digest in `index.json`, plus the image path and component.
  - **EPSS and KEV:** each citation must be one of the finding's own CVE aliases.
- **Pointer parsing:** pointers are parsed with a regex. An empty summary used to make the
  excerpt end in `" ::"`, which broke parsing; fixed with `pointer_excerpt`.

## D6-01 Popular-package source: npm-high-impact 1.13.0

- **User's choice** (option (a), then the source), from three candidates:
  - **npm registry search** works but is query-based, so it is not a complete ranking.
  - **ecosyste.ms** was returning HTTP 429.
- **The list:** 17,338 names meeting npm's own "high-impact" definition: at least 1,000,000
  weekly downloads or at least 500 dependents.
- **How it is fetched:**
  - Published 2026-06-08, which is older than the 7-day rule requires.
  - The tarball comes from registry.npmjs.org and is checked against its pinned SHA-512 integrity.
  - Only `package/lib/top.js` is read. A strict per-line pattern is applied, and anything that
    isn't a plain quoted name aborts the run. Nothing is executed or installed.
- **Comparison set:** the first 5,000 names, per the PDF.
- **Not-on-the-list:** used as the "not high-impact" fact. It means below both thresholds; it is
  not proof of low downloads.
- **Caveat:** the data is about 5 months old.

## D6-02 Typosquat rule: thresholds and severity

- **Distance:** optimal string alignment, which counts an adjacent swap as one edit.
  - Maximum distance is 2 (PDF), but 1 when either name is 6 characters or shorter.
  - Names under 4 characters are skipped, and so are names on the high-impact list.
- **Candidate pairs:** found with a deletion-neighbourhood index (SymSpell), then confirmed with
  an exact distance check. This takes about 4 seconds for 804 names.
- **Severity:**
  - medium at distance 1
  - low at distance 2
  - high when registry metadata shows the package is under 90 days old *and* has fewer than
    1,000 weekly downloads (PDF: "low age or downloads")
- **Confirmation:** none of this sets `confirmed_malicious` (D1-04).
- **Measured:** 4 low-severity false positives on the clean app. This is the expected cost of a
  name-only heuristic without registry age data for real packages.

## D6-03 Install-script and lockfile rules

- **GR-INST-001 (low):** the lockfile says `hasInstallScript`, but the script can't be inspected
  because nothing is installed. This is a fact, not a judgement.
- **GR-INST-002 (high):** a lifecycle script matches `curl`, `wget`, `base64`, `eval`, `nc`,
  `powershell`, `http(s)://` or `/dev/tcp`. It applies only when the manifest is available
  (the mock registry for seeded packages).
- **GR-LOCK-001 (high):** the resolved host is not `registry.npmjs.org`. Mutable branch refs are
  noted. Bundled entries are skipped: 515 entries have no `resolved` and are covered by their
  parent's integrity.
- **GR-LOCK-002 (medium):** the registry tarball path does not match name@version.
- **GR-LOCK-004 (high):** integrity changed with the same version, compared with the base commit.
- **GR-LOCK-005 (medium):** resolved URL changed with the same version, compared with the base
  commit.
- **GR-DEP-001 (medium):** a new non-direct install path whose introducing direct dependencies all
  had a same-major version bump.
- **GR-DEP-002 (high):** a new non-direct path where no introducing direct dependency changed.
- **Grouping:** one finding per (package, type). Evidence cites the exact lockfile or manifest
  lines in both commits.
- **Not done:** SHA-1-only integrity (646 entries) is not flagged, to avoid noise.
  "Suspicious update" (maintainer change, publish anomalies) needs live registry metadata and is
  not implemented.

## D6-04 Seeded fork and evaluation method

- **Mapping to the PDF:** scenarios follow the PDF's section 8 table. S3 to S8 are seeded; R1 to
  R4 are real issues already in the unmodified app.
- **Synthetic artefacts:**
  - Packages that don't exist anywhere.
  - Integrity values that are hashes of marker strings.
  - A postinstall that only echoes a marker and calls `127.0.0.1:9`, and is never run.
  - Labelled in the commit, `SEEDED.md` and the names.
  - The fork's `origin` remote is removed.
- **Recall:** a finding with the expected type, component and rule.
- **Precision:**
  - Computed over anomaly and posture findings in the seeded run that have no counterpart in the
    clean run. File-path components have the target's path prefix stripped for comparison.
  - A new finding is a true positive when its component or rule was seeded, or when it cites a
    line the seeding changed (worked out with difflib).
  - Caveat: a cited record with no line number counts as touching a changed file at file level.
- **Clean-run findings:** listed separately for manual review rather than scored.

## D6-05 Verifier coverage for anomaly evidence

- **Registry metadata from the popular list:** the cited name must be at the cited rank, the
  candidate must be the finding's component and not on the list, and the distance is recomputed.
- **Mock registry:** `created` and `weekly_downloads` must match `registry.json`.
- **Lines:** guardian-rule line citations, in either commit's lockfile or in a manifest, must
  match exactly.

## D7-01 Reachability from static imports, resolved to the installed copy

- **File roles** (by path):
  - **Server code (runtime):** anything not in a dev or client location.
  - **Dev:** `test/`, `tests/`, `cypress/`, `spec/`, `artifacts/` and `scripts/`, plus
    `Gruntfile.js` and similar, plus `*.test.js` and `*.spec.js`.
  - **Client:** `assets/`, `public/`, `static/` and `vendor/`, which are browser code and are
    ignored.
- **Imports:** static `require('x')`, `import ... from 'x'`, `import 'x'` and `import('x')` are
  mapped to package names. Builtins, local paths and commented lines are skipped. Dynamic
  requires are counted but not resolved.
- **IMPORTED (60):** a runtime import of the name *and* the finding's version equals the top-level
  `node_modules/<name>` version, which is what a bare `require` from the app root loads. It cites
  the import line (GR-REACH-001) and the lockfile `version` line (GR-REACH-002).
- **DEV_ONLY_UNUSED (0):** every install path is dev.
- **PRESENT_ONLY (30):** otherwise.
- **UNKNOWN:** image and config findings.
- **CALLED (100):** never claimed. There is no call graph; that is the PDF's timeboxed
  reachability spike.

## D7-02 Exposure rule

- **RUNTIME_NETWORK (100):** IMPORTED in an app with cited network facts, either a `.listen(` in
  server code or a Dockerfile `EXPOSE`. It cites those facts (GR-EXPO-001).
- **RUNTIME_INTERNAL (50):** other runtime packages, image packages, and Dockerfile findings,
  because the final stage is the runtime.
- **BUILD_OR_DEV (20):** dev-only packages and CI findings.
- **Judgement:** treating "imported by server code of a network server" as network-facing is a
  judgement, documented here. It does not prove that attacker input reaches the package.

## D7-03 Provenance points and the meaning of 0

- **Points table** (`context.PROVENANCE_POINTS`), taking the maximum over rule IDs cited for the
  same component:

  | Rule | Points |
  |---|---|
  | GR-TYPO-001 | 60 |
  | GR-INST-001 | 30 |
  | GR-INST-002 | 80 |
  | GR-LOCK-001 | 60 |
  | GR-LOCK-002 | 50 |
  | GR-LOCK-004 | 80 |
  | GR-LOCK-005 | 50 |
  | GR-DEP-001 | 40 |
  | GR-DEP-002 | 60 |
  | GR-CI-001 / unpinned-uses / GR-CI-003 (mutable reference) | 50 |
  | GR-IMG-001 | 40 |
  | GR-IMG-002 | 60 |

  Confirmed malicious scores 100.
- **Sharing:** anomaly-rule citations are copied onto every finding for the same name@version.
  So a CVE on a tampered package carries the tamper evidence and the raised provenance.
- **No hit:**
  - **npm packages: 0.** This means "no signal from the implemented checks" (name similarity,
    install script, source host, integrity). It does *not* mean verified trusted: registry age,
    maintainers and signatures are not checked.
  - **Image packages and other findings: unknown,** because the checks don't apply.
- **Consequence:** an ordinary package scores at most 85 (77 if imported rather than called), so
  most real CVEs fall in Medium.

## D7-04 Ranking, coverage and verification

- **Order:** findings are ordered by (forced override first, score descending, previous key).
- **Unknown factors:** handled per D1-02 (rescaling). Real data shows the trade-off: image
  packages (coverage 0.65) and GHSA-only advisories with no CVSS or EPSS (coverage 0.5) can
  outrank fully covered app findings. `weight_coverage` is stored and printed beside every score.
  Changing this needs a new decision, for example a neutral value for unknowns.
- **Verifier, for every scored finding:**
  - risk == `score_risk(factors)`
  - provenance == `expected_provenance` over the cited rule IDs
  - IMPORTED needs a cited import line of the package *and* a cited `version` line inside
    `node_modules/<name>` with that version
  - network exposure needs IMPORTED plus a cited GR-EXPO-001
  - dev-only reachability matches build/dev exposure
- **Unscored findings:** findings without a risk assessment (older fixtures) skip these checks.
  Pipeline runs score every finding, and the integration test asserts it.

## D7-05 Evidence store: SQLite schema v1

- **Location:** `runs/guardian.db`, which is git-ignored. Stdlib `sqlite3` with bound parameters
  only, and foreign keys on.
- **Tables:**
  - `runs`: run_id is the workspace-relative output directory.
  - `evidence`
  - `findings`: queryable columns plus the exact `finding_json`.
  - `finding_evidence`
  - `graph_nodes` and `graph_edges`
- **Saving:** each run is saved in one transaction, replacing any earlier rows. A failed save
  leaves the previous run intact (tested).
- **Version check:** a `meta.schema_version` mismatch refuses to open.
- **JSON files kept:** `findings.json` and `baseline.json` stay in each run directory as
  human-readable artefacts. The store adds query and history.

## D8-01 Agent framework pins and a project-wide cooldown

- **Pin:** `deepagents==0.7.38`, published 2026-11-13. 0.7.39 to 0.7.41 were under 7 days old.
- **Cooldown:** `[tool.uv] exclude-newer = "2026-11-16T00:00:00Z"` applies the 7-day rule to
  every transitive package. This moved pydantic to 2.14.3 and ruff to 0.17.5; all tests pass.
- **Provider SDKs pulled in:** deepagents hard-requires `langchain-anthropic`,
  `langchain-google-genai` and `langsmith`. They are installed but unused unless a provider is
  opted in.
- **API source:** the installed package source, because the Subagents and Backends doc pages had
  failed to load.

## D8-02 External model calls are opt-in, per run

> **Superseded in part by D9-03:** the scripted default was removed. The opt-in rule and the
> no-auto-install rule still apply; the only product model path is now a live provider.

- **Default:** the scripted model.
- **Real providers:** need `GUARDIAN_ALLOW_EXTERNAL_MODELS=1` *and* prior user authorization of
  the provider and the data it receives (LLM_PROVIDERS.md).
- **No auto-install:** missing provider packages are not installed automatically; each needs
  approval.
- **Tracing:** LangSmith tracing defaults to off.
- **Scripted model:** deterministic and offline, driving the real tool protocol. It exists so
  that the agent graph, tools, gate and store are tested end to end without network or cost. It
  is labelled "not an LLM" in every artefact.

## D8-03 Explanation gate rules

- **What's accepted:** `Explanation` (why it matters, reachability, confidence, confidence
  reason, and 1 to 20 cited evidence IDs) is accepted only if:
  - the schema is valid and the finding exists;
  - every cited *and* every mentioned `E-###` is that finding's evidence;
  - every CVE, GHSA or MAL ID mentioned is in its `advisory_ids` (the broad GHSA shape is
    matched, so invented IDs can't escape);
  - every `pkg@version` is the component or on its path or `introduced_by`;
  - every x.y.z version is the component's, a path version or a tool-reported fix version
    (single-dot decimals such as CVSS and EPSS are ignored);
  - the reachability sentence contains the computed word (imported, present, dev, unknown or
    called).
- **Rejections:** reasons are returned to the model, the attempt is stored as `rejected`, and
  there are at most 3 attempts per finding.
- **Second validation:** accepted text is applied to findings only through
  `Finding.rationale`, whose validator re-checks the citations.

## D8-04 Agent safety controls

- **Tools:** closures over `AgentContext`. Targets, run directory, database and run ID come from
  the CLI, never the model.
  - Discovery and detection take no arguments.
  - Analysis tools are read-only, except `submit_explanations`, which writes only gated records.
- **Untrusted text:** repository-derived text is returned as `untrusted_excerpt`, and every
  system prompt says it is data, not instructions.
- **Built-in filesystem:** `FilesystemMiddleware(tools=["read_file"])` on the default
  StateBackend, an in-state virtual filesystem with no disk access, for the main agent and
  each subagent.
- **Subagents:** the general-purpose subagent is disabled through a harness profile registered
  for the model's provider key.
- **Guards:**
  - `ToolAllowList` middleware on every agent blocks and records any tool call outside its
    list.
  - The main graph's tool node must be exactly {`task`, `read_file`}, or the run refuses to
    start.
  - The recursion limit is 60.
- **Not covered:** the orchestrator cannot apply patches, publish, or reach the network itself.
  Scanners keep their own `unshare -rn` sandbox. A real LLM provider would make network calls
  only from the model client, after opt-in.

## D9-01 Read-only evidence API, built UI and a computed checklist

- **Decision:** Step 9 is a read-only HTTP API over the existing SQLite store plus a static React
  build. It adds no new source of truth.
- **Read-only enforcement:**
  - GET/HEAD only (405 otherwise), no CORS, loopback-only CLI.
  - SQLite opened with URI `mode=ro`.
  - Strict CSP, `nosniff`, `no-referrer`, `frame-ancestors 'none'`.
- **Runs are an allow-list:** a run must already exist in `runs`; no path is taken from the
  client, so `../../etc` is a 404.
- **Graph view:** the API reuses the stored `DependencyGraph` and returns Cytoscape elements.
  - The runtime path (`exclude_dev=True`) is highlighted plus up to 10 other parents for context.
  - Image/config findings have no graph node, so their recorded `dependency_path` is drawn as a
    chain.
- **Checklist:** `guardian.checklist` evaluates the PDF section-10 items from the run files and
  the store. It reports pass/fail/`n/a` with the evidence used, and never assumes a pass. The two
  Day-2 items are `n/a` because Day 1 makes no changes.
- **UI text is data:** React escapes all scanner and repository text; links are built only from
  recognised advisory ID shapes.
- **Approval:** 2026-11-23, "Implement Step 9 and deliver a fully runnable demo".

## D9-02 DeepInfra as the selected external provider

- **Decision:** use DeepInfra through its OpenAI-compatible endpoint.
  - Base URL `https://api.deepinfra.com/v1/openai`, key `DEEPINFRA_API_KEY`.
  - Default model `meta-llama/Llama-3.3-70B-Instruct-Turbo` (tool calling). `--model` overrides
    it.
- **Packaging:** `langchain-openai` is an optional extra (`llm-openai`) in `pyproject.toml` and is
  in `uv.lock`, so `uv sync --locked --extra llm-openai` reproduces the provider client. It is
  not installed into the default environment and the core scanner path has no dependence on it.
- **Why an extra, not a core dependency:** the project starts with external models disabled
  (D8-02). Keeping the client out of the default sync preserves that default while making the
  chosen provider reproducible.
- **Key handling:** the key is read from the environment for the run only. It is never written to
  the store, run artifacts, reports or logs; the trace records only provider and model names.
- **No heuristic fallback:** the provider choice and model come from the CLI, never from code
  guessing. A missing key raises `DEEPINFRA_API_KEY is not set`; a missing package raises a
  provider-package error; both exit 2.
- **Approval:** 2026-11-23, "use deepsinfra provider for llm". The user supplies the key and
  authorizes the finding data (facts and quoted evidence excerpts) sent to DeepInfra.

## D9-03 Live model only, Agent Steps view and a controlled GitHub input

- **No offline model in the product.** `ScriptedModel`, `scripted` and `scripted-hallucinating`
  are removed. `ModelConfig` defaults to DeepInfra and `deepseek-ai/DeepSeek-V4.1-Flash-1017`.
  Tests inject a test-only `FakeChatModel` through `run_agents(..., model=...)` so the graph,
  tools and gate stay covered without network. A missing key is an explicit error, never a
  silent template.
- **Agent Steps instead of the checklist tab.** The UI reads a new `GET /api/agent-steps`
  endpoint built from `agent-trace.json` and `explanations.json`. It shows the orchestrator's
  `task` delegation, every tool call with arguments and result size, and accepted/rejected/blocked
  counts. The deterministic `guardian.checklist` is still computed and exposed at
  `/api/checklist` for audits, but it is no longer a UI tab.
- **One controlled write endpoint.** `POST /api/runs` is the only non-GET route. Everything else
  remains read-only. The job runs in a single-worker executor, so repositories are scanned one at
  a time.
- **Dynamic targets** (`guardian.targets`):
  - Only `https://github.com/<owner>/<repo>` is accepted; no credentials, query, fragment or
    extra path, and no `file://`/SSH URLs.
  - Clone with fixed argv and a fixed environment: depth 1, no tags, no hooks, no LFS smudge, no
    submodules, symlinks disabled, 5-minute timeout, 1 GiB working-tree cap.
  - The resolved commit is recorded, Git metadata is removed, the tree is made read-only and the
    target is registered in `targets/dynamic.json` (git-ignored).
  - Only npm projects with `package.json` and `package-lock.json` v2/v3 are accepted. A dynamic
    target has no base commit, so the diff-only anomaly rules are skipped; its base image is
    scanned only when it is already in the local OCI cache. Posture tools skip a missing
    Dockerfile/workflow set instead of failing the scan.
- **Why:** the user asked for a live DeepInfra-only path, the agent's actual steps rather than a
  static checklist, and the ability to point the guardian at an arbitrary GitHub repository.
- **Approval:** 2026-11-23, the revision instruction quoted in `PROGRESS.md`.


## D10-01 Agentic architecture: supervisor and specialists replace the fixed pipeline
- **Decision:** a Deep Agents supervisor plans, delegates to specialists with per-role tool
  rosters and step limits, replans, and stops on goal, budget or a human gate. The old fixed
  orchestrator and the mock model were deleted; `baseline()` remains only as a fixed composition
  of the same stages for regression.
- **Why:** AGENTS.md requires control flow from agent decisions and a live model only.
- **Controls:** deterministic gates (explanation, hypothesis grounding, report), a verifier role,
  budgets (steps, tool calls, seconds, tokens, optional USD), an append-only ledger.

## D10-02 Sandbox policy
- Untrusted code runs only in a container (`--network none`, read-only, caps dropped, digest-pinned
  image); no host fallback. `sbx` is detection only. Docker runtime is unverified here.

## D10-03 Evidence UI
- Same-origin React UI with live agent timeline, graph overview (focused subgraph, truncation
  stated), SBOM table, safe Markdown renderer. Not browser-verified here.

## D11-01 Day 2: deterministic proposals, human-only approval
- **Decision:** proposal action, target version, edits, compatibility and rollback are computed
  from tool-reported fix versions; an agent may only add a grounded justification. Approval is a
  separate gate (`decide`) with a named approver, a timestamp and the SHA-256 of the exact
  proposal; proposals, approvals and validations are append-only (schema v4 triggers). Agents
  have no approve tool; the API needs a per-server token plus loopback Host/Origin.
- **Why:** AGENTS.md section 2 (approval required) and section 4 (no invented versions).

## D11-02 Validation verdicts are conservative
- `verified` needs: finding gone, no new Critical/High, build and tests passed, SBOM diff
  explained. Build/tests need a sandbox and are `not_run` here, so the best verdict is
  `partially_verified`. Lockfile regeneration is the only networked step, opt-in
  (`GUARDIAN_ALLOW_REGISTRY_ACCESS=1`), `--ignore-scripts`, clean environment.

## D11-03 Confidence is computed, not asserted
- `finding_confidence` derives high/medium/low from scanner agreement, factor coverage and
  heuristic vs confirmed evidence, and lists the reasons.
