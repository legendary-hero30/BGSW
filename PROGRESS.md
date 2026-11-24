# Progress

## Workspace state found on 2026-11-23

- `/home/suthekshan/bosch` contained only `AGENTS.md` and the project PDF.
- `AGENTS.md` describes Day 0 work that is **not present** here:
  - Documents: `PROJECT_PLAN.md`, `PROGRESS.md`, `DECISIONS.md`, `SETUP.md`, `TEST_RESULTS.md`,
    `LLM_PROVIDERS.md`.
  - Environment and Git: `.venv` (3.12.14), `.guardian-git`, and the `origin` remote.
- It also says the PDF "has not been supplied". The PDF is now present and was read.
- Day 1 started fresh in this directory. `AGENTS.md` was not edited.

## Approval history

| Date | Approval | Scope |
|---|---|---|
| 2026-11-23 | "start execution of Day 1, Step 1" | D1.S1 as proposed: skeleton, contracts, scoring, tests, docs; pydantic, pytest, ruff; D1-02 to D1-04 scoring decisions |
| 2026-11-23 | "start execution of Day 1, Step 2" | D1.S2 as proposed: app shortlist and clone, pinned scanner binaries in tools/bin, DB/EPSS/KEV caching, Docker check |
| 2026-11-23 | "start execution of Day 1, Step 3" | D1.S3, given before D1.S2 finished. Only the D1.S2 parts D1.S3 needs were completed first. No detailed D1.S3 proposal was shown beforehand, so the roadmap line was the scope. |
| 2026-11-23 | "start execution of Day 1, Step 4" | D1.S4. It was answered to "approve finishing Day 1, Step 2 and then executing Day 1, Step 4?", so finishing the D1.S2 caches was treated as part of the approval. |
| 2026-11-23 | "start execution of Day 1, Step 5" | D1.S5. No image option was chosen and Docker was still not running, so option (b) was used: pull only the base image from Docker Hub, digest-verified, then scan offline. |
| 2026-11-23 | "start execution of Day 1, Step 6 use a)" | D1.S6 with a downloaded popular-package list. The exact source was then chosen by the user in a follow-up question: npm-high-impact 1.13.0 from registry.npmjs.org, SHA-512 verified. |
| 2026-11-23 | "start execution of Day 1, Step 7 use SQLite" | D1.S7 with SQLite (stdlib `sqlite3`, no new dependency) as the evidence store. |
| 2026-11-23 | "start execution of Day 1, Step 8" | D1.S8 as proposed, including the deepagents/LangChain dependencies. No provider was named, so only the offline scripted model was used, with no external calls. Unknown-factor rescaling was kept (the recommended default). |
| 2026-11-23 | "Implement Step 9 and deliver a fully runnable demo" + "use deepsinfra provider for llm" | D1.S9 completion (read-only API, evidence-card UI, dependency-path highlight, Day-1 self-checklist), README/RUN/Makefile/demo runner, the optional `llm-openai` extra and the DeepInfra provider path with a default tool-calling model. Also authorizes the external call to DeepInfra when its key is supplied. |
| 2026-11-23 | "instead of Day 1 checklist give it as agent steps ... drop all the scriptable scripted model ... give an input box where they can input a github repo" | D1.S9 revision: Agent Steps tab (replaces the checklist tab), the scripted/mock model removed from the product (DeepInfra-only, test-only fake in tests), and the GitHub repository input with a controlled `POST /api/runs` job. |

## Steps

### D1.S1: project skeleton and contracts (complete)

- `uv` Python 3.12 project. Package `guardian` lives in `src/guardian`.
- `guardian.schemas`: evidence records and references, SBOM components, dependency graph, risk
  factors and assessment, findings, and finding sets.
- `guardian.scoring.score_risk`: the PDF formula, plus decisions D1-02 to D1-04.
- 75 unit tests pass, and ruff is clean (see TEST_RESULTS.md).

### D1.S2: sample app and scanners (complete, except Docker)

Done:
- **Sample app:** OWASP NodeGoat at `c5cb68a7084e4ae7dcc60e6a98768720a81841e8`.
  - Cloned with Git hooks disabled, then made read-only.
  - Registered in `targets/targets.json`.
  - Chosen as the default recommendation, because the user had not picked one (D2-02).
- **Scanners:** six pinned binaries in `tools/bin`: Syft 1.57.2, Grype 0.121.3, OSV-Scanner 2.7.1,
  Trivy 0.76.2, Hadolint 2.15.1 and zizmor 1.32.0.
  - All passed SHA-256 verification and report the pinned version (D2-01).

Finished at the start of D1.S4:
- **Caches** (about 5.3 GB in `cache/`):
  - Grype DB (schema v6.1.10, built 2026-11-23T06:28Z): 3.4 GB
  - Trivy DB (v2, updated 2026-11-23T07:04Z): 1.7 GB
  - OSV npm offline data: 212 MB
  - EPSS (score date 2026-11-22, about 411k CVEs)
  - CISA KEV (catalog 2026.11.20, 1,790 entries)
- **Offline check:** all four scanners ran inside an empty network namespace (`unshare -rn`),
  where even DNS fails.

Outstanding:
- The Docker CLI is present but its daemon is not running (`/var/run/docker.sock` is missing).
  It was not started. Image build and scan (D1.S5) need it.

### D1.S3: SBOM and dependency graph (complete)

- **SBOM:** `python -m guardian.sbom build --target nodegoat --out runs/d1s3` writes a CycloneDX
  1.5 SBOM (Syft), `graph.json` and `summary.json`.
- **NodeGoat results:**
  - Graph: 1,480 nodes (the root plus 1,479 install paths), 2,295 edges, max depth 13.
  - Packages: 380 unique runtime and 790 unique dev.
  - Direct dependencies: 16 runtime and 20 dev, which match `package.json`.
  - Every node is reachable from the root, and no required dependency is unresolved.
  - Cross-check: the lockfile graph and the Syft SBOM agree exactly (381 vs 381 unique runtime
    name@version, root included).
- **Discovery:** found 2 manifests, 1 Dockerfile, 1 compose file and 2 CI workflows. Syft also
  lists 4 tag-pinned GitHub Actions, inputs for the D1.S5 unpinned-CI rule.
- **Path queries:** `python -m guardian.sbom path --graph ... --package <name>` returns:
  - the dependency path (through runtime packages only, for runtime packages)
  - the direct dependencies that pull the package in
  - a `package-lock.json:<line>` evidence location

### D1.S4: scanner-only baseline (complete)

- **Command:** `python -m guardian.scan baseline --target nodegoat --out runs/d1s4`. It runs:
  1. the D1.S3 build
  2. Grype (on an SBOM that includes dev packages), Trivy and OSV-Scanner, all offline
  3. correlation of GHSA, CVE and other aliases for each name@version
  4. EPSS and KEV enrichment
  5. mapping onto the graph
  6. schema-validated findings, `baseline.md`, and an independent citation check
- **NodeGoat result:**
  - 324 findings over 133 packages: 93 runtime, 231 dev-only.
  - Types: 1 malicious package, 20 vulnerable direct, 303 vulnerable transitive.
  - Severity: 34 critical, 173 high, 97 medium, 20 low.
  - 312 findings have a fix version; 0 are in KEV.
- **Scanner agreement:** 310 of 324 advisory groups were found by all three scanners. 13 are
  Trivy-only NSWG advisories with no alias, so they can't be linked to the others. 1 (the
  fsevents malware) was found by Grype and OSV.
- **Genuine non-CVE anomaly:** `fsevents@1.2.9` matches MAL-2023-462 / GHSA-xv2f-5jw4-v95m
  (embedded malicious code, a real 2023 incident). It is reached in production through
  `forever@2.0.0`. It is a macOS-only optional package, absent on Linux.
- **Vulnerable direct dependencies:** `marked@0.3.5` (7 advisories), `body-parser@1.18.3`,
  `grunt@1.0.3`, `express@4.16.4`, `underscore@1.9.1`, `async@2.6.1`, `swig@1.4.2` and
  `mongodb@2.2.36`.
- **Citation check:** 7,335 of 7,335 cited facts resolve to raw tool output (100%). These are
  advisory IDs, package versions, JSON pointers, lockfile lines, graph paths, fix versions and
  `introduced_by`.

### D1.S5: container image and CI/CD inspection (complete)

- **Image:** `scripts/fetch_image.py` pulled `docker.io/library/node:12-alpine` for linux/amd64.
  - Manifest `sha256:4517380049fc…9498`, 4 layers, 30 MB.
  - Every blob was SHA-256-verified, then stored as an OCI layout in `cache/images/`.
  - Recorded in `targets/images.json`. No Docker daemon was needed.
  - It is the Dockerfile's base image (both `FROM` lines), not a build of NodeGoat's own image.
- **One command:** `python -m guardian.scan baseline --target nodegoat --out runs/d1s5` now also
  runs, all offline:
  - Trivy and Grype on the image
  - Hadolint and `trivy config` on the Dockerfile
  - zizmor on the workflows
  - guardian rules for image and CI pinning, latest/missing tags, root user and risky triggers
- **NodeGoat result:** 407 findings in total, which is the 324 dependency findings plus:
  - 70 vulnerable image packages. 69 of 70 groups are confirmed by both Trivy and Grype; Grype's
    144 CPE-only matches were excluded.
  - 8 unpinned/unsafe CI findings. All 6 tag-pinned actions are confirmed by both zizmor and
    GR-CI-001. 2 jobs have excessive permissions (zizmor).
  - 3 untrusted-image findings: `node:12-alpine` is not digest-pinned at Dockerfile lines 1 and
    7, and Trivy flags the base OS, Alpine 3.15.4, as end-of-service-life.
  - 2 misconfigurations: no HEALTHCHECK (Trivy DS-0026) and a non-numeric USER (Hadolint DL3066).
- **Citation check:** 8,782 of 8,782 cited facts resolve (100%).
- **Suspected false positive, kept as reported:** Grype matches `npm-cli-docs@0.1.0` in the image
  to GHSA-mwpr-cgch-q8vc, "Malware in npm-cli-docs". The matched file is
  `/usr/local/lib/node_modules/npm/docs/package.json`, which is npm's own bundled docs folder. It
  was read from the verified layer: name `npm-cli-docs`, description "npm cli docs", no
  `private` flag. This looks like a registry name collision, not a registry install. It was not
  suppressed; checking provenance is D1.S6/S7 work.
- **Outstanding:** Docker is still not running, so NodeGoat's own image was not built or scanned.

### D1.S6: anomaly rules and the seeded fork (complete)

- **Popular list:** `scripts/fetch_toplist.py` fetched `npm-high-impact` 1.13.0, the user's
  choice. It is SHA-512 verified against the pinned integrity, and only `lib/top.js` is read, as
  text (17,338 names). Saved to `cache/toplists/`.
- **Seeded fork:** `scripts/seed_anomalies.py` made `targets/nodegoat-seeded`.
  - Local clone with no remote, branch `seeded-anomalies`, commit `bb57ba2`, read-only.
  - Labelled SYNTHETIC in the commit message, `SEEDED.md` and the package names.
  - Scenarios S3 to S8: typosquat `expresss`; inert postinstall package; lookalike registry host
    for `marked`; changed `ms` integrity; a minor bump adding 3 transitive packages;
    `FROM node:latest` running as root; `pull_request_target` with checkout.
  - The mock registry is metadata in `targets/mock-registry/`. Ground truth is in
    `targets/seeded-ground-truth.json`. Nothing is installed, executed, pushed or published.
- **Anomaly rules** in `guardian.scan.anomaly`: GR-TYPO-001, GR-INST-001/002, GR-LOCK-001/002/
  004/005 and GR-DEP-001/002. They are part of the baseline command; the diff rules run against
  the base commit for targets with a `base_target`.
- **Evaluation** (`python -m guardian.scan evaluate`):
  - Seeded recall: **10/10**.
  - Real recall: **4/4** (direct CVE `marked`, transitive CVE `bson`, malicious `fsevents`,
    tag-pinned `actions/checkout`).
  - Precision on findings new to the seeded run: **20/20**.
  - Verification: 100% on both runs (8,835 and 7,853 cited facts).
- **Clean app anomaly and posture findings (21, reviewed):**
  - **17 valid:**
    - `grunt-if` resolved from the GitHub `tarball/master` branch (dev): a real
      mutable-source finding.
    - 3 install scripts (cypress, nodemon, fsevents).
    - 6 tag-pinned actions and 2 excessive permissions.
    - The end-of-life base OS and 2 undigested `FROM` lines.
    - 2 hygiene items.
  - **4 false positives**, all low severity at distance 2 from a popular name: `pad-stream`,
    `lodash.rest`, `node-eta` and `director`. Without registry age or download data, a
    name-only heuristic cannot rule these out.

### D1.S7: risk score v1 and the SQLite evidence store (complete)

- **App context** (`guardian.scan.context`):
  - **Imports:** static `require`/`import` lines in server code. Browser assets and test/tooling
    files are excluded.
  - **Resolution:** each import is resolved to the copy Node would load (top-level
    `node_modules/<name>`).
  - **Network-facing facts:** `server.js:145`, `server.js:152` and `Dockerfile:18 EXPOSE 4000`.
  - **Dynamic requires:** 2, both local config paths.
- **Factors:**
  - Reachability: imported 60, present only 30, dev-only unused 0. "Called" (100) is never
    claimed.
  - Exposure: network 100, internal 50, build/dev 20.
  - Provenance comes from a rule-points table over anomaly rules on the same component.
  - Each factor cites evidence; the score is `score_risk()`.
- **Ranking:** findings are now ordered by risk (forced Critical first).
- **Store:** `runs/guardian.db` holds runs, evidence, findings, finding↔evidence links and the
  graph. Saving replaces a run atomically, findings round-trip exactly, and foreign keys are on.
- **NodeGoat (clean):**
  - 415 findings: Critical 1 (fsevents, forced), Medium 97, Low 317.
  - Reachability: imported 16, present only 79, dev-only 237, unknown 83 (image and config).
  - The top dependency finding is `underscore@1.9.1` (CVSS 9.8, imported, network-facing):
    57.24, Medium.
  - Verification: 10,127/10,127 (100%), including recomputed factors and scores.
- **Seeded:** Critical 1, High 2, Medium 47, Low 312.
  - The two High findings are `marked` CVEs (72.0): imported, network-facing, and given
    provenance 60 by the seeded lookalike-host lockfile edit. That is the cross-signal
    correlation working.
  - Evaluation unchanged: 10/10, 4/4, 20/20. Verification: 9,082/9,082.
- **Bug caught by the verifier:** `underscore@1.8.3`, a nested dev copy, was first marked
  "imported" because the match was by name only. Imports now resolve to the installed copy and
  cite its lockfile `version` line (GR-REACH-002).
- **Calibration observations:**
  - **Provenance 0 caps ordinary packages:** with no suspicious provenance, an imported package
    tops out at 77 (High), and 85 needs "called". So most real CVEs land in Medium.
  - **Coverage rescaling lifts image packages:** image packages (coverage 0.65) and GHSA-only
    advisories (coverage 0.5) can outrank fully covered app findings. `weight_coverage` is
    stored and shown with every score.

### D1.S8: Deep Agents orchestrator, subagents and explanation gate (complete)

> **Superseded in the D1.S9 revision:** the offline scripted model named below was removed from
> the product. Every run now uses the live DeepInfra model; the test-only fake lives in
> `tests/fake_model.py`.

- **Dependencies:** `deepagents==0.7.38` plus LangChain 1.5.0, LangGraph 1.2.22 and the
  provider SDKs it requires (64 locked packages in total). A project-wide uv `exclude-newer`
  of 2026-11-16 keeps every package at least 7 days old.
- **Version adjustments:** pydantic 2.14.4 → 2.14.3 and ruff 0.17.6 → 0.17.5, because of the
  cutoff.
- **API source:** read from the installed source, because the Subagents and Backends doc pages
  had failed to load.
- **Agents** (`guardian.agents`):
  - An orchestrator that uses `task` to call `discovery`, `detection` and `analysis` subagents.
  - Each agent's tools are closures; the model cannot choose targets, paths or runs.
  - The filesystem is limited to `read_file` on the in-state virtual backend, and the
    general-purpose subagent is disabled.
  - An allow-list middleware runs on every agent. The main graph is checked to expose only
    `task` and `read_file`.
- **Gate** (`agents/gate.py`): an explanation is accepted only if its schema is valid and every
  evidence ID, advisory ID, `pkg@version` and x.y.z version belongs to the finding, and its
  reachability sentence states the computed value. Rejections go back to the model (up to 3
  attempts per finding), are stored as rejected, and are never displayed.
- **Store:** schema v2 adds the `explanations` table. The migration from v1 is additive.
- **Runs, all with the scripted model:**

  | Run | Result |
  |---|---|
  | `analyze --run runs/d1s7` (in `unshare -rn`, no network) | 5/5 accepted |
  | `analyze` with `scripted-hallucinating` on the seeded run | 0/3 accepted; every one rejected for E-9999 and CVE-2099-0001 |
  | `run --target nodegoat --out runs/d1s8` | discovery → detection → analysis; 10/10 accepted; independent verifier 10,127/10,127 |
  | `--provider anthropic` without the opt-in | Refused, exit 2 |

- **Outputs:** `explanations.json`, `explanations.md` and `agent-trace.json` in each run
  directory. Scripted output is labelled "offline scripted template (not an LLM)".

### D1.S9: API, evidence cards, agent steps and a GitHub repository input (complete)

- **API** (`guardian.api`):
  - Reads: `/api/runs`, `/api/summary`, `/api/findings` (type/level/search filters, bounded
    pagination), `/api/findings/{id}`, `/api/graph/{id}`, `/api/agent-steps`, `/api/checklist`,
    `/api/docs`.
  - One controlled write: `POST /api/runs` validates
    `https://github.com/<owner>/<repo>`, queues a background scan and returns a job; `GET
    /api/jobs/{id}` reports phase, live tool calls, run id and errors.
  - Loopback-only CLI; every other non-GET returns 405; the store is opened with SQLite
    `mode=ro`; strict CSP and security headers; no CORS; unknown runs/jobs are 404.
  - The finding card joins the stored evidence order and the latest accepted explanation.
  - The graph endpoint returns Cytoscape elements: the runtime dependency path plus other
    parents of the affected package; image/config findings use their recorded path.
- **UI** (`ui/`): React 19 + TypeScript + Tailwind + Cytoscape.
  - **GitHub repository box** at the top: submits a repo, polls the job and shows clone → scan →
    DeepInfra analysis with the live tool calls.
  - **Findings** tab: run selector, risk-ranked list, filters, evidence card, factor
    contributions, gated explanation and the highlighted dependency graph.
  - **Agent steps** tab (replaces the Day-1 checklist tab): orchestrator/subagent badges, every
    tool call with its arguments and result size, accepted/rejected/blocked counts and the final
    message.
  - `npm run build` (`tsc --noEmit` + Vite) succeeds and the API serves `ui/dist`.
- **Checklist** (`guardian.checklist`): the PDF section-10 self-checklist is still computed and
  exposed at `/api/checklist` for audits. It is no longer a UI tab; the UI shows agent steps.
- **Dynamic GitHub targets** (`guardian.targets`):
  - HTTPS GitHub URLs only; owner/repo pattern; no credentials, query, fragment or extra path.
  - Clone with fixed argv: depth 1, no tags, no hooks, no LFS smudge, no submodules, symlinks
    disabled, 5-minute timeout, 1 GiB working-tree cap.
  - The resolved commit is recorded, `.git` is removed, the tree is made read-only and the target
    is registered in `targets/dynamic.json` (git-ignored).
  - Only npm projects with `package.json` and `package-lock.json` v2/v3 are accepted.
- **Model layer:** the offline `ScriptedModel` and the `scripted`/`scripted-hallucinating`
  providers are **removed from the product**. `ModelConfig` defaults to DeepInfra and
  `deepseek-ai/DeepSeek-V4.1-Flash-1017`; `--model` is optional. Tests inject a test-only
  `FakeChatModel` into `run_agents(..., model=...)`; production never sees it.
- **Demo surface:** `README.md`, `RUN.md`, `Makefile` (`make demo`, `make deepinfra`, `make api`,
  `make test`, `make ui`, ...), `scripts/demo.sh` (DeepInfra-only; refuses without a key) and
  `scripts/deepinfra_demo.sh`.
- **Verified runs:**
  - `baseline --target nodegoat --out runs/demo`: 415 findings, 1,471 evidence records,
    **10,127/10,127 cited facts resolve (100%)**, 0 unmapped.
  - Dynamic clone through the API: `https://github.com/isaacs/node-lru-cache` cloned, scanned
    and stored **74 findings**; the job then reported the missing DeepInfra key instead of
    faking an analysis.
  - **Full UI flow with DeepInfra:** the same repository through `POST /api/runs` completed
    cloning → scanning → analyzing → done with **74 findings, 10 accepted, 1 rejected, 0 blocked
    and 14 tool calls**; the live job steps advanced as the model called its tools.
  - Dynamic clone of `https://github.com/OWASP/NodeGoat` pinned at
    `c5cb68a7...`; scan reproduced 415 findings and 100% citation verification.
  - `POST /api/runs` rejects `http://`, non-GitHub and malformed URLs with 400; `GET
    /api/jobs/{id}` returns the phase and final state.
- **Tests:** **267 unit/contract/API/job tests** pass; 4 real offline integration tests pass
  (197 s). `ruff check` and `ruff format --check` are clean. The UI typechecks and builds.
- **Live DeepInfra verified:** `deepinfra:deepseek-ai/DeepSeek-V4.1-Flash-1017` on
  `runs/OWASP__NodeGoat-20261123T125015Z` produced **10 accepted, 1 rejected attempt, 0 blocked,
  13 tool calls**; the Agent Steps view shows `task(analysis)` + `list_findings` + 10×
  `get_finding` + `submit_explanations`. The rejected attempt mentioned an advisory that was not
  attached to the finding, which is exactly what the gate is for.
- **Remaining:** Day 2 is still out of scope. The dynamic repository path supports npm lockfiles
  v2/v3 only.

### Next proposed: Day 2 (not approved)

Day 2 (remediation recommendation, human approval, rebuild/rescan, before-after report) remains a
separate approved step. A live DeepInfra analysis is already verified on the dynamic NodeGoat run;
re-run it any time with `make deepinfra` or the UI repository box.



## Agentic refactor, UI and Day 2 (2026-11-24)
- Agentic runtime, ledger, budgets, gates, sandbox layer, CLI, evidence UI: done (see D10-*).
- Day 2: confidence, lockfile comparison, deterministic proposals, approval gate (CLI, API, UI),
  isolated-branch validation with offline rescan, SBOM and findings diff, verdicts (D11-*).
- Not done / not verifiable here: build and test execution (no Docker daemon), a real browser
  check of the UI, a human-approved end-to-end validation on NodeGoat (needs an approver and
  `GUARDIAN_ALLOW_REGISTRY_ACCESS=1`; six real proposals R-009..R-014 are stored and waiting).
