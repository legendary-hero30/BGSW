# Project plan: Software Supply Chain Guardian

Source: *Software Supply Chain Guardian: Pipeline, Methodology, Plan & Tech Stack* (PDF in this
workspace, 17 pages, dated 2026-11-23). Text was extracted with a stdlib-only script; the three
diagrams (pages 3, 4, 13) are images and only their captions were read.

## Goal

An agentic AI "guardian" that finds supply-chain risk in a real open-source app. Day 1 explains
the risk with evidence; Day 2 proposes, applies (on a branch, after human approval) and
validates fixes. The deliverable is a traceable chain: repository → SBOM → dependency graph →
risk detection → evidence.

Day 1 checkpoint: *"Show us what is in the application, what changed, and what appears risky."*

## Core rules (from the PDF)

- Deterministic tools produce facts; the LLM only reasons over stored facts.
- Structured, schema-validated output only. Every claim cites an evidence ID that resolves.
- CVE IDs, fix versions and package names come only from OSV, NVD or registry data.
- Repository content is untrusted data and never grants tool authority.
- A human approval gate precedes any patch apply or merge; no auto-merge, deploy or publish.
- Scanner-only baseline first; it is also the fallback demo.

## Architecture

- **Orchestration:** LangChain Deep Agents (compiled LangGraph graph). See DECISIONS.md D1-01.
- **Agents:** an orchestrator plus five specialists. Day 1 uses Discovery, Detection and
  Analysis; Remediation and Validation are Day 2.
- **Stack:** Python 3.12, FastAPI, Pydantic, CycloneDX 1.5, Syft/cdxgen, Grype/OSV-Scanner/Trivy,
  Hadolint, zizmor, React UI. Dependencies are approved one step at a time.

## Day 1 roadmap (provisional; each step needs explicit approval)

| Step | Scope | Status |
|---|---|---|
| D1.S1 | Project skeleton, data contracts, risk scoring, unit tests | Complete |
| D1.S2 | Choose and pin the sample app; install pinned scanners; cache vulnerability DBs, EPSS and KEV | Complete, except the Docker daemon is not running |
| D1.S3 | SBOM generation (CycloneDX 1.5), parsing, dependency graph, dependency paths | Complete |
| D1.S4 | Grype, OSV, Trivy runners; normalize findings; trace transitive CVEs (scanner-only baseline) | Complete |
| D1.S5 | Container image and CI workflow inspection | Complete (base image scanned without Docker) |
| D1.S6 | Anomaly rules plus a seeded fork branch (inert, labeled synthetic) | Complete |
| D1.S7 | Apply risk score v1; persistent evidence store | Complete (SQLite) |
| D1.S8 | Deep Agents orchestrator and specialists, citation verifier, provider config (paid calls off) | Complete (the original offline fixture was removed in the S9 revision; live model only) |
| D1.S9 | FastAPI, evidence cards, graph view, Agent Steps and a GitHub repository input | Complete (live DeepInfra-only model path; scan/agent UI; dynamic clone; live call pending key) |

Day 2 (remediation, approval gate, rebuild, rescan, report) is out of scope until approved.
