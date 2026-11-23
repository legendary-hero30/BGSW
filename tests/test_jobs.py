"""The background job state machine for a user-supplied repository (no network)."""

import pytest

from guardian.agents.models import ModelDisabledError
from guardian.api import jobs
from guardian.targets import DynamicTargetError


def new_job():
    return {
        "id": "job-1",
        "repo": "https://github.com/a/b",
        "status": "queued",
        "step": "Queued",
        "run_id": None,
        "error": None,
        "steps": [],
        "accepted": 0,
        "rejected": 0,
        "blocked": 0,
        "findings": None,
        "created": "2026-11-23T00:00:00+00:00",
        "finished": None,
    }


def test_job_clones_scans_and_records_explanations(monkeypatch):
    job = new_job()
    monkeypatch.setattr(
        jobs, "prepare_target", lambda repo, progress=None: {"name": "a__b-1", "commit": "c" * 40}
    )
    monkeypatch.setattr(
        jobs,
        "baseline",
        lambda name, run_dir, db: {"findings": 2, "store": {"run_id": run_dir}},
    )
    monkeypatch.setattr(
        jobs,
        "run_agents",
        lambda ctx, cfg, mode: {"final": "done", "blocked_tool_calls": [], "tool_calls": 0},
    )
    monkeypatch.setattr(
        jobs,
        "export",
        lambda ctx, cfg, outcome: {"accepted": [1], "rejected": [], "blocked_tool_calls": []},
    )
    jobs.run_repo_job(job, "https://github.com/a/b", "runs/guardian.db")
    assert job["status"] == "done" and job["error"] is None
    assert job["run_id"] == "runs/a__b-1" and job["findings"] == 2
    assert job["accepted"] == 1 and job["finished"]


def test_job_keeps_the_scan_when_the_model_is_not_configured(monkeypatch):
    job = new_job()
    monkeypatch.setattr(
        jobs, "prepare_target", lambda repo, progress=None: {"name": "a__b-2", "commit": "c" * 40}
    )
    monkeypatch.setattr(
        jobs, "baseline", lambda name, run_dir, db: {"findings": 1, "store": {"run_id": run_dir}}
    )

    def no_model(ctx, cfg, mode):
        raise ModelDisabledError("DEEPINFRA_API_KEY is not set")

    monkeypatch.setattr(jobs, "run_agents", no_model)
    jobs.run_repo_job(job, "https://github.com/a/b", "runs/guardian.db")
    assert job["status"] == "done"
    assert job["error"] == "DEEPINFRA_API_KEY is not set"
    assert job["run_id"] == "runs/a__b-2"


def test_job_reports_clone_errors(monkeypatch):
    job = new_job()

    def broken(repo, progress=None):
        raise DynamicTargetError("only npm projects are supported")

    monkeypatch.setattr(jobs, "prepare_target", broken)
    jobs.run_repo_job(job, "https://github.com/a/b", "runs/guardian.db")
    assert job["status"] == "error"
    assert "only npm projects" in job["error"] and job["finished"]


def test_job_skips_the_model_when_there_are_no_findings(monkeypatch):
    job = new_job()
    monkeypatch.setattr(
        jobs, "prepare_target", lambda repo, progress=None: {"name": "a__b-3", "commit": "c" * 40}
    )
    monkeypatch.setattr(
        jobs, "baseline", lambda name, run_dir, db: {"findings": 0, "store": {"run_id": run_dir}}
    )

    def must_not_run(ctx, cfg, mode):
        pytest.fail("the model must not run when there are no findings")

    monkeypatch.setattr(jobs, "run_agents", must_not_run)
    jobs.run_repo_job(job, "https://github.com/a/b", "runs/guardian.db")
    assert job["status"] == "done" and "no findings" in job["step"]
