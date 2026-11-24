"""The background job state machine for a user-supplied repository.

These tests exercise the job's own status handling. The clone, scan and agent-run boundaries are
replaced by recorded return values; nothing here simulates an agent or a model. The live agent
run is covered by the opt-in test in tests/test_agents_live.py.
"""

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


def target(name):
    return lambda repo, progress=None: {"name": name, "commit": "c" * 40}


def test_completed_agent_run_is_recorded(monkeypatch):
    job = new_job()
    monkeypatch.setattr(jobs, "prepare_target", target("a__b-1"))
    seen = {}

    def run_goal(name, **kw):
        seen.update(kw, name=name)
        kw["on_event"]({"agent": "supervisor", "tool": "task", "args": {"subagent_type": "risk"}})
        kw["on_event"]({"agent": "risk", "tool": "build_findings", "args": {}, "error": True})
        return {
            "status": "completed",
            "stop_reason": None,
            "run_id": "runs/a__b-1",
            "findings": 7,
            "explanations": {"accepted": 3, "rejected": 1},
            "blocked_tool_calls": [],
        }

    monkeypatch.setattr(jobs, "run_goal", run_goal)
    jobs.run_repo_job(job, "https://github.com/a/b", "runs/guardian.db")
    assert job["status"] == "done" and job["error"] is None and job["finished"]
    assert job["run_id"] == "runs/a__b-1" and job["findings"] == 7
    assert (job["accepted"], job["rejected"], job["blocked"]) == (3, 1, 0)
    assert [s["tool"] for s in job["steps"]] == ["task", "build_findings"]
    assert job["steps"][0]["subagent"] == "risk" and job["steps"][1]["error"] is True
    assert seen["name"] == "a__b-1" and seen["out_dir"] == "runs/a__b-1"
    assert seen["limits"].max_steps >= 1 and seen["sandbox"] == "auto"


@pytest.mark.parametrize("status", ["budget_exhausted", "error", "incomplete"])
def test_unfinished_agent_runs_are_errors_with_the_reason(monkeypatch, status):
    job = new_job()
    monkeypatch.setattr(jobs, "prepare_target", target("a__b-2"))
    monkeypatch.setattr(
        jobs,
        "run_goal",
        lambda name, **kw: {
            "status": status,
            "stop_reason": "the reason",
            "run_id": "r",
            "blocked_tool_calls": [],
        },
    )
    jobs.run_repo_job(job, "https://github.com/a/b", "runs/guardian.db")
    assert job["status"] == "error" and job["error"] == "the reason"
    assert status in job["step"]


def test_without_a_model_the_job_falls_back_to_the_scanner_baseline(monkeypatch):
    job = new_job()
    monkeypatch.setattr(jobs, "prepare_target", target("a__b-3"))

    def no_model(name, **kw):
        raise ModelDisabledError("DEEPINFRA_API_KEY is not set")

    monkeypatch.setattr(jobs, "run_goal", no_model)
    monkeypatch.setattr(
        jobs, "baseline", lambda name, run_dir, db: {"findings": 4, "store": {"run_id": run_dir}}
    )
    jobs.run_repo_job(job, "https://github.com/a/b", "runs/guardian.db")
    assert job["status"] == "done" and job["findings"] == 4
    assert job["error"] == "DEEPINFRA_API_KEY is not set"
    assert "no agent run" in job["step"]
    assert job["steps"] == []  # nothing is presented as agent work


def test_clone_errors_are_reported(monkeypatch):
    job = new_job()

    def broken(repo, progress=None):
        raise DynamicTargetError("only npm projects are supported")

    monkeypatch.setattr(jobs, "prepare_target", broken)
    jobs.run_repo_job(job, "https://github.com/a/b", "runs/guardian.db")
    assert job["status"] == "error"
    assert "only npm projects" in job["error"] and job["finished"]


def test_unexpected_errors_fail_the_job_loudly(monkeypatch):
    job = new_job()
    monkeypatch.setattr(jobs, "prepare_target", target("a__b-4"))

    def boom(name, **kw):
        raise RuntimeError("scanner exploded")

    monkeypatch.setattr(jobs, "run_goal", boom)
    jobs.run_repo_job(job, "https://github.com/a/b", "runs/guardian.db")
    assert job["status"] == "error" and "scanner exploded" in job["error"]
