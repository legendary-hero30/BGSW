"""Dynamic GitHub target validation and the agent-step mapping."""

import pytest

from guardian.agents.trace import build_steps
from guardian.targets import DynamicTargetError, parse_repo


@pytest.mark.parametrize(
    ("url", "expected"),
    [
        ("https://github.com/OWASP/NodeGoat", ("OWASP", "NodeGoat")),
        ("https://github.com/OWASP/NodeGoat/", ("OWASP", "NodeGoat")),
        ("https://github.com/OWASP/NodeGoat.git", ("OWASP", "NodeGoat")),
        ("  https://github.com/a/b  ", ("a", "b")),
        ("https://github.com/a/b.c_d-e", ("a", "b.c_d-e")),
    ],
)
def test_parse_repo_accepts_plain_github_urls(url, expected):
    assert parse_repo(url) == expected


@pytest.mark.parametrize(
    "url",
    [
        "",
        "http://github.com/a/b",
        "git://github.com/a/b",
        "https://gitlab.com/a/b",
        "https://github.com/../b",
        "https://github.com/a/..",
        "https://github.com/a/.",
        "https://github.com/a",
        "https://github.com/a/b/tree/main",
        "https://github.com/a/b?ref=main",
        "https://github.com/a/b#readme",
        "https://user:pass@github.com/a/b",
        "https://github.com/-a/b",
        "https://github.com/a/b c",
        "ssh://git@github.com/a/b.git",
    ],
)
def test_parse_repo_rejects_anything_but_plain_github_urls(url):
    with pytest.raises(DynamicTargetError):
        parse_repo(url)


def test_build_steps_maps_tools_to_agents():
    steps = build_steps(
        [
            {"tool": "task", "args": {"subagent_type": "analysis"}, "result_chars": 1},
            {"tool": "list_findings", "args": {"limit": 10}, "result_chars": 2},
            {"tool": "get_finding", "args": {"finding_id": "F-001"}, "result_chars": 3},
            {"tool": "submit_explanations", "args": {"count": 1}, "result_chars": 4},
            {"tool": "run_detection", "args": {}, "result_chars": 5},
        ]
    )
    assert [s["agent"] for s in steps] == [
        "orchestrator",
        "analysis",
        "analysis",
        "analysis",
        "detection",
    ]
    assert steps[0]["subagent"] == "analysis"
    assert [s["n"] for s in steps] == [1, 2, 3, 4, 5]


def test_build_steps_tolerates_missing_args():
    steps = build_steps([{"tool": "task"}, {"tool": "unknown"}])
    assert steps[0]["subagent"] is None
    assert steps[1]["agent"] == "orchestrator"
    assert steps[0]["result_chars"] == 0
