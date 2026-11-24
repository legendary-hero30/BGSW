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


def test_build_steps_attributes_each_step_to_the_agent_that_ran_it():
    """The agent is recorded by the runtime, never inferred from the tool name."""
    steps = build_steps(
        [
            {"agent": "supervisor", "tool": "task", "args": {"subagent_type": "risk"}},
            {"agent": "risk", "tool": "list_findings", "args": {"limit": 10}, "result_chars": 2},
            {"agent": "forensics", "tool": "list_findings", "args": {}, "result_chars": 3},
            {"agent": "risk", "tool": "get_finding", "args": {}, "error": True},
        ]
    )
    assert [s["agent"] for s in steps] == ["supervisor", "risk", "forensics", "risk"]
    assert steps[0]["subagent"] == "risk" and steps[1]["subagent"] is None
    assert [s["n"] for s in steps] == [1, 2, 3, 4]
    assert [s["error"] for s in steps] == [False, False, False, True]


def test_build_steps_tolerates_missing_fields():
    steps = build_steps([{"tool": "task"}, {"tool": "unknown"}])
    assert steps[0]["subagent"] is None and steps[1]["agent"] == "supervisor"
    assert steps[0]["result_chars"] == 0 and steps[0]["args"] == {}
