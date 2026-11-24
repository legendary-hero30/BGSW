"""CLI:  uv run --locked python -m guardian.api [--port 8000] [--db runs/guardian.db]

Serves the API and the built UI (ui/dist) on loopback only. The one controlled POST endpoint
starts a scan of a GitHub repo; its DeepInfra explanation needs DEEPINFRA_API_KEY and
GUARDIAN_ALLOW_EXTERNAL_MODELS=1 in this process's environment.
"""

from __future__ import annotations

import argparse
import os
import sys

from guardian.envfile import load_env
from guardian.log import setup as setup_logging

LOOPBACK = {"127.0.0.1", "localhost", "::1"}


def main(argv: list[str] | None = None) -> int:
    setup_logging()
    load_env()  # settings from the git-ignored .env; real environment variables win
    p = argparse.ArgumentParser(prog="guardian.api")
    p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--port", type=int, default=8000)
    p.add_argument("--db", default="runs/guardian.db")
    a = p.parse_args(argv)
    if a.host not in LOOPBACK:
        print(
            f"refused: {a.host} is not a loopback address (the API is local-only)", file=sys.stderr
        )
        return 2
    if os.environ.get("GUARDIAN_ALLOW_EXTERNAL_MODELS") != "1" or not os.environ.get(
        "DEEPINFRA_API_KEY"
    ):
        print(
            "warning: DeepInfra is not configured in this process; repository scans will run "
            "but the agent explanation step will report an error. Set "
            "GUARDIAN_ALLOW_EXTERNAL_MODELS=1 and DEEPINFRA_API_KEY.",
            file=sys.stderr,
        )

    import uvicorn

    from guardian.api.app import create_app

    uvicorn.run(create_app(a.db), host=a.host, port=a.port, log_level="info")
    return 0


if __name__ == "__main__":
    sys.exit(main())
