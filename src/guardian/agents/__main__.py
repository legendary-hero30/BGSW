"""``python -m guardian.agents`` is the same CLI as ``python -m guardian``."""

import sys

from guardian.cli import main

sys.exit(main())
