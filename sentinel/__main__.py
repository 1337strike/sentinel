"""Entry point for ``python -m sentinel``."""

from __future__ import annotations

import sys

from sentinel.cli import main

if __name__ == "__main__":
    sys.exit(main())
