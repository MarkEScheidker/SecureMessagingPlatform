"""Entry point for the secure messaging CLI client."""

from __future__ import annotations

import pathlib
import sys


def _bootstrap() -> None:
    """Ensure package imports resolve whether run as module or script."""
    if __package__ in {None, ""}:
        root = pathlib.Path(__file__).resolve().parent
        parent = root.parent
        if str(parent) not in sys.path:
            sys.path.insert(0, str(parent))
        module = "client.cli.main"
    else:
        module = ".cli.main"

    global main  # noqa: PLW0603
    if module.startswith("."):
        from .cli.main import main  # type: ignore[import-not-found]
    else:
        from client.cli.main import main  # type: ignore[import-not-found]


_bootstrap()


if __name__ == "__main__":
    main()
