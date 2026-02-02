"""aweb (Agent Web) package."""

from .cli import app

__all__ = ["app", "main"]


def main() -> None:
    app()
