from __future__ import annotations

import uvicorn

from folio.config import get_settings


def main() -> None:
    """Run the development server."""

    get_settings()  # validate env early
    uvicorn.run("folio.api:app", host="127.0.0.1", port=8765, reload=False)


if __name__ == "__main__":
    main()
