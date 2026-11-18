"""The one HTTP response for image bytes, whichever capability admitted the read."""

from aweb_naapp.runtime.app import NOINDEX_ROBOTS_HEADER
from fastapi.responses import Response

from folio.repository import TeamImage


def image_response(image: TeamImage) -> Response:
    """Serve an image as private user content (docs/sot.md §1, Images).

    no-store keeps a revoked or uninstalled capability from living on in a cache;
    nosniff pins the browser to the uploaded, magic-checked content type.
    """
    return Response(
        content=image.content,
        media_type=image.content_type,
        headers={
            "Cache-Control": "no-store",
            "X-Content-Type-Options": "nosniff",
            "X-Robots-Tag": NOINDEX_ROBOTS_HEADER,
        },
    )
