"""Snapshot transaction: restore proof before publishing or deleting the old base.

Operations must create candidate images under protected base labels outside the
transient run selector. Failed candidates are reported, never auto-deleted.
"""

from .errors import Infrastructure
from .signals import handling


def rebuild(operations):
    image = None
    result = None
    error = None
    try:
        operations.reserve()
        builder = operations.builder()
        operations.install(builder)
        image = operations.seal(builder)
        operations.delete_vm(builder)
        restored = operations.restore(image)
        manifest = operations.verify(restored)
        operations.delete_vm(restored)
        operations.publish_config(image, manifest)
        operations.delete_old()
        result = {"snapshot": image, "verified": True}
    except BaseException as exc:
        error = exc
    finally:
        try:
            with handling(cleanup=True):
                operations.cleanup()
                operations.settle()
        except BaseException as exc:
            error = Infrastructure(
                "snapshot cleanup/settlement failed: " + type(exc).__name__
            )
        if error is not None:
            error.snapshot = image
            raise error
    return result
