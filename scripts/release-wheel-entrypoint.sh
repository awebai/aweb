#!/bin/sh
set -eu
# Materialization includes entrypoint.sh only in wheel mode. A missing manifest
# in that mode must fail, rather than fall back to the developer source mode.
if [ -f "$RELEASE_WHEEL_DIR/entrypoint.sh" ] || [ -f "$RELEASE_WHEEL_DIR/manifest.json" ]; then
    # Package names are controlled by the image, never shell code.
    "$RELEASE_WHEEL_PYTHON" "$RELEASE_WHEEL_DIR/install.py" --check \
        --directory "$RELEASE_WHEEL_DIR" --python "$RELEASE_WHEEL_PYTHON" $RELEASE_WHEEL_PACKAGES
fi
exec "$@"
