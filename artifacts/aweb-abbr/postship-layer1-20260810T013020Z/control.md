# Loader-control calibration

The initial run stopped before the request-count assertion:

```text
AssertionError: channel-1.7.5: loader did not import the observable shipped copy
actual:   file:///private/tmp/.../channel-1.7.5-shipped-observable.mjs
expected: file:///tmp/.../channel-1.7.5-shipped-observable.mjs
```

macOS canonicalizes `/tmp` to `/private/tmp`. The harness was corrected to derive the expected URL from `realpath(copyPath)`. The unique `import.meta.url` equality assertion, byte-prefix assertion, and independently-defined suffix assertion remained intact. The successful run then imported both canonical observable-copy paths and completed the behavior test.
