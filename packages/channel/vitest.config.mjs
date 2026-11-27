import { defineConfig } from "vitest/config";

// Timeouts are hang guards, not timing assertions. The candidate gate runs
// every suite at once on a shared CPU budget, where a test can take several
// times its unloaded duration; vitest's 5 s and 10 s defaults then fail tests
// that are still making progress.
export default defineConfig({
  test: {
    testTimeout: 60_000,
    hookTimeout: 60_000,
  },
});
