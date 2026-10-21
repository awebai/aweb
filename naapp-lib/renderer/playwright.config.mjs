import { defineConfig } from "@playwright/test";
const port = Number(process.env.PAGE_GALLERY_PORT || 8740);
export default defineConfig({
  testDir: "./tests",
  testMatch: "**/*.spec.mjs",
  workers: 1,
  use: { baseURL: `http://127.0.0.1:${port}`, ignoreHTTPSErrors: true },
  webServer: {
    command: `../.venv/bin/python -m aweb_naapp.pages.gallery --port ${port}`,
    url: `http://127.0.0.1:${port}`,
    reuseExistingServer: false,
  },
});
