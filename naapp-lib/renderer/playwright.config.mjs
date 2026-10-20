import { defineConfig } from '@playwright/test';
export default defineConfig({
  testDir: './tests', workers: 1,
  use: { baseURL: 'http://127.0.0.1:8734' },
  webServer: { command: '../.venv/bin/python -m aweb_naapp.pages.gallery --port 8734', url: 'http://127.0.0.1:8734', reuseExistingServer: false },
});
