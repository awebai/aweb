export default {
  testDir: "./tests/browser",
  workers: 1,
  use: { baseURL: "http://127.0.0.1:8779" },
  webServer: {
    command:
      "python3 -m http.server 8779 --bind 127.0.0.1 --directory src/folio/assets",
    url: "http://127.0.0.1:8779",
    reuseExistingServer: false,
    stderr: "ignore",
  },
};
