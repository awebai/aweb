import { test, expect } from "@playwright/test";

test("a labeled typed form sends validated values with host CSRF and revisions", async ({
  page,
}) => {
  await page.goto("/");
  const form = page.locator('[data-widget="note-form"]');
  await form.getByRole("button", { name: "Save note" }).click();
  await expect(form.getByRole("alert")).toBeVisible();
  await form.getByLabel("Note", { exact: true }).fill("Inspect the entrance");
  await form.getByLabel("Guests", { exact: true }).fill("3");
  await form.getByLabel("Visit date", { exact: true }).fill("2026-11-04");
  await form.getByLabel("Priority", { exact: true }).selectOption("urgent");
  const sent = page.waitForRequest(
    (r) => r.url().endsWith("/api/invoke") && r.method() === "POST",
  );
  await form.getByRole("button", { name: "Save note" }).click();
  const request = await sent;
  expect(request.headers()["x-csrf-token"]).toBeTruthy();
  expect(request.postDataJSON()).toMatchObject({
    action_id: "save-note",
    expected_page_rev: 1,
    input: {
      note: "Inspect the entrance",
      guests: 3,
      priority: "urgent",
      visit: "2026-11-04",
    },
  });
  await expect(form.getByRole("status")).toContainText("Saved");
});

test("consequential buttons wait for host confirmation and intents report admission separately from execution", async ({
  page,
}) => {
  await page.goto("/");
  const button = page.getByRole("button", {
    name: "Ask the agent",
    exact: true,
  });
  await button.click();
  const dialog = page.locator("#action-confirmation");
  await expect(dialog).toBeVisible();
  await expect(
    dialog.getByRole("button", { name: "Cancel", exact: true }),
  ).toBeFocused();
  await dialog.getByRole("button", { name: "Confirm", exact: true }).click();
  await expect(
    page.locator('[data-widget="request-button"] [role="status"]'),
  ).toContainText("Execution not started");
});

test("bounded uploads use host CSRF and attachment IDs; unacceptable files stay local", async ({
  page,
}) => {
  await page.goto("/");
  const drop = page.locator('[data-widget="document-upload"]');
  await drop.getByLabel("Upload a document", { exact: true }).setInputFiles({
    name: "bad.svg",
    mimeType: "image/svg+xml",
    buffer: Buffer.from("<svg/>"),
  });
  await drop.getByRole("button", { name: "Upload", exact: true }).click();
  await expect(drop.getByRole("alert")).toContainText("file type");
  await drop.getByLabel("Upload a document", { exact: true }).setInputFiles({
    name: "notes.txt",
    mimeType: "text/plain",
    buffer: Buffer.from("A valid note"),
  });
  const sent = page.waitForRequest(
    (r) => r.url().endsWith("/api/upload") && r.method() === "POST",
  );
  await drop.getByRole("button", { name: "Upload", exact: true }).click();
  expect((await sent).headers()["x-csrf-token"]).toBeTruthy();
  await expect(drop.getByRole("status")).toContainText("attachment-");
});

test("media uses only the separate app asset origin and video has explicit playback controls", async ({
  page,
}) => {
  await page.goto("/");
  const image = page.locator('[data-widget="property-image"] img');
  await expect(image).toBeVisible();
  const origin = new URL(await image.getAttribute("src")).origin;
  expect(origin).not.toBe(new URL(page.url()).origin);
  expect(origin).toBe("https://127.0.0.1:8741");
  const video = page.locator('[data-widget="property-video"] video');
  await expect(video).toHaveAttribute("controls", "");
  await expect(video).not.toHaveAttribute("autoplay");
  await expect(page.locator('[data-widget="agent-health"]')).toContainText(
    "Status reported",
  );
  await page.getByRole("link", { name: "Open app console" }).click();
  await expect(page.getByRole("dialog").getByRole("heading")).toHaveText(
    "app.example",
  );
});

test("form drafts survive live updates and conflicts require an explicit reapply", async ({
  page,
}) => {
  await page.goto("/");
  const form = page.locator('[data-widget="note-form"]');
  const note = form.getByLabel("Note", { exact: true });
  await note.fill("Keep my draft");
  await form.getByLabel("Guests", { exact: true }).fill("2");
  await note.focus();
  await page.keyboard.press("Alt+u");
  await expect(page.locator("#announcements")).toContainText(
    "Projection updated",
  );
  await expect(note).toHaveValue("Keep my draft");
  await expect(note).toBeFocused();
  await form.getByRole("button", { name: "Save note" }).click();
  await expect(form.getByRole("alert")).toContainText("draft is kept");
  await form.getByRole("button", { name: "Review current page" }).click();
  await form.getByRole("button", { name: "Use current page revision" }).click();
  await expect(note).toHaveValue("Keep my draft");
  await form.getByRole("button", { name: "Save note" }).click();
  await expect(form.getByRole("status")).toContainText("Saved");
});

test("missing CSRF blocks dispatch and the real fixture host rejects a headerless POST", async ({
  page,
}) => {
  await page.goto("/?case=no-csrf");
  let mutations = 0;
  page.on("request", (request) => {
    if (request.url().endsWith("/api/invoke")) mutations++;
  });
  const form = page.locator('[data-widget="note-form"]');
  await form.getByLabel("Note", { exact: true }).fill("A valid note");
  await form.getByLabel("Guests", { exact: true }).fill("2");
  await form.getByRole("button", { name: "Save note" }).click();
  await expect(form.getByRole("alert")).toContainText("could not verify");
  expect(mutations).toBe(0);
  const response = await page.request.post("/api/invoke", { data: {} });
  expect(response.status()).toBe(403);
});

test("foreign media is refused before a network request and health loses a positive claim at expiry", async ({
  page,
}) => {
  const foreign = [];
  page.on("request", (r) => {
    if (r.url().includes("forbidden.example")) foreign.push(r.url());
  });
  await page.goto("/?case=wrong-asset");
  await expect(page.locator('[data-widget="property-image"]')).toContainText(
    "Media unavailable",
  );
  expect(foreign).toEqual([]);
  await page.goto("/?case=health-expiring");
  await expect(page.locator('[data-widget="agent-health"]')).toContainText(
    "Can receive messages",
  );
  await expect(page.locator('[data-widget="agent-health"]')).toContainText(
    "Status unavailable",
    { timeout: 5000 },
  );
});

test("file form fields resolve to attachment IDs before the typed form is invoked", async ({
  page,
}) => {
  await page.goto("/");
  const form = page.locator('[data-widget="note-form"]');
  await form.getByLabel("Note", { exact: true }).fill("A note with a file");
  await form.getByLabel("Guests", { exact: true }).fill("2");
  await form
    .getByLabel("Attachment", { exact: true })
    .setInputFiles({
      name: "note.txt",
      mimeType: "text/plain",
      buffer: Buffer.from("Attached text"),
    });
  const invocation = page.waitForRequest(
    (r) => r.url().endsWith("/api/invoke") && r.method() === "POST",
  );
  await form.getByRole("button", { name: "Save note" }).click();
  expect((await invocation).postDataJSON().input.attachment).toMatch(
    /^attachment-[a-f0-9]+$/,
  );
  await expect(form.getByRole("status")).toContainText("Saved");
});

test("upload size limits stop dispatch and equal-size different files get different request keys", async ({
  page,
}) => {
  await page.goto("/");
  const drop = page.locator('[data-widget="document-upload"]');
  await drop
    .getByLabel("Upload a document", { exact: true })
    .setInputFiles({
      name: "big.txt",
      mimeType: "text/plain",
      buffer: Buffer.alloc(1025),
    });
  await drop.getByRole("button", { name: "Upload", exact: true }).click();
  await expect(drop.getByRole("alert")).toContainText("size limit");
  const keys = [];
  for (const content of ["abc", "xyz"]) {
    await drop
      .getByLabel("Upload a document", { exact: true })
      .setInputFiles({
        name: "same.txt",
        mimeType: "text/plain",
        buffer: Buffer.from(content),
      });
    const sent = page.waitForRequest(
      (r) => r.url().endsWith("/api/upload") && r.method() === "POST",
    );
    await drop.getByRole("button", { name: "Upload", exact: true }).click();
    keys.push((await sent).postDataJSON().idempotency_key);
    await expect(drop.getByRole("status")).toContainText("attachment-");
  }
  expect(keys[0]).not.toBe(keys[1]);
});
