import { test, expect } from "@playwright/test";

// Browser-level adapter contract tests: defer real File reads and host callback
// completion without replacing renderer code or synthesizing trusted events.
async function mount(page, mode) {
  await page.goto("/");
  await expect(page.locator('[data-widget="note-form"]')).toBeVisible();
  await page.evaluate(async (mode) => {
    const { createPageRenderer } = await import("/assets/page-renderer.js");
    const snapshot = await fetch("/api/page").then((r) => r.json());
    const root = document.querySelector("#page");
    root.replaceChildren();
    root.id = "probe";
    const destinations = document.createElement("aside");
    const announcements = document.createElement("p");
    document.body.append(root, destinations, announcements);
    snapshot.layout = snapshot.layout.filter((w) =>
      ["note-form", "document-upload"].includes(w.id),
    );
    snapshot.widget_state = {};
    const action = snapshot.actions.find((a) => a.id === "save-note");
    const form = snapshot.layout.find((w) => w.id === "note-form");
    if (mode === "optional") {
      action.input_schema.required = action.input_schema.required.filter(
        (k) => k !== "guests",
      );
      form.props.fields.find((f) => f.id === "guests").required = false;
    }
    if (mode === "boolean") {
      action.input_schema.required.push("confirmed");
      form.props.fields.find((f) => f.id === "confirmed").required = true;
    }
    let release;
    const held = new Promise((resolve) => {
      release = resolve;
    });
    const probe = (window.probe = {
      calls: [],
      release,
      held: false,
      finished: false,
    });
    if (mode === "hash") {
      const native = File.prototype.arrayBuffer;
      File.prototype.arrayBuffer = async function () {
        const bytes = await native.call(this);
        probe.held = true;
        await held;
        return bytes;
      };
    }
    const host = {
      actionPolicy: () => ({ allowed: probe.allowed !== false }),
      csrfToken: () => {
        probe.calls.push({ kind: "csrf" });
        return "host-token";
      },
      upload: async (request) => {
        probe.calls.push({
          kind: "upload",
          name: request.file.name,
          mime: request.file.type,
          size: request.file.size,
          input: request.input,
        });
        if (mode === "authority" || mode === "policy") {
          probe.held = true;
          await held;
        }
        probe.finished = true;
        return { attachment_id: "attachment-test" };
      },
      invoke: async (request) => {
        probe.calls.push({ kind: "invoke", request });
        probe.finished = true;
        return { transaction_id: "saved" };
      },
    };
    const renderer = createPageRenderer({
      root,
      destinations,
      announcements,
      host,
    });
    renderer.update(snapshot);
    probe.switchActor = () => {
      renderer.clear();
      renderer.update({ ...snapshot, page_id: "second-actor-page" });
    };
  }, mode);
}
async function fillForm(page) {
  const form = page.locator('#probe [data-widget="note-form"]');
  await form
    .getByLabel("Note (required)", { exact: true })
    .fill("Original draft");
  await form
    .getByLabel(/^Guests(?: \(required\))?$/, { exact: true })
    .fill("2");
  return form;
}
for (const mode of ["authority", "policy"]) {
  test(`a deferred upload cannot continue after ${mode} changes`, async ({
    page,
  }) => {
    await mount(page, mode);
    const form = await fillForm(page);
    await form.getByLabel("Attachment", { exact: true }).setInputFiles({
      name: "note.txt",
      mimeType: "text/plain",
      buffer: Buffer.from("abc"),
    });
    await form.getByRole("button", { name: "Save note" }).click();
    await expect.poll(() => page.evaluate(() => window.probe.held)).toBe(true);
    await page.evaluate((mode) => {
      if (mode === "authority") window.probe.switchActor();
      else window.probe.allowed = false;
      window.probe.calls.length = 0;
      window.probe.release();
    }, mode);
    await expect
      .poll(() => page.evaluate(() => window.probe.finished))
      .toBe(true);
    // Flush the settled upload's continuation and its finally block.
    await page.evaluate(
      () =>
        new Promise((resolve) =>
          requestAnimationFrame(() => requestAnimationFrame(resolve)),
        ),
    );
    expect(await page.evaluate(() => window.probe.calls)).toEqual([]);
  });
}
test("an optional blank integer is absent and a required boolean may be false", async ({
  page,
}) => {
  for (const mode of ["optional", "boolean"]) {
    await mount(page, mode);
    const form = await fillForm(page);
    if (mode === "optional")
      await form
        .getByLabel(/^Guests(?: \(required\))?$/, { exact: true })
        .fill("");
    await form.getByRole("button", { name: "Save note" }).click();
    await expect(form.getByRole("status")).toContainText("Saved");
    const input = await page.evaluate(
      () => window.probe.calls.find((c) => c.kind === "invoke").request.input,
    );
    if (mode === "optional") expect(input).not.toHaveProperty("guests");
    else expect(input.confirmed).toBe(false);
  }
});
test("file_drop keeps the submitted File when selection changes during hashing", async ({
  page,
}) => {
  await mount(page, "hash");
  const drop = page.locator('#probe [data-widget="document-upload"]');
  const picker = drop.getByLabel("Upload a document", { exact: true });
  await picker.setInputFiles({
    name: "allowed.txt",
    mimeType: "text/plain",
    buffer: Buffer.from("abc"),
  });
  await drop.getByRole("button", { name: "Upload", exact: true }).click();
  await expect.poll(() => page.evaluate(() => window.probe.held)).toBe(true);
  await picker.setInputFiles({
    name: "blocked.svg",
    mimeType: "image/svg+xml",
    buffer: Buffer.alloc(1025),
  });
  await page.evaluate(() => window.probe.release());
  await expect(drop.getByRole("status")).toContainText("allowed.txt uploaded.");
  const upload = await page.evaluate(() =>
    window.probe.calls.find((c) => c.kind === "upload"),
  );
  expect(upload).toMatchObject({
    name: "allowed.txt",
    mime: "text/plain",
    size: 3,
    input: {
      name: "allowed.txt",
      mime: "text/plain",
      size: 3,
      file_sha256:
        "sha256:ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
    },
  });
});
