import { test, expect } from "@playwright/test";

test("authored heading ranks stay below the page title at both endpoints", async ({
  page,
}) => {
  await page.route("**/api/page?*", async (route) => {
    const response = await route.fetch();
    const snapshot = await response.json();
    snapshot.layout = [
      {
        id: "rank-one",
        type: "heading",
        props: { level: 1, text: "First authored rank" },
      },
      {
        id: "rank-six",
        type: "heading",
        props: { level: 6, text: "Sixth authored rank" },
      },
      {
        id: "markdown-ranks",
        type: "text",
        props: {
          markdown: "# First Markdown rank\n\n###### Sixth Markdown rank",
        },
      },
    ];
    snapshot.widget_state = {};
    await route.fulfill({ response, json: snapshot });
  });
  await page.goto("/");
  await expect(page.locator('[data-widget="rank-one"] h2')).toBeVisible();
  const deepest = page.locator('[data-widget="rank-six"] [role="heading"]');
  await expect(deepest).toBeVisible();
  await expect(deepest).toHaveAttribute("aria-level", "7");
  await expect(page.locator('[data-widget="markdown-ranks"] h2')).toBeVisible();
  await expect(
    page.locator('[data-widget="markdown-ranks"] [role="heading"]'),
  ).toHaveAttribute("aria-level", "7");
  await expect(page.locator("h1")).toHaveCount(1);
  await expect(page.locator("h1.page-title")).toBeVisible();
});

for (const colorScheme of ["light", "dark"]) {
  test(`unfocused controls have visible boundaries in ${colorScheme}`, async ({
    page,
  }) => {
    await page.emulateMedia({ colorScheme });
    await page.goto("/");
    await expect(page.locator(".page-form input").first()).toBeVisible();
    const measurements = await page
      .locator(".form-field input, .form-field select, .file-drop input")
      .evaluateAll((controls) => {
        const rgba = (text) => text.match(/[\d.]+/g).map(Number);
        const over = (foreground, background) =>
          foreground
            .slice(0, 3)
            .map(
              (v, i) =>
                v * (foreground[3] ?? 1) +
                background[i] * (1 - (foreground[3] ?? 1)),
            );
        const luminance = (rgb) =>
          rgb
            .map((v) => v / 255)
            .map((v) =>
              v <= 0.04045 ? v / 12.92 : ((v + 0.055) / 1.055) ** 2.4,
            )
            .reduce((sum, v, i) => sum + v * [0.2126, 0.7152, 0.0722][i], 0);
        const contrast = (a, b) =>
          (Math.max(luminance(a), luminance(b)) + 0.05) /
          (Math.min(luminance(a), luminance(b)) + 0.05);
        return controls.map((control) => {
          const style = getComputedStyle(control);
          const surface = rgba(
            getComputedStyle(control.closest("form")).backgroundColor,
          );
          const fill = over(rgba(style.backgroundColor), surface);
          const border = over(rgba(style.borderTopColor), fill);
          return {
            id: control.id,
            surface: contrast(border, surface),
            fill: contrast(border, fill),
          };
        });
      });
    expect(measurements.length).toBeGreaterThan(3);
    for (const control of measurements) {
      expect(control.surface, control.id).toBeGreaterThanOrEqual(3);
      expect(control.fill, control.id).toBeGreaterThanOrEqual(3);
    }
  });
}

test("English chrome and formatted dates keep their language inside authored content", async ({
  page,
}) => {
  // This also exercises the renderer independently of the discoverable fixture.
  await page.route("**/api/page?*", async (route) => {
    const response = await route.fetch();
    const snapshot = await response.json();
    snapshot.locale = "ca";
    await route.fulfill({ response, json: snapshot });
  });
  await page.goto("/");
  await expect(page.locator("#page")).toHaveAttribute("lang", "ca");
  await expect(page.locator(".decision-proposal bdi").first()).toBeVisible();
  const english = [
    ".pagination",
    ".pagination button",
    ".collection-count",
    ".timeline-time",
    ".widget-agent_presence > p:not(.widget-label)",
    ".decision-metadata dt",
    ".decision-metadata dd:last-child",
    ".widget-decision_card summary",
    ".decision-status",
    ".decision-form legend",
    ".decision-proposal dd bdi[lang]",
    ".file-drop > .field-description",
    ".form-field label span",
    ".field-error",
    ".action-status",
  ];
  for (const selector of english) {
    const languages = await page
      .locator(selector)
      .evaluateAll((nodes) =>
        nodes.map((node) => node.closest("[lang]")?.lang),
      );
    expect(languages.length, selector).toBeGreaterThan(0);
    expect(
      languages.every((lang) => lang === "en"),
      selector,
    ).toBe(true);
  }
  for (const selector of [
    ".page-title",
    ".markdown",
    ".form-field label",
    ".decision-proposal dt",
    ".decision-option span",
    ".decision-proposal dd bdi:not([lang])",
  ]) {
    const languages = await page
      .locator(selector)
      .evaluateAll((nodes) =>
        nodes.map((node) => node.closest("[lang]")?.lang),
      );
    expect(languages.length, selector).toBeGreaterThan(0);
    expect(
      languages.every((lang) => lang === "ca"),
      selector,
    ).toBe(true);
  }
});

test("gallery exposes an authored-language fixture with English chrome", async ({
  page,
}) => {
  await page.goto("/?case=authored-language");
  const response = await page.request.get("/api/page?case=authored-language");
  expect((await response.json()).locale).toBe("ca");
  await expect(page.locator("#page")).toHaveAttribute("lang", "ca");
  await expect(page.locator(".pagination").first()).toHaveAttribute(
    "lang",
    "en",
  );
});

for (const recoveryAction of ["retry", "discard"])
  test(`upload conflict retains the file until explicit ${recoveryAction}`, async ({
    page,
  }) => {
    await page.setViewportSize({ width: 375, height: 812 });
    await page.goto("/");
    const form = page.locator('[data-widget="note-form"]');
    await form.locator('[name="note"]').fill("Inspect the entrance");
    await form.locator('[name="guests"]').fill("2");
    const saved = page.waitForResponse(
      (response) => new URL(response.url()).pathname === "/api/invoke",
    );
    await form.locator('[type="submit"]').click();
    expect((await saved).ok()).toBe(true);
    await expect(form.locator("form")).toHaveAttribute("aria-busy", "false");
    await expect(form.locator('[role="status"]')).not.toBeEmpty();
    const upload = page.locator('[data-widget="document-upload"]');
    const requests = [];
    page.on("request", (request) => {
      if (new URL(request.url()).pathname === "/api/upload")
        requests.push(request.postDataJSON());
    });
    await upload.locator('input[type="file"]').setInputFiles({
      name: "note.txt",
      mimeType: "text/plain",
      buffer: Buffer.from("note"),
    });
    await upload.locator('[type="submit"]').click();
    const recovery = upload.locator(".conflict-recovery");
    await expect(recovery.locator("button")).toHaveCount(2);
    await expect(upload.locator('[role="status"]')).toBeEmpty();
    await expect(upload.locator("form")).toHaveAttribute("aria-busy", "false");
    expect(requests).toHaveLength(1);
    expect(
      await upload
        .locator('input[type="file"]')
        .evaluate((node) => node.files[0]?.name),
    ).toBe("note.txt");
    if (recoveryAction === "discard") {
      await recovery.locator("button").last().click();
      expect(
        await upload
          .locator('input[type="file"]')
          .evaluate((node) => node.files.length),
      ).toBe(0);
      expect(requests).toHaveLength(1);
      await expect(recovery.locator("button")).toHaveCount(0);
      await expect(upload.locator('[type="submit"]')).toBeVisible();
      await expect(upload.locator('[role="status"]')).toBeEmpty();
      return;
    }
    const retried = page.waitForResponse(
      (response) => new URL(response.url()).pathname === "/api/upload",
    );
    await recovery.locator("button").first().click();
    expect((await retried).ok()).toBe(true);
    await expect(upload.locator('[role="status"]')).not.toBeEmpty();
    expect(requests).toHaveLength(2);
    expect(requests[1].expected_page_rev).toBeGreaterThan(
      requests[0].expected_page_rev,
    );
    expect(requests[1].input).toEqual(requests[0].input);
    expect(requests[1].file).toEqual(requests[0].file);
    await expect(recovery.locator("button")).toHaveCount(0);
    await expect(upload.locator("form")).toHaveAttribute("aria-busy", "false");
  });

test("a final receipt replaces inactive choices and the advisory recommendation", async ({
  page,
}) => {
  await page.goto("/?case=decision-rejected");
  const card = page.locator('[data-widget="price-decision"]');
  await expect(card.locator(".recorded-choice")).toBeVisible();
  await expect(card.getByRole("radio")).toHaveCount(0);
  await expect(card.locator(".decision-recommendation")).toBeHidden();
  const evidence = await page.request
    .get(
      "/api/decision?task_id=" +
        (
          await page.request
            .get("/api/page?case=decision-rejected")
            .then((r) => r.json())
        ).layout.find((w) => w.id === "price-decision").props.task_id +
        "&case=decision-rejected",
    )
    .then((r) => r.json());
  await expect(card.locator(".recorded-choice bdi")).toHaveText(
    evidence.options.find((o) => o.value === evidence.answer.choice).label,
  );
});
