// Frozen d4304096c discovery schema/input: reproduce the actual enum locator
// failure and the accepted populated URL overflow. Host callbacks isolate the
// renderer boundary; the real Folio/CLI journey remains separate acceptance.
import { test, expect } from "@playwright/test";
import { mkdir, writeFile } from "node:fs/promises";

const schema = {
  type: "object",
  properties: {
    source_url: {
      type: "string",
      minLength: 1,
      maxLength: 2048,
      title: "Source",
    },
    date: {
      type: "string",
      minLength: 10,
      maxLength: 10,
      format: "date",
      title: "Date",
      description:
        "America/Vancouver read or discovery date, not publication date.",
    },
    finding: {
      type: "string",
      minLength: 1,
      maxLength: 8192,
      title: "Finding",
    },
    why_relevant: {
      type: "string",
      minLength: 1,
      maxLength: 8192,
      title: "Why relevant",
    },
    possible_contribution: {
      type: "string",
      maxLength: 8192,
      title: "Possible contribution",
    },
    status: {
      type: "string",
      minLength: 1,
      maxLength: 160,
      title: "Status",
    },
    next_follow_up: {
      type: "string",
      maxLength: 8192,
      title: "Next follow-up",
    },
    kind: {
      type: "string",
      enum: ["awareness", "interaction"],
      title: "Kind",
    },
  },
  required: ["source_url", "date", "finding", "why_relevant", "status", "kind"],
  additionalProperties: false,
};
const value = {
  source_url: "https://example.test/research?topic=pages",
  date: "2026-10-23",
  finding: "Synthetic record acceptance",
  why_relevant: "Verify the same row through signed tools and a table",
  status: "read",
  kind: "awareness",
};
async function open(page, editable) {
  await page.goto("/");
  await page.evaluate(
    async ({ schema, value, editable }) => {
      const { mountTableWidget } = await import("/assets/page-renderer.js");
      const root = document.createElement("section");
      root.id = "table-boundary";
      root.className = "folio-widget";
      root.style.margin = "16px";
      document.body.replaceChildren(root);
      const rows = [
        { id: "first", rev: 3, value: { ...value, status: "alice" } },
        {
          id: "second",
          rev: 1,
          value: {
            ...value,
            finding: "Second synthetic record",
            status: "later",
          },
        },
      ];
      const query = () => ({
        records: structuredClone(rows),
        count: rows.length,
        next_cursor: null,
        snapshot_rev: 4,
      });
      const widget = {
        id: "research",
        type: "table",
        bind: { collection: "records-acceptance", limit: 20 },
        props: {
          columns: Object.entries(schema.properties).map(([field, prop]) => ({
            field,
            label: prop.title || field,
            format: field === "source_url" ? "url" : "text",
          })),
        },
      };
      mountTableWidget({
        root,
        widgetId: "research",
        state: {
          state: "ready",
          data_mode: "live",
          query: query(),
          edit: {
            add: editable,
            patch_fields: editable ? Object.keys(schema.properties) : [],
            delete: false,
            reopen_to_edit: false,
          },
          page: {
            page_format: "aweb.page/1",
            page_id: "records",
            rev: 4,
            title: "Synthetic discovery records",
            locale: "en-CA",
            layout_version: 1,
            owner: "fixture",
            policy_ref: "fixture",
            layout: [widget],
            actions: [],
            widget_state: {},
            collections: [
              {
                id: "records-acceptance",
                schema_version: 1,
                schema,
                mode: "owned",
                records: rows,
              },
            ],
          },
        },
        host: {
          query: async () => query(),
          add: async (payload) => {
            window.addedRequest = structuredClone(payload);
            const record = { id: "added", rev: 1, value: payload.values };
            rows.push(record);
            return {
              collection_id: "records-acceptance",
              snapshot_rev: 5,
              record,
            };
          },
        },
      });
    },
    { schema, value, editable },
  );
  return page.locator("#table-boundary");
}

async function diagnostics(page, table, info) {
  await mkdir(info.outputDir, { recursive: true });
  const retain = async (name, { body, contentType }) => {
    const extension = {
      "text/html": ".html",
      "text/plain": ".yml",
      "application/json": ".json",
      "image/png": ".png",
    }[contentType];
    const path = info.outputPath(name + extension);
    await writeFile(path, body);
    await info.attach(name, { path, contentType });
  };
  await retain("table-dom", {
    body: await table.evaluate((node) => node.outerHTML),
    contentType: "text/html",
  });
  await retain("table-accessibility", {
    body: await table.ariaSnapshot(),
    contentType: "text/plain",
  });
  await retain("table-layout", {
    body: JSON.stringify(
      await page.evaluate(() => ({
        viewport: innerWidth,
        document: document.documentElement.scrollWidth,
        labels: [...document.querySelectorAll("label")].map((label) => ({
          text: label.textContent,
          for: label.htmlFor,
        })),
        nodes: [...document.querySelectorAll(".table-scroll,.sr-only")].map(
          (node) => ({
            className: node.className,
            right: node.getBoundingClientRect().right,
            width: node.getBoundingClientRect().width,
            scroll: node.scrollWidth,
          }),
        ),
      })),
    ),
    contentType: "application/json",
  });
  await retain("table-screen", {
    body: await page.screenshot(),
    contentType: "image/png",
  });
}

test("discovery Kind can be selected by its exact accessible role and name", async ({
  page,
}, info) => {
  const table = await open(page, true);
  await table.getByRole("button", { name: "Add row", exact: true }).click();
  try {
    // Retain the measured distinction that classified the original harness
    // failure. Role/name follows the same accessible control used by people.
    const counts = {
      kind_label: await table.getByLabel("Kind", { exact: true }).count(),
      kind_role: await table
        .getByRole("combobox", { name: "Kind", exact: true })
        .count(),
      finding_label: await table.getByLabel("Finding", { exact: true }).count(),
      finding_role: await table
        .getByRole("textbox", { name: "Finding", exact: true })
        .count(),
    };
    console.log("Discovery locator counts: " + JSON.stringify(counts));
    await mkdir(info.outputDir, { recursive: true });
    const countsPath = info.outputPath("locator-counts.json");
    await writeFile(countsPath, JSON.stringify(counts, null, 2));
    await info.attach("locator-counts", {
      path: countsPath,
      contentType: "application/json",
    });
    expect(counts).toEqual({
      kind_label: 0,
      kind_role: 1,
      finding_label: 1,
      finding_role: 1,
    });
    await expect(
      table.getByRole("combobox", { name: "Kind", exact: true }),
    ).toHaveAccessibleName("Kind");
    // Same values and enum index as the real Folio journey; select the
    // control by its verified accessible role and exact name.
    const added = { ...value, finding: "Browser added 1280", status: "added" };
    for (const [field, entry] of Object.entries(added)) {
      const control = table.getByRole(
        Array.isArray(schema.properties[field].enum) ? "combobox" : "textbox",
        { name: schema.properties[field].title || field, exact: true },
      );
      if (Array.isArray(schema.properties[field].enum))
        await control.selectOption(
          String(schema.properties[field].enum.indexOf(entry)),
          { timeout: 3000 },
        );
      else await control.fill(String(entry));
    }
    await expect(
      table.getByRole("combobox", { name: "Kind", exact: true }),
    ).toHaveValue("0");
    await table.getByRole("button", { name: "Save row", exact: true }).click();
    await expect(table.locator("tbody")).toContainText(added.finding);
    expect((await page.evaluate(() => window.addedRequest)).values).toEqual(
      added,
    );
  } finally {
    await diagnostics(page, table, info);
  }
});

for (const width of [1280, 375]) {
  test(`populated readonly URL columns stay within the document at ${width}px`, async ({
    page,
  }, info) => {
    await page.setViewportSize({ width, height: 800 });
    const table = await open(page, false);
    try {
      await expect(table.locator("tbody tr")).toHaveCount(2);
      await expect(table.getByRole("link").first()).toHaveAccessibleName(
        /https:\/\/example.test\/research\?topic=pages/,
      );
      const scroller = table.locator(".table-scroll");
      await expect(scroller).toHaveAttribute("tabindex", "0");
      await expect(scroller).toHaveAttribute("role", "region");
      await expect(scroller).toHaveAccessibleName("records");
      expect(
        await page.evaluate(() => document.documentElement.scrollWidth),
      ).toBeLessThanOrEqual(width);
    } finally {
      await diagnostics(page, table, info);
    }
  });
}
