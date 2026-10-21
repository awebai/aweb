import {
  test,
  expect,
} from "../../../../naapp-lib/renderer/node_modules/@playwright/test/index.mjs";

for (const width of [1280, 375]) {
  test(`missing link secret explains reopening the table at ${width}px`, async ({
    page,
  }) => {
    await page.setViewportSize({ width, height: 800 });
    await page.goto("/");
    await page.setContent(
      '<main id="page"><table><tr><td>Previously visible row</td></tr></table></main>',
    );
    await page.evaluate(async () => {
      const { showRecordTableFailure } = await import("/record-table-host.mjs");
      showRecordTableFailure(document.querySelector("#page"), {
        code: "link_unavailable",
      });
    });
    await expect(
      page.getByRole("heading", { name: "Open the link again" }),
    ).toBeVisible();
    await expect(page.getByRole("alert")).toContainText("dashboard");
    await expect(page.getByRole("alert")).toContainText("Documents");
    await expect(page.getByRole("alert")).toContainText("original link");
    await expect(page.getByRole("table")).toHaveCount(0);
    await expect(page.getByRole("heading")).toBeFocused();
    expect(
      await page.evaluate(
        () => document.documentElement.scrollWidth <= innerWidth,
      ),
    ).toBe(true);
    expect(
      await page.evaluate(() => [localStorage.length, sessionStorage.length]),
    ).toEqual([0, 0]);
  });
}

test("other failures use a safe generic screen and discard old rows", async ({
  page,
}) => {
  await page.goto("/");
  await page.setContent('<main id="page">Previously visible row</main>');
  await page.evaluate(async () => {
    const { showRecordTableFailure } = await import("/record-table-host.mjs");
    showRecordTableFailure(document.querySelector("#page"), {
      code: "current_membership_unavailable",
      message: "private diagnostic sentinel",
    });
  });
  await expect(
    page.getByRole("heading", { name: "Unable to open the table" }),
  ).toBeVisible();
  await expect(page.getByRole("main")).not.toContainText(
    "private diagnostic sentinel",
  );
  await expect(page.getByRole("main")).not.toContainText(
    "Previously visible row",
  );
});
