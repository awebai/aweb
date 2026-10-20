import { test, expect } from "@playwright/test";
async function mount(page, mode) {
  await page.goto("/");
  await expect(page.locator('[data-widget="note-form"]')).toBeVisible();
  await page.evaluate(async (mode) => {
    const { createPageRenderer } = await import("/assets/page-renderer.js");
    const snapshot = await fetch("/api/page").then((r) => r.json());
    snapshot.layout = snapshot.layout.filter(
      (w) =>
        w.id ===
        (mode === "bundle-display" ? "bundle-decision" : "price-decision"),
    );
    snapshot.widget_state = {};
    const root = document.querySelector("#page");
    root.replaceChildren();
    root.id = "probe";
    const destinations = document.createElement("aside"),
      announcements = document.createElement("p");
    document.body.append(destinations, announcements);
    const evidence = await fetch(
      "/api/decision?task_id=" + snapshot.layout[0].props.task_id,
    ).then((r) => r.json());
    if (["display", "bundle-display"].includes(mode))
      snapshot.collections.find((c) => c.id === "review-proposals").records[0]
        .value.price_minor++;
    if (mode === "expiry") {
      snapshot.layout[0].props.expires_at = new Date(
        Date.now() + 1200,
      ).toISOString();
      evidence.expires_at = snapshot.layout[0].props.expires_at;
    }
    if (mode === "passkey") evidence.authenticator = "passkey";
    const receipt = {
      current: true,
      task_id: evidence.task_id,
      question_rev: evidence.question_rev,
      proposal_rev: evidence.record_rev,
      proposal_sha256: evidence.proposal_sha256,
      choice: "approve",
      task_answer_ref: "test-answer",
      approval_state: "pending",
    };
    if (["superseded", "reopened"].includes(mode)) {
      evidence.task_rev += 2;
      evidence.question_rev += 1;
      evidence.answer = { ...receipt, current: false };
      if (mode === "reopened")
        snapshot.layout[0].props.task_rev = evidence.task_rev;
    }
    if (["current-old-rev", "answer-expired"].includes(mode)) {
      evidence.task_rev++;
      evidence.status = "answered";
      evidence.answer = receipt;
      if (mode === "answer-expired") {
        snapshot.layout[0].props.expires_at = "2020-01-01T00:00:00Z";
        evidence.expires_at = snapshot.layout[0].props.expires_at;
      }
    }
    let release;
    const held = new Promise((resolve) => {
      release = resolve;
    });
    const probe = (window.probe = {
      calls: [],
      release,
      held: false,
      block: false,
      finished: false,
    });
    const host = {
      actionPolicy: () => ({ allowed: probe.allowed !== false }),
      csrfToken: async () => {
        if (probe.blockCSRF) {
          probe.blockCSRF = false;
          probe.held = true;
          await held;
          probe.finished = true;
        }
        return "host-token";
      },
      decision: async () => {
        if (probe.block) {
          probe.block = false;
          probe.held = true;
          await held;
          probe.finished = true;
        }
        if (mode === "answered" && probe.refreshAnswer)
          return {
            ...evidence,
            task_rev: evidence.task_rev + 1,
            status: "answered",
            answer: { ...receipt, choice: "reject" },
          };
        return structuredClone(evidence);
      },
      answer: async (request, credential, event) => {
        probe.calls.push({ request, credential, trusted: event.isTrusted });
        if (mode === "unknown" && probe.calls.length === 1)
          throw new Error("network");
        if (mode === "passkey") return { approval_state: "pending" };
        return {
          ...receipt,
          question_rev: evidence.question_rev,
          choice: request.stage.choice,
          proposal_sha256:
            mode === "wrong-receipt"
              ? "sha256:" + "0".repeat(64)
              : receipt.proposal_sha256,
        };
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
  if (
    ![
      "display",
      "bundle-display",
      "superseded",
      "current-old-rev",
      "answer-expired",
    ].includes(mode)
  )
    await expect(
      page
        .locator("#probe")
        .getByRole("radio", { name: "Approve", exact: true }),
    ).toBeEnabled();
  return page.locator("#probe");
}
test("a decision read paused across clear/new authority cannot dispatch an answer", async ({
  page,
}) => {
  const card = await mount(page, "authority");
  await card.getByRole("radio", { name: "Approve", exact: true }).check();
  await page.evaluate(() => {
    window.probe.block = true;
  });
  await card
    .getByRole("button", { name: "Record decision", exact: true })
    .click();
  await expect.poll(() => page.evaluate(() => window.probe.held)).toBe(true);
  await page.evaluate(() => {
    window.probe.switchActor();
    window.probe.release();
  });
  await expect
    .poll(() => page.evaluate(() => window.probe.finished))
    .toBe(true);
  await page.evaluate(
    () =>
      new Promise((resolve) =>
        requestAnimationFrame(() => requestAnimationFrame(resolve)),
      ),
  );
  expect(await page.evaluate(() => window.probe.calls)).toEqual([]);
});
test("an answer recorded in another view overrides the local recommendation before dispatch", async ({
  page,
}) => {
  const card = await mount(page, "answered");
  await card.getByRole("radio", { name: "Approve", exact: true }).check();
  await page.evaluate(() => {
    window.probe.refreshAnswer = true;
  });
  await card
    .getByRole("button", { name: "Record decision", exact: true })
    .click();
  await expect(card).toContainText("Decision recorded: Reject");
  expect(await page.evaluate(() => window.probe.calls)).toEqual([]);
});
test("an unknown answer outcome locks the choice and retries with the same answer key", async ({
  page,
}) => {
  const card = await mount(page, "unknown");
  await card.getByRole("radio", { name: "Approve", exact: true }).check();
  await card
    .getByRole("button", { name: "Record decision", exact: true })
    .click();
  await expect(card).toContainText("The outcome is unknown");
  await expect(
    card.getByRole("radio", { name: "Reject", exact: true }),
  ).toBeDisabled();
  await card.getByRole("button", { name: "Check decision status" }).click();
  await card.getByRole("button", { name: "Retry recording decision" }).click();
  await expect(card).toContainText("Decision recorded: Approve");
  const calls = await page.evaluate(() => window.probe.calls);
  expect(calls).toHaveLength(2);
  expect(calls[0].request.stage).toEqual(calls[1].request.stage);
  expect(calls[0].credential).toEqual({ csrfToken: "host-token" });
  expect(calls.every((c) => c.trusted)).toBe(true);
});
test("a required passkey remains host-owned and pending verification is not a recorded decision", async ({
  page,
}) => {
  const card = await mount(page, "passkey");
  await expect(card).toContainText(
    "A passkey check on the app origin is required",
  );
  await card.getByRole("radio", { name: "Approve", exact: true }).check();
  await card
    .getByRole("button", { name: "Record decision", exact: true })
    .click();
  await expect(card.locator(".decision-status")).toHaveText(
    "Decision verification is pending.",
  );
  await expect(
    card.getByRole("radio", { name: "Reject", exact: true }),
  ).toBeDisabled();
  expect(
    await page.evaluate(() =>
      Object.keys(window.probe.calls[0].request.stage).sort(),
    ),
  ).toEqual([
    "answer_key",
    "choice",
    "expected_task_rev",
    "input",
    "proposal_rev",
    "proposal_sha256",
  ]);
});
test("decision expiry disables choices on its own clock", async ({ page }) => {
  await page.clock.install();
  const card = await mount(page, "expiry");
  await page.clock.fastForward(2000);
  await expect(card.locator(".decision-status")).toContainText("expired");
  await expect(
    card.getByRole("radio", { name: "Approve", exact: true }),
  ).toBeDisabled();
  expect(await page.evaluate(() => window.probe.calls)).toEqual([]);
});

for (const mode of ["display", "bundle-display"]) {
  test(`the ${mode} digest is checked against unchanged trusted host evidence`, async ({
    page,
  }) => {
    const card = await mount(page, mode);
    await expect(card.locator(".decision-status")).toContainText(
      "This proposal changed",
    );
    await expect(
      card.getByRole("radio", { name: "Approve", exact: true }),
    ).toBeDisabled();
    expect(await page.evaluate(() => window.probe.calls)).toEqual([]);
  });
}

for (const mode of ["current-old-rev", "answer-expired"]) {
  test(`${mode} displays the bound current answer without creating new approval authority`, async ({
    page,
  }) => {
    const card = await mount(page, mode);
    await expect(card).toContainText("Decision recorded: Approve");
    await expect(
      card.getByRole("radio", { name: "Reject", exact: true }),
    ).toBeDisabled();
  });
}
test("a reopened old card shows its earlier answer as superseded and refuses new answers", async ({
  page,
}) => {
  const card = await mount(page, "superseded");
  await expect(card).toContainText("Earlier answer: Approve · superseded.");
  await expect(card.locator(".decision-status")).toContainText(
    "This proposal changed",
  );
  await expect(
    card.getByRole("radio", { name: "Reject", exact: true }),
  ).toBeDisabled();
});
test("a new task revision can answer a reopened question without selecting the superseded choice", async ({
  page,
}) => {
  const card = await mount(page, "reopened");
  await expect(card).toContainText("Earlier answer: Approve · superseded.");
  await expect(card.getByRole("radio", { checked: true })).toHaveCount(0);
  await card.getByRole("radio", { name: "Reject", exact: true }).check();
  await card
    .getByRole("button", { name: "Record decision", exact: true })
    .click();
  await expect(card).toContainText("Decision recorded: Reject");
  expect(
    await page.evaluate(
      () => window.probe.calls[0].request.stage.expected_task_rev,
    ),
  ).toBe(3);
});
test("a current-looking receipt for another proposal never becomes the displayed decision", async ({
  page,
}) => {
  const card = await mount(page, "wrong-receipt");
  await card.getByRole("radio", { name: "Approve", exact: true }).check();
  await card
    .getByRole("button", { name: "Record decision", exact: true })
    .click();
  await expect(card.locator(".decision-status")).toHaveText(
    "Decision verification is pending.",
  );
  await expect(card).not.toContainText("Decision recorded:");
  await expect(
    card.getByRole("radio", { name: "Reject", exact: true }),
  ).toBeDisabled();
});

for (const revoke of ["actor", "policy"]) {
  test(`a ${revoke} change during decision CSRF retrieval prevents dispatch`, async ({
    page,
  }) => {
    const card = await mount(page, "csrf-continuation");
    await card.getByRole("radio", { name: "Approve", exact: true }).check();
    await page.evaluate(() => {
      window.probe.blockCSRF = true;
    });
    await card
      .getByRole("button", { name: "Record decision", exact: true })
      .click();
    await expect.poll(() => page.evaluate(() => window.probe.held)).toBe(true);
    await page.evaluate((revoke) => {
      if (revoke === "actor") window.probe.switchActor();
      else window.probe.allowed = false;
      window.probe.release();
    }, revoke);
    await expect
      .poll(() => page.evaluate(() => window.probe.finished))
      .toBe(true);
    await page.evaluate(
      () =>
        new Promise((resolve) =>
          requestAnimationFrame(() => requestAnimationFrame(resolve)),
        ),
    );
    expect(await page.evaluate(() => window.probe.calls)).toEqual([]);
  });
}
