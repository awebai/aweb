import { test, expect } from "@playwright/test";
async function mount(page, mode) {
  await page.goto("/");
  await expect(page.locator('[data-widget="note-form"]')).toBeVisible();
  await page.evaluate(async (mode) => {
    const { createPageRenderer } = await import("/assets/page-renderer.js");
    let snapshot = await fetch("/api/page").then((r) => r.json());
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
    announcements.id = "probe-announcements";
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
    if (mode === "schema-spoof") {
      const collection = snapshot.collections.find(
        (c) => c.id === "review-proposals",
      );
      collection.schema.properties.price_minor.title = "Account balance";
      collection.schema.properties.reason.title = "Do not show this title";
    }
    if (mode === "invalid-expiry") {
      snapshot.layout[0].props.expires_at = "invalid-expiry";
      evidence.expires_at = "invalid-expiry";
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
      block: mode === "prevalidation",
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
        if (probe.blockAnswer) {
          probe.held = true;
          await held;
        }
        if (mode === "unknown" && probe.calls.length === 1)
          throw new Error("network");
        if (mode === "passkey") return { approval_state: "pending" };
        return {
          ...receipt,
          question_rev: evidence.question_rev,
          proposal_rev: evidence.record_rev,
          choice: request.stage.choice,
          proposal_sha256:
            mode === "wrong-receipt"
              ? "sha256:" + "0".repeat(64)
              : evidence.proposal_sha256,
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
    probe.cosmeticUpdate = () => {
      snapshot = structuredClone(snapshot);
      snapshot.rev++;
      snapshot.layout[0].props.recommendation = "reject";
      renderer.update(snapshot);
    };
    const bundleEvidence = await fetch(
      "/api/decision?task_id=task-bundle",
    ).then((r) => r.json());
    probe.newProposal = () => {
      snapshot = structuredClone(snapshot);
      snapshot.rev++;
      evidence.task_rev++;
      const item = bundleEvidence.items[1];
      Object.assign(evidence, {
        record_id: item.record_id,
        record_rev: item.record_rev,
        proposal_sha256: item.proposal_sha256,
      });
      Object.assign(snapshot.layout[0].props, {
        task_rev: evidence.task_rev,
        record_id: evidence.record_id,
        record_rev: evidence.record_rev,
        proposal_sha256: evidence.proposal_sha256,
      });
      renderer.update(snapshot);
    };
    probe.newQuestion = () => {
      snapshot = structuredClone(snapshot);
      snapshot.rev++;
      evidence.task_rev++;
      evidence.question_rev++;
      snapshot.layout[0].props.task_rev = evidence.task_rev;
      renderer.update(snapshot);
    };
    probe.failRefresh = () => {
      evidence.proposal_sha256 = "sha256:" + "0".repeat(64);
      renderer.update({ ...snapshot, rev: snapshot.rev + 1 });
    };
    probe.switchActor = () => {
      renderer.clear();
      renderer.update({ ...snapshot, page_id: "second-actor-page" });
    };
  }, mode);
  if (
    ![
      "display",
      "bundle-display",
      "invalid-expiry",
      "prevalidation",
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
  await card.locator('button[type="submit"]').click();
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
  await card.locator('button[type="submit"]').click();
  await expect(card).toContainText(
    "You rejected this. The agent will be told.",
  );
  expect(await page.evaluate(() => window.probe.calls)).toEqual([]);
});
test("an unknown answer outcome locks the choice and retries with the same answer key", async ({
  page,
}) => {
  const card = await mount(page, "unknown");
  await card.getByRole("radio", { name: "Approve", exact: true }).check();
  await card.locator('button[type="submit"]').click();
  await expect(card).toContainText("The outcome is unknown");
  await expect(
    card.getByRole("radio", { name: "Reject", exact: true }),
  ).toBeDisabled();
  await card.getByRole("button", { name: "Check again" }).click();
  await expect(card.locator(".decision-status")).toHaveText(
    "Your decision wasn't recorded. Try again to record Approve.",
  );
  await expect(page.locator("#probe-announcements")).toHaveText(
    "Your decision wasn't recorded. Try again to record Approve.",
  );
  await card.getByRole("button", { name: "Record Approve again" }).click();
  await expect(card).toContainText(
    "You approved this. The agent will apply it.",
  );
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
  await card.locator('button[type="submit"]').click();
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
    await expect(card.getByRole("radio")).toHaveCount(0);
    await expect(card.locator(".decision-proposal")).toBeEmpty();
    await expect(card).not.toContainText("€120.01");
    expect(await page.evaluate(() => window.probe.calls)).toEqual([]);
  });
}

for (const mode of ["current-old-rev", "answer-expired"]) {
  test(`${mode} displays the bound current answer without creating new approval authority`, async ({
    page,
  }) => {
    const card = await mount(page, mode);
    await expect(card).toContainText(
      "You approved this. The agent will apply it.",
    );
    await expect(card.getByRole("radio")).toHaveCount(0);
    await expect(card.locator(".recorded-choice")).toBeVisible();
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
  await card.locator('button[type="submit"]').click();
  await expect(card).toContainText(
    "You rejected this. The agent will be told.",
  );
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
  await card.locator('button[type="submit"]').click();
  await expect(card.locator(".decision-status")).toHaveText(
    "Decision verification is pending.",
  );
  await expect(card).not.toContainText("You approved this.");
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
    await card.locator('button[type="submit"]').click();
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

test("no proposal value is mounted before its trusted read validates", async ({
  page,
}) => {
  const card = await mount(page, "prevalidation");
  await expect.poll(() => page.evaluate(() => window.probe.held)).toBe(true);
  await expect(card.locator(".decision-proposal")).toBeEmpty();
  await page.evaluate(() => window.probe.release());
  await expect(card.locator(".decision-proposal")).toContainText("€120.00");
});
test("a failed refresh removes values from the earlier verified proposal", async ({
  page,
}) => {
  const card = await mount(page, "refresh-mismatch");
  await expect(card.locator(".decision-proposal")).toContainText("€120.00");
  await page.evaluate(() => window.probe.failRefresh());
  await expect(card.locator(".decision-status")).toContainText(
    "This proposal changed",
  );
  await expect(card.locator(".decision-proposal")).toBeEmpty();
});
test("a malformed expiry is expired and never answerable", async ({ page }) => {
  const card = await mount(page, "invalid-expiry");
  await expect(card.locator(".decision-status")).toContainText("expired");
  await expect(card.getByRole("radio")).toHaveCount(0);
  await expect(card.locator(".decision-proposal")).toBeEmpty();
  expect(await page.evaluate(() => window.probe.calls)).toEqual([]);
});

test("recording a decision names the choice and announces the in-flight state", async ({
  page,
}) => {
  const card = await mount(page, "in-flight");
  await expect(card).toContainText("Choose an option to record your decision.");
  await card.getByRole("radio", { name: "Approve", exact: true }).check();
  await expect(card.locator('button[type="submit"]')).toHaveText("Approve");
  await expect(
    card.getByText("Choose an option to record your decision.", {
      exact: true,
    }),
  ).toBeHidden();
  await page.evaluate(() => {
    window.probe.blockAnswer = true;
  });
  await card.locator('button[type="submit"]').click();
  await expect.poll(() => page.evaluate(() => window.probe.held)).toBe(true);
  await expect(card.locator(".decision-status")).toHaveText(
    "Recording your decision…",
  );
  await expect(page.locator("#probe-announcements")).toHaveText(
    "Recording your decision…",
  );
  await page.evaluate(() => window.probe.release());
  await expect(card).toContainText(
    "You approved this. The agent will apply it.",
  );
});

test("an unknown answer keeps its locked choice and key after a cosmetic replacement", async ({
  page,
}) => {
  const card = await mount(page, "unknown");
  await card.getByRole("radio", { name: "Approve", exact: true }).check();
  await card.locator('button[type="submit"]').click();
  await expect(card).toContainText("The outcome is unknown");
  await page.evaluate(() => window.probe.cosmeticUpdate());
  await expect(
    card.getByRole("radio", { name: "Reject", exact: true }),
  ).toBeDisabled();
  await expect(card.locator('button[type="submit"]')).toHaveText(
    "Record Approve again",
  );
  await card.getByRole("button", { name: "Check again" }).click();
  await card.locator('button[type="submit"]').click();
  await expect(card).toContainText("You approved this.");
  const calls = await page.evaluate(() => window.probe.calls);
  expect(calls).toHaveLength(2);
  expect(calls[1].request.stage).toEqual(calls[0].request.stage);
});
for (const change of ["newQuestion", "newProposal", "switchActor"]) {
  test(`an unknown attempt is not reused after ${change}`, async ({ page }) => {
    const card = await mount(page, "unknown");
    await card.getByRole("radio", { name: "Approve", exact: true }).check();
    await card.locator('button[type="submit"]').click();
    await expect(card).toContainText("The outcome is unknown");
    await page.evaluate((change) => window.probe[change](), change);
    const reject = card.getByRole("radio", { name: "Reject", exact: true });
    await expect(reject).toBeEnabled();
    await expect(card.getByRole("radio", { checked: true })).toHaveCount(0);
    await reject.check();
    await card.locator('button[type="submit"]').click();
    await expect(card).toContainText("You rejected this.");
    const calls = await page.evaluate(() => window.probe.calls);
    expect(calls).toHaveLength(2);
    expect(calls[1].request.stage.answer_key).not.toBe(
      calls[0].request.stage.answer_key,
    );
    expect(calls[1].request.stage.choice).toBe("reject");
  });
}

test("unsigned schema titles cannot relabel trusted proposal values", async ({
  page,
}) => {
  const card = await mount(page, "schema-spoof");
  await expect(card.locator(".decision-proposal")).toContainText(
    "Nightly price",
  );
  await expect(card.locator(".decision-proposal")).toContainText("€120.00");
  await expect(card).not.toContainText("Account balance");
  await expect(card).not.toContainText("Do not show this title");
});

test("a cosmetic replacement cannot send another answer while the first call is outstanding", async ({
  page,
}) => {
  const card = await mount(page, "inflight-replacement");
  await card.getByRole("radio", { name: "Approve", exact: true }).check();
  await page.evaluate(() => {
    window.probe.blockAnswer = true;
  });
  await card.locator('button[type="submit"]').click();
  await expect.poll(() => page.evaluate(() => window.probe.held)).toBe(true);
  await page.evaluate(() => window.probe.cosmeticUpdate());
  await expect(card.locator(".decision-status")).toHaveText(
    "Recording your decision…",
  );
  await expect(card.locator('button[type="submit"]')).toBeDisabled();
  await card.getByRole("button", { name: "Check again" }).click();
  await expect(card.locator('button[type="submit"]')).toBeDisabled();
  expect(await page.evaluate(() => window.probe.calls.length)).toBe(1);
  await page.evaluate(() => {
    window.probe.blockAnswer = false;
    window.probe.release();
  });
  await card.getByRole("button", { name: "Check again" }).click();
  await expect(card.locator('button[type="submit"]')).toBeEnabled();
  await card.locator('button[type="submit"]').click();
  await expect(card).toContainText("You approved this.");
  const calls = await page.evaluate(() => window.probe.calls);
  expect(calls).toHaveLength(2);
  expect(calls[1].request.stage).toEqual(calls[0].request.stage);
});
