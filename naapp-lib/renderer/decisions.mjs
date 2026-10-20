import { element, valueText } from "./dom.mjs";
import { inputErrors } from "./input.mjs";
import { canonical, proposalDigest, bundleDigest } from "./digests.mjs";

const changed = "This proposal changed. Ask the agent for a new decision.";
const expired = "This proposal has expired. Ask the agent for a new proposal.";
const fail = (message) => {
  throw Object.assign(new Error(message), { publicMessage: message });
};
const recordFor = (page, collection, id) =>
  page.collections
    .find((c) => c.id === collection)
    ?.records.find((r) => r.id === id);

// The adapter owns authenticated reads and the entire approval ceremony. Page
// state is display-only and never grants answer authority.
export function createDecision({ box, w, host, actions, getPage, announce }) {
  const p = w.props;
  let disposed = false,
    serial = 0,
    busy = false,
    ready = false,
    answer,
    attempt,
    needsCheck = false;
  const heading = element("h2", p.operation.summary);
  const metadata = element("dl", null, "decision-metadata");
  for (const [label, value] of [
    ["Operation", p.operation.kind],
    ["Destination", p.operation.destination],
    ["Source version", p.source_version],
    ["Expires", valueText(p.expires_at, "date-time", "en", host.timeZone)],
  ]) {
    const dd = element("dd");
    dd.append(element("bdi", value));
    metadata.append(element("dt", label), dd);
  }
  const proposal = element("div", null, "decision-proposal");
  const details = element("details");
  details.append(element("summary", "Proposal details"));
  for (const text of [
    `Record: ${p.collection}/${p.record_id}`,
    `Revision: ${p.record_rev}`,
    `Digest: ${p.proposal_sha256}`,
  ])
    details.append(element("p", text, "field-description"));
  box.append(heading, metadata, proposal, details);
  if (p.bundle)
    box.append(
      element(
        "p",
        "All items together · one decision for the complete bundle.",
        "field-description",
      ),
    );
  if (p.recommendation) {
    const option = p.options.find((o) => o.value === p.recommendation);
    if (option)
      box.append(
        element(
          "p",
          `Agent recommendation: ${option.label} · advisory only`,
          "field-description",
        ),
      );
  }
  const form = element("form", null, "decision-form"),
    choices = element("fieldset");
  const legend = element("legend", "Your decision");
  legend.lang = "en";
  choices.append(legend);
  const radios = [];
  for (const option of p.options) {
    const label = element("label", null, "decision-option"),
      radio = element("input");
    radio.type = "radio";
    radio.name = `decision-${w.id}`;
    radio.value = option.value;
    radio.dataset.focusKey = `choice:${option.value}`;
    label.append(radio, element("span", option.label));
    choices.append(label);
    radios.push(radio);
    radio.onchange = () => paint();
  }
  const submit = element("button", "Record decision", "primary-button");
  submit.type = "submit";
  submit.dataset.focusKey = "decision-submit";
  const status = element("p", "Checking decision…", "decision-status");
  status.setAttribute("role", "status");
  status.tabIndex = -1;
  const history = element("p", null, "field-description");
  history.hidden = true;
  const stepup = element("p", null, "field-description");
  const check = element("button", "Check decision status");
  check.type = "button";
  check.hidden = true;
  for (const node of [history, stepup, submit, status, check]) node.lang = "en";
  form.append(history, choices, stepup, submit, status, check);
  box.append(form);
  const labelFor = (value) => p.options.find((o) => o.value === value)?.label;
  const selected = () => p.options[radios.findIndex((r) => r.checked)]?.value;
  function paint() {
    if (disposed) return;
    const active = document.activeElement;
    const isExpired = Date.parse(p.expires_at) <= Date.now();
    if (isExpired && !answer) {
      ready = false;
      status.textContent = expired;
    }
    for (const radio of radios)
      radio.disabled = busy || !ready || !!answer || !!attempt;
    submit.hidden = !!answer;
    submit.disabled = busy || !ready || !selected() || isExpired;
    submit.textContent = attempt
      ? "Retry recording decision"
      : "Record decision";
    check.hidden =
      (!attempt && !needsCheck) ||
      (!!answer && answer.approval_state !== "pending");
    check.disabled = busy;
    form.setAttribute("aria-busy", String(busy));
    if (box.contains(active) && (active.disabled || active.hidden))
      status.focus({ preventScroll: true });
  }
  function showRecords(page) {
    const record = recordFor(page, p.collection, p.record_id);
    const items = p.bundle ? record?.value?.items : undefined;
    const records = p.bundle
      ? (items || []).map((item) =>
          recordFor(page, p.items_collection, item.record_id),
        )
      : [record];
    proposal.replaceChildren();
    for (const [index, item] of records.entries()) {
      if (!item) continue;
      const section = element(
        "section",
        null,
        p.bundle ? "bundle-item" : "proposal-record",
      );
      if (p.bundle)
        section.append(
          element("h3", `Item ${index + 1} · revision ${item.rev}`),
        );
      const fields = element("dl"),
        collection = p.bundle ? p.items_collection : p.collection;
      const schema = page.collections.find((c) => c.id === collection)?.schema;
      for (const [field, value] of Object.entries(item.value)) {
        const property = schema?.properties?.[field];
        const dd = element("dd");
        dd.append(
          element(
            "bdi",
            valueText(
              value,
              ["date", "date-time"].includes(property?.format)
                ? property.format
                : typeof value === "number"
                  ? "number"
                  : "text",
              "en",
              host.timeZone,
            ),
          ),
        );
        fields.append(element("dt", property?.title || field), dd);
      }
      section.append(fields);
      proposal.append(section);
    }
  }
  async function validate(page, evidence, context) {
    const assert = () => {
      if (disposed) throw { silent: true };
      if (context) actions.assertCurrent(context);
      if (page !== getPage()) fail(changed);
    };
    assert();
    if (
      !evidence ||
      evidence.task_id !== p.task_id ||
      !Number.isSafeInteger(evidence.task_rev) ||
      !Number.isSafeInteger(evidence.question_rev) ||
      evidence.question_rev < 0
    )
      fail(changed);
    for (const key of [
      "collection",
      "record_id",
      "record_rev",
      "proposal_sha256",
      "source_version",
      "expires_at",
    ])
      if (evidence[key] !== p[key]) fail(changed);
    if (
      !evidence.operation ||
      canonical(evidence.operation) !== canonical(p.operation)
    )
      fail(changed);
    const record = recordFor(page, p.collection, p.record_id);
    if (!record || record.rev !== p.record_rev) fail(changed);
    if (p.bundle) {
      const items = record.value.items;
      if (
        !Array.isArray(items) ||
        !Array.isArray(evidence.items) ||
        canonical(evidence.items) !== canonical(items)
      )
        fail(changed);
      for (const item of items) {
        const current = recordFor(page, p.items_collection, item.record_id);
        if (
          !current ||
          current.rev !== item.record_rev ||
          (await proposalDigest(p.items_collection, current)) !==
            item.proposal_sha256
        )
          fail(changed);
        assert();
      }
      if ((await bundleDigest(items)) !== p.proposal_sha256) fail(changed);
    } else if (
      (await proposalDigest(p.collection, record)) !== p.proposal_sha256
    )
      fail(changed);
    assert();
    if (
      evidence.answer?.current !== true &&
      Date.parse(p.expires_at) <= Date.now()
    )
      fail(expired);
    if (!["member_session", "passkey"].includes(evidence.authenticator))
      fail("Verified approval is unavailable.");
    return record;
  }
  function currentReceipt(receipt, evidence) {
    return (
      receipt?.current === true &&
      receipt.task_id === p.task_id &&
      receipt.question_rev === evidence.question_rev &&
      receipt.proposal_rev === p.record_rev &&
      receipt.proposal_sha256 === p.proposal_sha256 &&
      /^[A-Za-z0-9._-]{1,128}$/.test(receipt.task_answer_ref || "") &&
      !!labelFor(receipt.choice)
    );
  }
  function showHistory(evidence) {
    history.hidden = evidence.answer?.current !== false;
    const label = labelFor(evidence.answer?.choice);
    history.textContent = label
      ? `Earlier answer: ${label} · superseded.`
      : "Earlier answer is superseded.";
  }
  function applyEvidence(evidence) {
    if (evidence.answer?.current === true) {
      if (!currentReceipt(evidence.answer, evidence))
        fail("The recorded decision is unavailable. Check with the agent.");
      answer = evidence.answer;
      needsCheck = answer.approval_state === "pending";
      ready = false;
      status.textContent = `Decision recorded: ${labelFor(answer.choice)}${answer.approval_state === "pending" ? ". Waiting for verification." : ""}`;
    } else if (evidence.task_rev !== p.task_rev) {
      ready = false;
      status.textContent = changed;
    } else if (evidence.status !== "open") {
      ready = false;
      needsCheck = evidence.status === "pending";
      status.textContent =
        evidence.status === "pending"
          ? "Decision verification is pending."
          : "This decision is closed.";
    } else if (!evidence.allowed) {
      ready = false;
      status.textContent = "You cannot answer this decision.";
    } else {
      ready = true;
      status.textContent = attempt
        ? "The outcome is not confirmed. Retry only the same decision, or check its status."
        : "Choose an option to record your decision.";
    }
    stepup.textContent =
      evidence.authenticator === "passkey"
        ? "A passkey check on the app origin is required to record this decision."
        : "";
    paint();
  }
  async function inspect(context) {
    const page = getPage();
    if (!host.decision || !host.answer) fail("This decision is unavailable.");
    const evidence = await host.decision(p.task_id);
    if (disposed) throw { silent: true };
    if (context) actions.assertCurrent(context);
    if (evidence?.task_id === p.task_id) showHistory(evidence);
    await validate(page, evidence, context);
    if (disposed) throw { silent: true };
    const action = page.actions.find((a) => a.id === p.answer_action);
    if (!action || action.kind !== "answer")
      fail("This decision is unavailable.");
    if (
      evidence.answer?.current !== true &&
      inputErrors({}, action.input_schema).length
    )
      fail(
        "This decision requires additional input that this page cannot collect. Ask the agent to revise it.",
      );
    return { page, evidence };
  }
  async function refresh() {
    if (busy || disposed) return;
    const request = ++serial;
    try {
      const { page, evidence } = await inspect();
      if (request !== serial || disposed) return;
      showRecords(page);
      if (
        evidence.allowed &&
        evidence.task_rev === p.task_rev &&
        evidence.status === "open" &&
        evidence.answer?.current !== true
      ) {
        const context = actions.capture(
          w,
          p.answer_action,
          recordFor(page, p.collection, p.record_id),
        );
        await actions.csrf(context);
        if (request !== serial || disposed) return;
      }
      applyEvidence(evidence);
    } catch (error) {
      if (disposed || request !== serial || error?.silent) return;
      ready = false;
      needsCheck = true;
      status.textContent =
        error?.code === "csrf_required"
          ? "The host could not verify this request. Refresh the page."
          : error.publicMessage || "This decision is unavailable.";
      paint();
    }
  }
  check.onclick = (event) => {
    if (event.isTrusted && !busy) refresh();
  };
  form.onsubmit = async (event) => {
    event.preventDefault();
    if (!event.isTrusted || busy || !ready || !selected() || answer) return;
    const choice = attempt?.stage.choice || selected();
    let context;
    busy = true;
    ++serial;
    paint();
    try {
      const page = getPage();
      context = actions.capture(
        w,
        p.answer_action,
        recordFor(page, p.collection, p.record_id),
      );
      const inspection = await inspect(context);
      actions.assertCurrent(context);
      if (
        inspection.evidence.task_rev !== p.task_rev ||
        inspection.evidence.status !== "open" ||
        inspection.evidence.answer?.current === true ||
        !inspection.evidence.allowed
      ) {
        applyEvidence(inspection.evidence);
        return;
      }
      const credential = await actions.csrf(context);
      actions.assertCurrent(context);
      if (disposed || getPage() !== inspection.page) fail(changed);
      if (Date.parse(p.expires_at) <= Date.now()) fail(expired);
      attempt ??= {
        page_id: context.page_id,
        widget_id: w.id,
        action_id: p.answer_action,
        task_id: p.task_id,
        stage: {
          expected_task_rev: p.task_rev,
          choice,
          input: {},
          proposal_rev: p.record_rev,
          proposal_sha256: p.proposal_sha256,
          answer_key: crypto.randomUUID(),
        },
      };
      const receipt = await host.answer(
        structuredClone(attempt),
        credential,
        event,
      );
      actions.assertCurrent(context);
      if (disposed) return;
      if (
        currentReceipt(receipt, inspection.evidence) &&
        receipt.choice === choice
      ) {
        applyEvidence({
          ...inspection.evidence,
          status: "answered",
          answer: receipt,
        });
        announce(status.textContent);
      } else {
        ready = false;
        needsCheck = true;
        status.textContent = "Decision verification is pending.";
      }
    } catch (error) {
      if (disposed || error?.silent) return;
      ready = false;
      needsCheck = true;
      status.textContent = attempt
        ? "The outcome is unknown. Check decision status before retrying."
        : error.publicMessage ||
          "This decision is unavailable. Refresh the page.";
      announce(status.textContent);
    } finally {
      busy = false;
      if (!disposed) {
        paint();
        (submit.hidden || submit.disabled ? status : submit).focus({
          preventScroll: true,
        });
      }
    }
  };
  try {
    showRecords(getPage());
  } catch {
    status.textContent = changed;
  }
  paint();
  refresh();
  const timer = setInterval(() => {
    if (ready && Date.parse(p.expires_at) <= Date.now()) {
      paint();
      announce(status.textContent);
    }
  }, 1000);
  return {
    refresh,
    clear() {
      disposed = true;
      ++serial;
      clearInterval(timer);
    },
  };
}
