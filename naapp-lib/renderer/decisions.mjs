import { element, valueText } from "./dom.mjs";
import { decisionRows } from "./decision-display.mjs";
import { inputErrors } from "./input.mjs";
import { canonical, proposalDigest, bundleDigest } from "./digests.mjs";

const changed = "This proposal changed. Ask the agent for a new proposal.";
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
export function createDecision({
  box,
  w,
  host,
  actions,
  attempts,
  getPage,
  announce,
}) {
  const p = w.props;
  const expiresAt = Date.parse(p.expires_at);
  const isExpired = () =>
    !Number.isFinite(expiresAt) || expiresAt <= Date.now();
  let disposed = false,
    serial = 0,
    busy = false,
    ready = false,
    answer,
    attempt,
    attemptKey,
    trustedOptions = [],
    needsCheck = false;
  const heading = element("h2", p.operation.summary);
  const metadata = element("dl", null, "decision-metadata");
  const destination = element(
    "dd",
    `${p.operation.summary} · ${p.operation.destination}`,
  );
  const expiryLabel = element("dt", "Expires"),
    expiryValue = element("dd");
  metadata.append(
    element("dt", "What approving does"),
    destination,
    expiryLabel,
    expiryValue,
  );
  function updateExpiry() {
    expiryLabel.textContent = isExpired() ? "Expired" : "Expires";
    if (!Number.isFinite(expiresAt)) {
      expiryValue.textContent = "Expiry unavailable";
      return;
    }
    if (isExpired())
      expiryValue.textContent = valueText(
        p.expires_at,
        "date",
        "en",
        host.timeZone,
      );
    else {
      const minutes = Math.ceil((expiresAt - Date.now()) / 60000);
      const unit = minutes >= 60 ? "hour" : "minute";
      const amount =
        unit === "hour" ? Math.ceil(minutes / 60) : Math.max(1, minutes);
      const relative = new Intl.RelativeTimeFormat("en").format(amount, unit);
      const time = new Intl.DateTimeFormat("en", {
        timeStyle: "short",
        timeZone: host.timeZone,
      }).format(expiresAt);
      expiryValue.textContent = `${relative} (${time})`;
    }
  }
  const proposal = element("div", null, "decision-proposal");
  const details = element("details");
  details.append(element("summary", "Proposal details"));
  for (const text of [
    `Operation: ${p.operation.kind}`,
    `Source version: ${p.source_version}`,
    `Record: ${p.collection}/${p.record_id}`,
    `Revision: ${p.record_rev}`,
    `Digest: ${p.proposal_sha256}`,
  ])
    details.append(element("p", text, "field-description"));
  const bundleSummary = element("p", null, "field-description");
  bundleSummary.hidden = !p.bundle;
  const recommendation = element("p", null, "field-description");
  recommendation.hidden = true;
  const form = element("form", null, "decision-form"),
    choices = element("fieldset");
  const legend = element("legend", "Your decision");
  legend.lang = "en";
  choices.append(legend);
  const radios = [];
  function setOptions(options) {
    trustedOptions = options;
    if (!radios.length)
      for (const option of options) {
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
    const recommended = options.find((o) => o.value === p.recommendation);
    recommendation.hidden = !recommended;
    recommendation.textContent = recommended
      ? `The agent recommends ${recommended.label}.`
      : "";
  }
  const submit = element("button", "Record decision", "primary-button");
  submit.type = "submit";
  submit.dataset.focusKey = "decision-submit";
  const status = element("p", "Checking decision…", "decision-status");
  // The host announcement region is the single polite live channel.
  // Actions also focus this visible status; avoid a second live announcement.
  status.tabIndex = -1;
  const history = element("p", null, "field-description");
  history.hidden = true;
  const stepup = element("p", null, "field-description");
  const check = element("button", "Check again");
  check.type = "button";
  check.hidden = true;
  for (const node of [history, stepup, submit, status, check]) node.lang = "en";
  const hint = element(
    "p",
    "Choose an option to record your decision.",
    "field-description",
  );
  hint.lang = "en";
  form.append(choices, stepup, hint, submit, check);
  box.append(
    heading,
    status,
    history,
    bundleSummary,
    proposal,
    metadata,
    recommendation,
    form,
    details,
  );
  const labelFor = (value) =>
    trustedOptions.find((o) => o.value === value)?.label;
  const selected = () =>
    trustedOptions[radios.findIndex((r) => r.checked)]?.value;
  function paint() {
    if (disposed) return;
    const active = document.activeElement;
    updateExpiry();
    if (isExpired() && !answer) {
      ready = false;
      status.textContent = expired;
    }
    for (const radio of radios)
      radio.disabled = busy || !ready || !!answer || !!attempt;
    submit.hidden = !!answer;
    submit.disabled = busy || !ready || !selected() || isExpired();
    submit.textContent = attempt
      ? `Record ${labelFor(attempt.stage.choice)} again`
      : labelFor(selected()) || "Record decision";
    hint.hidden = !!selected() || !ready || !!answer || !!attempt;
    status.hidden = !status.textContent;
    check.hidden = (!attempt && !needsCheck) || (!!answer && !needsCheck);
    check.disabled = busy;
    form.setAttribute("aria-busy", String(busy));
    if (box.contains(active) && (active.disabled || active.hidden))
      status.focus({ preventScroll: true });
  }
  function showRecords(page, evidence) {
    const record = recordFor(page, p.collection, p.record_id);
    const items = p.bundle ? record?.value?.items : undefined;
    const records = p.bundle
      ? (items || []).map((item) =>
          recordFor(page, p.items_collection, item.record_id),
        )
      : [record];
    proposal.replaceChildren();
    if (p.bundle)
      bundleSummary.textContent =
        records.length === 2
          ? "One decision covers both items."
          : `One decision covers all ${records.length} items.`;
    for (const [index, item] of records.entries()) {
      if (!item) continue;
      const section = element(
        "section",
        null,
        p.bundle ? "bundle-item" : "proposal-record",
      );
      if (p.bundle)
        section.append(element("h3", `${index + 1} of ${records.length}`));
      const fields = element("dl");
      for (const [label, value, format, currency] of decisionRows(
        p.options,
        evidence,
        item.value,
      )) {
        const dd = element("dd");
        dd.append(
          element(
            "bdi",
            valueText(value, format, "en", host.timeZone, currency),
          ),
        );
        fields.append(element("dt", label), dd);
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
    const displayRecords = p.bundle
      ? record.value.items.map((item) =>
          recordFor(page, p.items_collection, item.record_id),
        )
      : [record];
    try {
      for (const item of displayRecords)
        decisionRows(p.options, evidence, item.value);
    } catch {
      fail(
        "This proposal's verified choices or display fields changed. Ask the agent for a new proposal.",
      );
    }
    if (
      !Number.isFinite(expiresAt) ||
      (evidence.answer?.current !== true && isExpired())
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
      attempts.delete(attemptKey);
      attempt = undefined;
      const pendingVerification =
        evidence.authenticator === "passkey" &&
        !["approved", "rejected"].includes(answer.approval_state);
      needsCheck =
        pendingVerification ||
        (answer.choice === "approve" &&
          !["applied", "failed"].includes(evidence.application_state));
      ready = false;
      status.textContent = pendingVerification
        ? "Your decision was recorded. Verification is pending."
        : evidence.application_state === "applied"
          ? "Applied."
          : evidence.application_state === "failed"
            ? "Your decision was recorded. It could not be applied. Check with the agent."
            : answer.choice === "approve"
              ? "You approved this. The agent will apply it."
              : answer.choice === "reject"
                ? "You rejected this. The agent will be told."
                : `Your decision was recorded: ${labelFor(answer.choice)}.`;
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
    } else if (attempts.get(attemptKey)?.state === "inflight") {
      ready = false;
      needsCheck = true;
      status.textContent = "Recording your decision…";
    } else {
      ready = true;
      status.textContent = attempt
        ? `Your decision wasn't recorded. Try again to record ${labelFor(attempt.stage.choice)}.`
        : "";
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
    await validate(page, evidence, context);
    setOptions(evidence.options);
    if (evidence?.task_id === p.task_id) showHistory(evidence);
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
    attemptKey = canonical({
      page_id: page.page_id,
      task_id: p.task_id,
      question_rev: evidence.question_rev,
      collection: p.collection,
      record_id: p.record_id,
      record_rev: p.record_rev,
      proposal_sha256: p.proposal_sha256,
      operation: p.operation,
      source_version: p.source_version,
      expires_at: p.expires_at,
    });
    const pending = attempts.get(attemptKey);
    if (pending && evidence.answer?.current !== true) {
      attempt = structuredClone(pending.request);
      needsCheck = true;
      if (
        attempt.stage.expected_task_rev !== p.task_rev ||
        attempt.action_id !== p.answer_action ||
        attempt.widget_id !== w.id
      )
        fail(
          "An earlier decision is awaiting confirmation. Check with the agent before answering again.",
        );
      for (const [index, radio] of radios.entries())
        radio.checked = trustedOptions[index].value === attempt.stage.choice;
    }
    return { page, evidence };
  }
  async function refresh(announceResult = false) {
    if (busy || disposed) return;
    const request = ++serial;
    try {
      const { page, evidence } = await inspect();
      if (request !== serial || disposed) return;
      showRecords(page, evidence);
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
      if (announceResult) announce(status.textContent);
    } catch (error) {
      if (disposed || request !== serial || error?.silent) return;
      proposal.replaceChildren();
      ready = false;
      needsCheck = true;
      status.textContent =
        error?.code === "csrf_required"
          ? "The host could not verify this request. Refresh the page."
          : error.publicMessage || "This decision is unavailable.";
      paint();
      if (announceResult) announce(status.textContent);
    }
  }
  check.onclick = (event) => {
    if (event.isTrusted && !busy) refresh(true);
  };
  form.onsubmit = async (event) => {
    event.preventDefault();
    if (!event.isTrusted || busy || !ready || !selected() || answer) return;
    const choice = attempt?.stage.choice || selected();
    let context;
    busy = true;
    status.textContent = "Recording your decision…";
    announce(status.textContent);
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
      if (isExpired()) fail(expired);
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
      const pending = { request: structuredClone(attempt), state: "inflight" };
      attempts.set(attemptKey, pending);
      let receipt;
      try {
        receipt = await host.answer(
          structuredClone(attempt),
          credential,
          event,
        );
      } finally {
        // Private bookkeeping survives disposal; it never dispatches or adopts
        // a receipt. The next controller must obtain a new authoritative read.
        pending.state = "unknown";
      }
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
      proposal.replaceChildren();
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
  paint();
  refresh();
  const timer = setInterval(() => {
    updateExpiry();
    if (ready && isExpired()) {
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
