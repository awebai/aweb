"use strict";

import { validateProtectedPresentation } from "/handoff-assets/protected-presentation.mjs";
import { operationTable } from "/handoff-assets/operations.mjs";
import { renderDisplay, displayRefusal } from "/handoff-assets/protected-display.mjs";

(() => {
  const {handoffId, purpose} = document.body.dataset;
  const prefix = `/handoff/${handoffId}/${purpose}`;
  const action = document.getElementById("handoff-action");
  const confirm = document.getElementById("handoff-confirm");
  const allow = document.getElementById("handoff-allow");
  const status = document.getElementById("handoff-status");
  const governance = purpose === "governance";
  const loginScope = document.body.dataset.loginScope;
  const csrfKey = document.body.dataset.consoleCsrfKey;
  const deny = document.getElementById("handoff-deny");
  const note = document.getElementById("handoff-choice-note");
  // A mailed personal link carries its approver's token in the fragment,
  // which the browser never sends. Take it, then drop it from the address bar
  // and history; it is only ever sent in a POST body.
  const linkToken = governance ? new URLSearchParams(window.location.hash.slice(1)).get("k") : null;
  if (linkToken !== null) history.replaceState(null, "", window.location.pathname);
  const linked = typeof linkToken === "string" && linkToken.length > 0;
  let loggedIn = false;
  let operationId;
  let submitted = false;
  let frozenRedirect;
  let csrf;
  let display;

  document.getElementById("handoff-origin").textContent = window.location.origin;

  async function fetchJSON(path, body) {
    const headers = body === undefined ? {} : {
      "Content-Type": "application/json", "X-CSRF-Token": csrf,
    };
    const response = await fetch(path, {
      method: body === undefined ? "GET" : "POST",
      credentials: "same-origin", cache: "no-store", redirect: "error", headers,
      body: body === undefined ? undefined : JSON.stringify(body),
    });
    if (!response.ok) {
      const error = new Error("handoff_refused");
      error.status = response.status;
      throw error;
    }
    return response.json();
  }

  function request(suffix, body) {
    return fetchJSON(prefix + suffix, body);
  }

  function failed() {
    // Completion may have committed even if its response was lost. Never
    // replay a completion or an Allow, and never collect the result here.
    action.disabled = true;
    confirm.disabled = true;
    allow.hidden = true;
    deny.hidden = true;
    note.hidden = true;
    if (governance) {
      document.getElementById("handoff-governance").hidden = true;
      document.getElementById("handoff-scope").hidden = true;
    }
    csrf = undefined;
    document.body.dataset.handoffState = governance && submitted ? "unconfirmed" : "refused";
    status.textContent = governance
      ? "This page could not confirm what happened. Your owner page shows the outcome under History."
      : "This request could not be completed. Return to your terminal and start again.";
  }

  function complete(result) {
    if (typeof result.redirect_uri !== "string") throw new Error("handoff_refused");
    csrf = undefined;
    document.body.dataset.handoffState = "complete";
    status.textContent = "Complete. Returning to your terminal…";
    // Only the existing completion route supplies the stored, validated
    // loopback URI. No URL, scope, code or verifier comes from page parameters.
    window.location.assign(result.redirect_uri);
  }

  function nonempty(value) {
    return typeof value === "string" && value.length > 0;
  }

  async function governanceState(state) {
    const {payload, digest} = state;
    const {request} = await validateProtectedPresentation(state, handoffId, operationTable);
    display = operationTable[`${request.operation}|${request.variant}`].display;
    const words = renderDisplay(display, request);
    operationId = state.operation_id;
    frozenRedirect = request.redirect_uri;
    if (frozenRedirect !== undefined) {
      if (!nonempty(frozenRedirect)) throw new Error("handoff_refused");
      const redirect = new URL(frozenRedirect);
      if (redirect.protocol !== "http:" || redirect.search || redirect.hash ||
          redirect.username || redirect.password) throw new Error("handoff_refused");
    }
    setTitle(words.title);
    document.getElementById("handoff-consequences").replaceChildren(...words.consequences.map(line => {
      const item = document.createElement("li");
      item.textContent = line;
      return item;
    }));
    rows("handoff-names", words.names);
    rows("handoff-technical", words.technical);
    document.getElementById("handoff-act").textContent = request.operation;
    document.getElementById("handoff-digest").textContent = digest;
    document.getElementById("handoff-fingerprint").textContent = digest.slice(0, 16).match(/.{4}/g).join(" ");
    document.getElementById("handoff-payload").textContent = JSON.stringify(payload, null, 2);
    const asked = request.artifact?.issued_at;
    document.getElementById("handoff-requested").textContent =
      (words.requester ?? request.requester) + (nonempty(asked) ? `, asked ${when(asked)}` : "");
    document.getElementById("handoff-expires").textContent = when(state.expires_at);
    document.getElementById("handoff-governance").hidden = false;
    document.getElementById("handoff-explanation").hidden = true;
    action.textContent = "Approve";
    deny.hidden = false;
    deny.disabled = false;
    note.hidden = false;
    status.textContent = "Check the request before you decide.";
    document.body.dataset.handoffState = "ready";
    action.disabled = false;
    document.getElementById("handoff-title").focus();
  }

  // Label/value rows of a description list, as text only.
  function rows(id, pairs) {
    document.getElementById(id).replaceChildren(...pairs.flatMap(([label, value]) => {
      const term = document.createElement("dt");
      const detail = document.createElement("dd");
      term.textContent = label;
      detail.textContent = value;
      return [term, detail];
    }));
  }

  // A stored time in the reader's own zone, with the zone named.
  function when(stamp) {
    return new Date(stamp).toLocaleString(undefined, {
      year: "numeric", month: "short", day: "numeric", hour: "numeric", minute: "2-digit",
      timeZoneName: "short",
    });
  }

  // The page's heading is its state: the request, then what became of it.
  function setTitle(text) {
    document.getElementById("handoff-title").textContent = text;
    document.title = text;
  }

  function stopChoices() {
    action.hidden = true;
    deny.hidden = true;
    note.hidden = true;
    document.getElementById("handoff-explanation").hidden = true;
  }

  function governanceComplete(result) {
    if (result.state === "pending") {
      if (result.redirect_uri !== undefined || !nonempty(result.expires_at) ||
          !Number.isFinite(Date.parse(result.expires_at))) throw new Error("handoff_refused");
      document.body.dataset.handoffState = "pending";
      outcome("Approved", "It is still being carried out. Your owner page shows the outcome under History.");
      return;
    }
    if (result.state !== "committed" || !result.result ||
        typeof result.result !== "object" || Array.isArray(result.result) ||
        !nonempty(result.result.signing) || !nonempty(result.result.signature)) {
      throw new Error("handoff_refused");
    }
    if (frozenRedirect === undefined) {
      if (result.redirect_uri !== undefined) throw new Error("handoff_refused");
      csrf = undefined;
      document.body.dataset.handoffState = "complete";
      outcome("Approved", "Done. There is nothing else to do here.");
      return;
    }
    if (!nonempty(result.redirect_uri)) throw new Error("handoff_refused");
    const redirect = new URL(result.redirect_uri);
    const expected = new URL(frozenRedirect);
    expected.searchParams.set("handoff_id", handoffId);
    if (redirect.href !== expected.href) {
      throw new Error("handoff_refused");
    }
    // Only the committed route supplies the frozen loopback; the callback is
    // a code-less hint. aw independently authenticates its receipt read.
    complete(result);
  }

  // The mailed link's own narrow routes: no cookie, no CSRF token, no
  // session. The token authenticates only its approver's view and ceremony.
  async function linkPost(suffix, body) {
    const response = await fetch(`/handoff/${handoffId}/link${suffix}`, {
      method: "POST", credentials: "omit", cache: "no-store", redirect: "error",
      referrerPolicy: "no-referrer", headers: {"Content-Type": "application/json"},
      body: JSON.stringify(body),
    });
    if (!response.ok) {
      const error = new Error("handoff_refused");
      error.status = response.status;
      if (response.status === 410) error.expiresAt = (await response.json().catch(() => ({}))).expires_at;
      throw error;
    }
    return response.json();
  }

  function ownerPageSentence(before) {
    const owner = document.createElement("a");
    owner.href = "/";
    owner.textContent = "owner page";
    status.replaceChildren(before, owner, ".");
  }

  function linkUnavailable() {
    stopChoices();
    document.getElementById("handoff-governance").hidden = true;
    document.body.dataset.handoffState = "refused";
    setTitle("This link no longer works");
    ownerPageSentence("This link is not valid any more. Requests still waiting for you are on your ");
    document.getElementById("handoff-title").focus();
  }

  let decided = false;
  let inFlight = false;
  let expiresAt;

  function linkExpired(at) {
    if (decided) return;
    decided = true;
    stopChoices();
    document.getElementById("handoff-governance").hidden = true;
    document.body.dataset.handoffState = "expired";
    setTitle("Request expired");
    status.textContent = (at ? `This request expired at ${when(at)} without a decision.` :
      "This request expired without a decision.") + " Nothing was signed.";
    document.getElementById("handoff-title").focus();
  }

  function checkAt(delay) {
    setTimeout(checkExpiry, Math.max(0, Math.min(delay, 2 ** 31 - 1)));
  }

  // A local clock never establishes an outcome. A decision on its way keeps
  // the page until its own answer; otherwise the signer says what is true.
  async function checkExpiry() {
    if (decided || inFlight) return;
    try {
      await linkPost("", {token: linkToken});
      checkAt(30000);  // Still pending at the signer: the clocks differ.
    } catch (error) {
      if (decided || inFlight) return;
      if (error.status === 410) linkExpired(nonempty(error.expiresAt) ? error.expiresAt : expiresAt);
      else linkUnavailable();
    }
  }

  async function linkLoad() {
    try {
      const state = await linkPost("", {token: linkToken});
      if (state.mode !== "governance-link") throw new Error("handoff_refused");
      await governanceState({...state, mode: "governance"});
      document.getElementById("handoff-explanation").hidden = true;
      // At its expiry the page asks the signer again: only the signer's own
      // answer can say the request expired undecided.
      expiresAt = state.expires_at;
      checkAt(Date.parse(state.expires_at) - Date.now());
    } catch (error) {
      if (error.status === 410) linkExpired(nonempty(error.expiresAt) ? error.expiresAt : undefined);
      else linkUnavailable();
    }
  }

  // What a refused decision means for the approver, in words.
  const refusals = {
    human_refused: ["Denied", "The request is refused. Nothing was signed."],
    approval_expired: ["Not completed", "Your approval came too late to be used. Nothing was signed."],
    operation_expired: ["Expired", "This request expired before it was decided. Nothing was signed."],
    proof_invalid: ["Not completed", "Your passkey answer could not be checked, so nothing was decided."],
    approval_spent: ["Not completed", "Your passkeys or access changed, so this approval cannot be used."],
    stale_binding: ["Not completed", "Your passkeys or access changed while this was waiting."],
    policy_changed: ["Not completed", "The team's policy changed after this was requested, so this approval cannot apply."],
    authority_changed: ["Not completed", "The team's signing key or approvers changed after this was requested."],
  };

  const unconfirmed = ["Not confirmed",
    "This page could not confirm what happened. Your owner page shows the outcome under History."];

  function outcome(title, text) {
    decided = true;
    // Once decided, the card describes what was asked, not what it does.
    document.getElementById("handoff-governance-title").textContent = "What was asked";
    stopChoices();
    status.textContent = "";
    setTitle(title);
    const sentence = document.getElementById("handoff-outcome-text");
    sentence.textContent = text;
    sentence.hidden = false;
    document.getElementById("handoff-title").focus();
  }

  function linkOutcome(result) {
    document.body.dataset.handoffState = "complete";
    if (result.state === "committed") {
      outcome("Approved", "Done. There is nothing else to do here.");
    } else if (result.state === "pending") {
      outcome("Approved", "It is still being carried out. Your owner page shows the outcome under History.");
    } else if (result.state === "refused" && refusals[result.code]) {
      outcome(...refusals[result.code]);
    } else if (result.state === "refused" && display && displayRefusal(display, result.code)) {
      // The operation's own sentence for why it cannot go ahead.
      outcome("Not completed", `${displayRefusal(display, result.code)} Nothing was signed.`);
    } else {
      // A code this page does not know: it cannot say what happened.
      outcome(...unconfirmed);
    }
  }

  async function decide(decision) {
    const pressed = decision === "reject" ? deny : action;
    inFlight = true;
    action.disabled = true;
    deny.disabled = true;
    document.body.dataset.handoffState = "verifying";
    status.textContent = "Waiting for your passkey…";
    status.focus();
    let sent = false;
    try {
      const options = await linkPost("/options", {token: linkToken, decision});
      if (options.userVerification !== "required") throw new Error("handoff_refused");
      const credential = await navigator.credentials.get({
        publicKey: PublicKeyCredential.parseRequestOptionsFromJSON(options),
      });
      if (!credential) throw new Error("handoff_refused");
      sent = true;
      linkOutcome(await linkPost("/decide", {token: linkToken, decision, assertion: credential.toJSON()}));
    } catch (error) {
      if (!sent && error.name === "NotAllowedError") {
        // Nothing was sent: a new choice gets fresh options.
        // WebAuthn reports a cancel and a missing passkey alike.
        status.textContent = "Nothing was decided. If your passkey is on another device, open this link there.";
        action.disabled = false;
        deny.disabled = false;
        document.body.dataset.handoffState = "ready";
        inFlight = false;
        pressed.focus();
      } else if (sent) {
        document.body.dataset.handoffState = "unconfirmed";
        outcome(...unconfirmed);
      } else if (error.status === 410) {
        // The signer itself answered that the request expired undecided.
        linkExpired(nonempty(error.expiresAt) ? error.expiresAt : expiresAt);
      } else {
        linkUnavailable();
      }
    }
  }

  async function load() {
    if (linked) {
      await linkLoad();
      return;
    }
    try {
      if (governance && !loggedIn && nonempty(csrfKey) && nonempty(sessionStorage.getItem(csrfKey))) {
        // This tab already signed in (for example from the owner page): its
        // own token and the session cookie are checked by the server again.
        csrf = sessionStorage.getItem(csrfKey);
        try {
          await governanceState(await request(""));
          loggedIn = true;
          return;
        } catch {
          csrf = undefined;
        }
      }
      if (governance && !loggedIn) {
        if (!nonempty(loginScope) || !nonempty(csrfKey)) throw new Error("handoff_refused");
        // A new tab shares cookies but not the console token. Always use the
        // existing LOGIN in place; never guess a token or navigate to root.
        // The explanation already says to sign in; the status stays quiet.
        status.textContent = "";
        document.body.dataset.handoffState = "login-required";
        action.disabled = false;
        return;
      }
      const state = await request("");
      if (governance) {
        await governanceState(state);
        return;
      }
      if (typeof state.csrf_token !== "string" || !state.csrf_token) throw new Error("handoff_refused");
      for (const [field, id] of [
        ["principal", "handoff-principal"], ["role", "handoff-role"],
        ["installation_id", "handoff-installation"],
      ]) {
        if (typeof state.scope?.[field] !== "string") throw new Error("handoff_refused");
        document.getElementById(id).textContent = state.scope[field];
      }
      // An agent may prepare a session start for its own human parent. Show
      // which agent asked, apart from the identity being signed in.
      if (state.requester !== null && state.requester !== undefined) {
        const { id, address, key_fingerprint: fingerprint } = state.requester;
        if (typeof id !== "string" || !id || typeof fingerprint !== "string" || !fingerprint) {
          throw new Error("handoff_refused");
        }
        if (address !== null && address !== undefined && typeof address !== "string") {
          throw new Error("handoff_refused");
        }
        document.getElementById("handoff-requester").textContent =
          (address ? `${address} (${id})` : id) + ` · key ${fingerprint}`;
        document.getElementById("handoff-requester-label").hidden = false;
        document.getElementById("handoff-requester").hidden = false;
      }
      csrf = state.csrf_token;
      document.getElementById("handoff-scope").hidden = false;
      status.textContent = "Check the identity and role before continuing.";
      action.disabled = false;
      document.body.dataset.handoffState = "ready";
    } catch {
      failed();
    }
  }

  deny.addEventListener("click", () => (linked ? decide("reject") : sessionDeny()));

  // The session ended before anything was sent: nothing was decided, and
  // the next step is to sign in again in place.
  function signedOut() {
    loggedIn = false;
    csrf = undefined;
    sessionStorage.removeItem(csrfKey);
    deny.hidden = true;
    note.hidden = true;
    action.hidden = false;
    action.textContent = "Sign in with passkey";
    action.disabled = false;
    document.body.dataset.handoffState = "login-required";
    status.textContent = "You were signed out. Sign in again to decide.";
    action.focus();
  }

  // A signed-in approver's Deny: the same single exact-act passkey touch.
  async function sessionDeny() {
    action.disabled = true;
    deny.disabled = true;
    document.body.dataset.handoffState = "verifying";
    status.textContent = "Waiting for your passkey…";
    status.focus();
    let sent = false;
    try {
      const options = await request("/options", {decision: "reject"});
      if (options.userVerification !== "required") throw new Error("handoff_refused");
      const credential = await navigator.credentials.get({
        publicKey: PublicKeyCredential.parseRequestOptionsFromJSON(options),
      });
      if (!credential) throw new Error("handoff_refused");
      sent = true;
      linkOutcome(await request("/execute", {assertion: credential.toJSON(), decision: "reject"}));
    } catch (error) {
      if (!sent && error.name === "NotAllowedError") {
        status.textContent = "Nothing was decided. Choose again.";
        action.disabled = false;
        deny.disabled = false;
        document.body.dataset.handoffState = "ready";
        deny.focus();
      } else if (!sent && error.status === 401) {
        signedOut();
      } else {
        submitted = sent;
        failed();
      }
    }
  }

  action.addEventListener("click", async () => {
    if (linked) {
      await decide("approve");
      return;
    }
    action.disabled = true;
    deny.disabled = true;
    document.body.dataset.handoffState = "verifying";
    status.textContent = "Follow your browser’s passkey prompt.";
    try {
      if (governance && !loggedIn) {
        const options = await fetchJSON("/login/options", {scope: loginScope});
        if (options.userVerification !== "required") throw new Error("handoff_refused");
        const credential = await navigator.credentials.get({
          publicKey: PublicKeyCredential.parseRequestOptionsFromJSON(options),
        });
        if (!credential) throw new Error("handoff_refused");
        const result = await fetchJSON("/login", {scope: loginScope, assertion: credential.toJSON()});
        if (!nonempty(result.csrf_token)) throw new Error("handoff_refused");
        // This is S4's own tab token, not a governance cookie or a result.
        sessionStorage.setItem(csrfKey, result.csrf_token);
        csrf = result.csrf_token;
        loggedIn = true;
        await load();
        return;
      }
      const options = await request("/options", {});
      if (governance) {
        if (!operationId || options.userVerification !== "required") throw new Error("handoff_refused");
        const credential = await navigator.credentials.get({
          publicKey: PublicKeyCredential.parseRequestOptionsFromJSON(options),
        });
        if (!credential) throw new Error("handoff_refused");
        submitted = true;
        governanceComplete(await request("/execute", {assertion: credential.toJSON()}));
        return;
      }
      if (purpose === "credential") {
        const credential = await navigator.credentials.create({
          publicKey: PublicKeyCredential.parseCreationOptionsFromJSON(options),
        });
        if (!credential) throw new Error("handoff_refused");
        complete(await request("/complete", {credential: credential.toJSON()}));
      } else {
        const credential = await navigator.credentials.get({
          publicKey: PublicKeyCredential.parseRequestOptionsFromJSON(options),
        });
        if (!credential) throw new Error("handoff_refused");
        const result = await request("/login", {assertion: credential.toJSON()});
        if (result.logged_in !== true) throw new Error("handoff_refused");
        action.hidden = true;
        status.textContent = "Passkey verified. Review the identity and role, then choose Allow.";
        allow.hidden = false;
        document.body.dataset.handoffState = "awaiting-allow";
        document.getElementById("handoff-allow-title").focus();
      }
    } catch (error) {
      if (error.name === "NotAllowedError") {
        // No completion was sent: an explicit retry obtains fresh options.
        status.textContent = governance && loggedIn
          ? "Nothing was decided. Choose again."
          : "The passkey prompt was cancelled. You can try again.";
        action.disabled = false;
        deny.disabled = false;
        document.body.dataset.handoffState = governance && !loggedIn ? "login-required" : "ready";
        action.focus();
      } else if (governance && loggedIn && !submitted && error.status === 401) {
        signedOut();
      } else {
        failed();
      }
    }
  });

  confirm.addEventListener("click", async () => {
    confirm.disabled = true;
    document.body.dataset.handoffState = "allowing";
    status.textContent = "Allowing this terminal session…";
    try {
      complete(await request("/allow", {allow: true}));
    } catch {
      failed();
    }
  });

  load();
})();
