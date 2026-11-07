(() => {
  const button = document.getElementById('complete');
  const notice = document.getElementById('notice');
  const continueLink = document.getElementById('continue');
  // The app's page names the ceremony and the copy shown here.
  const config = document.body.dataset;
  const ceremony = config.ceremony;
  const fragment = window.location.hash.slice(1);
  window.history.replaceState(null, '', window.location.pathname);
  let token = new URLSearchParams(fragment).get('token');
  if (!token) {
    notice.textContent = config.copyMissingLink;
    return;
  }
  button.disabled = false;

  async function post(path, body) {
    const response = await fetch(path, {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      credentials: 'omit',
      body: JSON.stringify(body),
    });
    if (!response.ok) throw new Error('ceremony_refused');
    return response.json();
  }

  button.addEventListener('click', async () => {
    button.disabled = true;
    notice.textContent = config.copyCompleting;
    try {
      if (ceremony === 'enrolment') {
        // Each explicit retry obtains a new registration challenge. A failed
        // effect may leave the link usable, but the old challenge is spent.
        const options = await post('/enrolment/options', {link_token: token});
        const credential = await navigator.credentials.create({
          publicKey: PublicKeyCredential.parseCreationOptionsFromJSON(options),
        });
        if (!credential) throw new Error('registration_cancelled');
        const result = await post('/enrolment', {
          link_token: token, credential: credential.toJSON(),
        });
        notice.textContent = config.copyDone;
        if (typeof result.scope === 'string' && result.scope) {
          continueLink.href = '/login?' + new URLSearchParams({scope: result.scope});
          continueLink.hidden = false;
        }
      } else {
        await post('/contact-proof', {proof_token: token});
        notice.textContent = config.copyDone;
      }
      token = '';
    } catch {
      notice.textContent = config.copyCeremonyFailed;
      button.disabled = false;
    }
  });
})();
