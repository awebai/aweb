(() => {
  const button = document.getElementById('complete');
  const notice = document.getElementById('notice');
  const continueLink = document.getElementById('continue');
  const ceremony = document.body.dataset.ceremony;
  const fragment = window.location.hash.slice(1);
  window.history.replaceState(null, '', window.location.pathname);
  let token = new URLSearchParams(fragment).get('token');
  if (!token) {
    notice.textContent = 'Open the link from your email to continue.';
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
    notice.textContent = 'Completing your request…';
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
        notice.textContent = 'Passkey is ready.';
        if (typeof result.scope === 'string' && result.scope) {
          continueLink.href = '/login?' + new URLSearchParams({scope: result.scope});
          continueLink.hidden = false;
        }
      } else {
        await post('/contact-proof', {proof_token: token});
        notice.textContent = 'Email address confirmed. The waiting period still applies.';
      }
      token = '';
    } catch {
      notice.textContent = 'Unable to finish. Try again, or request a new link.';
      button.disabled = false;
    }
  });
})();
