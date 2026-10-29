const result = document.querySelector('#result');
const authenticateButton = document.querySelector('#authenticate');

function toBase64Url(buffer) {
  let binary = '';
  for (const byte of new Uint8Array(buffer)) binary += String.fromCharCode(byte);
  return btoa(binary).replaceAll('+', '-').replaceAll('/', '_').replace(/=+$/u, '');
}

function fromBase64Url(value) {
  const normalized = value.replaceAll('-', '+').replaceAll('_', '/');
  const binary = atob(normalized + '='.repeat((4 - normalized.length % 4) % 4));
  return Uint8Array.from(binary, (character) => character.charCodeAt(0)).buffer;
}

function creationOptions(options) {
  return {
    ...options,
    challenge: fromBase64Url(options.challenge),
    user: { ...options.user, id: fromBase64Url(options.user.id) },
    excludeCredentials: options.excludeCredentials?.map((item) => ({ ...item, id: fromBase64Url(item.id) })),
  };
}

function requestOptions(options) {
  return {
    ...options,
    challenge: fromBase64Url(options.challenge),
    allowCredentials: options.allowCredentials?.map((item) => ({ ...item, id: fromBase64Url(item.id) })),
  };
}

function serializeCredential(credential) {
  const response = credential.response;
  const serialized = {
    id: credential.id,
    rawId: toBase64Url(credential.rawId),
    type: credential.type,
    authenticatorAttachment: credential.authenticatorAttachment,
    clientExtensionResults: credential.getClientExtensionResults(),
    response: {
      clientDataJSON: toBase64Url(response.clientDataJSON),
    },
  };

  if (response instanceof AuthenticatorAttestationResponse) {
    serialized.response.attestationObject = toBase64Url(response.attestationObject);
    serialized.response.transports = response.getTransports?.() ?? [];
  } else if (response instanceof AuthenticatorAssertionResponse) {
    serialized.response.authenticatorData = toBase64Url(response.authenticatorData);
    serialized.response.signature = toBase64Url(response.signature);
    serialized.response.userHandle = response.userHandle ? toBase64Url(response.userHandle) : null;
  }
  return serialized;
}

async function api(path, body) {
  const response = await fetch(path, {
    method: body === undefined ? 'GET' : 'POST',
    headers: body === undefined ? undefined : { 'Content-Type': 'application/json' },
    body: body === undefined ? undefined : JSON.stringify(body),
    credentials: 'same-origin',
    cache: 'no-store',
  });
  const value = await response.json();
  if (!response.ok) throw new Error(value.error ?? `Request failed (${response.status}).`);
  return value;
}

async function runCeremony(button, operation) {
  button.disabled = true;
  authenticateButton.disabled = true;
  result.textContent = 'Waiting for browser and authenticator…';
  try {
    await operation();
  } catch (error) {
    result.textContent = `Ceremony failed: ${error instanceof Error ? error.message : 'Unknown error.'}`;
  } finally {
    button.disabled = false;
  }
}

document.querySelector('#register').addEventListener('click', (event) => {
  runCeremony(event.currentTarget, async () => {
    const options = await api('/api/register/options');
    const credential = await navigator.credentials.create({ publicKey: creationOptions(options) });
    if (!(credential instanceof PublicKeyCredential)) throw new Error('The browser returned no public-key credential.');
    const verified = await api('/api/register/verify', serializeCredential(credential));
    authenticateButton.disabled = false;
    result.textContent = `Registration verified by the RP server.\nCredential ID: ${verified.credentialId}\nInitial counter: ${verified.counter}`;
  });
});

authenticateButton.addEventListener('click', (event) => {
  runCeremony(event.currentTarget, async () => {
    const options = await api('/api/authenticate/options');
    const credential = await navigator.credentials.get({ publicKey: requestOptions(options) });
    if (!(credential instanceof PublicKeyCredential)) throw new Error('The browser returned no public-key credential.');
    const verified = await api('/api/authenticate/verify', serializeCredential(credential));
    result.textContent = `Assertion signature verified by the RP server.\nCredential ID: ${verified.credentialId}\nSignature counter: ${verified.counter}\nWebAuthn user-verified flag: ${verified.userVerified}`;
  });
});

api('/api/session').then((session) => {
  document.querySelector('#identity').textContent = `RP ID: ${session.rpID} · Origin: ${session.origin}`;
  authenticateButton.disabled = !session.credentialRegistered;
}).catch((error) => {
  result.textContent = `Could not initialize the local RP: ${error.message}`;
});
