import { randomBytes } from 'node:crypto';
import { createServer } from 'node:http';
import { readFile } from 'node:fs/promises';
import { extname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  generateAuthenticationOptions,
  generateRegistrationOptions,
  verifyAuthenticationResponse,
  verifyRegistrationResponse,
} from '@simplewebauthn/server';

const directory = fileURLToPath(new URL('.', import.meta.url));
const port = Number(process.env.PORT ?? 8787);
if (!Number.isInteger(port) || port < 1024 || port > 65535) {
  throw new Error('PORT must be an integer from 1024 through 65535.');
}
const rpID = 'localhost';
const origin = `http://localhost:${port}`;
const rpName = 'Ghost FIDO Local Test RP';
const sessionLifetimeMs = 30 * 60 * 1000;
const ceremonyLifetimeMs = 2 * 60 * 1000;
const maxBodyBytes = 64 * 1024;
const sessions = new Map();

function newSession() {
  return {
    createdAt: Date.now(),
    registration: undefined,
    authentication: undefined,
    credential: undefined,
  };
}

function sessionFor(request, response) {
  const cookie = request.headers.cookie ?? '';
  const match = /(?:^|;\s*)ghost_fido_rp=([A-Za-z0-9_-]{40,64})(?:;|$)/.exec(cookie);
  let id = match?.[1];
  let session = id ? sessions.get(id) : undefined;

  if (!session || Date.now() - session.createdAt > sessionLifetimeMs) {
    id = randomBytes(32).toString('base64url');
    session = newSession();
    if (sessions.size >= 100) sessions.delete(sessions.keys().next().value);
    sessions.set(id, session);
    response.setHeader('Set-Cookie', `ghost_fido_rp=${id}; HttpOnly; SameSite=Strict; Path=/; Max-Age=1800`);
  }
  return session;
}

function sendJson(response, status, value) {
  response.writeHead(status, {
    'Content-Type': 'application/json; charset=utf-8',
    'Cache-Control': 'no-store',
    'X-Content-Type-Options': 'nosniff',
  });
  response.end(JSON.stringify(value));
}

async function readJson(request) {
  if (!request.headers['content-type']?.startsWith('application/json')) {
    throw Object.assign(new Error('Expected JSON request body.'), { status: 415 });
  }
  const chunks = [];
  let size = 0;
  for await (const chunk of request) {
    size += chunk.length;
    if (size > maxBodyBytes) throw Object.assign(new Error('Request body is too large.'), { status: 413 });
    chunks.push(chunk);
  }
  try {
    const value = JSON.parse(Buffer.concat(chunks).toString('utf8'));
    if (!value || typeof value !== 'object' || Array.isArray(value)) throw new Error('Expected object.');
    return value;
  } catch {
    throw Object.assign(new Error('Malformed JSON request body.'), { status: 400 });
  }
}

function assertLiveCeremony(ceremony) {
  if (!ceremony || Date.now() - ceremony.createdAt > ceremonyLifetimeMs) {
    throw Object.assign(new Error('The ceremony expired. Start it again.'), { status: 400 });
  }
}

function ceremonySettings(body) {
  const timeout = body.timeout ?? 60_000;
  if (!Number.isInteger(timeout) || timeout < 1_000 || timeout > 120_000) {
    throw Object.assign(new Error('Timeout must be between 1000 and 120000 milliseconds.'), { status: 400 });
  }
  return timeout;
}

function enumSetting(value, allowed, name, fallback) {
  const selected = value ?? fallback;
  if (!allowed.includes(selected)) {
    throw Object.assign(new Error(`Unsupported ${name} value.`), { status: 400 });
  }
  return selected;
}

async function verifyCeremony(verify) {
  try {
    return await verify();
  } catch {
    throw Object.assign(new Error('WebAuthn ceremony verification failed.'), { status: 400 });
  }
}

function securityHeaders() {
  return {
    'Content-Security-Policy': "default-src 'self'; script-src 'self'; style-src 'self'; connect-src 'self'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'",
    'Referrer-Policy': 'no-referrer',
    'X-Content-Type-Options': 'nosniff',
    'X-Frame-Options': 'DENY',
  };
}

const server = createServer(async (request, response) => {
  for (const [name, value] of Object.entries(securityHeaders())) response.setHeader(name, value);

  try {
    const url = new URL(request.url ?? '/', origin);
    if (request.headers.host !== `localhost:${port}`) {
      sendJson(response, 400, { error: 'Open the harness at its localhost URL.' });
      return;
    }

    const session = sessionFor(request, response);
    if (request.method === 'GET' && url.pathname === '/') {
      const html = await readFile(join(directory, 'public', 'index.html'));
      response.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-store' });
      response.end(html);
      return;
    }
    if (request.method === 'GET' && url.pathname === '/app.js') {
      const script = await readFile(join(directory, 'public', 'app.js'));
      response.writeHead(200, { 'Content-Type': 'text/javascript; charset=utf-8', 'Cache-Control': 'no-store' });
      response.end(script);
      return;
    }
    if (request.method === 'GET' && url.pathname === '/style.css') {
      const stylesheet = await readFile(join(directory, 'public', 'style.css'));
      response.writeHead(200, { 'Content-Type': 'text/css; charset=utf-8', 'Cache-Control': 'no-store' });
      response.end(stylesheet);
      return;
    }
    if (request.method === 'GET' && url.pathname === '/api/session') {
      sendJson(response, 200, { rpName, rpID, origin, credentialRegistered: Boolean(session.credential) });
      return;
    }
    if (request.method !== 'POST' || !url.pathname.startsWith('/api/')) {
      sendJson(response, 404, { error: 'Not found.' });
      return;
    }
    if (request.headers.origin !== origin) {
      sendJson(response, 403, { error: 'Request origin is not allowed.' });
      return;
    }

    if (url.pathname === '/api/register/options') {
      const body = await readJson(request);
      const residentKey = enumSetting(body.residentKey, ['preferred', 'required'], 'resident-key', 'preferred');
      const timeout = ceremonySettings(body);
      const options = await generateRegistrationOptions({
        rpName,
        rpID,
        userName: 'local-test-user',
        userDisplayName: 'Local test user',
        userID: randomBytes(32),
        attestationType: 'none',
        timeout,
        authenticatorSelection: { residentKey, userVerification: 'preferred' },
      });
      session.registration = { challenge: options.challenge, createdAt: Date.now() };
      session.authentication = undefined;
      sendJson(response, 200, options);
      return;
    }

    if (url.pathname === '/api/register/verify') {
      const body = await readJson(request);
      const ceremony = session.registration;
      session.registration = undefined;
      assertLiveCeremony(ceremony);
      const verification = await verifyCeremony(() => verifyRegistrationResponse({
        response: body,
        expectedChallenge: ceremony.challenge,
        expectedOrigin: origin,
        expectedRPID: rpID,
      }));
      if (!verification.verified || !verification.registrationInfo) {
        session.credential = undefined;
        sendJson(response, 400, { error: 'Registration response was not verified.' });
        return;
      }
      const { credential } = verification.registrationInfo;
      session.credential = {
        id: credential.id,
        publicKey: credential.publicKey,
        counter: credential.counter,
        transports: credential.transports,
      };
      sendJson(response, 200, { verified: true, credentialId: credential.id, counter: credential.counter });
      return;
    }

    if (url.pathname === '/api/authenticate/options') {
      const body = await readJson(request);
      const credentialMode = enumSetting(body.credentialMode, ['allow-list', 'discoverable'], 'credential mode', 'allow-list');
      const userVerification = enumSetting(body.userVerification, ['preferred', 'required'], 'user-verification', 'preferred');
      const timeout = ceremonySettings(body);
      if (!session.credential) {
        sendJson(response, 409, { error: 'Register a credential in this session first.' });
        return;
      }
      const options = await generateAuthenticationOptions({
        rpID,
        timeout,
        userVerification,
        ...(credentialMode === 'allow-list'
          ? { allowCredentials: [{ id: session.credential.id, transports: session.credential.transports }] }
          : {}),
      });
      session.authentication = { challenge: options.challenge, createdAt: Date.now(), userVerification };
      sendJson(response, 200, options);
      return;
    }

    if (url.pathname === '/api/credential/clear') {
      session.credential = undefined;
      session.registration = undefined;
      session.authentication = undefined;
      sendJson(response, 200, { credentialRegistered: false });
      return;
    }

    if (url.pathname === '/api/authenticate/verify') {
      const body = await readJson(request);
      const ceremony = session.authentication;
      session.authentication = undefined;
      assertLiveCeremony(ceremony);
      if (!session.credential) {
        sendJson(response, 409, { error: 'No credential is registered in this session.' });
        return;
      }
      const verification = await verifyCeremony(() => verifyAuthenticationResponse({
        response: body,
        expectedChallenge: ceremony.challenge,
        expectedOrigin: origin,
        expectedRPID: rpID,
        credential: session.credential,
        requireUserVerification: ceremony.userVerification === 'required',
      }));
      if (!verification.verified) {
        sendJson(response, 400, { error: 'Assertion response was not verified.' });
        return;
      }
      session.credential.counter = verification.authenticationInfo.newCounter;
      sendJson(response, 200, {
        verified: true,
        credentialId: session.credential.id,
        counter: session.credential.counter,
        userVerified: verification.authenticationInfo.userVerified,
      });
      return;
    }

    sendJson(response, 404, { error: 'Not found.' });
  } catch (error) {
    const status = Number.isInteger(error?.status) ? error.status : 500;
    if (status >= 500) console.error('Local RP request failed.');
    const message = status >= 500 ? 'The local RP could not complete the request.' : error.message;
    sendJson(response, status, { error: message });
  }
});

server.listen(port, '127.0.0.1', () => {
  console.log(`Ghost FIDO local test RP listening at ${origin}`);
});

const cleanupTimer = setInterval(() => {
  const cutoff = Date.now() - sessionLifetimeMs;
  for (const [id, session] of sessions) if (session.createdAt < cutoff) sessions.delete(id);
}, 60_000);
cleanupTimer.unref();

function close() {
  clearInterval(cleanupTimer);
  server.close(() => process.exit(0));
}
process.on('SIGINT', close);
process.on('SIGTERM', close);
