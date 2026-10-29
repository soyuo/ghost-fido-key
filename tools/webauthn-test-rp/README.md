# Local WebAuthn test RP

This development-only relying party helps separate browser/RP verification failures from authenticator discovery and transport failures. It listens on loopback, accepts only `http://localhost:<port>`, holds one credential per browser session in process memory, and discards all state when stopped. Do not use real account data or expose the port beyond loopback.

## Run a manual ceremony

Requirements: Node.js LTS 22 or later and a current Chrome or Edge browser.

```sh
npm ci --prefix tools/webauthn-test-rp
npm start --prefix tools/webauthn-test-rp
```

Open `http://localhost:8787` in the same browser profile, select **Register credential**, then select **Authenticate**. The RP server verifies the registration challenge, origin, RP ID and response, then verifies the assertion signature and updates the signature counter. User verification is not required for the ceremony; the signed WebAuthn user-verified flag is displayed separately. That flag is not proof of a biometric or OS-native verification prompt. A verified result is server-side evidence for that run. Browser cancellation and timeout are shown as failures and do not become a verified result.

Use a fresh browser session and record the exact OS build, CPU architecture, browser name/version, app/driver version, and timestamp for each support-matrix row. Record each layer separately:

1. Whether the virtual device enumerated in the OS.
2. Whether the browser offered/discovered the FIDO authenticator.
3. CTAPHID and CTAP2 request/response outcome.
4. Whether this RP accepted registration and verified the later assertion signature.

This harness does not provide a virtual authenticator, prove OS HID enumeration, approve a platform, or establish release readiness. It intentionally stores no durable accounts or credentials and is not production infrastructure.
