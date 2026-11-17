# App attestation for backend auth

How the backend can tell a genuine BlackShield install from a script or a repackaged app, and what to build when.

## Today: a shared build key

Every `/v1` request carries the build's API key (`X-API-Key`). It is compiled into the APK, so anyone can extract it.
It identifies the *app build* (for rotation and per-build rate limits); it is not a secret and not proof of a genuine
app. That is acceptable while the API only serves public threat data: an attacker gains nothing they could not
download anyway, and the per-key and per-IP rate limits bound scraping. Crash reports are the one write endpoint; their
strict schema and rate limits bound abuse to junk rows that expire after 90 days.

On the device, `AppIntegrity` refuses to run a release build that is debuggable or signed with an unknown key. That
stops casual repackaging (a clone posing as BlackShield) but is a local check an attacker can patch out. **The backend
must never trust it.**

## When to add attestation

Add one of the options below before any endpoint that:

- accepts data that changes what other users get (for example user-submitted samples or false-positive reports
  feeding the signature pipeline), or
- costs real money per call (for example cloud sandbox analysis), or
- returns anything that is not public.

## Option A (recommended): Play Integrity API, standard requests

Google Play signs a verdict that says whether the request comes from the genuine, Play-recognised app binary on a
genuine Android device.

Flow:

1. App start: `IntegrityManagerFactory.createStandard(context).prepareIntegrityToken(cloudProjectNumber)` (warms up;
   cheap to call again).
2. Per protected request: compute `requestHash = SHA-256(method + path + body)` and call
   `tokenProvider.request(requestHash)`; send the token in `X-Integrity-Token`.
3. Backend: decrypt and verify the token with Google's `playintegrity.googleapis.com` `decodeIntegrityToken` (server
   to server; the service account key stays on the backend), then check:
   - `requestDetails.requestHash` equals the hash of the request it came with (binds the token to this request),
     and `requestDetails.timestampMillis` is within a few minutes;
   - `appIntegrity.appRecognitionVerdict == PLAY_RECOGNIZED`, `packageName == com.blackshield.app` and
     `certificateSha256Digest` contains the Play app signing certificate;
   - `deviceIntegrity.deviceRecognitionVerdict` contains `MEETS_DEVICE_INTEGRITY` (or `MEETS_BASIC_INTEGRITY` for a
     softer policy: security apps are often installed on older or rooted phones, which are the ones that need them).
4. Decide per endpoint: reject, or accept with lower trust (for example a sample report from an unverified device is
   queued for manual review instead of feeding the pipeline).

Cost and limits: free up to a daily quota (10,000 standard requests per day by default; increase on request). Needs
Google Play services; sideloaded or non-Play installs (F-Droid, AppGallery) get `UNRECOGNIZED_VERSION`, so keep a path
for them (option B or reduced trust).

Backend work: a `require_integrity` FastAPI dependency next to `require_api_client`, the Google API client and a
service account in the secrets manager, metrics for verdict counts, and a kill switch setting.

## Option B (simpler, no Google dependency): Key Attestation + per-install keys

1. First launch: generate an EC P-256 key pair in the Android Keystore with an attestation challenge from
   `POST /v1/installs/challenge`. The certificate chain proves the key is hardware-backed and records the app's
   package name and signing certificate (`attestationApplicationId`).
2. `POST /v1/installs` with the chain: the backend verifies it up to a Google attestation root, checks the
   challenge, package name and signing certificate digest, and stores the public key with a random install id.
3. Every protected request is signed with the key (`X-Install-Id`, `X-Signature` over method, path, body hash and
   timestamp); the backend verifies the signature and the timestamp.

It proves "a genuine BlackShield signing key built this app, on a real device with a Keystore", per install, without
quotas. It does not detect a rooted device or a hooked process the way Play Integrity's device verdict tries to, and
the backend must check the revocation list for attestation keys. It introduces a per-install identifier, which must be
added to [privacy.md](privacy.md) and the Data safety form.

## Option C: none (current)

Keep the shared key while the API serves only public data. Rotate it with each major version (`API_KEYS` accepts
several keys), and watch `blackshield_auth_failures_total` and `blackshield_rate_limited_total` for abuse.

## Recommendation

Stay on option C for 1.0 (no endpoint needs more). Implement option A when the first endpoint from "When to add
attestation" is planned, with option B as the fallback for non-Play distribution.
