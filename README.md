# signer

`susanbeasles/signer` owns the production Cloudflare Worker named `signer`.
The native implementation is in `native/`; `npm run deploy` selects
`deployment/native.mjs`. It uses a Worker and a SQLite Durable Object. It
does not need a Container, 1Password account, exported signing key, or local
privileged installation.

## Security and lifecycle

The Durable Object generates Ed25519 identities as non-extractable CryptoKeys.
Private signing keys exist only in memory. Durable storage contains public-key
registration metadata, hashed session credentials, one-use grants and audit
receipts. Eviction replaces a key instead of reconstructing it.

GitHub App credentials and expiring user tokens are AES-GCM encrypted before
durable storage. Their wrapping key must be supplied by the Cloudflare native
`secret_key` binding `CREDENTIAL_WRAPPING_KEY`. Builds preserve that binding
without reading its value. This is software isolation, not hardware-backed
non-exportability or protection against a compromised signing runtime.

`/setup` and `/owner/*` independently validate owner Access JWTs using the exact
configured audience, issuer, signature, expiry and owner email. GitHub manifest
and OAuth callbacks validate browser-bound state, expiry and one-use custody.
OAuth uses PKCE. The App requests only `git_signing_ssh_public_keys: write`.
Signing-key administration uses a GitHub App user access token. Installation
tokens are never used for user signing-key operations.

Authorized remote sessions last at most 15 minutes. The owner can approve a
remote bootstrap request at `/owner/pending` without handling its credential.
GitHub Actions OIDC can mint a session only for explicitly configured actor,
repository identity, event, audience and workflow allowlists. The default
workflow allowlist is empty and the initial repository allowlist is only this
repository. Broader access requires an owner-controlled policy configuration.

Each signing grant binds exact unsigned Git commit bytes, repository name and
numeric ID, caller identity, session, operation and expiry. Consumption is
durable and transactional. Invalid, replayed, expired, cross-repository and
revoked requests fail closed. Session and grant credentials are never logged.

Expired private identities are discarded. Public registrations are retained
for a 24-hour publication window, then reconciled and removed only when both
their recorded title and public key match. GitHub preserves already-created
verification records after revocation. Commits published for the first time
after their signing key is removed may not verify. An SSH commit signature
does not prevent someone copying that same signed object into another
repository; repository authorization is enforced by this service and its
receipts. Publication requires separate repository credentials and protections.

## Remote Git integration

Use Node 24 and Git with SSH signature support. No signing private key is
installed on the remote agent. `native/client.mjs` implements Git's SSH signing
program protocol, including temporary commit-buffer and `.sig` handling, and
independently verifies each returned signature. It supports UTF-8 commit
messages and rejects unsupported commit headers and signatures on tags.

`native/agent.mjs --repository susanbeasles/signer -- command [args]` obtains
owner approval or uses an upstream workload JWT in `SIGNER_WORKLOAD_TOKEN`,
then gives the short-lived session only to its child process environment.
It never prints that session. It configures the child process's Git signing
program and public signing key through process-scoped Git configuration;
it does not modify global or repository Git configuration.
The returned public identity may rotate after eviction; the adapter verifies
the new signature before returning it to Git. Missing authorization prevents
commit creation instead of creating an unsigned commit.

## Deployment and commissioning

Cloudflare Builds must run tests and `npm run deploy` for `main`. Deployment
refuses a source SHA that differs from current main or lacks GitHub's verified
signature. It bundles one immutable module, records its SHA-256, preserves
native key custody, disables invocation URL logs, redacts query strings, and
reads back the installed source/artifact identities and deployment record.
`/health` exposes only nonsecret deployment identity and authorization status.

Commission the native wrapping-key binding, the owner Access application for
`/owner/*` and `/setup`, its `ACCESS_AUD`, and the repository's Cloudflare Builds
trigger before production deployment. App registration and owner consent then
run through `/setup` and official GitHub consent screens. Runtime credentials
must never be injected into a build environment.

The older `cloudflare/`, `runtime/`, `bootstrap/` and container deployment APIs
remain for protocol regression coverage and migration review. Their versioned
schemas and internal callback names are preserved. They are not selected by
the production deploy command. Do not activate the old Container path.

Retire the deployed legacy Worker `signing-control` only after the canonical
Worker has passed live authorization, signing, GitHub verification, rotation,
restart, negative tests and automatic-deployment checks. Passing local tests
or merging this source does not establish that commissioning is complete.

## Verification

`node --test test/native-signer.test.mjs test/native-deployment.test.mjs` runs
the dependency-free native tests, including an actual signed Git commit and
OpenSSH verification. `npm test` also runs the preserved regression suite and
the real Workerd ingress tests through the pinned esbuild/Miniflare toolchain.
Tests use synthetic credentials and must not mutate live provider resources.
