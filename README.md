# Signing Control

This repository, `susanbeasles/signing_control`, owns the dedicated out-of-band
Git signing service. Its Cloudflare Worker is named `signing-control`. The signer
owns direct deployment of its Worker/container to Cloudflare.

The service is disabled by default and has no public route. The bootstrap UI
prepares nonsecret, digest-bound review requests for separate setup operations.
A review request is an intent to review; it is not an approval or a credential.

## Local checks

Use Node.js 24 or later:

```sh
npm ci --ignore-scripts
npm test
```

Preview the public bootstrap review UI with `npm run preview:bootstrap`, then
open `http://127.0.0.1:8765/`. It binds only to loopback and cannot make provider
requests. To produce a self-contained offline page:

```sh
npm run bootstrap -- render --out /tmp/signing-control-review.html
```

The output path must be new. See `bootstrap/README.md` for the public input
schema and individual operation review commands.

Tests use synthetic fixtures. They must not use a live 1Password account,
register a key, or mutate GitHub or Cloudflare resources.

## Components

* `bootstrap/` contains the public configuration compiler and review UI.
* `src/service/` composes exact Git object policy, source verification,
  durable reservations, signing, and independent evidence capabilities.
* `runtime/` implements the pinned official `op` to ephemeral SSH agent path.
* `cloudflare/` contains the private Worker and disposable container controller.

The runtime accepts an immutable vault/item reference, an independently pinned
public key, and exact executable hashes. Its dedicated service-account token
belongs only in the private credential handoff. The fixed `op` subprocess gets
that token; SSH tools and Git do not. The private key travels through a pipe to
an ephemeral agent, never a command argument or a persistent key file.

Automated SSH signing is separate from owner hardware approval. The service
does not convert a software key, an ordinary signature, or a caller boolean
into hardware provenance. Missing independent policy or evidence capabilities
deny the operation.

## Source publication

Feature signing runs in the standalone Cloudflare signer. workflow_depot
owns the accepted producer policy and automatically authorizes eligible exact
commit intents; no per-feature owner approval is added. The request binds the
repository, parent, producer-claimed tree hash, feature ref, author, committer,
message, nonce, expiry, and pinned signing key. A digest binds those exact
canonical commit bytes; the signer signs the commit bytes, not the digest text.

This signature proves an authenticated, policy-eligible producer intent. It
does not claim that source contents were transferred, inspected, or scanned.
The feature path needs neither a local Git store beside the signer nor the
later CI, scan, review, hardware-approval, or publication capabilities. Missing
or revoked depot producer authorization prevents key access. The signer stores
an irreversible reservation before consuming the one-use depot grant, and
retains uncertainty after an ambiguous result instead of signing again.

The response contains a signature and a receipt. The separately authorized
producer assembles the signed commit locally, verifies the pinned key, exact
metadata and object hash, and uses normal Git for publication. Source files,
blobs, trees, and history archives never travel through signer RPC or R2.
`lookupFeature` can return only the exact retained signed commit metadata.

Promotion signing remains a separate path starting from an existing source PR.
It still requires independently verified source objects, CI, complete scans,
review, and the existing owner approvals before promotion. Feature signing does
not grant main writes or bypass those gates.

## Commissioning state

No dedicated vault, signing key, service account, public-key registration,
deployed signer, or activated policy is created by this package. Actual public
identities, immutable image and toolchain hashes, private capability bindings,
and resource readbacks are required before activation. Each security-sensitive
setup operation needs its own explicit authorization.

The separate, pending four-Worker pipeline bootstrap does not include this
signer or any signing credential. A local test result is not evidence that
production authentication, signing, publication, or deployment works.

## Fixed integration lifecycle

workflow_depot owns the private IntegrationActions entrypoint and durable
repository-scoped reconciliation. It invokes this standalone signer through the
private SourceActions binding. Working PRs map to `int/<working-branch>`; source or main
changes close/delete/recreate that ref and its PR. Each eligible candidate has
exactly one parent, current main, and one signed squash commit. Empty changes
retire any previous integration. Durable operation IDs prevent blind signing
retries after uncertain outcomes.

This source is disabled and uncommissioned. Activation requires accepted source-PR-scoped policy and integrationIntent capability, trusted
read credentials, signer/publisher bindings, webhook installation, a configured
candidate admission endpoint, and qualified provider protection rules. No live
keys, secrets, deployments or protection settings were changed by this work.

## Deployment ownership

This repository owns its own deployment directly to Cloudflare. It does not
require delivery_control to deploy the signer. Shared integration orchestration
and signing eligibility policy remain owned by workflow_depot. The Cloudflare
Worker and isolated signing container stay in this standalone repository.

Pushes to `main` automatically run `.github/workflows/deploy.yml`, building and
publishing the matching container and deploying the enabled Worker directly to
Cloudflare. No manual sign/deploy action or delivery_control call is required.
See [deployment setup](deployment/README.md) for the exact one-time inputs and
verified resource blockers. The disabled `cloudflare/wrangler.jsonc` remains a
reference template; the release command generates the enabled configuration.
