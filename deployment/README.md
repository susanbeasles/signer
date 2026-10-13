# Automatic standalone deployment

A push to this repository's `main` automatically runs `.github/workflows/deploy.yml`.
There is no dashboard signing action, manual workflow dispatch, delivery_control
call, or per-release approval job. Integration checks remain on `int/**`.

The workflow installs lockfile-pinned Wrangler, validates the approved public
runtime inputs, builds this commit's isolated container, pushes it to the account's
Cloudflare registry, resolves its immutable digest, and deploys the matching
Worker with `ENABLED=true`. It retains the private SourceActions interface and
SOURCE_POLICY eligibility checks. Eligible requests execute automatically; this
workflow does not authorize arbitrary requests or replace depot orchestration.

The runner checks current main before publication and immediately before Worker
deployment. Releases are serialized without cancelling an in-flight upload. An
uncertain provider failure is reported, not automatically retried. Successful
Worker deployment requires readback of runtime configuration and private bindings.

## One-time installation inputs

These must be installed before merging to main; the workflow reports missing
inputs rather than deploying the disabled template or pretending signing works.

- Repository secret `CLOUDFLARE_API_TOKEN`: an existing approved deployment
  credential for account `1a799c6e699d2ef7e87398692ce3ad7b`, authorized for the
  `signing-control` Worker, its Durable Object migration and container registry/
  application. This source does not create a token or change its grants.
- Repository variable `SIGNING_DEPLOYMENT_JSON`: the schema in
  `deployment/config.example.json`. Fill it with approved immutable base-image
  digest, Node/setpriv/tool executable hashes, supported repository allowlist,
  1Password item/field reference, pinned public key/fingerprint, allowed op
  origins, and exact private service binding targets. The example deliberately
  contains unresolved values; it is not a working configuration.
- Existing `OP_SERVICE_ACCOUNT_TOKEN`: either already installed as the Cloudflare
  Worker's secret or provided as a repository secret for the first deployment.
  It must be the existing account scoped to the referenced signing item. It is
  written only to a mode-0600 temporary secrets file for Wrangler's additive
  secret upload, never to Docker build arguments, the image, logs or artifacts.
  Later deployments preserve the existing Worker secret without fetching it.
- The configured SOURCE_POLICY Worker and any additional private capability
  targets must already exist. Feature signing only requires SOURCE_POLICY;
  integration promotion retains its separate capability requirements.

The signer repo owns this deployment path directly. The bootstrap preview remains
a non-executing resource-review tool; it is not part of the automatic release path.

## Verification and current resource findings

110 local tests passed, including eight deployment tests exercising automatic
sequencing, secret separation, stale-main rejection, immutable image selection,
cleanup and no blind retry. Wrangler 4.149.0 compiled the enabled Worker and
container configuration with synthetic public references using `deploy --dry-run`.
No live container build, image publication, deployment or signing was performed.

The read-only Cloudflare check on 2026-10-12 returned error 10007: `signing-control`
does not exist in the configured account. The retained commissioning example has
no approved key/item reference or image/tool pins. GitHub secret/variable metadata
reads were denied, so their installation has not been verified. Activation needs
one-time provisioning of those exact resources/inputs; no new credential or grant
was created by this change.
