# Signing Control bootstrap review

This directory is an executable, local bootstrap compiler and review UI for the separate private signer extension. It does not extend or execute the existing four-worker bootstrap. The source repository is exactly `susanbeasles/signer`; the Worker is `signing-control`. Repository creation is outside this compiler.

Run with Node 24 from the source root. No dependencies or provider credentials are needed:

```sh
node --test bootstrap/test/*.test.mjs
node bootstrap/cli.mjs preview --port 8765
```

Open `http://127.0.0.1:8765/`. The server binds only loopback, accepts a fixed host and GET/HEAD, and serves six fixed assets. It has no API or apply endpoint. Browser code has no external scripts, network requests, analytics, or persistence. Changing an input invalidates the current plan and selected review. All DOM values use text rendering.

For a single HTML file that also works offline:

```sh
node bootstrap/cli.mjs render --out /tmp/signing-control-review.html
```

The rendered file contains the same compiler and UI, with CSP hashes for inline code/styles and `connect-src 'none'`. Output files must not already exist. The UI includes only public ID, hash, origin, and public SSH key fields; there is no secret/token/private-key field.

Compile public JSON locally:

```sh
node bootstrap/cli.mjs example > /tmp/signing-control-public.json
node bootstrap/cli.mjs plan --input /tmp/signing-control-public.json --out /tmp/signing-control-plan
```

The example intentionally contains null references and hashes, plus an empty origin list. Replace those only with reviewed public metadata. The compiler does not discover, retrieve, or fabricate them. It never reads the environment, resolves an `op://` reference, generates a key, invokes `op`, invokes a signer, creates a repository, or contacts a provider.

The fresh output directory contains:

| Artifact | Meaning |
| --- | --- |
| `bootstrap-plan.json` | Seven individual operation intents, digests, exact payloads, and commissioning blockers. |
| `wrangler.bootstrap.json` | Disabled Worker/DO/container configuration intended for the source root; `main` is `cloudflare/worker.mjs`. No routes, workers.dev, previews, or observability. No fabricated private binding destinations. A container declaration is omitted while its immutable image digest is missing. |
| `public-runtime-config.json` | Exact `{service,runtime,platform}` for `SIGNING_CONTROL_CONFIG_JSON`. `ENABLED=false` is separate. |
| `image-runtime-config.json` | Exact `{service,runtime}` for `/opt/signing-control/config/runtime.json` in the reviewed image. The image does not embed its own digest. |

These are review artifacts, not a deploy command. The output directory is not a deployable bundle: `main` intentionally resolves from the source repository root. A future owner-authorized materialization must place the reviewed `wrangler.bootstrap.json` at that root, check the exact reviewed source/artifact digests and paths, and satisfy every operation prerequisite before deployment. Do not invoke Wrangler against the output-directory configuration as-is. The compiler does not prove a source revision, image, resource, public key, account scope, or target ownership exists.

The account is pinned to `1a799c6e699d2ef7e87398692ce3ad7b`. `https://control.vespoli.me` remains the owner authority reference, not a new signer route. The source repository pin uses underscore; a hyphenated source repository is rejected. One configured target repository may independently select an existing `susanbeasles/*` repository. Its ID is a positive safe integer, distinct from the source repository's public metadata ID string.

The public schema is closed and bounded to 64 KiB. Unknown fields, private-key markers, common token prefixes, mutable image tags, mismatched public-key fingerprints, vault/item aliases, alternate tool paths, unsafe target ID coercions, and secret-shaped extensions are rejected without echoing input. `onePassword.vaultName` is configurable display metadata; the unresolved example uses null. `onePassword.itemName` defaults to `gh-signing-key` and accepts lower-case vendor-scope-credentialType names, including longer hyphenated scopes. Neither label selects a credential. `runtime.runtime.opRef` is explicitly entered as `op://vaultID/itemID/[sectionID/]fieldID?ssh-format=openssh`; there is no field fallback or reference derivation. Vault/item IDs must equal the separately supplied 26-character IDs. Field/section identifiers are bounded alphanumeric/underscore/hyphen tokens because 1Password also uses IDs such as `private_key`. Syntax cannot distinguish an ID from an identical-looking label: commissioning must confirm the exact field/section IDs against public item metadata. Encoded path components, spaces, extra path segments, fragments and alternate/additional query parameters are rejected. No ID or service account scope is inferred from a name. `runtime.opOrigins` is an explicit, separately qualified list of up to eight unique HTTPS origins; account-domain text never grants egress. Empty origins remain a blocker.

`bootstrap/plan.mjs` exports `compilePlan(input)`, `createReviewRequest(input, expectedPlanDigest, operationID)`, `parsePublicInput(text)`, `validatePublicInput(input)`, `publicKeyFingerprint(publicKey)`, `canonicalJson(value)`, and `artifactText(value)`. Its imports are browser-safe. `exampleInput()` is in `bootstrap/example.mjs`.

`inputDigest`, `configDigest`, operation digests, and plan digest use SHA-256 over UTF-8 canonical JSON with recursively sorted object keys, unchanged array order, and no whitespace. `configDigest` matches the controller's digest of the whole `{service,runtime,platform}` object. `artifactDigests` hash the exact emitted UTF-8 artifact bytes: recursively sorted keys, two-space JSON indentation, terminal newline. The full configuration and image configuration have separate hashes. Changing the vault, item, field or section reference changes the runtime/configuration and plan digests, requires a newly reviewed image configuration, and invalidates prior operation review requests. Changing a display label changes the plan digest but does not change the credential selector or runtime digest.

Seven separate review requests cover Worker installation, Durable Object migration, container configuration, the dedicated vault reference, item reference, service-account reference, and GitHub public SSH signing-key registration. The 1Password steps bind public references; they do not create a vault/item/account or manufacture credentials. Secure service-account token provisioning remains a separately authorized external operation. GitHub registration identifies the signing-key endpoint and requires fresh numeric authenticated-user verification, existing-key deduplication, and explicit authorization. No SSH authentication-key endpoint is included.

To write one review request, use the exact plan digest printed by `plan`:

```sh
node bootstrap/cli.mjs review --input /tmp/signing-control-public.json --plan-digest REVIEWED_PLAN_SHA256 --operation github.ssh-signing-key.register --out /tmp/signing-key-review.json
```

This recompiles the public input and refuses stale digests. Its result is explicitly an `unauthenticated-review-request`. It has no owner identity, signature, approval boolean, or authorization credential. Possession of a request is never authority. There is no `apply` command.

A future apply implementation must independently obtain and verify fresh, one-use, operation-specific owner authorization under the existing owner mechanism, bound to the input/configuration/plan/operation digests and actual resource identity. It must recompile the current inputs, verify all prerequisites against actual provider metadata and trusted runtime capabilities, and refuse absent, expired, replayed, or mismatched authority. When Worker, DO migration, and container changes share a deployment, all three exact operation authorizations must be satisfied before that deployment. This compiler deliberately does not implement or simulate that authority.

The deployment target is exclusively a private Cloudflare Worker and Container. The loopback command above serves a static review UI only; it is not a signer host. Minimum feature commissioning uses Worker `signing-control`, DO binding `SIGNING_CONTROL_STATE` / class `SigningControlRepository`, exact public `SIGNING_CONTROL_CONFIG_JSON`, the separately installed native Secrets Store binding `SIGNER_SERVICE_ACCOUNT_TOKEN`, and `SOURCE_POLICY` bound to workflow_depot's named `SourceFeaturePolicy` entrypoint. The policy capability supplies `current`, `authorizeFeatureCommit`, `consumeFeatureCommit`, and `checkFeatureCommit`. Producer admission belongs to workflow_depot's `/v1/source-features/admit`, under pinned producer OIDC or an independently installed private verifier. It is not a public signing endpoint and does not require a new signer-side producer binding. Accepted policy decides eligibility automatically; caller-supplied metadata or a review intent is not authorization.

The feature protocol passes bounded canonical commit metadata and independently retained producer evidence. It does not require Cloudflare to fetch unpublished local source, receive a source archive, or claim a local tree is retained in the disposable container. Feature prerequisites appear in `blockers`. Promotion is separate: `promotionPrerequisites` retains `OWNER_HARDWARE`, `SOURCE_CI`, `SOURCE_SCANS`, `SOURCE_REVIEW`, `SOURCE_INVENTORY`, `SOURCE_PUBLISHER`, authenticated-repository `SOURCE_READ_CREDENTIAL`, and independently accepted durable history custody. Those capabilities are not fabricated or disabled by completing feature commissioning. Disposable container storage does not satisfy durable promotion retention.

For 1Password, use a dedicated service account with only `read_items` on the explicitly approved vault ID. The vault name is interchangeable, but changing the ID is a new digest-bound configuration and scope review. No vault write/share scope is needed by the signer. The token is supplied through the separately approved native Secrets Store reference into `SIGNER_SERVICE_ACCOUNT_TOKEN`, then the private controller/container handoff; it is never a public JSON/UI field. The runtime reads the selected key into the short-lived agent's memory, so it is not a never-export key service. Register only the pinned public SSH key as a GitHub **signing** key under the independently verified account; the SSH authentication key is a separate identity.

One-time creation of the new Worker requires Workers product `Admin`; once it exists, this repository’s direct deployment uses `Editor` scoped to `signing-control`. The proposal adds no Worker route/custom domain and requests no zone route permission. Binding the existing named capability does not mean granting the signer an account API token. Exact Container/image and DO migration permissions and resource availability must be verified during the separately authorized bootstrap; the compiler does not infer them from existing Worker read access. Signer releases deploy directly from this standalone repository to Cloudflare; delivery_control is not required for signer deployment. workflow_depot retains signing-eligibility policy and shared orchestration ownership. Runtime stays disabled until the actual image, deny/allow egress, teardown, private capability bindings, accepted producer trust/policy, dedicated read-only vault grant, public signing identity and exact configuration have been verified. No software SSH signature is advertised as hardware provenance.

Contract references: [Cloudflare container configuration](https://developers.cloudflare.com/containers/reference/wrangler-configuration/), [1Password secret reference syntax](https://www.1password.dev/cli/secret-reference-syntax), [1Password service-account scope](https://www.1password.dev/service-accounts/get-started), and [GitHub SSH signing-key registration](https://docs.github.com/en/rest/users/ssh-signing-keys#create-a-ssh-signing-key-for-the-authenticated-user). [1Password explicit field IDs](https://www.1password.dev/cli/item-template-json) and [Workers roles](https://developers.cloudflare.com/workers/authorization/workers/) explain identifier and deployment permission boundaries. These links document public interfaces; the compiler makes no live calls to them.
