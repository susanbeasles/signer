# Private signing controller

`worker.mjs` is the disabled Cloudflare service boundary for the dedicated
`signing_control` source producer. Public HTTP returns 404. The checked-in
Wrangler configuration has no routes, workers.dev, preview URL, installed
capability destinations, or credentials. No live resource is created by these
files or their tests.

## Private interfaces

| Entry point | Methods | Purpose |
| --- | --- | --- |
| `SourceActions` | `execute(job)`, `status({id})` | Submit one immutable operation or inspect its retained outcome. |
| `SourceCandidates` | `lookupCandidate(input)`, `lookupReviewPolicy(input)`, `lookupFeature(input)` | Run the existing read-only source-proof checks in the pinned runtime. |
| `SigningReceipts` | `lookupReceipt({receiptDigest})`, `verifyPromotion({receiptDigest})` | Verify retained receipts and current source/evidence where required by the core. |
| `PublicationAuthority` | `verify(effect)` | Atomically consume one exact, existing publication grant for an installed publisher. |

Installation must bind each consumer only to its required entry point. A private
binding is an authority boundary; an application must not receive `SourceActions`
or `PublicationAuthority` merely because it may read a candidate. No entry point
exposes a raw signing primitive or an arbitrary shell/program/URL.

The operator-installed public config is `{services,runtime,platform}`, with at
most 32 unique repository IDs and names. A single-service
`{service,runtime,platform}` installation remains supported. A feature request
selects only the installed service whose numeric repository ID matches; neither
caller-provided configuration nor a first-repository default is accepted.
Each unchanged job configuration is `{service,runtime,platform}`, and its
canonical SHA-256 is `job.configDigest`. The image contains the fixed
`{services,runtime}` allowlist; the controller verifies the configured immutable
image digest before private handoff. `ENABLED` remains a separate Worker variable.

`SourceActions.status` uses `{id,repositoryID}` for a multi-repository
installation. Existing receipt-only APIs cannot identify a repository there,
so they fail closed. A later promotion installation needs an explicit scoped
binding or reviewed API change; this does not block feature prepare/lookup,
which already carry `repositoryID`.

A job is exactly `{version:1,id,action,input,configDigest,deadline}`. The deadline
is Unix seconds, at most five minutes away. Each configured repository has one
`SigningControlRepository` Durable Object and one active container. Mutating
jobs reserve before launch. An ambiguous mutation permanently retains its lock
for explicit reconciliation; it is never automatically retried. Completed
jobs release only after confirmed container destruction. Failed read-only jobs
also release after destruction because their callback permissions cannot sign,
write source state, publish, or obtain the op token. Read failure is never a
successful proof.

## Feature metadata authorization

`prepareFeature` accepts bounded canonical commit metadata: repository ID,
parent/tree hashes, exact feature ref, author/committer identities, message,
nonce and expiry. The shared pure contract reconstructs the unsigned Git
commit; no arbitrary byte/digest signing endpoint exists. The controller asks
workflow_depot `SOURCE_POLICY` for exact automatic producer authorization
before container start or service-token handoff. No per-feature owner prompt
or local Git mount/tree proof is needed.

A depot grant binds the complete request, signer, accepted policy, producer,
producer evidence digest, one-use grant ID and expiry. Before key use, the
runtime first reserves its durable signing effect and then consumes the grant
through the fixed private policy callback. The controller separately enforces
that ordering and forwards consumption only once. A fresh depot check after
signing must still return the identical grant. The returned signature and
receipt come only from the retained completed record; the receipt's claim is
`authenticated-producer-intent`. It does not attest scanned content, tree
availability, tests, reviewer acceptance or permission to promote main.

For the initial frozen changes, workflow_depot can use an explicitly installed
operator-owned intent allowlist through the existing approved administration
boundary. Dynamic producers use pinned existing GitHub OIDC admission. Missing
or unaccepted producer evidence denies; there is no new attestor identity or
self-asserted producer flag.

## Data and lifecycle boundaries

The sole runtime callback origin is `https://signing-control.internal`, resolved
through job-bound Cloudflare outbound interception. A random callback token is
handed to the runtime; only its hash is retained. The signed Git key and op
service token are never stored in Durable Object state. The service token is
read only for `prepare`, `prepareFeature`, or `approve`, then sent by private
handoff to the supervisor's isolated FD path. Reads receive null.

The container starts with general Internet access disabled. The controller
allows only exact configured 1Password origins for signing actions and normal
Git read endpoints for the configured GitHub repository. Redirects are not
followed. Git upload-pack is source acquisition; the signer cannot use this
route for receive-pack or arbitrary GitHub API writes.

Callbacks contain bounded metadata and use revision compare-and-swap without
retry. Action, repository, generation, typed record fields and immutable
receipt/effect tombstones constrain the state adapter. Only exact retained
signed commit/tag metadata may reach the fixed publisher, with Git object IDs
recomputed. Blob/tree/object-closure/archive payloads have no callback, storage,
or R2 route. Source acquisition and publication use normal Git transport;
the feature signing path transfers no source files and makes no source-custody
claim. Later promotion operations retain their separate full-history requirements.

Alarms, monitor completion and eviction recovery never relaunch a job. Cleanup
is serialized and checks the active generation. A late monitor cannot destroy
a newer container or remove its alarm. Failed destruction retains the lock and
an alarm for cleanup only. `PublicationAuthority` reads the retained generation,
reservation and grant directly, checks current policy and expiry, and records a
one-use consumption tombstone without a container round trip.

## Commissioning blockers and evidence

Feature activation requires the accepted depot `SOURCE_POLICY` private binding
with `current`, `authorizeFeatureCommit`, `consumeFeatureCommit` and
`checkFeatureCommit`, approved producer admission or retained intent policy,
and the signer runtime/DO. Actual pinned public key, immutable op reference,
approved op origins, tool/image digests, service-only op credential and live
container isolation/interception/cleanup qualification remain required.

Later promotion actions still separately require independently installed
`OWNER_HARDWARE`, `SOURCE_CI`, `SOURCE_SCANS`, `SOURCE_REVIEW`,
`SOURCE_INVENTORY`, `SOURCE_PUBLISHER`, full-history custody and the original
promotion policy/owner approval. Private repository Git reads additionally
require `SOURCE_READ_CREDENTIAL`. These unused promotion dependencies do not
block feature signing. Missing dependencies never receive an accepting
fallback, and configuration does not establish live hardware or deployment
qualification.

`test/cloudflare-controller.test.mjs` exercises replay/CAS, expiry, cleanup,
read-only confinement, bounded metadata, publisher grant consumption, exact Git
egress and the actual core's two-stage tag storage. `test/cloudflare-worker.test.mjs`
bundles and runs the actual named entry points in Workerd. These tests use local
synthetic capabilities and signatures; they do not start a real Cloudflare
container, call 1Password, create a key, or qualify a live installation.

The implementation uses the native Durable Object container API and SQLite
Durable Object storage. Relevant provider references:
[Container API](https://developers.cloudflare.com/durable-objects/api/container/)
and [Durable Object limits](https://developers.cloudflare.com/durable-objects/platform/limits/).
