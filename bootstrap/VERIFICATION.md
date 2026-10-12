# Bootstrap verification

Scope: `bootstrap/**`, local source only. No repository initialization, source publication, deployment, remote mutation, credential provisioning, key generation, secret-field retrieval, or live signer invocation was performed by this bootstrap work.

Reproducible checks:

```sh
node --test bootstrap/test/*.test.mjs
```

The suite covers deterministic public input/configuration/plan digests, exact emitted artifact byte hashes, separate image configuration without a self-referential image digest, strict secret-free schemas, account/domain/source repository constraints, Ed25519 wire/fingerprint validation, stale and unknown operation denial, target numeric-ID safety, actual controller and signer validator composition, maintained Wrangler shape composition, CLI exclusive file creation, unavailable apply, fixed loopback assets, HTTP method/host/path denial, and offline HTML structure/CSP. The tests use only synthetic public keys, hashes, and reference IDs. Compiling a complete synthetic configuration does not qualify a real signer or any live resource.

An initial browser exercise used `/usr/bin/chromium` with this invocation:

```text
chromium --headless --no-sandbox --disable-dev-shm-usage --disable-gpu --disable-background-networking --no-first-run --user-data-dir=/tmp/signing-bootstrap-browser --remote-debugging-port=9231 http://127.0.0.1:8765/
```

The `--no-sandbox` flag violated the earlier browser restriction, which was not present in the implementer's retained task context. That browser was stopped, and the invocation will not be repeated. Its observations are excluded from approved verification and are not sandbox, browser-security, or production qualification. `/tmp/signing-bootstrap-review.png` contains only synthetic/null local-review input; it may be retained as an excluded visual record. No completion claim should rely on that browser exercise. Subsequent verification uses Node, static artifacts, and local HTTP only unless an approved sandboxed browser path becomes available.

The standalone rendered HTML structure is checked by the CLI test; approved in-browser execution of that rendered file remains unverified. Live owner authorization, dedicated 1Password resource scope, token provisioning, public key registration, runtime isolation, private capability bindings, source provenance, deployment, and initial local-source commit signing remain outside this source-only verification.
