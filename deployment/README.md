# Central signer deployment source

A main push calls the immutable `workflow_depot/request-deployment.yml` capability for registered target `signing-control`. The source repository holds only the existing `RELEASE_DISPATCH_TOKEN` reference; it does not inject Cloudflare or 1Password credentials. Central admission verifies the exact signed current-main source and caller run before any target execution.

`deployment/deploy.mjs` refuses standalone main execution. It accepts only central `delivery_control` workflow dispatch with exact `SOURCE_REPOSITORY`, `SOURCE_REPOSITORY_ID` and `SOURCE_SHA`. Cloudflare deployment credentials belong to the existing central runtime. Runtime signing credentials remain in the existing Worker: runner-provided `OP_SERVICE_ACCOUNT_TOKEN` and secret-file upload are prohibited. Missing retained custody blocks execution and requires separately approved commissioning.

Public `SIGNING_DEPLOYMENT_JSON` remains the existing deployment schema: approved immutable image/tool pins, signing public-key/item references and private service bindings. No values are invented. Existing stale-main checks, provider readback, serialization and no retry on uncertain writes remain intact.

Current central registry lists `signing-control` as blocked. Central workflow configuration is disabled with empty targets/enrollment; its provider supports the existing Worker artifact contract, while signer Container publication still requires reviewed commissioning/wiring. This caller migration alone does not activate signing or make central deployment operational. Do not merge as an activation shortcut.

Focused tests mock every provider operation. No live deployment, image push, token upload or signing is performed by these tests.
