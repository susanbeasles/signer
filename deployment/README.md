# Central signer deployment source

A main push calls the immutable `workflow_depot/request-app-deployment.yml` capability for registered target `signing-control`. The source caller passes only exact nonsecret existing App identity/item references and its existing scoped 1Password bootstrap to the approved reusable adapter. No static RELEASE_DISPATCH_TOKEN, PAT, Cloudflare credential or stored App private key is introduced. Commissioning defaults false; the adapter reads the key only with the official CLI after separately approved identity/permission checks. Central admission verifies the exact signed current-main source and caller run before any target execution.

`deployment/deploy.mjs` refuses standalone main execution. It accepts only central `delivery_control` workflow dispatch with exact `SOURCE_REPOSITORY`, `SOURCE_REPOSITORY_ID` and `SOURCE_SHA`. Cloudflare deployment credentials belong to the existing central runtime. Runtime signing credentials remain in the existing Worker: runner-provided `OP_SERVICE_ACCOUNT_TOKEN` and secret-file upload are prohibited. Missing retained custody blocks execution and requires separately approved commissioning.

Public `SIGNING_DEPLOYMENT_JSON` remains the existing deployment schema: approved immutable image/tool pins, signing public-key/item references and private service bindings. No values are invented. Existing stale-main checks, provider readback, serialization and no retry on uncertain writes remain intact.

Current central registry lists `signing-control` as blocked. Central workflow configuration is disabled with empty targets/enrollment; its provider supports the existing Worker artifact contract, while signer Container publication still requires reviewed commissioning/wiring. This caller migration alone does not activate signing or make central deployment operational. Do not merge as an activation shortcut.

Focused tests mock every provider operation. No live deployment, image push, token upload or signing is performed by these tests.

Required existing App ID/client ID/slug, central installation ID and exact 1Password App RSA field reference are currently unknown: metadata reads are Forbidden. No credential was configured or token minted. This source deliberately fails before key access until the existing identity is identified and explicitly commissioned.
