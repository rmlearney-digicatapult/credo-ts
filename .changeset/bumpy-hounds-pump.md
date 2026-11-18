---
'@credo-ts/webvh': patch
---

Upgrade `didwebvh-ts` to 3.2.0 (requires Node.js >=22.12.0) and use its exported DID URL parser and HTTPS converter for Credo resource dereferencing.

- Require complete caller-authored documents for create/update, create fields under `options`, and explicit document/controller KMS mappings.
- Automatically register DID adapters through `WebVhModule`, preserving explicitly configured adapters.
- Add deactivation, publication data (including the parallel did:web document that `didwebvh-ts` returns from the latest write, for `did.json`), proof storage, KMS-backed witness signing, proof verification/fetching, unpublished-log resolution, and portable U-label migration via `WebVhApi.migrate`. Applications remain responsible for witness coordination and publication; finished operations indicate local persistence only.
- `agent.dids.*` supports ordinary DID create, resolve, update, and deactivate operations; `agent.modules.webvh.*` supports WebVH-specific controller and witness agent actions, resources, and migration (`webvh` is the configured module key).
- Resolve published logs through upstream with version selectors and validation metadata/errors preserved. Use cache and local-record shortcuts for unversioned DIDs; query selectors bypass them. Valid deactivation returns a null document with `deactivated: true`.
- Verify DID logs and witness proofs with the strict Ed25519 verifier built into `didwebvh-ts`, which other did:webvh implementations agree with, instead of through the agent's KMS. `WebVhDidCrypto` is removed.
- Import the parallel did:web document that `didwebvh-ts` returns as a created DID with the KMS keys of the did:webvh document, so the agent can resolve and sign as the did:web. A write fails when another did:webvh at the same location provides that did:web, and a did:web record the application created there is replaced. A did:web record that no longer applies is kept for now.
- Preserve encoding boundaries in non-unique domain tags and allow different SCIDs at the same publication location.
- Fix resource URL conversion and replace `WebVhDidResolverOptions.maxResourceBytes` with agent `fetchLimits.maxResponseBytes`.
- Keep DID log typing aligned with `didwebvh-ts` and limit public resource exports to the attested-resource models and guard; storage metadata and parsing helpers remain internal.

Re-issue unsupported v0.5 and single-label-host DIDs. Disable pre-rotation with a full-document update before deactivation. Import context-free `getWitnessRequirements` and `deriveNextKeyHash` utilities directly from `didwebvh-ts`.
