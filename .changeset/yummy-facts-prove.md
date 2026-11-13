---
"@credo-ts/anoncreds": minor
"@credo-ts/didcomm": minor
---

Support equivalent AnonCreds identifier forms across resolution, proofs, and DIDComm revocation lookups.

Registries can provide equivalent identifiers through the optional `getIdentifierVariants` method,
with the canonical form first. Without it, identifiers retain exact-match behavior. Variants are
used for stored-record and credential queries, proof restrictions and verification, and DIDComm
auto-response comparisons, allowing percent-encoded and unencoded identifiers to interoperate
when supported by the registry.

AnonCreds revocation-notification processing now lives in `@credo-ts/anoncreds/didcomm`.
Register `AnonCredsDidCommRevocationNotificationModule` alongside the AnonCreds and DIDComm modules to process these
notifications. DIDComm dispatches through a protocol-neutral processor interface and rejects
incoming notifications when no processor is registered.
