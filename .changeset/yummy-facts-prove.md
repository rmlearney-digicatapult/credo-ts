---
"@credo-ts/anoncreds": minor
---

Support equivalent AnonCreds identifier forms across resolution, proofs, and DIDComm revocation lookups.

Registries can provide equivalent identifiers through the optional `getIdentifierVariants` method,
with the canonical form first. Without it, identifiers retain exact-match behavior. Variants are
used for stored-record and credential queries, proof restrictions and verification, and DIDComm
auto-response comparisons, allowing percent-encoded and unencoded identifiers to interoperate
when supported by the registry.

The AnonCreds DIDComm revocation-notification processor also uses registry-provided variants
when matching notifications to credential exchange records.
