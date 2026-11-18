---
'@credo-ts/core': patch
---

`DidResolverService` no longer serves a DID URL with a query, such as `did:webvh:…?versionId=…`, from the cache or from a locally created DID record, and no longer caches its result. Both are keyed by the DID alone, so a versioned request returned the current document, and its result replaced the cached current document. A DID URL with a query is now always resolved by the DID method's resolver.
