---
'@credo-ts/webvh': patch
---

The `WebVhAnonCredsRegistry` verifies the proof and content digest of a did:webvh attested resource on the resource as fetched. It checked a copy whose `type` was converted to an array, so a resource signed with a string `type` failed to resolve.
