---
'@credo-ts/webvh': patch
---

`WebVhApi.resolveResource` and the `WebVhAnonCredsRegistry` parse a did:webvh resource served as `application/ld+json`, or any other `+json` media type, as JSON. Before, it was returned as a string, so an attested resource served that way failed to resolve.
