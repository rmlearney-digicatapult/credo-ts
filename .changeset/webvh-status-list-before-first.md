---
'@credo-ts/webvh': patch
---

The `WebVhAnonCredsRegistry` returned the latest revocation status list when asked for a timestamp before the first status list was published. It now returns a `notFound` error, as no status list existed at that time.
