---
'@credo-ts/core': minor
'@credo-ts/didcomm': minor
'@credo-ts/node': minor
---

Move the built-in DIDComm HTTP and WebSocket inbound transports from
`@credo-ts/node` to `@credo-ts/didcomm`. Configure inbound and outbound
transport instances in `DidCommModule`'s `transports.inbound` and
`transports.outbound` arrays, or register them before agent initialization.
Transport instances are no longer created implicitly. Node applications can
pass `httpServerHost` from `@credo-ts/node/http` or `webSocketHost` from
`@credo-ts/node/websocket` for Credo-owned listeners, or `expressHost` from
`@credo-ts/node/express` to attach an application-owned Express app.

Harden inbound lifecycle: share an HTTP listener across transports using the
same Express host, release it after the last transport stops, and close DIDComm
sessions before detaching. Bound shutdown of owned HTTP listeners even when
requests stall while uploading. Applications retain ownership of servers they
supply.

Expose framework-neutral HTTP handlers and WebSocket acceptors from DIDComm for
other runtimes to mount. Export Fetch-based HTTP and standard-shaped WebSocket
contracts from `@credo-ts/core/http` and `@credo-ts/core/websocket`, without
adding Express or Node WebSocket dependencies to core or DIDComm.
