# Public CONNECT authority v1

Public Client-to-Gateway database sessions use TLS 1.3 with ALPN `h2` and a
regular HTTP/2 CONNECT stream. The v1 Endpoint hostname is exactly:

```text
<endpoint_id>.db.service.internal.tiana.com
endpoint_id = ^ep-[0-7][0-9a-hjkmnp-tv-z]{25}$
```

`wire.PublicConnectEndpointSuffixV1`,
`wire.PublicConnectDefaultPortV1`, and
`fixtures/gateway/public-connect-authority-v1.json` are the executable
cross-language authority. Implementations must not copy a different suffix or
derive it from an unrelated deployment setting.

The TLS SNI and normalized CONNECT `:authority` hostname must be identical and
name one Endpoint. DNS case is normalized to lowercase. An omitted authority
port means 443; the only allowed explicit port is `:443`. A physical connection
is bound to its SNI Endpoint, so a stream for another Endpoint is rejected and
must not reach policy lookup, activation, Runtime, or Agent I/O.

The L4 listener may be reached through a different transport port such as a
Kubernetes NodePort, but that deployment detail does not change the canonical
`:authority` port. The listener terminates TLS itself; an L4 proxy must not
terminate TLS, rewrite SNI or CONNECT headers, or inspect the optional raw
InstanceToken.

This authority replaces the unreleased `.db.tiana.dev` design value. Gateways
and SDKs that accept that suffix are incompatible with this v1 authority and
must not serve production traffic.
