# Generic Rust transport boundary (2026-09-28)

User requires this repository to provide only generic channel capabilities and
explicitly says old interface compatibility and migration are unnecessary.
This supersedes previous application-enum and helper-preservation decisions.

Baseline: 615d4c9d497de3e3569bc0ec5326ed43eb11c153.
Previously authorized companion-helper removal remains included in this worktree.
The CLI owns its Go BuiltinHelperLauncher. Do not restore a Rust binary, private
helper control framing, local sockets, application classifiers, adapters or
built-in application profile constants here.

Use the validated owned Protocol identifier instead of the application-specific
enumeration. Bound it to 1–64 ASCII alphanumerics / dot / underscore / hyphen;
forward it unchanged using the existing tiana-database-protocol header. The
Gateway owns support/policy decisions. Client/Tunnel interpret no payload bytes.
Protocol is not Copy; Tunnel::protocol returns a borrow. No compatibility aliases.

Preserve Endpoint/SNI/authority binding, TLS trust, credential handling, diagnostic
request IDs, no-replay behavior, H2 multiplexing, flow control and half-close.
No storage format, durability behavior, token semantics or server wire change.
Protocol validation allocates once per connection, not per payload operation.
Dropped streams must not disrupt siblings; failure never implies safe retry.

Validation: normal and all-feature tests, fmt, all-target/all-feature Clippy with
warnings denied, source package inspection. Run generic TLS/H2 transport tests by
default (the old disabled legacy-tests feature is removed). Verify profiles are
passed unchanged, invalid identifiers cannot inject headers, payloads are opaque,
and failed streams and diagnostic callbacks remain isolated. Keep original frozen
conformance provenance; do not rewrite those source artifacts to invent contracts.
Do not commit, push or publish without a fresh explicit user request.


## 2026-09-28: opaque Gateway credentials

A Gateway-accepted 48-character credential was rejected by the former fixed
47-character/base64 InstanceToken parsers. Treat credentials as opaque, as sdk-go
and current Public CONNECT/Token specifications require. Accept 1..4096 visible
ASCII bytes (0x21..0x7e); reject empty, whitespace, control, non-ASCII and oversized
input before I/O/allocation. Do not infer prefix/version/type/scope, decode base64,
trim, normalize or append padding. The maximum is a resource bound with headroom
under the existing 16 KiB header-list budget, not a token-format discriminator.
Gateway remains the authentication authority; no authentication bypass/fallback.

Preserve exact Bearer bytes, never-indexed/sensitive headers, redacted errors,
owned-buffer clearing where supported and existing no-replay/TLS guarantees.
Removing base64 parsing removes temporary decoded secrets; validation is one
bounded linear scan at configuration time, with no payload hot-path work. No
storage, transaction, persisted schema or server wire change. This deliberately
accepts additional opaque representations; rollback reinstates the old client
rejection and must not transform saved credentials. Go's broader HTTP header
value check is the opacity reference, not a claim of identical whitespace policy.

Use only synthetic credentials in committed tests. Cover old/new-length and
non-prefix tokens, exact protected header forwarding, invalid/control/oversize
input, redaction and owned-buffer cleanup. Validate installed built artifacts
and real read-only notes demos without persisting user credentials. Isolated
verification may exercise unpublished changed artifacts; production adapter
manifests remain pinned remote HTTPS and must be refreshed after authorized
publication. No commit/push is authorized by this fix alone.


## 2026-09-28: PEM CA files

User removes the DER-only CA-file requirement. PEM files with one or more
CERTIFICATE blocks are the standard input, matching the other language SDKs.
This supersedes the earlier DER-only demo/conversion guidance. Keep the low-level
DER builder available for decoded certificate bytes, not as a file requirement.
The core exposes add_root_certificates_pem and validates at build time with the
existing rustls PEM reader; no new dependencies or home-grown ASN.1/PEM parser.
Empty bundles, parse failures and invalid certificates fail closed, even with
public roots enabled. Demo custom roots replace built-ins as before. Never
relax chain/hostname, TLS1.3, ALPN, SNI or authority checks; do not log CA contents.

The SQLite example parses PEM using its existing rustls dev dependency and
passes decoded certificates to the pinned remote core's DER API. This lets the
example work before publication of the new core API; production Git HTTPS pins
remain unchanged and no local dependency fallback is introduced. This is input
format decoding only, not a second transport implementation.

Parsing occurs once during client configuration, linear in the caller-supplied
bundle size, with allocations proportional to certificates/input. No file I/O
or parsing on the per-query path, network round trips, storage format, SQL,
transaction, durability, recovery or concurrency changes. File size remains
caller-controlled as before. Rollback of demo/docs together would restore the
DER-only requirement. Preserve earlier uncommitted opaque-token and adapter work.
Test multi-certificate PEM trust (including CRLF), empty/malformed/invalid/mixed
bundles, wrong-host and unrelated-root rejection, and actual TLS/H2. Verify
SQLite examples against the unchanged remote core plus isolated fixed-core
integration. No commit or push is authorized.
