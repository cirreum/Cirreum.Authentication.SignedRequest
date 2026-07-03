# Cirreum.Authentication.SignedRequest 1.0.0 — the RFC 9421 server scheme

The server-side SignedRequest authentication scheme: **verifies** inbound RFC 9421 HTTP Message
Signatures (RFC 9530 `Content-Digest`) and can **sign** outbound requests / webhooks. Successor to
the deprecated `Cirreum.Authorization.SignedRequest`, re-homed under the Authentication pillar and
re-designed to a genuine RFC 9421 / 9530 wire format.

> **Breaking migration.** This is not a drop-in rename — the wire format changed from the legacy
> custom-header envelope to RFC 9421. Signer and verifier must upgrade together. See
> [`MIGRATION-v1.md`](MIGRATION-v1.md).

## Why this release exists

`Cirreum.Authorization.SignedRequest` authenticated partner / M2M callers, but (1) its name placed it
in the Authorization pillar when signing proves *identity*, and (2) it used a bespoke custom-header
envelope. The Cirreum 1.0 Foundation Reset corrects both: the scheme moves to the Authentication
pillar and adopts standard RFC 9421 HTTP Message Signatures + RFC 9530 Content-Digest, sharing one
signature-base implementation with the client SDK so signer and verifier cannot drift.

## What's new

### RFC 9421 / RFC 9530 verification

Inbound requests carry `Signature` / `Signature-Input` (signed `@method` / `@path` / `@query` /
`content-digest` with `created` / `expires` / `nonce` / `keyid` / `tag` parameters) and a
`Content-Digest` header — **no custom `X-*` headers**. The credential is identified by `keyid`. The
signature is verified before the body is read; freshness (`created` / `expires`) is bounded; the body
is bound via Content-Digest.

### Code-first composition

```csharp
builder.AddAuthentication(auth => {
    auth.AddSignedRequest<MyCredentialResolver>(o => o.ConfigureValidation(v => {
        v.RequireStrictNonce = true;
        v.TimestampTolerance = TimeSpan.FromMinutes(2);
    }));
    auth.AddCoordination(c => c.UseInMemory());   // strict-nonce backend (or .UseRedis())
});
```

`AddSignedRequest<TClientResolver>(...)` — no appsettings section; the resolver is the sole source of
signing credentials (implement `DynamicSignedRequestClientResolver`, keyed by `keyid`, for zero-downtime
rotation).

### Pluggable algorithm seam

`ISignedRequestAlgorithm` / `ISignedRequestAlgorithmResolver` live in the dependency-free
`Cirreum.SignedRequest` package (shared with the client SDK), with `HmacSha256SignedRequestAlgorithm`
built in. Asymmetric algorithms (Ed25519, future PQ) register additively without touching the signature
base or wire format.

### Strict-nonce replay protection

`RequireStrictNonce` claims each `nonce` through `IReplayGuard` (from `Cirreum.Coordination`), held for
the credential's effective freshness window — true single-use protection over a shared backend.

### Selector-based dispatch

`SignedRequestAuthenticationSchemeSelector` (`ISchemeSelector`, `SchemeCategory.Machine`) routes inbound
requests carrying the signature headers to this scheme.

## Compatibility

- **.NET 10.0**; `FrameworkReference Microsoft.AspNetCore.App`.
- **Breaking successor** to `Cirreum.Authorization.SignedRequest` — the wire format changed; follow
  [`MIGRATION-v1.md`](MIGRATION-v1.md) and cut signer + verifier over together.
- Depends on `Cirreum.AuthenticationProvider 1.1.0`, `Cirreum.SignedRequest 1.0.0`, `Cirreum.Coordination 1.0.0`.

## See also

- `Cirreum.SignedRequest` — the shared RFC 9421 / 9530 primitives + signer
- `Cirreum.Authentication.SignedRequest.Client` — the outbound-signing + webhook-validation SDK
- [`MIGRATION-v1.md`](MIGRATION-v1.md), [`CHANGELOG.md`](CHANGELOG.md)
