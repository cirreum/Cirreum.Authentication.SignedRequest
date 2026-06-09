# Cirreum Authentication - SignedRequest

[![NuGet Version](https://img.shields.io/nuget/v/Cirreum.Authentication.SignedRequest.svg?style=flat-square&labelColor=1F1F1F&color=003D8F)](https://www.nuget.org/packages/Cirreum.Authentication.SignedRequest/)
[![NuGet Downloads](https://img.shields.io/nuget/dt/Cirreum.Authentication.SignedRequest.svg?style=flat-square&labelColor=1F1F1F&color=003D8F)](https://www.nuget.org/packages/Cirreum.Authentication.SignedRequest/)
[![GitHub Release](https://img.shields.io/github/v/release/cirreum/Cirreum.Authentication.SignedRequest?style=flat-square&labelColor=1F1F1F&color=FF3B2E)](https://github.com/cirreum/Cirreum.Authentication.SignedRequest/releases)
[![License](https://img.shields.io/badge/license-MIT-F2F2F2?style=flat-square&labelColor=1F1F1F)](https://github.com/cirreum/Cirreum.Authentication.SignedRequest/blob/main/LICENSE)
[![.NET](https://img.shields.io/badge/.NET-10.0-003D8F?style=flat-square&labelColor=1F1F1F)](https://dotnet.microsoft.com/)

**RFC 9421 HTTP Message Signatures authentication for service-to-service and webhook traffic**

## Overview

**Cirreum.Authentication.SignedRequest** is the server side of the SignedRequest pillar. It **verifies** inbound RFC 9421 (HTTP Message Signatures) + RFC 9530 (Content-Digest) requests, and can **sign** outbound ones (downstream calls, webhooks). The signature primitives are the shared, dependency-free [`Cirreum.SignedRequest`](https://github.com/cirreum/Cirreum.SignedRequest) package — the same code the [client SDK](https://github.com/cirreum/Cirreum.Authentication.SignedRequest.Client) uses — so a request signed on one side verifies byte-identically on the other.

Signatures are HMAC-SHA256 today; the `ISignedRequestAlgorithm` seam admits more (e.g. Ed25519) additively.

### What it does

- **Verifies** the RFC 9421 signature, the RFC 9530 `Content-Digest` body binding, and `created` / `expires` freshness against a bounded window.
- **Resolves credentials dynamically** — you implement `DynamicSignedRequestClientResolver` over your credential store; the scheme tries each active credential (zero-downtime key rotation).
- **Replay protection** — an optional strict-nonce posture claims each RFC 9421 `nonce` through an `IReplayGuard`, held for exactly the credential's effective freshness window.
- **Signs outbound** requests / webhooks via `HttpRequestMessage.SignRequestAsync(...)` and `HttpClient.SendSignedAsync(...)`.
- **Fails closed** on every error path; constant-time signature and digest comparison; the algorithm is pinned to the credential and a minimum secret-strength floor is enforced.

## Installation

```bash
dotnet add package Cirreum.Authentication.SignedRequest
```

## Composing the scheme

SignedRequest is **code-composed** — there is no appsettings section. The client resolver is the sole source of signing credentials, so it is a required type parameter. Compose it inside `AddAuthentication` on the umbrella package:

```csharp
builder.AddAuthentication(auth => {
    auth.AddSignedRequest<MyCredentialResolver>(o => o.ConfigureValidation(v => {
        v.RequireStrictNonce = true;                  // optional: single-use nonce replay protection
        v.TimestampTolerance = TimeSpan.FromMinutes(2);
    }));

    // Strict-nonce requires a coordination backend — the host fails fast at startup without one.
    auth.AddCoordination(c => c.UseInMemory());        // or .UseRedis() for multi-node
});
```

Your resolver returns the active signing credentials for a presenting `keyid`:

```csharp
public sealed class MyCredentialResolver(
        ICredentialRepository repo,
        ISignedRequestAlgorithmResolver algorithms,
        IOptions<SignatureValidationOptions> options,
        ILogger<MyCredentialResolver> logger)
    : DynamicSignedRequestClientResolver(algorithms, options, logger) {

    protected override Task<IEnumerable<StoredSigningCredential>> LookupCredentialsAsync(
        string keyId, CancellationToken ct) => repo.FindActiveByKeyIdAsync(keyId, ct);
}
```

## Wire format (RFC 9421 / RFC 9530)

| Header | Description |
|---|---|
| `Signature-Input` | The covered-component list + signature parameters (`created`, `expires`, `nonce`, `keyid`, `alg`, `tag`) |
| `Signature` | The HMAC over the RFC 9421 signature base, as an RFC 8941 byte sequence |
| `Content-Digest` | RFC 9530 `sha-256=:…:` over the body, binding it into the signature |

The default covered set is `@method`, `@path`, `@query`, `content-digest`. The credential is identified by the `keyid` parameter — there are no custom `X-*` headers.

## Signing outbound requests

```csharp
// Sign a prepared HttpRequestMessage:
await request.SignRequestAsync(keyId, signingSecret);

// Or sign + send with a JSON body in one call:
var response = await client.SendSignedAsync(
    HttpMethod.Post, "/v1/events", keyId, signingSecret, new { eventType = "order.placed", id });
```

`OutboundSigningOptions` controls the algorithm, covered components, signature label, `expires` window, and nonce (≥ 128-bit).

## RFC conformance profile

> Cirreum SignedRequest implements a constrained Cirreum profile of RFC 9421 and RFC 9530. The implementation intentionally supports the covered components, algorithms, digest forms, and validation behavior documented here; unsupported general RFC features are out of scope unless explicitly listed.

| Area | Supported | Not supported |
|---|---|---|
| Covered components | `@method`, `@path`, `@query`, HTTP fields (`content-digest`) | `@authority` (intentionally dropped), `@target-uri`, `@scheme`, `@status` (response signing), `@query-param`, component parameters (`sf` / `key` / `bs` / `req`) |
| Algorithms | `hmac-sha256` | others are additive via `ISignedRequestAlgorithm`; a credential must opt into a non-default algorithm |
| Digest (RFC 9530) | `Content-Digest` with `sha-256` | other digest algorithms (ignored), `Repr-Digest` / `Want-*-Digest` |
| Signatures per request | exactly one | multi-signature messages are rejected |
| Structured fields (RFC 8941) | the dictionary / inner-list / string / byte-sequence / integer subset these headers use | a general RFC 8941 parser |

`@path` / `@query` are normalized to the RFC 9421 §2.2.6/§2.2.7 + RFC 3986 §6.2.2 canonical form in one shared place, so signer and verifier converge. Conformance is verified against RFC 4231 (HMAC-SHA-256) and RFC 9530 (Content-Digest) published vectors, the signature base is locked by a known-answer vector, and the wire parser is fuzz-hardened.

## Security considerations

- **Replay** — enable `RequireStrictNonce` for true single-use protection; without it a request is replayable until the freshness window lapses.
- **Secret strength** — secrets below 128 bits are rejected; ≥ 256-bit is recommended. Store encrypted at rest and rotate by adding a new active credential.
- **Audience binding** — set a credential's `Audience` (the RFC 9421 `tag`) when a secret is shared across services, so a request for one audience cannot be replayed against another.
- **Transport** — always use HTTPS; the signature protects the covered components and body digest, not everything else.
- **Abuse control** — implement `ISignatureValidationEvents` to observe outcomes and block repeat-failing clients before validation.

## License

MIT — see [LICENSE](LICENSE).

---

**Cirreum Foundation Framework**
*Layered simplicity for modern .NET*
