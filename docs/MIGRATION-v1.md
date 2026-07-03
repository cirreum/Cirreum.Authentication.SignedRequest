# Migration to Cirreum.Authentication.SignedRequest v1.0

> **From:** `Cirreum.Authorization.SignedRequest 1.0.x` (now deprecated) &nbsp;•&nbsp; **To:** `Cirreum.Authentication.SignedRequest 1.0.0`

## ⚠️ This is a breaking protocol change, not a drop-in rename

`Cirreum.Authentication.SignedRequest` is the renamed **and re-designed** successor to the
deprecated `Cirreum.Authorization.SignedRequest`. Two things changed together:

1. **The pillar rename** — the package moved from the Authorization pillar to Authentication
   (signing proves *identity*), so the package id, namespaces, and composition root change.
2. **The wire format is now genuinely RFC 9421 / RFC 9530** — the previous custom-header envelope
   (`X-Client-Id` / `X-Timestamp` / `X-Signature` over a `{timestamp}.{method}.{path}.{bodyHash}`
   canonical string) is **gone**. Signatures are now RFC 9421 HTTP Message Signatures (`Signature` /
   `Signature-Input` with signed `@method` / `@path` / `@query` / `content-digest` components and
   `created` / `expires` / `nonce` / `keyid` / `tag` parameters) plus an RFC 9530 `Content-Digest`.

**Because the wire format changed, a signer and a verifier must upgrade together.** An old client
signing the legacy envelope will *not* authenticate against this scheme, and vice versa. Plan the
cutover so the outbound signer (`Cirreum.Authentication.SignedRequest.Client` or this package's
outbound signer) and the verifier move in the same deployment.

## Breaking Changes — Find/Replace Table

| Before (`Cirreum.Authorization.SignedRequest`) | After (`Cirreum.Authentication.SignedRequest`) |
|---|---|
| `<PackageReference Include="Cirreum.Authorization.SignedRequest" .../>` | `<PackageReference Include="Cirreum.Authentication.SignedRequest" Version="1.0.0" />` |
| `using Cirreum.Authorization.SignedRequest;` / `using Cirreum.AuthorizationProvider.SignedRequest;` | `using Cirreum.Authentication.SignedRequest;` |
| `AddAuthorization(authz => authz.AddSignedRequest(...))` | `AddAuthentication(auth => auth.AddSignedRequest<TResolver>(...))` |
| `Cirreum:Authorization:Providers:SignedRequest:...` | (code-first — no appsettings section; tune via `SignedRequestOptions.ConfigureValidation(...)`) |

## Protocol Changes — Find/Replace Table (the wire format)

| Legacy | v1.0 (RFC 9421 / 9530) |
|---|---|
| `X-Client-Id` header | `keyid` parameter in `Signature-Input` |
| `X-Timestamp` header | `created` / `expires` parameters |
| `X-Signature: v1={hex}` | `Signature: sig1=:{base64}:` (RFC 8941 byte sequence) |
| Canonical `{timestamp}.{method}.{path}.{bodyHash}` | RFC 9421 signature base over `("@method" "@path" "@query" "content-digest")` |
| body hash folded into the canonical string | RFC 9530 `Content-Digest: sha-256=:…:` header, covered by the signature |
| (n/a) | `nonce` parameter + optional strict-nonce single-use replay posture |

## New / Changed Capabilities

- **`AddSignedRequest<TClientResolver>(...)`** is code-first, composed inside `AddAuthentication(...)`.
  The client resolver is a **required type parameter** — it is the sole source of signing credentials
  (implement `DynamicSignedRequestClientResolver`, keyed by `keyid`). `ConfigureValidation(v => …)`
  tunes freshness / strict-nonce / required components in code.
- **Pluggable algorithm seam** — `ISignedRequestAlgorithm` / `ISignedRequestAlgorithmResolver` are
  defined in the dependency-free **`Cirreum.SignedRequest`** package (not `Cirreum.AuthenticationProvider`),
  so this scheme and the client SDK build the byte-identical signature base. `hmac-sha256` ships built in;
  asymmetric algorithms register additively.
- **Strict-nonce replay** — `RequireStrictNonce` claims each `nonce` through `IReplayGuard` (from
  `Cirreum.Coordination`); register a backend with `auth.AddCoordination(c => c.UseInMemory())` (or Redis).

## Migration Walkthrough

1. Swap the package reference to `Cirreum.Authentication.SignedRequest 1.0.0`.
2. Apply the id/namespace/composition find/replace table; make the resolver a type parameter on
   `AddSignedRequest<TResolver>`.
3. Delete the `Cirreum:Authorization:Providers:SignedRequest` appsettings; move tuning to
   `ConfigureValidation(...)`.
4. **Upgrade every signer to the RFC 9421 wire format** (use `Cirreum.Authentication.SignedRequest.Client`
   or the outbound signer), and cut the signer + verifier over together.
5. If using strict-nonce, register a coordination backend (`auth.AddCoordination(...)`).

## What Didn't Change

- The **credential-resolver model** — credentials are still resolved dynamically from your store by a
  `keyid`, with rotation by adding a new active credential.
- **HMAC-SHA256** remains the default (and only v1) algorithm; the shared secret is still held at rest.
- Constant-time verification and fail-closed posture.

## Downstream Package Impact

- **`Cirreum.AuthorizationProvider`** → **`Cirreum.AuthenticationProvider`** (auth-pillar abstractions).
- **`Cirreum.Authorization.SignedRequest.Client`** → **`Cirreum.Authentication.SignedRequest.Client`**,
  which shares the RFC 9421 signer from `Cirreum.SignedRequest` — upgrade it in lockstep so outbound
  signatures match this verifier.
