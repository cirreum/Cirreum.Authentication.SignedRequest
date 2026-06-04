# Migration to Cirreum.Authentication.SignedRequest v1.0

**From:** `Cirreum.Authorization.SignedRequest 1.0.x` (now deprecated)
**To:** `Cirreum.Authentication.SignedRequest 1.0.0`

## Why v1

`Cirreum.Authentication.SignedRequest` is a renamed-and-rebuilt successor to the deprecated `Cirreum.Authorization.SignedRequest`. Like the rest of the **Cirreum 1.0 Foundation Reset**, the rename brings the package name in line with what it actually does — HMAC-signed request envelopes prove caller identity, which is authentication (under the three-pillar separation).

The release also lays the foundation for future RFC 9421 HTTP Message Signatures alignment via the new pluggable algorithm contract.

## Breaking Changes — Find/Replace Table

| Before (`Cirreum.Authorization.SignedRequest`) | After (`Cirreum.Authentication.SignedRequest`) |
|---|---|
| `using Cirreum.Authorization.SignedRequest;` | `using Cirreum.Authentication.SignedRequest;` |
| `using Cirreum.AuthorizationProvider.SignedRequest;` | `using Cirreum.Authentication.SignedRequest;` |
| `AddAuthorization(authz => authz.AddSignedRequest(...))` | `AddAuthentication(auth => auth.AddSignedRequest(...))` |
| `Cirreum:Authorization:Providers:SignedRequest:Instances:{name}` | `Cirreum:Authentication:Providers:SignedRequest:Instances:{name}` |

## New Capabilities

**Version-pluggable crypto.** The `ISignedRequestAlgorithm` / `ISignedRequestAlgorithmResolver` contracts (in `Cirreum.AuthenticationProvider`) let apps register additional algorithms (Ed25519, future post-quantum) without modifying framework code. The default `HmacSha256SignedRequestAlgorithm` implements the new contract; future algorithms register additively.

**Selector-based dispatch.** Ships `SignedRequestAuthenticationSchemeSelector` (an `ISchemeSelector` with `SchemeCategory.Machine`). The dynamic forward resolver picks the SignedRequest scheme when the configured signature headers are present.

## Migration Walkthrough

1. **Update `<PackageReference>` entries** — replace `Cirreum.Authorization.SignedRequest` with `Cirreum.Authentication.SignedRequest`, bump to `1.0.0`.
2. **Apply the find/replace table** across your codebase.
3. **Update `appsettings.json`** — rename the configuration root from `Cirreum:Authorization` to `Cirreum:Authentication`.
4. **Move the `AddSignedRequest` call** from `AddAuthorization(...)` to a new `AddAuthentication(...)` builder.
5. **Rebuild and verify** the existing HMAC-SHA256 signed requests continue to authenticate as before.

## What Didn't Change

- HMAC-SHA256 signature algorithm and canonical-input format.
- Header names (`X-Client-Id`, `X-Timestamp`, `X-Signature`) and validation behavior.
- `ISignedRequestClientResolver` resolver contract (configuration / dynamic-resolution patterns).
- Event surface (`ISignatureValidationEvents`, success/failure contexts).
- Replay protection and rate-limiting hooks.

## Downstream Package Impact

- **`Cirreum.AuthorizationProvider`** — auth-pillar abstractions migrated to `Cirreum.AuthenticationProvider` (including the new `ISignedRequestAlgorithm` contract). The old `Cirreum.AuthorizationProvider` 2.0.0 retains authorization-only content.
- **`Cirreum.Authentication.SignedRequest.Client`** — companion client-side signing package; rebuilt alongside this one.
