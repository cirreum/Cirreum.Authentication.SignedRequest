# Cirreum.Authentication.SignedRequest Changelog

All notable changes to **Cirreum.Authentication.SignedRequest** are documented in this file.

Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) — [SemVer](https://semver.org/spec/v2.0.0.html).

---

## [Unreleased]

## [1.0.5] - 2026-07-19

### Updated

- Updated NuGet packages.

## [1.0.1] - 2026-07-04

### Updated

- Updated NuGet packages.

## [1.0.0] - 2026-07-03

### Added

- Initial release. Cirreum.Authentication.SignedRequest is the SignedRequest authentication scheme of the Cirreum framework, established as part of the **Cirreum 1.0 Foundation Reset** wave.
- **Renamed and re-homed from the deprecated `Cirreum.Authorization.SignedRequest`** under the Three Security Pillars separation.
- **SignedRequest scheme content absorbed from former `Cirreum.AuthorizationProvider.SignedRequest`**:
  - `ISignedRequestClientResolver`, `SignedRequestClient`, `StoredSigningCredential`
  - `SignedRequestContext`, `SignedRequestValidationResult`, `SignatureFailureType`
  - `ISignatureValidator` + `DefaultSignatureValidator`
  - `ISignatureValidationEvents` + contexts + `NullSignatureValidationEvents`
  - `SignatureValidationOptions`, `SignatureVersions`, `SignedRequestDefaults`
  - `DynamicSignedRequestClientResolver`
- **`ISignedRequestAlgorithm` / `ISignedRequestAlgorithmResolver`** — the pluggable signing/verification seam, defined in the dependency-free `Cirreum.SignedRequest` package so the server scheme and the client SDK build against one source of truth:
  - `HmacSha256SignedRequestAlgorithm` implements the contract (`"hmac-sha256"`).
  - `SignedRequestAlgorithmResolver` resolves algorithms by canonical identifier.
  - Apps can register additional `ISignedRequestAlgorithm` implementations via DI (Ed25519, future post-quantum).
- **NEW — `SignedRequestAuthenticationSchemeSelector`** implements `ISchemeSelector` with `SchemeCategory.Machine`. Probes inbound requests for the configured signature headers and routes to the SignedRequest scheme.
- **NEW — `AddSignedRequest<TClientResolver>(...)` composition verb** on `IAuthenticationBuilder`, the app-facing entry point (composed inside `AddAuthentication(...)`; not auto-registered by the umbrella package). **Code-first — no appsettings section or registrar** (in the Cirreum provider model an appsettings section and a registrar are a matched pair, and SignedRequest has no per-instance data):
  - The client resolver is a **required type parameter** — it is the sole source of signing credentials (unlike ApiKey, where a resolver is additive on top of appsettings clients).
  - `SignedRequestOptions.ConfigureValidation(v => …)` tunes `SignatureValidationOptions` in code; apps wanting config-driven tuning bind their own configuration there.
  - `SignedRequestSchemes.Default` (`"SignedRequest"`) — the policy-facing scheme constant.
  - Supersedes the interim `AddDynamicSignedRequest<T>` verb and removes the foundation-reset-era `SignedRequestAuthenticationRegistrar` + `SignedRequestAuthenticationSettings` / `SignedRequestAuthenticationInstanceSettings` (migration artifacts — the original scheme was code-composed, which this restores).

### Migration

Apps consuming `Cirreum.Authorization.SignedRequest` migrate by installing `Cirreum.Authentication.SignedRequest` and switching their composition root from `AddAuthorization(authz => authz.AddSignedRequest<MyResolver>(...))` to `AddAuthentication(auth => auth.AddSignedRequest<MyResolver>(...))`. **This is a breaking protocol change, not just a rename** — the wire format is now RFC 9421 / RFC 9530 (the legacy `X-Client-Id` / `X-Timestamp` / `X-Signature` custom-header envelope is gone), so the signer and verifier must upgrade together. See [`docs/MIGRATION-v1.md`](MIGRATION-v1.md).
