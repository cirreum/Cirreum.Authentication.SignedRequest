# Cirreum.Authentication.SignedRequest 1.0.0 — Renamed home for the SignedRequest scheme

## Why this release exists

`Cirreum.Authorization.SignedRequest` validates HMAC-SHA256 signed request envelopes to authenticate partner/M2M callers — but its package name placed it in the Authorization pillar. The **Cirreum 1.0 Foundation Reset** corrects this by recognizing Authentication as a first-class security pillar and moving the scheme packages to their proper home.

This release is the rename + the foundation for future RFC 9421 HTTP Message Signatures alignment.

## What's new

### Version-pluggable crypto

The new `ISignedRequestAlgorithm` + `ISignedRequestAlgorithmResolver` contracts (in `Cirreum.AuthenticationProvider`) replace the legacy fixed-algorithm switch. Apps register algorithms additively via DI:

```csharp
public interface ISignedRequestAlgorithm {
    string AlgorithmId { get; }
    bool Verify(ReadOnlySpan<byte> canonicalInput, ReadOnlySpan<byte> signature, ReadOnlySpan<byte> keyMaterial);
    byte[] Sign(ReadOnlySpan<byte> canonicalInput, ReadOnlySpan<byte> keyMaterial);
}
```

`HmacSha256SignedRequestAlgorithm` implements the new contract for the existing HMAC-SHA256 algorithm. Apps adding Ed25519, future post-quantum algorithms, etc. register additional implementations without modifying framework code.

### Selector-based dispatch

`SignedRequestAuthenticationSchemeSelector` implements `ISchemeSelector` with `SchemeCategory.Machine`. The dynamic forward resolver picks the SignedRequest scheme when configured signature headers are present.

## How it pairs with the rest of the Authentication pillar

| Package | Role |
|---|---|
| `Cirreum.Kernel` | Versioned-message primitive, `INotification` markers, auth event bus, `AuthenticationContextKeys` |
| `Cirreum.AuthenticationProvider` | Registrar bases, `ISchemeSelector`, `ISignedRequestAlgorithm`, `SchemeCategory` |
| **`Cirreum.Authentication.SignedRequest`** *(this release)* | SignedRequest scheme handler + signature validator + algorithm registry + selector |
| `Cirreum.Authentication.SignedRequest.Client` | Companion outbound-signing client package |
| `Cirreum.Runtime.AuthenticationProvider` | Dynamic forward resolver, selector iteration |
| `Cirreum.Runtime.Authentication` | App-facing `AddAuthentication(...)` builder |

## Compatibility

- **.NET 10.0** target.
- **Cirreum.Providers 1.2.0+** required.
- **Cirreum.AuthenticationProvider 1.0.0+** required.
- Apps migrating from `Cirreum.Authorization.SignedRequest` follow [`MIGRATION-v1.md`](MIGRATION-v1.md).
- Existing HMAC-SHA256 signed requests continue to validate without on-the-wire changes.

## See also

- [`MIGRATION-v1.md`](MIGRATION-v1.md), [`CHANGELOG.md`](CHANGELOG.md)
