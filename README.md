# Cirreum Authentication - SignedRequest

[![NuGet Version](https://img.shields.io/nuget/v/Cirreum.Authentication.SignedRequest.svg?style=flat-square&labelColor=1F1F1F&color=003D8F)](https://www.nuget.org/packages/Cirreum.Authentication.SignedRequest/)
[![NuGet Downloads](https://img.shields.io/nuget/dt/Cirreum.Authentication.SignedRequest.svg?style=flat-square&labelColor=1F1F1F&color=003D8F)](https://www.nuget.org/packages/Cirreum.Authentication.SignedRequest/)
[![GitHub Release](https://img.shields.io/github/v/release/cirreum/Cirreum.Authentication.SignedRequest?style=flat-square&labelColor=1F1F1F&color=FF3B2E)](https://github.com/cirreum/Cirreum.Authentication.SignedRequest/releases)
[![License](https://img.shields.io/github/license/cirreum/Cirreum.Authentication.SignedRequest?style=flat-square&labelColor=1F1F1F&color=F2F2F2)](https://github.com/cirreum/Cirreum.Authentication.SignedRequest/blob/main/LICENSE)
[![.NET](https://img.shields.io/badge/.NET-10.0-003D8F?style=flat-square&labelColor=1F1F1F)](https://dotnet.microsoft.com/)

**HMAC-signed request authentication scheme for the Cirreum framework**

> **Migrating from `Cirreum.Authorization.SignedRequest`?** This package is its renamed successor — same scheme, proper pillar. See [`docs/MIGRATION-v1.md`](docs/MIGRATION-v1.md).

## Overview

**Cirreum.Authentication.SignedRequest** authenticates partner/M2M callers via HMAC-SHA256 (and pluggable future algorithms) signed-request envelopes. Apps register configured or dynamically-resolved client credentials; the handler validates the inbound signature, timestamp, and body hash against the registered key material.

The package implements the SignedRequest scheme of the Cirreum Authentication pillar.

### Key features

- **HMAC-SHA256 signatures** over `{timestamp}.{method}.{path}.{bodyHash}` canonical input
- **Pluggable algorithm contracts** via `ISignedRequestAlgorithm` + `ISignedRequestAlgorithmResolver` — register Ed25519, post-quantum, etc., additively
- **Configuration and dynamic client resolution** (database-backed via `DynamicSignedRequestClientResolver`)
- **Replay protection** via timestamp window
- **Selector-based dispatch** — ships `SignedRequestAuthenticationSchemeSelector`
- **Validation events** — `ISignatureValidationEvents` for success/failure observability, rate limiting, and client blocking

## Installation

```bash
dotnet add package Cirreum.Authentication.SignedRequest
```

## Configuration

```json
{
  "Cirreum": {
    "Authentication": {
      "Providers": {
        "SignedRequest": {
          "Instances": {
            "PartnerA": {
              "Enabled": true,
              "ClientId": "partner-a",
              "ClientName": "Partner A",
              "Roles": ["App.Partner"]
            }
          }
        }
      }
    }
  }
}
```

The signing credentials themselves are loaded by the configured `ISignedRequestClientResolver` — typically from a database in production deployments.

## Headers

| Header | Required | Description |
|---|---|---|
| `X-Client-Id` | Yes | Public client identifier; used for credential lookup |
| `X-Timestamp` | Yes | Unix timestamp; rejected when outside the configured window |
| `X-Signature` | Yes | HMAC signature in format `v1=hexstring` |

## What changed

### Version-pluggable crypto

The `ISignedRequestAlgorithm` contract (in `Cirreum.AuthenticationProvider`) lets apps register additional algorithms. Built-in: `HmacSha256SignedRequestAlgorithm` (algorithm ID `"hmac-sha256"`).

```csharp
public interface ISignedRequestAlgorithm {
    string AlgorithmId { get; }
    bool Verify(ReadOnlySpan<byte> canonicalInput, ReadOnlySpan<byte> signature, ReadOnlySpan<byte> keyMaterial);
    byte[] Sign(ReadOnlySpan<byte> canonicalInput, ReadOnlySpan<byte> keyMaterial);
}
```

App registers a custom algorithm:

```csharp
builder.Services.AddSingleton<ISignedRequestAlgorithm, Ed25519SignedRequestAlgorithm>();
```

### Selector-based dispatch

`SignedRequestAuthenticationSchemeSelector` implements `ISchemeSelector` with `SchemeCategory.Machine`. The forward resolver picks SignedRequest when the configured signature headers are present.

## Security considerations

- **Timestamp window** — Configure narrowly (60-300 seconds typical) to limit replay window.
- **Key storage** — Signing credentials stored in your data layer; rotate keys periodically.
- **Transport security** — Always use HTTPS to protect signed-request bodies from tampering attacks beyond the signature's scope.
- **Rate limiting via `ISignatureValidationEvents.IsClientBlockedAsync`** — apps can refuse repeat-failing clients before validation.

## License

MIT — see [LICENSE](LICENSE).

---

**Cirreum Foundation Framework**
*Layered simplicity for modern .NET*
