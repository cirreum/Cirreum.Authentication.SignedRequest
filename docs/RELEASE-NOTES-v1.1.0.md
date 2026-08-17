# Cirreum.Authentication.SignedRequest 1.1.0 — SignedRequest declares its machines

## Why this release exists

The attribute-authority model has providers declare what kind of party they authenticate, so
nothing downstream infers it from token contents. RFC 9421 message signatures authenticate a
calling service by key pair — there is no human subject, no profile to build, and roles come
from the credential record consulted live on every request. This release says so through the
registration funnel.

## What's new

**`SubjectKind.Machine`, declared at registration.** `AddSignedRequest<T>(...)` registers and
declares the scheme through `IAuthenticationBuilder.AddScheme` in one act. Claim authority stays
`Unspecified` — the two authority axes arbitrate between an identity provider and an application
store for *human* callers, and neither pole describes a credential record the handler already
consults as part of authenticating.

## Compatibility

- **Applications have nothing to change.** Composition, the client resolver contract, and
  signature validation are untouched.
- The declaration is read by higher-layer packages releasing later in the same wave; until then
  it changes no behavior.

## See also

- `Cirreum.AuthenticationProvider 3.0.1` — the registration funnel.
- `Cirreum.Kernel 2.1.0` — the `SubjectKind` / `ClaimAuthority` vocabulary.
