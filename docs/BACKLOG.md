# Backlog

Deferred work for **Cirreum.Authentication.SignedRequest**. Items here are tracked but not yet ready
to ship — either because the cost outweighs the benefit in isolation, or
because they're waiting on a forcing function (a related change, a consumer
upgrade, a coordinated multi-repo rollout).

## How this file works

- Each item is a `###` heading so it can be linked to and parsed.
- Each item declares **`SemVer:`** (`Patch` | `Minor` | `Major` | `Unspecified`),
  **`Trigger:`** (the human-readable condition that will make it ready), and
  **`Noted:`** (the date the item was added).
- The Cirreum DevOps release scripts (`PatchRelease`, `MinorRelease`,
  `MajorRelease`) surface items at-or-below the requested bump level so the
  operator can decide whether to fold them in before tagging.
- Items that ship: move from this file to `docs/CHANGELOG.md` under
  `[Unreleased]`. Items that grow into design discussions: promote to an ADR.

## Queued

### Composition-path tests for `AddSignedRequest<T>`

**SemVer:** Patch
**Trigger:** Next release of any kind, or any change touching `SignedRequestAuthenticationBuilderExtensions`.
**Noted:** 2026-07-18

The test suite exercises components directly; nothing invokes the `AddSignedRequest<T>(...)`
composition verb. This is the exact escape vector behind Cirreum.Authentication.ApiKey issue #1,
where `AddApiKey()` threw unconditionally at composition time through five published versions
because no test ever called it. A 2026-07-18 sweep audited this verb (statically and via a
bare-host runtime probe: compose, `BuildServiceProvider`, resolve the registered graph, both
call-twice guards) and found **no defect** — this item is preventive coverage so a future
regression in the registration path cannot ship silently. Model the tests on
`ApiKeyCompositionTests.cs` in Cirreum.Authentication.ApiKey (substituted `IAuthenticationBuilder`
with a real `AuthenticationBuilder` + empty `ConfigurationRoot`): bare-host compose must not
throw, the registered services must resolve, and the call-twice guard must surface as
`InvalidOperationException`.
