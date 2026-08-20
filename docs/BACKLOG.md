# Backlog

Deferred work for **Cirreum.Runtime.Authentication**. Items here are tracked but not yet ready
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

### Antiforgery advisory driven by the cookie-scheme declaration

**SemVer:** Minor
**Trigger:** the attribute-authority rung 4 (scheme-declaration map + close-validation) has shipped in this package.
**Noted:** 2026-08-19

The platform-default cookie scheme is the framework's only *ambient* credential — the one the
browser attaches without the page's cooperation, and therefore the only scheme for which CSRF
exists. The framework composes it (the Entra/Oidc WebApp paths declare it once per host) but
says nothing about antiforgery anywhere. Once the declaration map ships, whether a host needs
antiforgery stops being guesswork: the composition root holds the fact.

**Premise updated 2026-08-19:** `Cirreum.Runtime.Server` 1.3.0 shipped posture-driven
antiforgery — `DomainRuntimeType.WebApp` registers the services and `UseDefaultMiddleware()`
runs `UseAntiforgery()` after authorization, with `MapDefaultAntiforgeryToken()` for browser
clients. The protection itself is no longer this item's job. What remains for the umbrella is
the **mismatch advisory** — the case the runtime type cannot see from where it sits:

- **Cookie scheme declared while the host's declared posture is not `WebApp`** → a Web API
  host composed the WebApp cookie flows; its cookie-authenticated endpoints have no
  antiforgery and `DisableAntiforgery` reasoning ("no ambient credential") is invalid there.
  Detection keys on the cookie scheme's declaration record — the same record that serves as
  the once-per-host guard.
- **Consider the inverse** (`WebApp` posture, no cookie scheme declared → antiforgery is dead
  weight), but decide it deliberately — it may be legitimate mid-composition noise.

Emit via config-time `IDeferredLogger`, the same pattern as the
in-memory-coordination-outside-Development notice. Design question to settle: whether
"ambient credential" deserves its own axis on the declaration record someday, or whether
keying on the known cookie scheme name is enough (recommendation: the latter until a second
ambient scheme exists). Deliberately kept out of rung 4 itself — the wave's governing
articulation has no antiforgery concept, and rung 4's contents map to its R1–R10.

### `AddEventCoordination` overload that also selects the backend

**SemVer:** Minor
**Trigger:** the attribute-authority wave, which touches this package anyway for the claim-authority declaration.
**Noted:** 2026-08-16

Turning on cross-replica auth events currently takes two calls in the composition callback:

```csharp
auth.AddEventCoordination()
    .ConfigureCoordination(c => c.UseRedisFromConfiguration(builder));
```

Add an overload taking the same configure delegate, so the common case is one call:

```csharp
auth.AddEventCoordination(c => c.UseRedisFromConfiguration(builder));
```

**Keep `ConfigureCoordination` as a standalone verb — do not merge the two.** They answer
different questions, and only one of them belongs to the authentication track:

- `AddEventCoordination()` decides *whether auth events cross replicas* — an auth-track feature.
- `ConfigureCoordination(...)` decides *which coordination backend the host uses*, and that
  backend serves `IReplayGuard`, `IRequestThrottle`, and `ISignalBroadcaster` as well.
  SignedRequest's replay protection and ApiKey's nonce guard consume it with no auth events
  involved at all.

An application can legitimately need a distributed backend for replay protection while wanting
no cross-replica auth delivery, so folding the backend choice into the auth-event verb would
misstate what owns it. The overload is a convenience for the overlap, not a merge: its
documentation must say plainly that it also selects the shared backend, so an app calling it
does not later wonder why its throttle changed behaviour.

The implementation is a delegation, not a reimplementation — `ConfigureCoordination` lives in
`Cirreum.AuthenticationProvider` (Core), which this package sits above:

```csharp
public static IAuthenticationBuilder AddEventCoordination(
    this IAuthenticationBuilder builder,
    Action<CoordinationBuilder> configure) =>
    builder.ConfigureCoordination(configure).AddEventCoordination();
```

**Pairs with the scope-default de-duplication** filed against `Cirreum.AuthenticationProvider`.
`AddEventCoordination` currently repeats that package's `CoordinationScope` `TryAddSingleton`
block verbatim — same lambda, same error message. Take the shared helper when it lands rather
than leaving a third copy behind.
