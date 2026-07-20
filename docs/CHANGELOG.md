# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [Unreleased]

## [1.2.0] - 2026-07-20

### Added

- Composition-close audience validation: one audience claimed by two different schemes
  now fails `AddAuthentication()` with every collision reported (audience, both scheme
  names, both contributing providers) instead of surfacing as request-time 401s. A
  clean set logs the live audience → scheme routing table at startup via the deferred
  logger, so audience dispatch is visible and diagnosable at boot (ADR-0030/0031).
- The `Cirreum.Ambiguous` rejection Warning now names its cause: the unmapped JWT
  `aud` value when a genuine token matched no registered audience, or the colliding
  scheme names when distinct credential carriers were presented together (ADR-0030).
  The caller-facing response is unchanged — diagnostics go to the server log only.

### Fixed

- **Scheme-aware authentication-boundary classification is restored (ADR-0032).**
  The pre-reset framework registered a primary-scheme boundary resolver during
  authorization composition; the Foundation Reset dropped it (along with every other
  resolver registration), so all user states stamped `AuthenticationBoundary.None`
  and grant providers gating on `Global`/`Tenant` could never pass.
  `AddAuthentication()` now registers `PrimarySchemeAuthenticationBoundaryResolver`
  where it reads `Cirreum:Authentication:PrimaryScheme`: primary scheme → `Global`,
  other authenticated schemes → `Tenant`, unauthenticated → `None` (case-insensitive
  scheme match). `TryAdd` — an application-registered resolver wins.

### Changed

- **`JwtAudienceSchemeSelector` now builds its audience index from the
  `AudienceSchemeRegistration` set** contributed by audience-based registrars,
  aggregated once at construction into an immutable case-insensitive index
  (ADR-0031). This fixes multi-provider audience dispatch: previously each audience
  instance registration created a fresh scheme map and last-wins DI resolution kept
  only the final one, so in any composition with more than one audience instance
  every earlier audience silently 401'd as `Cirreum.Ambiguous`. The umbrella no
  longer registers an audience map service.

## [1.1.1] - 2026-07-19

### Updated

- Updated NuGet packages.

## [1.1.0] - 2026-07-09

### Added

- **Auth-event delivery (ADR-0025).** `AddAuthentication(...)` now registers the default `InProcessAuthenticationEventPublisher` (`TryAdd` — an app-registered publisher wins): synchronous, ordered dispatch — consumer handlers first (each isolated; a throwing handler is logged and the rest still run), transport bridges last, failures surfaced to the caller as an `AggregateException` so an admin command reports partial failure and can safely retry (handlers are idempotent). Dispatch keys on the event's **runtime** type, so publishing through a less-derived binding (e.g. iterating `IAuthenticationEvent` items) still reaches every concrete-typed handler. A single-replica app is complete with zero wiring.
- `auth.AddEventCoordination()` — turns on cross-replica delivery over the `Cirreum.Coordination` broadcast primitive (`ISignalBroadcaster`): a versioned event registry (`AuthenticationEventRegistry`, built on the Kernel's `MessageRegistryBase`/`[MessageVersion]` machinery — resolves the four framework events plus any app-defined public `[MessageVersion]`-tagged `IAuthenticationEvent`; a concrete event type *missing* the attribute is warned about at startup, and the bridge reports it as a permanent configuration error rather than implying a retry could succeed), an open-generic outbound transport bridge, and an inbound subscriber that dispatches wire events to local handlers *excluding* bridges — preventing a publish-receive loop on the dispatch flow, with an ambient inbound-dispatch scope as the second line of defense against wire re-entry from handlers that publish (handlers must not publish, directly or deferred to a detached flow). The subscription opens in the `ISystemInitializer` phase — before any hosted service, including scheme boot hydrators — closing the startup race by construction. Delivery is at-most-once; boot hydration remains the durable backstop. The wire format is a minimal `{identifier, version, payload}` envelope on the reserved `cirreum:_auth-events` channel; hostile or unknown wire input — malformed JSON, missing envelope members, unknown identities, payloads failing to deserialize with *any* exception type — is logged and dropped, never faulting the subscription.
- `AddEventCoordination()` defaults the `CoordinationScope` to the canonical `{applicationName}:{environmentName}` (from `IDomainEnvironment`, with an actionable error when it's absent) when none is registered — an explicit `ConfigureCoordination(c => c.WithScope(...))` wins in any order.
- Direct `Cirreum.Coordination.Redis` reference (consistent with the umbrella's reference-everything/opt-in-via-code pattern), so `auth.ConfigureCoordination(c => c.UseRedis())` needs no extra package.
- Test suite grown 10 → 62: the publisher's ordering/isolation/failure-surfacing contract incl. runtime-type dispatch, both wire legs (envelope round-trip, bridge exclusion, hostile input incl. payload-less envelopes, self-echo semantics, the wire-re-entry guard, the unversioned-event permanent error), the registry's two-way resolution, scope defaulting/override, plus first coverage for the scheme-dispatch pipeline (`SchemeResolver`, conflict sentinel, anonymous fallback, handlers) — rewritten from four pre-reset test files recovered from `Cirreum.Runtime.AuthenticationProvider`, where they had never compiled. An adversarial three-lens review (security/loop, concurrency/startup, DI-composition) refuted the headline risks against code and drove the runtime-type-dispatch, hostile-envelope, and permanent-config-error hardening above.

### Changed

- **`AuthenticationEventRegistry` slimmed to the Kernel base.** It no longer hand-rolls a second assembly scan, its own identity map, or a bespoke `TryResolveType(identifier, version, out Type)` — the Kernel's `MessageRegistryBase` now captures type-by-identity in its single scan and exposes a nullable `ResolveType(identifier, version)`, and it emits the missing-`[MessageVersion]` warning as family policy. The registry is now just the base plus a thin `InitializeAsync()`; the inbound receiver resolves through the base `ResolveType`. No behavioral change.
- **Internal event-delivery types renamed** (no public API): `AuthenticationEventTransportBridge<T>` → `AuthenticationEventSender<T>` (the outbound leg) and `AuthenticationEventInboundSubscriber` → `AuthenticationEventReceiver` (the inbound leg). The published Kernel marker interface `IAuthenticationEventTransportBridge` is unchanged — it names a capability, not the role. Apps are unaffected: publishing via `IAuthenticationEventPublisher` and handling via `IAuthenticationEventHandler<TEvent>` are the only surfaces they touch.

### Fixed

- The in-memory-coordination-outside-Development advisory named the old `auth.AddCoordination(...)` verb; it now names `auth.ConfigureCoordination(...)`.

## [1.0.1] - 2026-07-04

### Updated

- Updated NuGet packages.

## [1.0.0] - 2026-07-03

### Added

- **Initial release.** The app-facing umbrella package and entry point for the Authentication pillar.
- `builder.AddAuthentication(configure?, authentication?)` extension on `IHostApplicationBuilder` — auto-registers the appsettings-bound scheme providers (Oidc, Entra, External), lets the app compose providers + dynamic-resolver registrations + ASP.NET-level options in the callback, and initializes the runtime. **ApiKey, SignedRequest, and SessionTicket are not auto-registered** — the app composes them via `auth.AddApiKey(...)` / `auth.AddSignedRequest<T>(...)` / `auth.AddSessionTicket(...)`.
- `CirreumAuthenticationBuilder` — concrete `IAuthenticationBuilder` (defined in `Cirreum.AuthenticationProvider`); carries the host `IConfiguration` so composition verbs can bind their provider sections. The scheme packages contribute extension methods (`AddApiKey(...)`, `AddSignedRequest<T>(...)`, `AddExternalTenantResolver<T>`) on this interface.
- Transitively references all six `Cirreum.Authentication.*` scheme packages (ApiKey, SignedRequest, SessionTicket, Oidc, Entra, External). Apps install this single package to get the full Authentication track; only the schemes you turn on — via an appsettings section (Oidc/Entra/External) or a composition verb (ApiKey/SignedRequest/SessionTicket) — activate.
