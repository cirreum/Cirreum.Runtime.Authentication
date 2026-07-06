# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [Unreleased]

### Added

- **Auth-event delivery (ADR-0025).** `AddAuthentication(...)` now registers the default `InProcessAuthenticationEventPublisher` (`TryAdd` — an app-registered publisher wins): synchronous, ordered dispatch — consumer handlers first (each isolated; a throwing handler is logged and the rest still run), transport bridges last, failures surfaced to the caller as an `AggregateException` so an admin command reports partial failure and can safely retry (handlers are idempotent). A single-replica app is complete with zero wiring.
- `auth.AddEventCoordination()` — turns on cross-replica delivery over the `Cirreum.Coordination` broadcast primitive (`ISignalBroadcaster`): a versioned event registry (`AuthenticationEventRegistry`, built on the Kernel's `MessageRegistryBase`/`[MessageVersion]` machinery — resolves the four framework events plus any app-defined public `[MessageVersion]`-tagged `IAuthenticationEvent`), an open-generic outbound transport bridge, and an inbound subscriber that dispatches wire events to local handlers *excluding* bridges (a publish-receive loop is structurally impossible; an ambient inbound-dispatch scope additionally bars wire re-entry from handlers that publish). The subscription opens in the `ISystemInitializer` phase — before any hosted service, including scheme boot hydrators — closing the startup race by construction. Delivery is at-most-once; boot hydration remains the durable backstop. The wire format is a minimal `{identifier, version, payload}` envelope on the reserved `cirreum:_auth-events` channel; hostile or unknown wire input is logged and dropped, never faulting the subscription.
- `AddEventCoordination()` defaults the `CoordinationScope` to the canonical `{applicationName}:{environmentName}` (from `IDomainEnvironment`) when none is registered — an explicit `ConfigureCoordination(c => c.WithScope(...))` wins in any order.
- Direct `Cirreum.Coordination.Redis` reference (consistent with the umbrella's reference-everything/opt-in-via-code pattern), so `auth.ConfigureCoordination(c => c.UseRedis())` needs no extra package.
- Test suite grown 10 → 59: the publisher's ordering/isolation/failure-surfacing contract, both wire legs (envelope round-trip, bridge exclusion, hostile input, self-echo semantics, the wire-re-entry guard), the registry's two-way resolution, scope defaulting/override, plus first coverage for the scheme-dispatch pipeline (`SchemeResolver`, conflict sentinel, anonymous fallback, handlers) — rewritten from four pre-reset test files recovered from `Cirreum.Runtime.AuthenticationProvider`, where they had never compiled.

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
