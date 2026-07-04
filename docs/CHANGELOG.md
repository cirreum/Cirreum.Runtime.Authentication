# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [Unreleased]

### Updated

- Updated NuGet packages.

## [1.0.0] - 2026-07-03

### Added

- **Initial release.** The app-facing umbrella package and entry point for the Authentication pillar.
- `builder.AddAuthentication(configure?, authentication?)` extension on `IHostApplicationBuilder` — auto-registers the appsettings-bound scheme providers (Oidc, Entra, External), lets the app compose providers + dynamic-resolver registrations + ASP.NET-level options in the callback, and initializes the runtime. **ApiKey, SignedRequest, and SessionTicket are not auto-registered** — the app composes them via `auth.AddApiKey(...)` / `auth.AddSignedRequest<T>(...)` / `auth.AddSessionTicket(...)`.
- `CirreumAuthenticationBuilder` — concrete `IAuthenticationBuilder` (defined in `Cirreum.AuthenticationProvider`); carries the host `IConfiguration` so composition verbs can bind their provider sections. The scheme packages contribute extension methods (`AddApiKey(...)`, `AddSignedRequest<T>(...)`, `AddExternalTenantResolver<T>`) on this interface.
- Transitively references all six `Cirreum.Authentication.*` scheme packages (ApiKey, SignedRequest, SessionTicket, Oidc, Entra, External). Apps install this single package to get the full Authentication track; only the schemes you turn on — via an appsettings section (Oidc/Entra/External) or a composition verb (ApiKey/SignedRequest/SessionTicket) — activate.
