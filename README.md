# Cirreum Runtime Authentication

[![NuGet Version](https://img.shields.io/nuget/v/Cirreum.Runtime.Authentication.svg?style=flat-square&labelColor=1F1F1F&color=003D8F)](https://www.nuget.org/packages/Cirreum.Runtime.Authentication/)
[![NuGet Downloads](https://img.shields.io/nuget/dt/Cirreum.Runtime.Authentication.svg?style=flat-square&labelColor=1F1F1F&color=003D8F)](https://www.nuget.org/packages/Cirreum.Runtime.Authentication/)
[![GitHub Release](https://img.shields.io/github/v/release/cirreum/Cirreum.Runtime.Authentication?style=flat-square&labelColor=1F1F1F&color=FF3B2E)](https://github.com/cirreum/Cirreum.Runtime.Authentication/releases)
[![License](https://img.shields.io/badge/license-MIT-F2F2F2?style=flat-square&labelColor=1F1F1F)](https://github.com/cirreum/Cirreum.Runtime.Authentication/blob/main/LICENSE)
[![.NET](https://img.shields.io/badge/.NET-10.0-003D8F?style=flat-square&labelColor=1F1F1F)](https://dotnet.microsoft.com/)

**App-facing umbrella for the Cirreum Authentication track. Install this one package to wire up authentication behind a single `AddAuthentication()` call — every framework-shipped scheme flows in transitively, and only the ones you configure activate.**

## Overview

`Cirreum.Runtime.Authentication` is the package your application installs to turn on authentication. A single `builder.AddAuthentication(...)` call composes the whole track: the framework-shipped schemes, a dynamic forward scheme that picks the right one per request, the audience-routed claims transformer that produces your Cirreum `IApplicationUser`, and a boot-time validator that fails fast on misconfiguration.

Schemes come in two flavours:

- **Configuration-declared** — `Oidc`, `Entra`, and `External` activate automatically from their `Cirreum:Authentication:Providers:*` config sections. No code call is needed; presence of the section is the opt-in.
- **Code-composed** — `ApiKey`, `SignedRequest`, and `SessionTicket` are turned on with a verb inside the `AddAuthentication` callback.

Every scheme's registration bails early when it isn't configured, so installing this package doesn't activate anything you haven't asked for.

## Installation

```
dotnet add package Cirreum.Runtime.Authentication
```

## Usage

```csharp
using Cirreum.Runtime;
using Microsoft.Extensions.Hosting;

var builder = DomainApplication.CreateBuilder(args);

builder.AddAuthentication(auth => auth
    // Code-composed schemes:
    .AddApiKey(options => { /* static clients and/or .AddResolver<T>() */ })
    .AddSignedRequest<MyClientResolver>()
    .AddSessionTicket());
    // Oidc / Entra / External activate automatically from their
    // Cirreum:Authentication:Providers:* configuration sections.

await using var app = builder.Build();

app.UseDefaultMiddleware();   // includes UseAuthentication() + UseAuthorization()

app.MapApiEndpoints("/api/v1", api => { /* ... */ });

await app.RunAsync();
```

`AddAuthentication()` must run on a Cirreum host (`DomainApplication.CreateBuilder`), which declares the host's runtime type — the audience-based providers branch on whether the host is a Web API or a Web App. It is idempotent: call it once and reuse the returned `CirreumAuthenticationBuilder` for any further composition.

### Scheme reference

| Scheme | How to enable |
|---|---|
| **Oidc** | config section `Cirreum:Authentication:Providers:Oidc` |
| **Entra** | config section `Cirreum:Authentication:Providers:Entra` |
| **External** | config section `Cirreum:Authentication:Providers:External` (+ `auth.AddExternalTenantResolver<T>()` for the tenant resolver) |
| **ApiKey** | `auth.AddApiKey(...)` (also reads its config section) |
| **SignedRequest** | `auth.AddSignedRequest<TClientResolver>(...)` |
| **SessionTicket** | `auth.AddSessionTicket(bearerPrefix?)` |

See each scheme's package for its configuration shape and security model — e.g. [`Cirreum.Authentication.ApiKey`](https://www.nuget.org/packages/Cirreum.Authentication.ApiKey/), [`Cirreum.Authentication.Oidc`](https://www.nuget.org/packages/Cirreum.Authentication.Oidc/), [`Cirreum.Authentication.SignedRequest`](https://www.nuget.org/packages/Cirreum.Authentication.SignedRequest/), [`Cirreum.Authentication.SessionTicket`](https://www.nuget.org/packages/Cirreum.Authentication.SessionTicket/).

## How requests are dispatched

`AddAuthentication` makes a **dynamic forward scheme** the default. On each request a chain of selectors decides which concrete scheme handles it:

- a **conflict sentinel** runs first and fails the request closed (401) when credentials for two different scheme categories are present;
- an **audience selector** routes Bearer JWTs to the matching configured provider;
- an **anonymous fallback** claims anything left over and returns no result, so `[AllowAnonymous]` endpoints work.

At startup a Bearer-prefix validator ensures opaque-Bearer schemes (ApiKey, SessionTicket, …) declare unique token prefixes, failing fast on a collision rather than mis-routing at runtime.

## Auth events — revocation and termination delivery

Admin actions like "revoke this API key", "disable this user", or "force sign-out" publish an event through `IAuthenticationEventPublisher`; framework handlers consume it (the ApiKey denylist, the grant-cache invalidator, the server's connection terminator). The default in-process publisher is registered automatically — a single-replica app needs no wiring at all.

For multi-replica deployments, turn on cross-replica delivery inside the same callback:

```csharp
builder.AddAuthentication(auth => auth
    .AddApiKey(...)
    .AddEventCoordination()                          // cross-replica auth-event delivery
    .ConfigureCoordination(c => c.UseRedis()));      // Redis-backed coordination (order-independent)
```

`AddEventCoordination()` rides the coordination broadcast primitive: events published on one replica are applied locally first, then fanned out to every other replica. Delivery is at-most-once — a replica that misses an event while disconnected heals at its next boot hydration, which remains the durable backstop.

Coordination state (and this channel) is namespaced per application and environment automatically (`{app}:{env}`); override with `ConfigureCoordination(c => c.WithScope(...))`. Two operational notes: whoever can publish on the coordination backend's connection can forge auth events — give coordination its own connection (`c.UseRedis("connectionKey")`) when the shared one has a broader writer set; and on Azure Managed Redis, pub/sub does **not** cross active geo-replication regions — run region-local coordination backends when active-active, and let cross-region convergence ride authoritative state. Channels under the `cirreum:` prefix are framework-reserved.

To publish your own events, inject `IAuthenticationEventPublisher` and publish one of the `Cirreum.Authentication.Events` records (or an app-defined `[MessageVersion]`-tagged `IAuthenticationEvent`). Handlers implement `IAuthenticationEventHandler<TEvent>` and **must be idempotent** — the receiver does not de-duplicate. Two mechanics make that a hard requirement, not a nicety: delivery is at-most-once, and boot hydration re-applies the entire revoked-credential set on every restart, so a handler will see the same effect more than once. The framework's own handlers (the ApiKey denylist, the grant-cache invalidator, the connection terminator) satisfy this by construction — a denylist add or a cache eviction is naturally a no-op the second time — so for the built-in revocation flow you write nothing. Hold your own handlers to the same discipline: treat an auth event as a **state fact to converge on** ("credential X is revoked"), not a command to run exactly once.

## What this package contains

- **`builder.AddAuthentication(configure?, authentication?)`** — the one entry point; composes the schemes, selectors, handlers, the dynamic forward scheme, the claims transformer, and the default auth-event publisher, then runs the boot-time validator. Returns a `CirreumAuthenticationBuilder`.
- The framework-shipped **selectors** (conflict sentinel, audience, anonymous) and **handlers** (anonymous, ambiguous) and the **`CirreumAuthenticationBuilder`** the scheme packages extend (`AddApiKey`, `AddSignedRequest<T>`, `AddSessionTicket`, `AddExternalTenantResolver<T>`, `AddApplicationUserResolver<T>`).
- The **auth-event delivery machinery** — the in-process `IAuthenticationEventPublisher` and, behind `auth.AddEventCoordination()`, the versioned event registry, the outbound transport bridge, and the inbound subscriber over the coordination broadcast channel.

Composition is driven by `Cirreum.Runtime.AuthenticationProvider`, which flows in transitively.

## Dependencies

- **Cirreum.Runtime.AuthenticationProvider** — the runtime composition driver
- All six `Cirreum.Authentication.*` scheme packages (ApiKey, SignedRequest, SessionTicket, Oidc, Entra, External) — transitive
- **Microsoft.AspNetCore.App**

## Versioning

Follows [Semantic Versioning](https://semver.org/).

## License

MIT — see [LICENSE](LICENSE).

---

**Cirreum Foundation Framework**  
*Layered simplicity for modern .NET*
