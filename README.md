# Cirreum Runtime Authentication

[![NuGet Version](https://img.shields.io/nuget/v/Cirreum.Runtime.Authentication.svg?style=flat-square&labelColor=1F1F1F&color=003D8F)](https://www.nuget.org/packages/Cirreum.Runtime.Authentication/)
[![NuGet Downloads](https://img.shields.io/nuget/dt/Cirreum.Runtime.Authentication.svg?style=flat-square&labelColor=1F1F1F&color=003D8F)](https://www.nuget.org/packages/Cirreum.Runtime.Authentication/)
[![GitHub Release](https://img.shields.io/github/v/release/cirreum/Cirreum.Runtime.Authentication?style=flat-square&labelColor=1F1F1F&color=FF3B2E)](https://github.com/cirreum/Cirreum.Runtime.Authentication/releases)
[![License](https://img.shields.io/github/license/cirreum/Cirreum.Runtime.Authentication?style=flat-square&labelColor=1F1F1F&color=F2F2F2)](https://github.com/cirreum/Cirreum.Runtime.Authentication/blob/main/LICENSE)
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

## What this package contains

- **`builder.AddAuthentication(configure?, authentication?)`** — the one entry point; composes the schemes, selectors, handlers, the dynamic forward scheme, and the claims transformer, then runs the boot-time validator. Returns a `CirreumAuthenticationBuilder`.
- The framework-shipped **selectors** (conflict sentinel, audience, anonymous) and **handlers** (anonymous, ambiguous) and the **`CirreumAuthenticationBuilder`** the scheme packages extend (`AddApiKey`, `AddSignedRequest<T>`, `AddSessionTicket`, `AddExternalTenantResolver<T>`, `AddApplicationUserResolver<T>`).

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
