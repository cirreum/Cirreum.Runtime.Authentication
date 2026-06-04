# Cirreum.Runtime.Authentication 1.0.0 — One package, one `AddAuthentication()` call

`Cirreum.Runtime.Authentication` is the app-facing umbrella for the Authentication pillar. Install this one package, call `AddAuthentication(...)` once, and the whole track wires up — the framework-shipped schemes, a dynamic forward scheme that picks the right one per request, the audience-routed claims transformer that produces your Cirreum `IApplicationUser`, and a boot-time validator that fails fast on misconfiguration. Only the schemes you configure activate.

**Strictly additive — initial release.** A new package in the Cirreum 1.0 Foundation Reset; no predecessor. Targets .NET 10.0.

---

## Why this release exists

Wiring authentication by hand means composing six scheme packages, a per-request dispatch chain, a claims transformer, and a startup validator — and getting the order and the fail-fast behavior right. The umbrella does it behind a single call, so an app turns on exactly the schemes it wants and nothing it doesn't.

---

## What's new

### `builder.AddAuthentication(...)` — the one entry point

```csharp
var builder = DomainApplication.CreateBuilder(args);

builder.AddAuthentication(auth => auth
    .AddApiKey(options => { /* static clients and/or .AddResolver<T>() */ })
    .AddSignedRequest<MyClientResolver>()
    .AddSessionTicket());
    // Oidc / Entra / External activate automatically from their
    // Cirreum:Authentication:Providers:* configuration sections.

await using var app = builder.Build();
app.UseDefaultMiddleware();   // includes UseAuthentication() + UseAuthorization()
```

One call composes the schemes, selectors, handlers, the dynamic forward scheme, and the claims transformer, then runs the boot-time validator. It must run on a Cirreum host (`DomainApplication.CreateBuilder`) — the audience providers branch on Web API vs Web App — and it's idempotent, returning a `CirreumAuthenticationBuilder` you can reuse.

### Two ways a scheme turns on

- **Configuration-declared** — `Oidc`, `Entra`, `External` activate from their `Cirreum:Authentication:Providers:*` sections; presence of the section is the opt-in (no code call).
- **Code-composed** — `ApiKey`, `SignedRequest`, `SessionTicket` are enabled with a verb in the callback (`AddApiKey`, `AddSignedRequest<T>`, `AddSessionTicket`).

Every scheme's registration bails early when it isn't configured, so installing the package activates nothing you haven't asked for.

### Per-request dispatch + fail-fast validation

`AddAuthentication` makes a **dynamic forward scheme** the default. Per request, a chain of selectors decides the handler: a **conflict sentinel** runs first and fails closed (401) when credentials for two different scheme categories are present; an **audience selector** routes Bearer JWTs to the matching configured provider; an **anonymous fallback** claims the rest so `[AllowAnonymous]` works. At startup, a **Bearer-prefix validator** ensures opaque-Bearer schemes (ApiKey, SessionTicket, …) declare unique token prefixes — failing fast on a collision rather than mis-routing at runtime.

### `CirreumAuthenticationBuilder`

The builder the scheme packages extend — `AddApiKey`, `AddSignedRequest<T>`, `AddSessionTicket`, `AddExternalTenantResolver<T>`, `AddApplicationUserResolver<T>` — carrying the host `IConfiguration` so each verb can bind its own provider section.

---

## How it pairs with the rest of the Authentication pillar

This umbrella transitively references all six `Cirreum.Authentication.*` scheme packages and the `Cirreum.Runtime.AuthenticationProvider` composition driver. Apps install **only** this package; the schemes and the driver flow in, and each scheme's own package documents its configuration and security model.

---

## Compatibility

- **Additive.** Initial release.
- **.NET 10.0.** Requires a Cirreum host (`DomainApplication.CreateBuilder`).
- Transitively references the six scheme packages (ApiKey, SignedRequest, SessionTicket, Oidc, Entra, External), `Cirreum.Runtime.AuthenticationProvider`, and the ASP.NET shared framework.

---

## See also

- `CHANGELOG.md` — condensed change list for `1.0.0`.
- `README.md` — full usage, scheme reference, and dispatch model.
