# Cirreum.Runtime.Authentication 1.3.0 — which scheme handled the request

## Why this release exists

Cirreum could not tell you which authentication scheme a request resolved to.

That gap got sharper when `IdentityProviderType` was removed in the Kernel 2.0.0 wave. Before, an
application could ask a `UserProfile` which provider it came from. Now the **authenticated scheme is
the single authoritative answer** to "which identity provider handled this request" — and it was
recorded only on an activity, visible in a trace you already knew to open. There was no way to see
the distribution across a multi-IdP deployment, and no way to see how often selection matched
nothing at all.

## What's new

`SchemeResolver.Resolve` now records **`cirreum.authn.selections`**:

| Tag | Value |
|---|---|
| `cirreum.authn.scheme` | the scheme the request resolved to |
| `cirreum.authn.selector` | the `ISchemeSelector` type that claimed it — or `none` |

**Nothing to configure.** `AddCirreum()` already registers the `Cirreum.Authentication` meter, so
the counter appears wherever the track's existing instruments do.

### `selector = none` is the one to alert on

It means **no selector claimed the request** and the resolver fell through to its default. That is
not the same as a genuine Anonymous selection — where the Anonymous fallback selector claimed and
named itself — and until now the two were indistinguishable. A steady `none` rate says the selector
set is misconfigured, most likely that the Anonymous fallback was never registered.

### Why the resolver, and not each selector

`SchemeResolver.Resolve` is the single site every `ISchemeSelector` is dispatched through. One call
there covers the whole registered set — the framework-shipped selectors and anything an application
registers — so adding a scheme never leaves a hole in the distribution, and nobody has to remember
to instrument a new selector.

It also kept the six Infrastructure scheme packages untouched, which mattered: they had already
shipped in this wave.

### One thing it does not see

Routes wired to an explicit scheme bypass the dynamic forward selector entirely, so they never reach
`Resolve` and never record a selection. The claims transformer still stamps
`AuthenticationContextKeys.AuthenticatedScheme` defensively for those routes, so they remain visible
in traces — but they will not appear in this counter. If your selection totals run below your
request totals, explicitly-wired routes are the likely reason rather than dropped telemetry.

## How it pairs with Cirreum.Runtime.AuthenticationProvider 2.0.0

That release rebuilt the authentication track's telemetry — renaming
`AuthenticationProviderDiagnostics` to `AuthenticationTelemetry`, adding a transformation-duration
histogram, and giving the transformation counter `scheme` and `resolver` dimensions. It also
published `RecordSchemeSelection`, the entry point this release calls.

Together they answer the four questions the track could not: which scheme was selected, how often
selection matched nothing, how often a scheme's `IApplicationUserResolver` failed or found no user,
and how long transformation took.

## Compatibility

**Not breaking.** This package's public surface is unchanged — `AddAuthentication()`,
`CirreumAuthenticationBuilder`, the scheme composition verbs, and `SchemeResolver.Resolve`'s
signature and return value are all as before. `Resolve` gains one counter increment; the scheme it
picks and the stamp it writes are identical.

Every Cirreum dependency re-pins onto the released Kernel 2.0.0 foundation, and **those majors are
where a break would come from** — notably `Cirreum.Kernel` 2.0.0 (`IdentityProviderType` removed,
`INotification` → `IDomainEvent`, `DomainContext.CurrentActivityKind` → `EntryPointActivityKind`)
and `Cirreum.Runtime.AuthenticationProvider` 2.0.0. Take their migration guides, not this one.

## See also

- [`CHANGELOG.md`](CHANGELOG.md)
