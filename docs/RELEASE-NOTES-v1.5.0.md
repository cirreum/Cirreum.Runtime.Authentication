# Cirreum.Runtime.Authentication 1.5.0 — Host work is operator work

## Why this release exists

The primary-scheme boundary resolver answers one question: is this caller operator staff
(`Global`) or a customer-tenant caller (`Tenant`)? It did so by comparing the scheme to
`Cirreum:Authentication:PrimaryScheme` and treating every other authenticated scheme as
`Tenant`.

`Cirreum.Contracts` 6.2.0 introduced host invocations, which authenticate on the
`Cirreum.Host` scheme. Left alone, the resolver would have classified the operator's own
application, running a nightly job or a received message, as a customer tenant, and every
tenant-scoped authorizer would have treated it as one.

## What's new

`PrimarySchemeAuthenticationBoundaryResolver` resolves `Cirreum.Host` to `Global` alongside
the primary scheme. The host is the operator's application, and operator is what `Global`
means.

A continuation that carries a subject's origin scheme still resolves for that scheme:
user-state assembly hands the resolver the effective scheme, which is the origin when one is
stamped, so a tenant user's work continued after their request stays `Tenant`.

Unauthenticated callers still resolve `None`, on every scheme.

## Compatibility

Additive. Hosts that do not begin host invocations see no change. The package now references
`Cirreum.Contracts` directly for the scheme constant.

## See also

- `docs/CHANGELOG.md` — `[1.5.0]`
- `Cirreum.Services.Server` 1.7.0 release notes — the host principal
