# Cirreum.Runtime.Authentication 1.2.0 — Multi-provider audience dispatch, fixed and observable

In any composition with more than one audience-based scheme instance, only the
last-registered instance's audience actually routed — every other bearer token was
rejected fail-closed as `Cirreum.Ambiguous`, with a log line that named no cause. This
release fixes the dispatch defect at its root, validates the audience set at
composition close, and makes every no-match rejection name exactly what didn't match.

Requires `Cirreum.AuthenticationProvider` 1.3.0 (coordinated upgrade).

---

## Why this release exists

`JwtAudienceSchemeSelector` routed by looking up the token's `aud` claim in a shared
audience map service. The map's delivery mechanism was broken under this umbrella's
own composition: each audience instance registration created a fresh map, DI's
last-wins resolution kept only the final one, and which instance survived depended on
configuration key ordering. An app with a Descope OIDC instance and two Entra
instances had exactly one working audience — the alphabetically last — and two that
401'd on every request.

The rejection was also undiagnosable from logs. The Ambiguous handler's warning
covered three distinct causes (unmapped audience, empty routing table, conflicting
credential carriers) with one generic sentence, so a misconfiguration cost a debugging
session instead of a log read.

## What's new

**The selector owns its index.** `JwtAudienceSchemeSelector` now takes the
`AudienceSchemeRegistration` set contributed by every audience registrar and builds an
immutable, case-insensitive index once, at construction. There is no map service, no
descriptor scanning, and no ordering sensitivity — every registered audience routes,
full stop.

**Composition-close validation.** `AddAuthentication()` now validates the complete
audience set after provider composition: one audience claimed by two different schemes
fails the host immediately, reporting **every** collision with the contributing
provider and scheme on each side. A clean set logs the live routing table through the
deferred startup log:

```text
Audience routing: 'P3Cm…' → descope (Oidc), '2640…' → entraWorkforce (Entra), '50ec…' → entraExternal (Entra).
```

One line at boot now answers the question that used to require a debugger: *what will
this host actually route?*

**Self-explanatory rejections.** The `Cirreum.Ambiguous` warning names its cause. A
genuine JWT whose audience matches nothing logs the offending `aud` value; conflicting
credential carriers log the colliding scheme names. The selectors stash the diagnostic
on `HttpContext.Items` and the handler logs exactly once per rejected request — probe
passes by the conflict sentinel stay silent, and the caller-facing 401 remains
deliberately generic.

## Compatibility

- **Coordinated upgrade:** requires `Cirreum.AuthenticationProvider` 1.3.0 (this
  release compiles against the registration record and no longer registers the
  removed audience map service).
- **A latent misconfiguration now fails at startup.** Two provider instances claiming
  the same audience for different schemes previously went undetected (the fragmented
  maps could never see across providers) and manifested as one instance silently
  winning. That configuration now stops the host at composition with both claimants
  named. This is the defect surfacing earlier, not new strictness for correct apps.
- Dispatch behavior for correctly-configured single-audience apps is unchanged;
  multi-audience apps regain the routing they were always configured for.

## See also

- `Cirreum.AuthenticationProvider` 1.3.0 — `AudienceSchemeRegistration` and the
  container-owned data model
- `Cirreum.Runtime.IdentityProvider` 1.1.0 — the companion diagnostic for the
  identity track's silent no-match failure mode
