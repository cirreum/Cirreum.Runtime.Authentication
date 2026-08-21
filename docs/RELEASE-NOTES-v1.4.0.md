# Cirreum.Runtime.Authentication 1.4.0 — the declaration becomes the answer

## Why this release exists

Across the last several releases the framework grew a complete set of readers for a question it
had never actually asked: *who owns this user's attributes?* User-state assembly resolves a
subject kind from it. The role-claims transformer branches on it. The app-name fallback gates on
it. Every one of them has been shipping dormant, resolving `Undeclared` and falling back to the
behaviour that predates the model — because nothing composed the declarations into a map.

This release composes it. It is the switch.

## What's new

**`AddAuthentication()` publishes an `ISchemeClaimAuthorityMap`.** Built once from every
`SchemeClaimAuthorityRegistration` the providers contributed during composition, keyed
ordinally — the same way ASP.NET Core keys its own scheme registry, so a declaration can never
be resolved for a scheme that merely differs by case. From this release, the readers downstream
answer from what the application declared:

| Declaration | What changes |
|---|---|
| `SubjectKind.Machine` | the app-name fallback may name the caller; the role transformer skips the store |
| `SubjectKind.Human` | a thin token is never named after the calling application |
| `Roles: ApplicationStore` | roles read per request, so revocation is immediate |
| `Roles: IdentityProvider` | the token's roles stand |
| Undeclared | exactly today's behaviour |

**The builder implements the funnel.** `AddScheme<TOptions, THandler>` registers a scheme with
ASP.NET and declares it in one call. `DeclareScheme` declares a scheme registered through
another extension — `AddJwtBearer`, `AddOpenIdConnect`, `AddCookie`:

```csharp
builder.AddAuthentication(auth => auth
    .DeclareScheme("descope", SubjectKind.Human, roles: ClaimAuthority.ApplicationStore));
```

**Composition-close validation.** A scheme declared two different ways fails the host, with
every conflict named. Identical duplicates collapse silently — a platform-default scheme is
commonly declared by more than one provider, and two providers stating the same thing is
agreement, not conflict. The clean set is logged at startup beside the audience routing table,
so the live declaration table is visible rather than latent.

**The framework declares its own schemes.** Anonymous, Ambiguous, and the dynamic forward
scheme are declared `SubjectKind.Unknown` — none authenticates a subject; the dynamic scheme
forwards to whichever scheme does, and that scheme's declaration governs. Declared rather than
left undeclared so they appear in the table an operator reads.

## Also in this release

**`AddEventCoordination(configure)`** — an overload that turns on cross-replica auth-event
delivery and selects the coordination backend in one call:

```csharp
auth.AddEventCoordination(c => c.UseRedisFromConfiguration(builder));
```

`ConfigureCoordination` stays a standalone verb rather than being folded away. It selects the
application's *shared* coordination backend, which also serves replay protection, request
throttling, and signal broadcast — an application can legitimately need a distributed backend
for those while wanting no cross-replica auth delivery at all. The overload is a convenience
for the overlap, not a merge.

## Compatibility

- **A host that declares nothing keeps working.** Undeclared is legal and resolves to the
  pre-declaration behaviour on every reader. No application is required to edit configuration.
- **A host whose providers declare — which is every host composing framework-shipped schemes —
  gets the declared behaviour.** The changes worth knowing, all of them the point of the work:
  a human subject on a thin token is no longer named after the calling application; a
  store-owns scheme reads roles per request rather than trusting a token that already carried
  them; and a machine subject's roles come from its credential record rather than the
  application-user store.
- Declaring one scheme two different ways now fails composition rather than resolving
  arbitrarily.

## See also

- `Cirreum.Kernel 2.1.0`/`2.2.0` — `SubjectKind`, `ClaimAuthority`, `ISchemeClaimAuthorityMap`,
  and the canonicalization posture.
- `Cirreum.Runtime.AuthenticationProvider 2.1.0` — the role-claims transformer that reads these
  declarations.
- `Cirreum.Services.Server 1.5.0` — subject-kind resolution and effective-scheme dispatch in
  user-state assembly.
- `Cirreum.Contracts 4.4.0` — `OriginScheme` / `EffectiveScheme`, which decide *which* scheme's
  declaration governs a given invocation.
