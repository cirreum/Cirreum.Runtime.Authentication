# Cirreum.Runtime.Authentication 1.1.0 — Live auth-event delivery

## Why this release exists

Until now, the auth-event contracts in `Cirreum.Kernel` (`IAuthenticationEvent`, `IAuthenticationEventPublisher`, the four framework event records) had handlers but no delivery path: an admin action like "revoke this API key" or "force sign-out" had no way to reach a running replica. Revocation was correct **at startup** (boot hydration + the per-request fail-closed consult) but a credential revoked while a replica was running stayed usable there until that replica restarted.

This release ships the missing live-delivery leg. Together with the already-released consumers — the ApiKey denylist handler, the grant-cache invalidator in `Cirreum.Domain`, and the connection terminator in `Cirreum.Services.Server` — publishing one event now takes effect immediately, on every replica.

## What's new

**The default publisher, registered automatically.** `AddAuthentication(...)` now registers `InProcessAuthenticationEventPublisher` (`TryAdd` — your own registration wins). Dispatch is synchronous and ordered: consumer handlers first, each isolated (a throwing handler is logged and the rest still run), transport bridges last — so an event never ships with unapplied local effects. Failures surface to the caller as an `AggregateException`; handlers are idempotent, so republishing is the safe retry. A single-replica app is complete with zero wiring:

```csharp
public sealed class RevokeApiKeyHandler(IAuthenticationEventPublisher events) {
    public async Task<Result> HandleAsync(RevokeApiKey command, CancellationToken ct) {
        // ...revoke in the store (the durable, authoritative act)...
        await events.PublishAsync(new CredentialRevoked(command.KeyId, command.Subject, DateTimeOffset.UtcNow) {
            CredentialType = "apikey",
            ExpiresAt = command.KeyExpiry,
        }, ct);
        return Result.Success();
    }
}
```

**Cross-replica delivery: `auth.AddEventCoordination()`.** Rides the `Cirreum.Coordination` broadcast primitive (`ISignalBroadcaster`) — Redis pub/sub in production, the safe in-process default otherwise:

```csharp
builder.AddAuthentication(auth => auth
    .AddApiKey(...)
    .AddEventCoordination()                          // cross-replica auth-event delivery
    .ConfigureCoordination(c => c.UseRedis()));      // order-independent
```

Behind the verb: a versioned event registry (Kernel `[MessageVersion]` machinery — the four framework events plus any public app-defined `IAuthenticationEvent`), an outbound **sender**, and an inbound **receiver** that dispatches wire events to local handlers *except the senders themselves* — a publish-receive loop is structurally impossible, and an ambient inbound-dispatch scope additionally bars wire re-entry from handlers that publish. The subscription opens in the `ISystemInitializer` phase, before any boot hydrator, closing the startup race by construction.

**Scoped by default.** Coordination state — including this channel — is namespaced to `{applicationName}:{environmentName}` automatically (both here and via `ConfigureCoordination` in `Cirreum.AuthenticationProvider 1.2.0`); an explicit `WithScope(...)` always wins.

## Delivery semantics

At-most-once, unbuffered — a replica disconnected from the backend misses events published in that window, permanently. This is deliberate: boot hydration + the per-request fail-closed consult remain the durable correctness path; this channel is the low-latency leg. Two operational caveats: whoever can publish on the coordination connection can forge auth events (isolate it via `UseRedis("connectionKey")` when its writer set is broader than the app), and on Azure Managed Redis pub/sub does **not** cross active geo-replication regions — run region-local backends when active-active.

## Compatibility

Additive minor. Nothing activates unless you call `AddEventCoordination()`; without it, behavior is identical to 1.0.x plus the (previously missing) in-process publisher. `StackExchange.Redis` becomes an ambient transitive dependency via the new direct `Cirreum.Coordination.Redis` reference — consistent with the umbrella's reference-everything/opt-in-via-code pattern.

This release also folds in an internal consolidation with no public-API or wire change: the event registry now takes its inbound `(identifier, version)` → type resolution from the shared Kernel registry base (dropping a duplicate assembly scan it used to carry), and the two internal delivery types were renamed to the framework's sender/receiver vocabulary. Apps touch neither — `IAuthenticationEventPublisher` and `IAuthenticationEventHandler<TEvent>` are unchanged, and the published `IAuthenticationEventTransportBridge` marker keeps its name.

## See also

- `Cirreum.Coordination` 1.2.0 — `ISignalBroadcaster`, `CoordinationScope`
- `Cirreum.Services.Server` 1.3.0 — connection registry + termination handler
- `Cirreum.Authentication.ApiKey` 1.0.2 — denylist evict-on-expiry
