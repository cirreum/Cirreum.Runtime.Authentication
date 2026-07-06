namespace Cirreum.Authentication;

using Cirreum.Authentication.Events;
using Cirreum.AuthenticationProvider;
using Cirreum.Coordination;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;

/// <summary>
/// Composition verb for cross-replica auth-event delivery (ADR-0025).
/// </summary>
public static class AuthenticationEventCoordinationExtensions {

	/// <summary>
	/// Turns on cross-replica auth-event delivery: events published through
	/// <c>IAuthenticationEventPublisher</c> are forwarded onto the coordination broadcast
	/// channel after their local effects apply, and events received from other replicas
	/// are dispatched to this replica's local handlers.
	/// </summary>
	/// <param name="builder">The Cirreum authentication builder.</param>
	/// <returns>The builder for chaining.</returns>
	/// <remarks>
	/// <para>
	/// Takes no backend argument — it activates the registry, transport bridge, and
	/// inbound subscriber over whichever <c>ISignalBroadcaster</c> is registered: Redis
	/// when the app selects it anywhere
	/// (<c>auth.ConfigureCoordination(c =&gt; c.UseRedis())</c> — order-independent with
	/// this call), otherwise the safe in-process default. Delivery is at-most-once with
	/// no buffering; a replica that misses events while disconnected heals at its next
	/// boot hydration.
	/// </para>
	/// <para>
	/// A publishing replica is itself subscribed, so every publish is also received back
	/// (self-echo) and consumer handlers run a second time — inline on the in-process
	/// default, via the backend on Redis. Correct under the handlers-are-idempotent
	/// contract; echo-pass failures are logged rather than surfaced to the publishing
	/// caller. Consequently, do not hold a non-reentrant async lock across
	/// <c>PublishAsync</c> that a handler also acquires.
	/// </para>
	/// <para>
	/// When no <c>CoordinationScope</c> has been registered, this call defaults it to the
	/// canonical <c>{applicationName}:{environmentName}</c> (from
	/// <c>IDomainEnvironment</c>), so applications and environments sharing a backend
	/// never share coordination state. An explicit
	/// <c>ConfigureCoordination(c =&gt; c.WithScope(...))</c> always wins, in any order.
	/// </para>
	/// <para>
	/// <strong>Trust boundary:</strong> whoever can publish on the coordination backend's
	/// connection can forge auth events for this application's scope. Isolate the
	/// coordination connection (<c>c.UseRedis(connectionKey)</c>) when the shared
	/// connection's writer set is broader than the app itself, and never let unrelated
	/// applications share a scope. Channels under the <c>cirreum:</c> prefix are
	/// framework-reserved.
	/// </para>
	/// <para>
	/// <strong>Azure Managed Redis geo-replication:</strong> pub/sub does not cross
	/// active geo-replication regions — a signal publishes only to subscribers connected
	/// to the same region's instance. Cross-region convergence rides authoritative state
	/// (boot hydration + per-request consult), not this channel. Deploy region-local
	/// coordination backends when running active-active.
	/// </para>
	/// <para>
	/// Serverless hosts are out of scope: a Functions host doesn't hold a long-lived
	/// subscriber; those heads rely on boot hydration and per-request consult.
	/// </para>
	/// </remarks>
	public static IAuthenticationBuilder AddEventCoordination(this IAuthenticationBuilder builder) {

		ArgumentNullException.ThrowIfNull(builder);
		var services = builder.Services;

		// Pull the coordination machinery — ISignalBroadcaster gets the safe in-process
		// default; a UseRedis()/UseInMemory() selection elsewhere Replaces it regardless
		// of call order.
		services.AddCoordination();

		// Default the coordination scope to the canonical {app}:{env}. TryAdd, and
		// WithScope(...) uses Replace — so an explicit scope wins in any order.
		services.TryAddSingleton<CoordinationScope>(static sp => {
			var environment = sp.GetService<IDomainEnvironment>()
				?? throw new InvalidOperationException(
					"The default CoordinationScope derives {app}:{env} from IDomainEnvironment, " +
					"which is not registered. Host via DomainApplication.CreateBuilder, or register " +
					"an explicit scope: auth.ConfigureCoordination(c => c.WithScope(...)).");
			return CoordinationScope.For(environment.ApplicationName, environment.EnvironmentName);
		});

		services.TryAddSingleton<AuthenticationEventRegistry>();
		services.TryAddSingleton<AuthenticationEventInboundSubscriber>();

		// The outbound bridge — an ordinary handler carrying the transport-bridge marker.
		// Open-generic: one registration covers the framework's four events plus any
		// app-defined event type. Its presence is what turns distribution on.
		services.TryAddEnumerable(ServiceDescriptor.Singleton(
			typeof(IAuthenticationEventHandler<>),
			typeof(AuthenticationEventTransportBridge<>)));

		return builder;
	}

}
