namespace Cirreum.Authentication.Events;

using Cirreum.Coordination;
using Cirreum.Messaging;
using System.Text.Json;

/// <summary>
/// The outbound leg of cross-replica auth-event delivery: an ordinary
/// <see cref="IAuthenticationEventHandler{TEvent}"/> that forwards the event, through the
/// <see cref="AuthenticationEventRegistry"/>, onto the coordination broadcast channel.
/// Registered open-generic by <c>auth.AddEventCoordination()</c> — its presence is what
/// turns distribution on; the publisher needs no compile-time knowledge of it.
/// </summary>
/// <remarks>
/// <para>
/// Implements <see cref="IAuthenticationEventTransportBridge"/>, so the in-process
/// publisher runs it after all consumer handlers (the wire only ever carries an event
/// whose local effects have applied) and the inbound receiver excludes it from
/// dispatch (no publish-receive loop). It additionally refuses to forward while the
/// current flow is inbound dispatch — the second line of defense against wire re-entry.
/// </para>
/// <para>
/// The publishing replica is itself subscribed to the channel, so it receives its own
/// events back (self-echo). This is a known, accepted inefficiency — handlers are
/// idempotent — not a loop.
/// </para>
/// </remarks>
internal sealed class AuthenticationEventSender<TEvent>(
	AuthenticationEventRegistry registry,
	ISignalBroadcaster broadcaster
) : IAuthenticationEventHandler<TEvent>, IAuthenticationEventTransportBridge
	where TEvent : IAuthenticationEvent {

	/// <inheritdoc/>
	public async ValueTask HandleAsync(TEvent evt, CancellationToken cancellationToken = default) {

		ArgumentNullException.ThrowIfNull(evt);

		if (AuthenticationEventDispatchScope.IsInboundDispatch) {
			return;
		}

		// Resolve identity from the runtime type — TEvent may be a less-derived binding.
		var eventType = evt.GetType();
		MessageDefinition definition;
		try {
			definition = registry.GetDefinitionFor(eventType);
		} catch (InvalidOperationException e) {
			// Distinguish this from transient handler failures: republishing can never
			// fix a missing wire identity, and the publisher's retry guidance would
			// otherwise send the operator in circles.
			throw new InvalidOperationException(
				$"{eventType.Name} cannot cross replicas: no [MessageVersion] wire identity " +
				"was discovered for it. This is a permanent configuration error — " +
				"republishing will not succeed. Tag the event type with " +
				"[MessageVersion(identifier, version)] and make it public so the registry " +
				"scan can discover it. (Local handlers have already run.)", e);
		}

		var envelope = new AuthenticationEventEnvelope(
			definition.Identifier,
			definition.Version,
			JsonSerializer.SerializeToElement(evt, eventType));

		var payload = JsonSerializer.SerializeToUtf8Bytes(envelope);

		await broadcaster.PublishAsync(AuthenticationEventChannel.Name, payload, cancellationToken)
			.ConfigureAwait(false);
	}

}
