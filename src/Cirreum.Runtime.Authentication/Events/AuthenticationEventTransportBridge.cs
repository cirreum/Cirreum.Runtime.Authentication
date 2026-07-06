namespace Cirreum.Authentication.Events;

using Cirreum.Coordination;
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
/// whose local effects have applied) and the inbound subscriber excludes it from
/// dispatch (no publish-receive loop). It additionally refuses to forward while the
/// current flow is inbound dispatch — the second line of defense against wire re-entry.
/// </para>
/// <para>
/// The publishing replica is itself subscribed to the channel, so it receives its own
/// events back (self-echo). This is a known, accepted inefficiency — handlers are
/// idempotent — not a loop.
/// </para>
/// </remarks>
internal sealed class AuthenticationEventTransportBridge<TEvent>(
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
		var definition = registry.GetDefinitionFor(eventType);

		var envelope = new AuthenticationEventEnvelope(
			definition.Identifier,
			definition.Version,
			JsonSerializer.SerializeToElement(evt, eventType));

		var payload = JsonSerializer.SerializeToUtf8Bytes(envelope);

		await broadcaster.PublishAsync(AuthenticationEventChannel.Name, payload, cancellationToken)
			.ConfigureAwait(false);
	}

}
