namespace Cirreum.Authentication.Events;

using Cirreum.Coordination;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using System.Text.Json;

/// <summary>
/// The inbound leg of cross-replica auth-event delivery: subscribes once to the
/// coordination broadcast channel, resolves each received envelope to its concrete event
/// type through the <see cref="AuthenticationEventRegistry"/>, and dispatches to every
/// local <see cref="IAuthenticationEventHandler{TEvent}"/> <em>except</em> transport
/// bridges — excluding bridges prevents a publish-receive loop on the dispatch flow (see
/// <see cref="AuthenticationEventDispatchScope"/> for the guard's reach and its limit).
/// </summary>
/// <remarks>
/// <para>
/// Subscribed during the <c>ISystemInitializer</c> startup phase (see
/// <see cref="AuthenticationEventCoordinationBootstrap"/>), which runs before any
/// <c>IHostedService</c> starts — including scheme boot hydrators — so the subscription
/// is live before any hydrator snapshots its store. No cross-package ordering convention
/// required.
/// </para>
/// <para>
/// Wire input is treated as untrusted in shape (whoever can publish on the coordination
/// connection can put arbitrary bytes on the channel): malformed envelopes, unknown
/// <c>(identifier, version)</c> identities, and payloads that fail to deserialize —
/// whatever the exception type — are logged and dropped; they never fault the
/// subscription.
/// </para>
/// <para>
/// Handler failures during inbound dispatch are logged and isolated per handler; there is
/// no remote caller to surface them to. Boot hydration remains the durable backstop for
/// any missed or failed delivery.
/// </para>
/// </remarks>
internal sealed partial class AuthenticationEventInboundSubscriber(
	ISignalBroadcaster broadcaster,
	AuthenticationEventRegistry registry,
	IServiceScopeFactory scopeFactory,
	ILogger<AuthenticationEventInboundSubscriber> logger
) {

	/// <summary>
	/// Subscribes to the auth-event channel. Called once at startup; the subscription
	/// lives for the application's lifetime (the broadcaster contract has no
	/// unsubscribe).
	/// </summary>
	public ValueTask SubscribeAsync(CancellationToken cancellationToken = default) =>
		broadcaster.SubscribeAsync(AuthenticationEventChannel.Name, this.OnSignalAsync, cancellationToken);

	private async ValueTask OnSignalAsync(ReadOnlyMemory<byte> payload, CancellationToken cancellationToken) {

		AuthenticationEventEnvelope? envelope;
		try {
			envelope = JsonSerializer.Deserialize<AuthenticationEventEnvelope>(payload.Span);
		} catch (JsonException e) {
			Log.MalformedEnvelope(logger, e);
			return;
		}

		if (envelope is null
			|| string.IsNullOrWhiteSpace(envelope.Identifier)
			|| string.IsNullOrWhiteSpace(envelope.Version)
			|| envelope.Payload.ValueKind is JsonValueKind.Undefined) {
			Log.IncompleteEnvelope(logger);
			return;
		}

		if (!registry.TryResolveType(envelope.Identifier, envelope.Version, out var eventType)) {
			Log.UnknownEventIdentity(logger, envelope.Identifier, envelope.Version);
			return;
		}

		object? evt;
		try {
			evt = envelope.Payload.Deserialize(eventType);
		} catch (Exception e) when (e is not OperationCanceledException) {
			// Hostile wire input can produce more than JsonException here (e.g.
			// InvalidOperationException, NotSupportedException) — anything that escaped
			// would be swallowed silently by the logger-free Redis pump. Log and drop.
			Log.PayloadDeserializationFailed(logger, e, envelope.Identifier, envelope.Version);
			return;
		}
		if (evt is null) {
			Log.PayloadDeserializationFailed(logger, null, envelope.Identifier, envelope.Version);
			return;
		}

		await this.DispatchAsync(evt, eventType, cancellationToken).ConfigureAwait(false);
	}

	private async ValueTask DispatchAsync(object evt, Type eventType, CancellationToken cancellationToken) {

		using var scope = scopeFactory.CreateScope();
		var (serviceType, handleMethod) = AuthenticationEventHandlerInvoker.For(eventType);

		AuthenticationEventDispatchScope.EnterInboundDispatch();
		try {
			foreach (var handler in scope.ServiceProvider.GetServices(serviceType)) {
				if (handler is null or IAuthenticationEventTransportBridge) {
					continue;
				}
				try {
					await AuthenticationEventHandlerInvoker
						.InvokeAsync(handleMethod, handler, evt, cancellationToken)
						.ConfigureAwait(false);
				} catch (Exception e) {
					var cause = AuthenticationEventHandlerInvoker.Unwrap(e);
					if (cause is OperationCanceledException && cancellationToken.IsCancellationRequested) {
						throw;
					}
					Log.InboundHandlerFailed(logger, cause, handler.GetType().Name, eventType.Name);
				}
			}
		} finally {
			AuthenticationEventDispatchScope.ExitInboundDispatch();
		}
	}

	private static partial class Log {

		[LoggerMessage(EventId = 1, Level = LogLevel.Warning,
			Message = "Dropped an auth-event signal: the envelope was not valid JSON.")]
		public static partial void MalformedEnvelope(ILogger logger, Exception exception);

		[LoggerMessage(EventId = 2, Level = LogLevel.Warning,
			Message = "Dropped an auth-event signal: the envelope was missing its identifier, version, or payload.")]
		public static partial void IncompleteEnvelope(ILogger logger);

		[LoggerMessage(EventId = 3, Level = LogLevel.Warning,
			Message = "Dropped an auth-event signal for unknown identity [{Identifier}|v{Version}] — no matching [MessageVersion] event type is loaded in this replica (a version skew during rolling upgrade is the benign cause; boot hydration heals any missed effect).")]
		public static partial void UnknownEventIdentity(ILogger logger, string identifier, string version);

		[LoggerMessage(EventId = 4, Level = LogLevel.Warning,
			Message = "Dropped an auth-event signal for [{Identifier}|v{Version}]: the payload failed to deserialize.")]
		public static partial void PayloadDeserializationFailed(ILogger logger, Exception? exception, string identifier, string version);

		[LoggerMessage(EventId = 5, Level = LogLevel.Error,
			Message = "Authentication event handler '{Handler}' failed during inbound dispatch of {EventType}. Remaining handlers still run; boot hydration is the durable backstop.")]
		public static partial void InboundHandlerFailed(ILogger logger, Exception exception, string handler, string eventType);

	}

}
