namespace Cirreum.Authentication.Events;

using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;

/// <summary>
/// The default <see cref="IAuthenticationEventPublisher"/> — synchronous, ordered,
/// in-process dispatch. Consumer handlers run first (each isolated — a throwing handler
/// is logged and the rest still run); any handler implementing
/// <see cref="IAuthenticationEventTransportBridge"/> runs last, so a bridge only ever
/// ships an event whose local effects have already applied.
/// </summary>
/// <remarks>
/// <para>
/// After all handlers run, failures are surfaced to the caller as an
/// <see cref="AggregateException"/> — an admin command reports partial failure, and the
/// operator's retry (safe: handlers are idempotent) becomes the publishing replica's own
/// retry leg.
/// </para>
/// <para>
/// Registered by <c>AddAuthentication(...)</c> via <c>TryAddSingleton</c>, so an app can
/// replace it wholesale. A single-replica app is complete with this publisher and zero
/// additional wiring; cross-replica delivery is turned on by
/// <c>auth.AddEventCoordination()</c>, which registers the transport bridge this
/// publisher discovers through ordinary handler resolution.
/// </para>
/// </remarks>
internal sealed partial class InProcessAuthenticationEventPublisher(
	IServiceScopeFactory scopeFactory,
	ILogger<InProcessAuthenticationEventPublisher> logger
) : IAuthenticationEventPublisher {

	/// <inheritdoc/>
	public async ValueTask PublishAsync<TEvent>(
		TEvent evt,
		CancellationToken cancellationToken = default)
		where TEvent : IAuthenticationEvent {

		ArgumentNullException.ThrowIfNull(evt);

		using var scope = scopeFactory.CreateScope();
		var handlers = scope.ServiceProvider
			.GetServices<IAuthenticationEventHandler<TEvent>>()
			.ToArray();

		List<Exception>? failures = null;

		// Consumers first — local effects apply before anything ships.
		foreach (var handler in handlers) {
			if (handler is IAuthenticationEventTransportBridge) {
				continue;
			}
			failures = await RunIsolatedAsync(handler, evt, failures, cancellationToken)
				.ConfigureAwait(false);
		}

		// Bridges last — an event on the wire always reflects already-applied local state.
		foreach (var handler in handlers) {
			if (handler is not IAuthenticationEventTransportBridge) {
				continue;
			}
			failures = await RunIsolatedAsync(handler, evt, failures, cancellationToken)
				.ConfigureAwait(false);
		}

		if (failures is { Count: > 0 }) {
			throw new AggregateException(
				$"One or more handlers failed while publishing {typeof(TEvent).Name}. " +
				"Local effects from succeeding handlers have applied; handlers are " +
				"idempotent, so republishing the event is the safe retry.",
				failures);
		}
	}

	private async ValueTask<List<Exception>?> RunIsolatedAsync<TEvent>(
		IAuthenticationEventHandler<TEvent> handler,
		TEvent evt,
		List<Exception>? failures,
		CancellationToken cancellationToken)
		where TEvent : IAuthenticationEvent {

		try {
			await handler.HandleAsync(evt, cancellationToken).ConfigureAwait(false);
		} catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) {
			throw;
		} catch (Exception e) {
			Log.HandlerFailed(logger, e, handler.GetType().Name, typeof(TEvent).Name);
			(failures ??= []).Add(e);
		}
		return failures;
	}

	private static partial class Log {

		[LoggerMessage(EventId = 1, Level = LogLevel.Error,
			Message = "Authentication event handler '{Handler}' failed while handling {EventType}. Remaining handlers still run; the failure is surfaced to the publisher's caller.")]
		public static partial void HandlerFailed(ILogger logger, Exception exception, string handler, string eventType);

	}

}
