namespace Cirreum.Authentication.Events;

using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using System.Runtime.ExceptionServices;

/// <summary>
/// The default <see cref="IAuthenticationEventPublisher"/> — synchronous, ordered,
/// in-process dispatch. Consumer handlers run first (each isolated — a throwing handler
/// is logged and the rest still run); any handler implementing
/// <see cref="IAuthenticationEventTransportBridge"/> runs last, so a bridge only ever
/// ships an event whose local effects have already applied.
/// </summary>
/// <remarks>
/// <para>
/// Dispatch keys on the event's <em>runtime</em> type, not the static
/// <c>TEvent</c> binding of the <c>PublishAsync</c> call — handlers
/// register against concrete event types, so publishing through a less-derived reference
/// (e.g. iterating a collection of <see cref="IAuthenticationEvent"/>) still reaches
/// every concrete-typed handler, and the wire identity the bridge stamps always matches
/// the handlers that ran locally.
/// </para>
/// <para>
/// After all handlers run, failures are surfaced to the caller as an
/// <see cref="AggregateException"/> — an admin command reports partial failure, and the
/// operator's retry (safe: handlers are idempotent) becomes the publishing replica's own
/// retry leg. One exception: a missing <c>[MessageVersion]</c> wire identity is a
/// permanent configuration error the bridge reports as such — republishing cannot fix it.
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

		var eventType = evt.GetType();
		var (serviceType, handleMethod) = AuthenticationEventHandlerInvoker.For(eventType);

		using var scope = scopeFactory.CreateScope();
		var handlers = scope.ServiceProvider
			.GetServices(serviceType)
			.Where(static h => h is not null)
			.ToArray();

		List<Exception>? failures = null;

		// Consumers first — local effects apply before anything ships.
		foreach (var handler in handlers) {
			if (handler is IAuthenticationEventTransportBridge) {
				continue;
			}
			failures = await this.RunIsolatedAsync(
				handleMethod, handler!, evt, eventType, failures, cancellationToken)
				.ConfigureAwait(false);
		}

		// Bridges last — an event on the wire always reflects already-applied local state.
		foreach (var handler in handlers) {
			if (handler is not IAuthenticationEventTransportBridge) {
				continue;
			}
			failures = await this.RunIsolatedAsync(
				handleMethod, handler, evt, eventType, failures, cancellationToken)
				.ConfigureAwait(false);
		}

		if (failures is { Count: > 0 }) {
			throw new AggregateException(
				$"One or more handlers failed while publishing {eventType.Name}. " +
				"Local effects from succeeding handlers have applied; handlers are " +
				"idempotent, so republishing the event is the safe retry (see the inner " +
				"exceptions — a permanent configuration error says so explicitly).",
				failures);
		}
	}

	private async ValueTask<List<Exception>?> RunIsolatedAsync(
		System.Reflection.MethodInfo handleMethod,
		object handler,
		object evt,
		Type eventType,
		List<Exception>? failures,
		CancellationToken cancellationToken) {

		try {
			await AuthenticationEventHandlerInvoker
				.InvokeAsync(handleMethod, handler, evt, cancellationToken)
				.ConfigureAwait(false);
		} catch (Exception e) {
			var cause = AuthenticationEventHandlerInvoker.Unwrap(e);
			if (cause is OperationCanceledException && cancellationToken.IsCancellationRequested) {
				// The caller gave up — propagate cancellation rather than aggregating.
				ExceptionDispatchInfo.Capture(cause).Throw();
			}
			Log.HandlerFailed(logger, cause, handler.GetType().Name, eventType.Name);
			(failures ??= []).Add(cause);
		}
		return failures;
	}

	private static partial class Log {

		[LoggerMessage(EventId = 1, Level = LogLevel.Error,
			Message = "Authentication event handler '{Handler}' failed while handling {EventType}. Remaining handlers still run; the failure is surfaced to the publisher's caller.")]
		public static partial void HandlerFailed(ILogger logger, Exception exception, string handler, string eventType);

	}

}
