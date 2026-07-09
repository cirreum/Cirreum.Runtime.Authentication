namespace Cirreum.Authentication.Events;

using System.Collections.Concurrent;
using System.Reflection;

/// <summary>
/// Shared runtime-typed handler dispatch for the auth-event bus. Both the publisher and
/// the inbound subscriber resolve handlers by the event's <em>runtime</em> type —
/// handlers register against concrete event types, and the transport bridge stamps the
/// runtime type's wire identity, so dispatching on a less-derived static binding would
/// silently skip them.
/// </summary>
internal static class AuthenticationEventHandlerInvoker {

	private static readonly ConcurrentDictionary<Type, (Type ServiceType, MethodInfo HandleMethod)> _cache = new();

	/// <summary>
	/// Resolves the closed <c>IAuthenticationEventHandler&lt;&gt;</c> service type and its
	/// <c>HandleAsync</c> method for a concrete event type. Cached per event type.
	/// </summary>
	public static (Type ServiceType, MethodInfo HandleMethod) For(Type eventType) =>
		_cache.GetOrAdd(eventType, static t => {
			var serviceType = typeof(IAuthenticationEventHandler<>).MakeGenericType(t);
			var handleMethod = serviceType.GetMethod(
				nameof(IAuthenticationEventHandler<>.HandleAsync))!;
			return (serviceType, handleMethod);
		});

	/// <summary>
	/// Invokes <c>HandleAsync</c> on a handler instance. A synchronous throw arrives
	/// wrapped in <see cref="TargetInvocationException"/>; an asynchronous fault throws
	/// raw on await — <see cref="Unwrap"/> normalizes the two.
	/// </summary>
	public static ValueTask InvokeAsync(
		MethodInfo handleMethod,
		object handler,
		object evt,
		CancellationToken cancellationToken) =>
		(ValueTask)handleMethod.Invoke(handler, [evt, cancellationToken])!;

	/// <summary>Normalizes a reflection-wrapped handler exception to its cause.</summary>
	public static Exception Unwrap(Exception exception) =>
		exception is TargetInvocationException { InnerException: { } inner } ? inner : exception;

}
