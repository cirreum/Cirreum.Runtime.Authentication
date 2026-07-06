namespace Cirreum.Authentication.Events;

/// <summary>
/// Ambient marker for "the current async flow is dispatching an event that arrived over
/// the wire". The outbound transport bridge refuses to forward while this is set, so a
/// handler that (against guidance) publishes from within inbound handling can only ever
/// reach local consumers — wire re-entry is blocked on the dispatch flow.
/// </summary>
/// <remarks>
/// <para>
/// The primary loop guard is the publisher/subscriber design itself (the inbound
/// subscriber never dispatches to bridge handlers); this scope is the second line of
/// defense, covering re-entry through a fresh <c>PublishAsync</c> call rather than
/// direct bridge dispatch.
/// </para>
/// <para>
/// The marker rides the ambient <see cref="System.Threading.ExecutionContext"/> — it
/// flows through <c>await</c>, <c>Task.Run</c>, and parallel continuations, but a
/// handler that defers its publish to a flow whose context predates the dispatch (a
/// worker fed by a channel, <c>ExecutionContext.SuppressFlow</c>) escapes both defenses.
/// Handlers must not publish events, directly or deferred; the guards exist to contain
/// the direct case, not to license the pattern.
/// </para>
/// </remarks>
internal static class AuthenticationEventDispatchScope {

	private static readonly AsyncLocal<bool> _inbound = new();

	/// <summary>Whether the current async flow originates from inbound wire dispatch.</summary>
	public static bool IsInboundDispatch => _inbound.Value;

	/// <summary>Marks the current async flow as inbound dispatch.</summary>
	public static void EnterInboundDispatch() => _inbound.Value = true;

	/// <summary>Clears the inbound-dispatch marker for the current async flow.</summary>
	public static void ExitInboundDispatch() => _inbound.Value = false;

}
