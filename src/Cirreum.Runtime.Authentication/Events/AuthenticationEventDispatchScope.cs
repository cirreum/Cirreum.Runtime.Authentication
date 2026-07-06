namespace Cirreum.Authentication.Events;

/// <summary>
/// Ambient marker for "the current async flow is dispatching an event that arrived over
/// the wire". The outbound transport bridge refuses to forward while this is set, so a
/// handler that (against guidance) publishes from within inbound handling can only ever
/// reach local consumers — wire re-entry is structurally impossible.
/// </summary>
/// <remarks>
/// The primary loop guard is the publisher/subscriber design itself (the inbound
/// subscriber never dispatches to bridge handlers); this scope is the second line of
/// defense, covering re-entry through a fresh <c>PublishAsync</c> call rather than
/// direct bridge dispatch.
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
