namespace Cirreum.Authentication.Events;

/// <summary>
/// The framework's auth-event broadcast channel name.
/// </summary>
/// <remarks>
/// <para>
/// A plain constant, deliberately carrying no application or environment identity — the
/// distributed <c>ISignalBroadcaster</c> adapters namespace every channel under the
/// registered <c>CoordinationScope</c> (canonically <c>{app}:{env}</c>), so scoping the
/// name here would double-encode it.
/// </para>
/// <para>
/// The leading <c>cirreum:</c> segment marks the channel as framework-reserved; the
/// underscore prefix on the leaf marks it as an internal wire, not an app-facing channel.
/// Applications must not publish or subscribe on <c>cirreum:</c>-prefixed channels
/// directly — the framework owns that namespace.
/// </para>
/// </remarks>
internal static class AuthenticationEventChannel {

	/// <summary>The channel every auth-event bridge publishes to and every inbound
	/// subscriber listens on.</summary>
	public const string Name = "cirreum:_auth-events";

}
