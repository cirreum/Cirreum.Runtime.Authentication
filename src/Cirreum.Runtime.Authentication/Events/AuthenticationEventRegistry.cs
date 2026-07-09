namespace Cirreum.Authentication.Events;

using Cirreum.Messaging;
using Microsoft.Extensions.Logging;

/// <summary>
/// The auth-event channel's versioned-message registry — resolves the four framework
/// events plus any app-defined <c>[MessageVersion]</c>-tagged
/// <see cref="IAuthenticationEvent"/> type in both directions: CLR type → wire identity
/// (outbound, via <c>GetDefinitionFor</c>) and wire identity → CLR type (inbound, via the
/// base <see cref="MessageRegistryBase{TBase}.ResolveType(string, string)"/>).
/// </summary>
/// <remarks>
/// <para>
/// A thin specialization of the Kernel's generic registry
/// (<see cref="MessageRegistryBase{TBase}"/> / <c>MessageScanner</c> / <c>[MessageVersion]</c>):
/// the base's single scan captures both lookup directions and warns about concrete
/// <see cref="IAuthenticationEvent"/> types missing <c>[MessageVersion]</c>, so this type
/// carries no bespoke scan or identity map of its own. No <c>Cirreum.Messaging.Distributed</c>
/// envelope is involved; the wire shape is the minimal <see cref="AuthenticationEventEnvelope"/>.
/// </para>
/// <para>
/// Initialized once, during the <c>ISystemInitializer</c> startup phase (see
/// <see cref="AuthenticationEventCoordinationBootstrap"/>), so lookups are populated
/// before any hosted service — including a scheme's boot hydrator — can publish or
/// receive.
/// </para>
/// </remarks>
public sealed class AuthenticationEventRegistry(
	ILogger<AuthenticationEventRegistry> logger
) : MessageRegistryBase<IAuthenticationEvent>(logger) {

	/// <summary>
	/// Runs the Kernel scan that populates both lookup directions for this channel's
	/// family. Called once at startup by <see cref="AuthenticationEventCoordinationBootstrap"/>.
	/// </summary>
	public ValueTask InitializeAsync() => this.DefaultInitializationAsync();

}
