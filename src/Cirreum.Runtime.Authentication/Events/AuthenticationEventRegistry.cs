namespace Cirreum.Authentication.Events;

using Cirreum.Messaging;
using Microsoft.Extensions.Logging;
using System.Collections.Concurrent;
using System.Diagnostics.CodeAnalysis;
using System.Reflection;

/// <summary>
/// The auth-event channel's versioned-message registry — resolves the four framework
/// events plus any app-defined <c>[MessageVersion]</c>-tagged
/// <see cref="IAuthenticationEvent"/> type, in both directions: CLR type → wire identity
/// (outbound, via the base <see cref="MessageRegistryBase{TBase}"/> surface) and wire
/// identity → CLR type (inbound, via <see cref="TryResolveType"/>).
/// </summary>
/// <remarks>
/// <para>
/// Built entirely on the Kernel's generic registry machinery
/// (<see cref="MessageRegistryBase{TBase}"/> / <c>MessageScanner</c> /
/// <c>[MessageVersion]</c>) — no <c>Cirreum.Messaging.Distributed</c> envelope is
/// involved; the wire shape is the minimal <see cref="AuthenticationEventEnvelope"/>.
/// </para>
/// <para>
/// The inbound type map is built from a direct assembly-scan pass capturing
/// <see cref="Type"/> instances, never from <see cref="Type.GetType(string)"/> over
/// captured names — <c>Type.GetType</c> with a plain full name only resolves types in
/// this assembly or the core library, so app-defined event types would silently fail to
/// resolve. App-defined events must be <see langword="public"/> (the scan enumerates
/// exported types).
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

	private readonly ConcurrentDictionary<string, Type> _typesByIdentity = new(StringComparer.Ordinal);

	/// <summary>
	/// Performs the standard Kernel scan and additionally captures the concrete
	/// <see cref="Type"/> for each discovered <c>(identifier, version)</c> pair, for
	/// inbound wire resolution.
	/// </summary>
	public async ValueTask InitializeAsync() {
		await this.DefaultInitializationAsync().ConfigureAwait(false);
		foreach (var type in AssemblyScanner.ScanExportedTypes(IsConcreteAuthenticationEvent)) {
			var attr = type.GetCustomAttribute<MessageVersionAttribute>();
			if (attr is null) {
				// Publishable and locally handleable, but it can never cross replicas —
				// the transport bridge will fail for it, permanently. Surface the
				// misconfiguration at startup, where the fix is obvious, instead of at
				// first publish.
				logger.LogWarning(
					"Concrete IAuthenticationEvent type {EventType} carries no [MessageVersion] attribute. " +
					"It can be published and handled locally, but it cannot cross replicas — " +
					"the auth-event transport bridge will fail for it.",
					type.FullName);
				continue;
			}
			this._typesByIdentity.TryAdd(KeyFor(attr.Identifier, attr.Version), type);
		}
	}

	/// <summary>
	/// Resolves the concrete event type for a wire <c>(identifier, version)</c> identity.
	/// A miss is a normal condition, not an error — e.g. a newer replica published an
	/// event version this replica doesn't know yet; callers drop the event and log.
	/// </summary>
	/// <param name="identifier">The stable logical identifier from the wire envelope.</param>
	/// <param name="version">The schema version from the wire envelope.</param>
	/// <param name="eventType">The resolved concrete type when found.</param>
	/// <returns><see langword="true"/> when resolved.</returns>
	public bool TryResolveType(
		string identifier,
		string version,
		[NotNullWhen(true)] out Type? eventType) =>
		this._typesByIdentity.TryGetValue(KeyFor(identifier, version), out eventType);

	private static string KeyFor(string identifier, string version) =>
		$"{identifier}|{version}";

	private static bool IsConcreteAuthenticationEvent(Type type) =>
		type.IsClass
		&& !type.IsAbstract
		&& typeof(IAuthenticationEvent).IsAssignableFrom(type);

}
