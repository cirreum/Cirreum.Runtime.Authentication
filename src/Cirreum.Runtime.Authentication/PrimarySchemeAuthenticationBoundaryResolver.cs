namespace Cirreum.Authentication;

using Cirreum.Invocation;
using Cirreum.Security;

/// <summary>
/// Resolves <see cref="AuthenticationBoundary"/> by comparing the caller's authentication
/// scheme against the configured <c>Cirreum:Authentication:PrimaryScheme</c>.
/// </summary>
/// <remarks>
/// <para>
/// Callers who authenticate via the primary scheme are classified as
/// <see cref="AuthenticationBoundary.Global"/> (operator staff), as is work the host starts
/// on its own behalf (<see cref="HostInvocationDefaults.Scheme"/>): the host is the
/// operator's application. All other authenticated schemes — External (BYOID), API keys,
/// signed requests, secondary Entra or OIDC instances — are classified as
/// <see cref="AuthenticationBoundary.Tenant"/>.
/// </para>
/// <para>
/// Registered by <c>AddAuthentication()</c> with <c>TryAdd</c> semantics, so an
/// application-registered <see cref="IAuthenticationBoundaryResolver"/> — either before
/// <c>AddAuthentication()</c> or inside its composition callback — wins.
/// </para>
/// </remarks>
internal sealed class PrimarySchemeAuthenticationBoundaryResolver(string primaryScheme)
	: IAuthenticationBoundaryResolver {

	/// <inheritdoc/>
	public AuthenticationBoundary Resolve(IUserState userState, string? authenticationScheme) {
		if (!userState.IsAuthenticated) {
			return AuthenticationBoundary.None;
		}
		return string.Equals(authenticationScheme, primaryScheme, StringComparison.OrdinalIgnoreCase)
			|| string.Equals(authenticationScheme, HostInvocationDefaults.Scheme, StringComparison.Ordinal)
			? AuthenticationBoundary.Global
			: AuthenticationBoundary.Tenant;
	}
}
