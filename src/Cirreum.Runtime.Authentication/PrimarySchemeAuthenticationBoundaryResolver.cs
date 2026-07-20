namespace Cirreum.Authentication;

using Cirreum.Security;

/// <summary>
/// Resolves <see cref="AuthenticationBoundary"/> by comparing the caller's authentication
/// scheme against the configured <c>Cirreum:Authentication:PrimaryScheme</c>.
/// </summary>
/// <remarks>
/// <para>
/// Callers who authenticate via the primary scheme are classified as
/// <see cref="AuthenticationBoundary.Global"/> (operator staff). All other authenticated
/// schemes — External (BYOID), API keys, signed requests, secondary Entra or OIDC
/// instances — are classified as <see cref="AuthenticationBoundary.Tenant"/>.
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
			? AuthenticationBoundary.Global
			: AuthenticationBoundary.Tenant;
	}
}
