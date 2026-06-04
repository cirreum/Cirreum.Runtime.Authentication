namespace Cirreum.Authentication;

using Cirreum.AuthenticationProvider;
using Microsoft.AspNetCore.Http;

/// <summary>
/// Framework-shipped catch-all <see cref="ISchemeSelector"/> — always claims, returns
/// <see cref="AuthenticationSchemes.Anonymous"/>. Registered at
/// <see cref="SchemeSelectorPriority.Anonymous"/> so it runs LAST in the dispatch
/// order; any scheme selector that claims the request will preempt it.
/// </summary>
/// <remarks>
/// When no scheme selector claims, this fallback
/// ensures every request gets routed to a valid scheme — the Anonymous scheme's
/// handler returns <see cref="Microsoft.AspNetCore.Authentication.AuthenticateResult.NoResult"/>,
/// which preserves <c>[AllowAnonymous]</c> semantics for endpoints that don't
/// require authentication.
/// </remarks>
public sealed class AnonymousAuthenticationSchemeSelector : ISchemeSelector {

	/// <inheritdoc/>
	public int Priority => SchemeSelectorPriority.Anonymous;

	/// <inheritdoc/>
	public (bool Matches, string? SchemeName) TrySelect(HttpContext context) =>
		(true, AuthenticationSchemes.Anonymous);

}
