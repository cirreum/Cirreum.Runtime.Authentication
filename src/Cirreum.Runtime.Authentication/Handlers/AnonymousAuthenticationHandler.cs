namespace Cirreum.Authentication;

using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using System.Text.Encodings.Web;

/// <summary>
/// Framework-shipped authentication handler that returns <see cref="AuthenticateResult.NoResult"/>
/// for the Anonymous fallback scheme. Routed to by
/// <see cref="AnonymousAuthenticationSchemeSelector"/> at the bottom of the dispatch
/// order so requests with no recognized credentials reach <c>[AllowAnonymous]</c>
/// endpoints cleanly.
/// </summary>
/// <remarks>
/// Returning
/// <see cref="AuthenticateResult.NoResult"/> signals that authentication was not
/// attempted, allowing endpoints marked with <c>[AllowAnonymous]</c> to proceed
/// without triggering authentication failures.
/// </remarks>
public sealed class AnonymousAuthenticationHandler(
	IOptionsMonitor<AuthenticationSchemeOptions> options,
	ILoggerFactory logger,
	UrlEncoder encoder
) : AuthenticationHandler<AuthenticationSchemeOptions>(options, logger, encoder) {

	/// <inheritdoc/>
	protected override Task<AuthenticateResult> HandleAuthenticateAsync() =>
		Task.FromResult(AuthenticateResult.NoResult());

}
