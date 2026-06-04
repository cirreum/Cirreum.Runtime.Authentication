namespace Cirreum.Authentication;

using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using System.Text.Encodings.Web;

/// <summary>
/// Framework-shipped authentication handler that fails closed with a 401 status.
/// Routed to by <see cref="ConflictSentinelSchemeSelector"/> when the inbound
/// request carries distinct credential-carriers (potential scheme-shopping), or by
/// <see cref="JwtAudienceSchemeSelector"/> when a JWT arrives with an unrecognized
/// <c>aud</c> claim.
/// </summary>
/// <remarks>
/// <para>
/// Fails closed on ambiguity — rather than
/// silently picking one scheme when multiple are signaled, or accepting a JWT no
/// configured scheme owns, the request is rejected so the caller surfaces the
/// misconfiguration / attack rather than being authenticated by an unintended
/// handler.
/// </para>
/// </remarks>
public sealed class AmbiguousRequestAuthenticationHandler(
	IOptionsMonitor<AmbiguousRequestAuthenticationOptions> options,
	ILoggerFactory logger,
	UrlEncoder encoder
) : AuthenticationHandler<AmbiguousRequestAuthenticationOptions>(options, logger, encoder) {

	/// <inheritdoc/>
	protected override Task<AuthenticateResult> HandleAuthenticateAsync() {
		if (this.Logger.IsEnabled(LogLevel.Warning)) {
			this.Logger.LogWarning(
				"Request rejected: unable to determine authentication scheme. " +
				"This may be due to conflicting authentication headers or a credential " +
				"that doesn't match any configured provider.");
		}
		return Task.FromResult(AuthenticateResult.Fail(this.Options.FailureMessage));
	}

}
