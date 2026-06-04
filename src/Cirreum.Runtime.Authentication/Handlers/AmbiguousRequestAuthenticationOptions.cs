namespace Cirreum.Authentication;

using Microsoft.AspNetCore.Authentication;

/// <summary>
/// Options for the <see cref="AmbiguousRequestAuthenticationHandler"/>.
/// </summary>
public sealed class AmbiguousRequestAuthenticationOptions : AuthenticationSchemeOptions {

	/// <summary>
	/// The message returned when authentication fails because the inbound request
	/// carried distinct credential-carriers (scheme-shopping) or a credential whose
	/// owner couldn't be determined.
	/// </summary>
	public string FailureMessage { get; set; } =
		"Unable to determine authentication method. " +
		"Verify your credentials match a configured authentication provider.";

}
