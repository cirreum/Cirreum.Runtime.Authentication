namespace Cirreum.Authentication;

using Cirreum.AuthenticationProvider;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;

/// <summary>
/// Framework-shipped <see cref="ISchemeSelector"/> that detects scheme-shopping
/// attempts. Runs FIRST in the dispatch order (Priority = 0). When two or more
/// distinct non-sentinel, non-Anonymous selectors would claim the request, the
/// sentinel routes to <see cref="AuthenticationSchemes.Ambiguous"/> for fail-closed
/// rejection by <see cref="AmbiguousRequestAuthenticationHandler"/>.
/// </summary>
/// <remarks>
/// <para>
/// The sentinel fires only when **distinct
/// credential-carriers** are present (for example, a credential in a custom header
/// AND a credential in <c>Authorization: Bearer</c>). Multiple selectors competing
/// for the *same* credential-carrier (e.g. both <c>ApiKey:Bearer</c> and
/// <c>SessionTicket:Bearer</c> claiming the same Bearer header value) is overloaded
/// transport — that case is resolved by the opt-in token-prefix convention and the
/// boot-time <see cref="BearerSchemeValidator"/>, not by the sentinel.
/// </para>
/// <para>
/// Implementation note: the sentinel iterates all registered
/// <see cref="ISchemeSelector"/> services and counts distinct returned scheme names.
/// Two or more distinct scheme names indicate two or more carriers present
/// simultaneously. The sentinel itself and the Anonymous fallback (both
/// pseudo-selectors) are filtered out of the count.
/// </para>
/// </remarks>
public sealed class ConflictSentinelSchemeSelector : ISchemeSelector {

	/// <inheritdoc/>
	public int Priority => SchemeSelectorPriority.Conflict;

	/// <inheritdoc/>
	public (bool Matches, string? SchemeName) TrySelect(HttpContext context) {

		if (context is null) {
			return (false, null);
		}

		// TODO: should this be OrdinalIgnoreCase?
		// The scheme names are registered case-insensitively, but the selector returns them as-is.
		// If a scheme name is registered with different casing, it will be treated as distinct here.
		var matchedSchemes = new HashSet<string>(StringComparer.Ordinal);

		foreach (var selector in context.RequestServices.GetServices<ISchemeSelector>()) {
			// Skip the sentinel itself and the Anonymous catch-all — neither participates
			// in carrier counting.
			if (selector is ConflictSentinelSchemeSelector
				|| selector.Priority == SchemeSelectorPriority.Anonymous) {
				continue;
			}

			var (matches, schemeName) = selector.TrySelect(context);
			if (matches && !string.IsNullOrEmpty(schemeName)) {
				matchedSchemes.Add(schemeName);
				if (matchedSchemes.Count >= 2) {
					// Stash the colliding scheme names so the Ambiguous handler's
					// rejection log names them (the handler owns the single Warning
					// per rejected request).
					context.Items[AmbiguousRequestItemKeys.ConflictingSchemes] = matchedSchemes.ToArray();
					return (true, AuthenticationSchemes.Ambiguous);
				}
			}
		}

		return (false, null);
	}

}
