namespace Cirreum.Authentication;

using Cirreum.AuthenticationProvider;

/// <summary>
/// Boot-time validator that enforces the cross-provider Bearer-prefix uniqueness
/// invariant. Runs at the end of the <c>AddAuthentication()</c> composition,
/// after every scheme registrar and the optional app-supplied <c>configure</c> callback
/// have contributed their <see cref="IBearerSchemeSelector"/> instances.
/// </summary>
/// <remarks>
/// <para>
/// When multiple providers accept the
/// <c>Authorization: Bearer</c> transport (ApiKey, SessionTicket, future schemes),
/// the framework requires either:
/// </para>
/// <list type="bullet">
///   <item>Every Bearer-probing provider configures a unique <c>BearerPrefix</c>, OR</item>
///   <item>Only one Bearer-probing provider is registered (in which case the
///   prefix-less fallback to JWT-shape disambiguation suffices).</item>
/// </list>
/// <para>
/// Violations throw at boot — the host won't accept requests with ambiguous Bearer
/// dispatch.
/// </para>
/// </remarks>
public static class BearerSchemeValidator {

	/// <summary>
	/// Validates the registered <see cref="IBearerSchemeSelector"/> set. Throws
	/// <see cref="InvalidOperationException"/> on violation.
	/// </summary>
	public static void Validate(IEnumerable<IBearerSchemeSelector> bearerSelectors) {

		ArgumentNullException.ThrowIfNull(bearerSelectors);

		var list = bearerSelectors.ToList();
		if (list.Count <= 1) {
			// Zero or one Bearer-probing selector — no ambiguity possible.
			return;
		}

		// All-or-none invariant: when multiple Bearer-probing providers are registered,
		// every one must carry a configured BearerPrefix.
		var withoutPrefix = list.Where(s => string.IsNullOrEmpty(s.BearerPrefix)).ToList();
		if (withoutPrefix.Count > 0) {
			var names = string.Join(", ", withoutPrefix.Select(s => s.GetType().Name));
			throw new InvalidOperationException(
				$"Multiple Bearer-probing selectors are registered without a configured BearerPrefix: " +
				$"{names}. When multiple providers use the Bearer transport, each must configure a " +
				$"unique BearerPrefix at " +
				$"Cirreum:Authentication:Providers:{{ProviderName}}:BearerPrefix.");
		}

		// Cross-provider uniqueness: no two selectors may share the same prefix.
		var byPrefix = list.GroupBy(s => s.BearerPrefix!, StringComparer.Ordinal);
		foreach (var group in byPrefix) {
			if (group.Count() > 1) {
				var names = string.Join(", ", group.Select(s => s.GetType().Name));
				throw new InvalidOperationException(
					$"Multiple Bearer-probing selectors share BearerPrefix '{group.Key}': {names}. " +
					$"BearerPrefix must be unique across providers — otherwise the token's leading " +
					$"bytes can't disambiguate dispatch.");
			}
		}
	}

}
