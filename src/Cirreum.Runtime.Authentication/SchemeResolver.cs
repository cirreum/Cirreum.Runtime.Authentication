namespace Cirreum.Authentication;

using Cirreum.AuthenticationProvider;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;

/// <summary>
/// The dynamic forward-scheme algorithm. Wired into ASP.NET Core's
/// <c>PolicyScheme</c> via <c>ForwardDefaultSelector</c> by the umbrella package —
/// iterates every registered <see cref="ISchemeSelector"/> in ascending
/// <see cref="ISchemeSelector.Priority"/> order and returns the first claimant's
/// scheme name.
/// </summary>
/// <remarks>
/// <para>
/// The Anonymous fallback selector at
/// <see cref="SchemeSelectorPriority.Anonymous"/> always claims, so iteration is
/// guaranteed to terminate with a non-null scheme name in well-configured apps.
/// The explicit return at the end is defense-in-depth.
/// </para>
/// <para>
/// The resolver also stamps the resolved scheme name into
/// <c>HttpContext.Items[AuthenticationContextKeys.AuthenticatedScheme]</c> so
/// downstream consumers (the claims transformer, boundary resolver, application-user
/// resolver dispatcher) read the real scheme rather than the dynamic forward
/// scheme's policy name.
/// </para>
/// <para>
/// Selection is instrumented here rather than inside each <see cref="ISchemeSelector"/>:
/// this is the single site every selector is dispatched through, so one call covers the
/// whole registered set — framework-shipped schemes and app-supplied selectors alike —
/// and the resolved-scheme distribution stays complete when a new scheme is added.
/// </para>
/// </remarks>
public static class SchemeResolver {

	/// <summary>
	/// Resolves the authentication scheme for the current request. Idempotent —
	/// re-invoking on the same context returns the same result (selectors are
	/// cheap probes; the resolved scheme is stamped on items for downstream
	/// reads).
	/// </summary>
	public static string Resolve(HttpContext context) {

		ArgumentNullException.ThrowIfNull(context);

		var selectors = context.RequestServices.GetServices<ISchemeSelector>();
		var resolved = AuthenticationSchemes.Anonymous;
		var claimedBy = AuthenticationTelemetry.SelectorNone;

		foreach (var selector in selectors.OrderBy(s => s.Priority)) {
			var (matches, schemeName) = selector.TrySelect(context);
			if (matches && !string.IsNullOrWhiteSpace(schemeName)) {
				resolved = schemeName;
				claimedBy = selector.GetType().Name;
				break;
			}
		}

		// Stamp the resolved scheme into items so downstream consumers see the real
		// scheme, not the dynamic forward scheme's name. AuthenticationContextKeys
		// shares this file's namespace — it's reached directly.
		context.Items[AuthenticationContextKeys.AuthenticatedScheme] = resolved;

		// Records both halves of the selection question: which scheme won, and whether
		// anything claimed the request at all. A "none" selector means the Anonymous
		// fallback selector is not registered — the resolved scheme is a default, not a
		// decision.
		AuthenticationTelemetry.RecordSchemeSelection(resolved, claimedBy);

		return resolved;
	}

}
