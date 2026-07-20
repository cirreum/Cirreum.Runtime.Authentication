namespace Cirreum.Authentication;

/// <summary>
/// <c>HttpContext.Items</c> keys used by the scheme selectors to hand rejection
/// diagnostics to <see cref="AmbiguousRequestAuthenticationHandler"/>. The selectors
/// stash rather than log so that conflict-sentinel probing (which invokes every
/// selector speculatively) stays silent — the handler emits exactly one Warning per
/// rejected request, enriched with whichever diagnostic is present.
/// </summary>
internal static class AmbiguousRequestItemKeys {

	/// <summary>
	/// The <c>aud</c> claim value of a well-formed JWT that matched no registered
	/// audience. Stashed by <c>JwtAudienceSchemeSelector</c>.
	/// </summary>
	internal const string UnmappedAudience = "__Cirreum_Ambiguous_UnmappedAudience";

	/// <summary>
	/// The distinct scheme names claimed by separate credential carriers on one
	/// request (a <c>string[]</c>). Stashed by <c>ConflictSentinelSchemeSelector</c>.
	/// </summary>
	internal const string ConflictingSchemes = "__Cirreum_Ambiguous_ConflictingSchemes";

}
