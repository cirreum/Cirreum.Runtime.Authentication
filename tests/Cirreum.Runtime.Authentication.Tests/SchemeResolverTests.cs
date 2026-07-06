namespace Cirreum.Runtime.Authentication.Tests;

using Cirreum.Authentication;
using Cirreum.AuthenticationProvider;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;

/// <summary>
/// Unit tests for <see cref="SchemeResolver.Resolve"/> — the dynamic forward-scheme
/// algorithm. Verifies ascending-priority iteration, first-claimant-wins, the
/// defensive Anonymous fallback, and the AuthenticatedScheme stamp.
/// </summary>
public class SchemeResolverTests {

	[Fact]
	public void Resolve_EmptySelectorSet_FallsThroughToAnonymous() {
		var context = CreateContext();

		var result = SchemeResolver.Resolve(context);

		result.Should().Be(AuthenticationSchemes.Anonymous);
	}

	[Fact]
	public void Resolve_SingleMatchingSelector_ReturnsItsSchemeName() {
		var context = CreateContext(
			new TestSelector(SchemeSelectorPriority.Key, matches: true, schemeName: "ApiKey"));

		var result = SchemeResolver.Resolve(context);

		result.Should().Be("ApiKey");
	}

	[Fact]
	public void Resolve_MultipleClaimants_LowestPriorityValueWins() {
		// Ascending priority order: Key (100) runs before External (400).
		var context = CreateContext(
			new TestSelector(SchemeSelectorPriority.External, matches: true, schemeName: "External"),
			new TestSelector(SchemeSelectorPriority.Key, matches: true, schemeName: "ApiKey"));

		var result = SchemeResolver.Resolve(context);

		result.Should().Be("ApiKey");
	}

	[Fact]
	public void Resolve_SelectorMatchesButReturnsBlankName_SkippedAndCascades() {
		// Defensive: a buggy selector returning matches=true with a null/blank name is
		// skipped; iteration cascades to the next claimant.
		var context = CreateContext(
			new TestSelector(SchemeSelectorPriority.Key, matches: true, schemeName: null),
			new TestSelector(SchemeSelectorPriority.External, matches: true, schemeName: "External"));

		var result = SchemeResolver.Resolve(context);

		result.Should().Be("External");
	}

	[Fact]
	public void Resolve_NoSelectorClaims_ReturnsAnonymousAsDefense() {
		// Production always registers the Anonymous catch-all, but the resolver itself
		// defaults to Anonymous when iteration exits without a hit.
		var context = CreateContext(
			new TestSelector(SchemeSelectorPriority.Key, matches: false),
			new TestSelector(SchemeSelectorPriority.External, matches: false));

		var result = SchemeResolver.Resolve(context);

		result.Should().Be(AuthenticationSchemes.Anonymous);
	}

	[Fact]
	public void Resolve_ConflictSentinelClaims_WinsOverLaterClaimants() {
		// Conflict priority = 0 → iterates first; a sentinel match preempts real schemes.
		var context = CreateContext(
			new TestSelector(SchemeSelectorPriority.Conflict, matches: true, schemeName: AuthenticationSchemes.Ambiguous),
			new TestSelector(SchemeSelectorPriority.Key, matches: true, schemeName: "ApiKey"));

		var result = SchemeResolver.Resolve(context);

		result.Should().Be(AuthenticationSchemes.Ambiguous);
	}

	[Fact]
	public void Resolve_StampsResolvedSchemeIntoContextItems() {
		var context = CreateContext(
			new TestSelector(SchemeSelectorPriority.Key, matches: true, schemeName: "ApiKey"));

		SchemeResolver.Resolve(context);

		context.Items[AuthenticationContextKeys.AuthenticatedScheme].Should().Be("ApiKey");
	}

	private static HttpContext CreateContext(params ISchemeSelector[] selectors) {
		var services = new ServiceCollection();
		foreach (var selector in selectors) {
			services.AddSingleton(selector);
		}
		var provider = services.BuildServiceProvider();

		return new DefaultHttpContext {
			RequestServices = provider
		};
	}

}
