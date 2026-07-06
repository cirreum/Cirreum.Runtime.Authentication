namespace Cirreum.Runtime.Authentication.Tests;

using Cirreum.Authentication;
using Cirreum.AuthenticationProvider;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;

/// <summary>
/// Unit tests for <see cref="ConflictSentinelSchemeSelector"/>. Verifies the
/// distinct-carrier detection: two or more distinct scheme names claimed by
/// non-sentinel, non-Anonymous selectors route the request to the Ambiguous scheme
/// for fail-closed rejection.
/// </summary>
public class ConflictSentinelSchemeSelectorTests {

	[Fact]
	public void TrySelect_NoSelectorsRegistered_ReturnsNoMatch() {
		var context = CreateContext();
		var sentinel = new ConflictSentinelSchemeSelector();

		var result = sentinel.TrySelect(context);

		result.Matches.Should().BeFalse();
		result.SchemeName.Should().BeNull();
	}

	[Fact]
	public void TrySelect_SingleClaimingSelector_ReturnsNoMatch() {
		var context = CreateContext(
			new TestSelector(SchemeSelectorPriority.Key, matches: true, schemeName: "ApiKey"));
		var sentinel = new ConflictSentinelSchemeSelector();

		var result = sentinel.TrySelect(context);

		result.Matches.Should().BeFalse();
		result.SchemeName.Should().BeNull();
	}

	[Fact]
	public void TrySelect_TwoSelectorsClaimingSameScheme_ReturnsNoMatch() {
		// Two selectors resolving to the SAME scheme name is overloaded transport,
		// not scheme-shopping — resolved by priority, not the sentinel.
		var context = CreateContext(
			new TestSelector(SchemeSelectorPriority.Key, matches: true, schemeName: "ApiKey"),
			new TestSelector(SchemeSelectorPriority.Session, matches: true, schemeName: "ApiKey"));
		var sentinel = new ConflictSentinelSchemeSelector();

		var result = sentinel.TrySelect(context);

		result.Matches.Should().BeFalse();
	}

	[Fact]
	public void TrySelect_TwoDistinctSchemesClaimed_ReturnsAmbiguous() {
		// Classic scheme-shopping: two distinct credential-carriers on one request.
		var context = CreateContext(
			new TestSelector(SchemeSelectorPriority.Key, matches: true, schemeName: "ApiKey"),
			new TestSelector(SchemeSelectorPriority.External, matches: true, schemeName: "External"));
		var sentinel = new ConflictSentinelSchemeSelector();

		var result = sentinel.TrySelect(context);

		result.Matches.Should().BeTrue();
		result.SchemeName.Should().Be(AuthenticationSchemes.Ambiguous);
	}

	[Fact]
	public void TrySelect_ThreeDistinctSchemesClaimed_ReturnsAmbiguous() {
		var context = CreateContext(
			new TestSelector(SchemeSelectorPriority.Key, matches: true, schemeName: "ApiKey"),
			new TestSelector(SchemeSelectorPriority.Session, matches: true, schemeName: "SessionTicket"),
			new TestSelector(SchemeSelectorPriority.External, matches: true, schemeName: "External"));
		var sentinel = new ConflictSentinelSchemeSelector();

		var result = sentinel.TrySelect(context);

		result.Matches.Should().BeTrue();
		result.SchemeName.Should().Be(AuthenticationSchemes.Ambiguous);
	}

	[Fact]
	public void TrySelect_OnlyOneOfSeveralSelectorsClaims_ReturnsNoMatch() {
		var context = CreateContext(
			new TestSelector(SchemeSelectorPriority.Key, matches: true, schemeName: "ApiKey"),
			new TestSelector(SchemeSelectorPriority.Session, matches: false),
			new TestSelector(SchemeSelectorPriority.External, matches: false));
		var sentinel = new ConflictSentinelSchemeSelector();

		var result = sentinel.TrySelect(context);

		result.Matches.Should().BeFalse();
	}

	[Fact]
	public void TrySelect_SentinelInstanceInDi_IsFilteredFromTheCount() {
		// The registered sentinel service must not participate in carrier counting —
		// only one real carrier here, so no ambiguity.
		var context = CreateContext(
			new ConflictSentinelSchemeSelector(),
			new TestSelector(SchemeSelectorPriority.Key, matches: true, schemeName: "ApiKey"));
		var sentinel = new ConflictSentinelSchemeSelector();

		var result = sentinel.TrySelect(context);

		result.Matches.Should().BeFalse();
	}

	[Fact]
	public void TrySelect_AnonymousPrioritySelector_IsFilteredFromTheCount() {
		// The Anonymous catch-all always claims; if it counted as a carrier, every
		// request with any other claimant would be ambiguous.
		var context = CreateContext(
			new TestSelector(SchemeSelectorPriority.Anonymous, matches: true, schemeName: AuthenticationSchemes.Anonymous),
			new TestSelector(SchemeSelectorPriority.Key, matches: true, schemeName: "ApiKey"));
		var sentinel = new ConflictSentinelSchemeSelector();

		var result = sentinel.TrySelect(context);

		result.Matches.Should().BeFalse();
	}

	[Fact]
	public void Priority_IsConflict_SoItIteratesFirst() {
		var sentinel = new ConflictSentinelSchemeSelector();

		sentinel.Priority.Should().Be(SchemeSelectorPriority.Conflict);
	}

	// Builds an HttpContext whose RequestServices resolves the provided test selectors
	// via DI. Mirrors how the production code resolves selectors at request time —
	// the conflict sentinel iterates IEnumerable<ISchemeSelector> from RequestServices.
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
