namespace Cirreum.Runtime.Authentication.Tests;

using Cirreum.Authentication;
using Cirreum.AuthenticationProvider;

public sealed class BearerSchemeValidatorTests {

	private static IBearerSchemeSelector Selector(string? bearerPrefix) {
		var selector = Substitute.For<IBearerSchemeSelector>();
		selector.BearerPrefix.Returns(bearerPrefix);
		return selector;
	}

	[Fact]
	public void No_selectors_passes() {
		var act = () => BearerSchemeValidator.Validate([]);

		act.Should().NotThrow();
	}

	[Fact]
	public void A_single_selector_without_a_prefix_passes() {
		// One Bearer-probing provider needs no prefix — JWT-shape disambiguation suffices.
		var act = () => BearerSchemeValidator.Validate([Selector(null)]);

		act.Should().NotThrow();
	}

	[Fact]
	public void Multiple_selectors_with_one_missing_a_prefix_throws() {
		// All-or-none: once two Bearer providers exist, every one must carry a prefix.
		var act = () => BearerSchemeValidator.Validate([Selector("apk_"), Selector(null)]);

		act.Should().Throw<InvalidOperationException>();
	}

	[Fact]
	public void Multiple_selectors_sharing_a_prefix_throws() {
		var act = () => BearerSchemeValidator.Validate([Selector("dup_"), Selector("dup_")]);

		act.Should().Throw<InvalidOperationException>();
	}

	[Fact]
	public void Multiple_selectors_with_distinct_prefixes_passes() {
		var act = () => BearerSchemeValidator.Validate([Selector("apk_"), Selector("st_")]);

		act.Should().NotThrow();
	}

}
