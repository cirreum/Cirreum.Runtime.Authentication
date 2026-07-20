namespace Cirreum.Runtime.Authentication.Tests;

using Cirreum.Authentication;
using Cirreum.AuthenticationProvider;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using System.Text;
using System.Text.Json;

/// <summary>
/// Unit tests for <see cref="JwtAudienceSchemeSelector"/>. Verifies audience routing
/// against the registration set — in particular that EVERY registered audience is
/// routable regardless of how many providers or instances contributed entries
/// (multi-provider compositions previously lost all but the last-registered audience).
/// </summary>
public class JwtAudienceSchemeSelectorTests {

	private static readonly AudienceSchemeRegistration[] MultiProviderSet = [
		new("P3Cm1mP1ZDf2VoHXXYtPfFdgawbc", "descope", "Oidc"),
		new("2640e4f4-9924-4ec1-84a6-8797b466311e", "entraWorkforce", "Entra"),
		new("50eca7c5-8930-49f8-b9f4-373ed9e5d516", "entraExternal", "Entra"),
	];

	[Theory]
	[InlineData("P3Cm1mP1ZDf2VoHXXYtPfFdgawbc", "descope")]
	[InlineData("2640e4f4-9924-4ec1-84a6-8797b466311e", "entraWorkforce")]
	[InlineData("50eca7c5-8930-49f8-b9f4-373ed9e5d516", "entraExternal")]
	public void TrySelect_MultiProviderComposition_EveryRegisteredAudienceRoutes(
		string audience, string expectedScheme) {
		// Regression: with one Oidc and two Entra instances composed together, every
		// audience must route to its owning scheme — not just the last-registered one.
		var selector = new JwtAudienceSchemeSelector(MultiProviderSet);
		var context = CreateContextWithBearer(CreateJwt(audience));

		var result = selector.TrySelect(context);

		result.Matches.Should().BeTrue();
		result.SchemeName.Should().Be(expectedScheme);
	}

	[Fact]
	public void TrySelect_AudienceMatch_IsCaseInsensitive() {
		var selector = new JwtAudienceSchemeSelector(MultiProviderSet);
		var context = CreateContextWithBearer(CreateJwt("p3cm1mp1zdf2vohxxytpffdgawbc"));

		var result = selector.TrySelect(context);

		result.Matches.Should().BeTrue();
		result.SchemeName.Should().Be("descope");
	}

	[Fact]
	public void TrySelect_AudienceArray_RoutesByFirstElement() {
		var selector = new JwtAudienceSchemeSelector(MultiProviderSet);
		var context = CreateContextWithBearer(
			CreateJwt(audienceJson: """["P3Cm1mP1ZDf2VoHXXYtPfFdgawbc","other"]"""));

		var result = selector.TrySelect(context);

		result.Matches.Should().BeTrue();
		result.SchemeName.Should().Be("descope");
	}

	[Fact]
	public void TrySelect_IdenticalDuplicateRegistrations_ResolveDeterministically() {
		// Benign duplicates (same audience, same scheme) must not break construction.
		var selector = new JwtAudienceSchemeSelector([
			new("P3Cm1mP1ZDf2VoHXXYtPfFdgawbc", "descope", "Oidc"),
			new("P3Cm1mP1ZDf2VoHXXYtPfFdgawbc", "descope", "Oidc"),
		]);
		var context = CreateContextWithBearer(CreateJwt("P3Cm1mP1ZDf2VoHXXYtPfFdgawbc"));

		var result = selector.TrySelect(context);

		result.Matches.Should().BeTrue();
		result.SchemeName.Should().Be("descope");
	}

	[Fact]
	public void TrySelect_UnregisteredAudienceOnProtectedEndpoint_RoutesToAmbiguousAndStashesAudience() {
		var selector = new JwtAudienceSchemeSelector(MultiProviderSet);
		var context = CreateContextWithBearer(CreateJwt("unknown-audience"));

		var result = selector.TrySelect(context);

		result.Matches.Should().BeTrue();
		result.SchemeName.Should().Be(AuthenticationSchemes.Ambiguous);
		context.Items[AmbiguousRequestItemKeys.UnmappedAudience].Should().Be("unknown-audience");
	}

	[Fact]
	public void TrySelect_UnregisteredAudienceOnAllowAnonymousEndpoint_RoutesToAnonymous() {
		var selector = new JwtAudienceSchemeSelector(MultiProviderSet);
		var context = CreateContextWithBearer(CreateJwt("unknown-audience"));
		context.SetEndpoint(new Endpoint(
			requestDelegate: null,
			new EndpointMetadataCollection(new AllowAnonymousAttribute()),
			displayName: "test"));

		var result = selector.TrySelect(context);

		result.Matches.Should().BeTrue();
		result.SchemeName.Should().Be(AuthenticationSchemes.Anonymous);
		context.Items.Should().NotContainKey(AmbiguousRequestItemKeys.UnmappedAudience);
	}

	[Fact]
	public void TrySelect_EmptyRegistrationSet_RoutesGenuineJwtToAmbiguous() {
		// No audience providers composed, yet a JWT arrived on a protected endpoint —
		// fail closed rather than falling through to anonymous.
		var selector = new JwtAudienceSchemeSelector([]);
		var context = CreateContextWithBearer(CreateJwt("any"));

		var result = selector.TrySelect(context);

		result.Matches.Should().BeTrue();
		result.SchemeName.Should().Be(AuthenticationSchemes.Ambiguous);
	}

	[Fact]
	public void TrySelect_TokenWithoutAudClaim_DoesNotClaim() {
		var selector = new JwtAudienceSchemeSelector(MultiProviderSet);
		var context = CreateContextWithBearer(CreateJwt(audienceJson: null));

		var result = selector.TrySelect(context);

		result.Matches.Should().BeFalse();
	}

	[Fact]
	public void TrySelect_NonJwtBearerToken_DoesNotClaim() {
		var selector = new JwtAudienceSchemeSelector(MultiProviderSet);
		var context = CreateContextWithBearer("opaque-api-key-value");

		var result = selector.TrySelect(context);

		result.Matches.Should().BeFalse();
	}

	[Fact]
	public void TrySelect_NoAuthorizationHeader_DoesNotClaim() {
		var selector = new JwtAudienceSchemeSelector(MultiProviderSet);
		var context = new DefaultHttpContext();

		var result = selector.TrySelect(context);

		result.Matches.Should().BeFalse();
	}

	private static HttpContext CreateContextWithBearer(string token) {
		var context = new DefaultHttpContext();
		context.Request.Headers.Authorization = $"Bearer {token}";
		return context;
	}

	// Builds a structurally valid (unsigned-payload) JWT. audience sets a string aud;
	// audienceJson overrides the raw aud JSON (array form), null omits the claim.
	private static string CreateJwt(string? audience = null, string? audienceJson = "__use_audience__") {
		var header = Base64Url("""{"alg":"none","typ":"JWT"}""");
		var audPart = audienceJson switch {
			"__use_audience__" => $"\"aud\":{JsonSerializer.Serialize(audience)},",
			null => "",
			_ => $"\"aud\":{audienceJson},",
		};
		var payload = Base64Url($$"""{{{audPart}}"sub":"user-1","iss":"test"}""");
		return $"{header}.{payload}.signature";
	}

	private static string Base64Url(string json) =>
		Convert.ToBase64String(Encoding.UTF8.GetBytes(json))
			.TrimEnd('=').Replace('+', '-').Replace('/', '_');

}
