namespace Cirreum.Runtime.Authentication.Tests;

using Cirreum.Authentication;
using Cirreum.Security;
using Microsoft.Extensions.DependencyInjection;

/// <summary>
/// Unit tests for the composition-close scheme-declaration sweep and the map it publishes.
/// Locks the three rules the wave turns on: identical duplicate declarations collapse (a
/// platform-default scheme is commonly declared by more than one provider), a scheme declared
/// two different ways fails composition, and an undeclared scheme stays legal — resolving
/// <see cref="SchemeClaimAuthority.Undeclared"/>, which is what preserves the behaviour of a
/// host that declares nothing.
/// </summary>
public class SchemeDeclarationTests {

	private static IServiceCollection Compose(params SchemeClaimAuthorityRegistration[] registrations) {
		var services = new ServiceCollection();
		foreach (var registration in registrations) {
			services.AddSingleton(registration);
		}
		return services;
	}

	private static SchemeClaimAuthorityRegistration Human(
		string scheme,
		ClaimAuthority roles = ClaimAuthority.Unspecified) =>
		new(scheme, SubjectKind.Human, ClaimAuthority.Unspecified, roles);

	// Validation
	// -------------------------------------------------------------

	[Fact]
	public void Validate_EmptySet_DoesNotThrow() {
		var act = () => SchemeDeclarationValidator.Validate(new ServiceCollection());

		act.Should().NotThrow();
	}

	[Fact]
	public void Validate_CleanMultiProviderSet_DoesNotThrow() {
		var services = Compose(
			Human("descope", ClaimAuthority.ApplicationStore),
			Human("entraWorkforce", ClaimAuthority.IdentityProvider),
			new SchemeClaimAuthorityRegistration(
				"ApiKey:X-Api-Key", SubjectKind.Machine, ClaimAuthority.Unspecified, ClaimAuthority.Unspecified));

		var act = () => SchemeDeclarationValidator.Validate(services);

		act.Should().NotThrow();
	}

	[Fact]
	public void Validate_IdenticalDuplicateDeclarations_Collapse() {
		// Entra and Oidc both declare the platform-default cookie scheme. Two providers
		// stating the same thing is agreement, not conflict.
		var services = Compose(
			new SchemeClaimAuthorityRegistration("Cookies", SubjectKind.Unknown, default, default),
			new SchemeClaimAuthorityRegistration("Cookies", SubjectKind.Unknown, default, default));

		var act = () => SchemeDeclarationValidator.Validate(services);

		act.Should().NotThrow();
	}

	[Fact]
	public void Validate_ConflictingDeclarations_Throws_NamingTheScheme() {
		var services = Compose(
			Human("descope", ClaimAuthority.ApplicationStore),
			Human("descope", ClaimAuthority.IdentityProvider));

		var act = () => SchemeDeclarationValidator.Validate(services);

		act.Should().Throw<InvalidOperationException>()
			.WithMessage("*descope*")
			.WithMessage("*ApplicationStore*")
			.WithMessage("*IdentityProvider*");
	}

	[Fact]
	public void Validate_ConflictingSubjectKinds_Throws() {
		var services = Compose(
			Human("shared"),
			new SchemeClaimAuthorityRegistration("shared", SubjectKind.Machine, default, default));

		var act = () => SchemeDeclarationValidator.Validate(services);

		act.Should().Throw<InvalidOperationException>().WithMessage("*shared*");
	}

	[Fact]
	public void Validate_SchemesDifferingOnlyByCase_AreDistinct() {
		// ASP.NET keys its scheme registry ordinally, so these are two schemes — declaring
		// them differently is not a conflict.
		var services = Compose(
			Human("descope", ClaimAuthority.ApplicationStore),
			Human("Descope", ClaimAuthority.IdentityProvider));

		var act = () => SchemeDeclarationValidator.Validate(services);

		act.Should().NotThrow();
	}

	// The map
	// -------------------------------------------------------------

	[Fact]
	public void Map_ResolvesADeclaredScheme() {
		var map = new SchemeClaimAuthorityMap([
			new SchemeClaimAuthorityRegistration(
				"descope", SubjectKind.Human, ClaimAuthority.IdentityProvider, ClaimAuthority.ApplicationStore)]);

		var declaration = map.Get("descope");

		declaration.SubjectKind.Should().Be(SubjectKind.Human);
		declaration.Profile.Should().Be(ClaimAuthority.IdentityProvider);
		declaration.Roles.Should().Be(ClaimAuthority.ApplicationStore);
	}

	[Fact]
	public void Map_ResolvesUndeclaredForAnUnknownScheme() {
		var map = new SchemeClaimAuthorityMap([Human("descope")]);

		map.Get("somethingElse").Should().Be(SchemeClaimAuthority.Undeclared);
	}

	[Theory]
	[InlineData(null)]
	[InlineData("")]
	[InlineData("   ")]
	public void Map_ResolvesUndeclaredForABlankScheme(string? scheme) {
		var map = new SchemeClaimAuthorityMap([Human("descope")]);

		map.Get(scheme).Should().Be(SchemeClaimAuthority.Undeclared);
	}

	[Fact]
	public void Map_IsCaseSensitive_MatchingAspNetSchemeKeying() {
		var map = new SchemeClaimAuthorityMap([Human("descope")]);

		map.Get("Descope").Should().Be(SchemeClaimAuthority.Undeclared);
	}

	[Fact]
	public void Map_EmptySet_ResolvesUndeclaredForEverything() {
		// A host that declares nothing: every reader sees Undeclared and applies the
		// behaviour that predates declarations.
		var map = new SchemeClaimAuthorityMap([]);

		map.Get("descope").Should().Be(SchemeClaimAuthority.Undeclared);
	}

}
