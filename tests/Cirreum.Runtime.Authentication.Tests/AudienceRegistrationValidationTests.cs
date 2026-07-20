namespace Cirreum.Runtime.Authentication.Tests;

using Cirreum.Authentication;
using Cirreum.AuthenticationProvider;
using Microsoft.Extensions.DependencyInjection;

/// <summary>
/// Unit tests for the composition-close audience registration sweep. Verifies that
/// one audience claimed by two different schemes fails composition with every
/// collision reported, and that clean or empty sets pass.
/// </summary>
public class AudienceRegistrationValidationTests {

	[Fact]
	public void Validate_CleanMultiProviderSet_DoesNotThrow() {
		var services = Compose(
			new AudienceSchemeRegistration("P3Cm1mP1ZDf2VoHXXYtPfFdgawbc", "descope", "Oidc"),
			new AudienceSchemeRegistration("2640e4f4", "entraWorkforce", "Entra"),
			new AudienceSchemeRegistration("50eca7c5", "entraExternal", "Entra"));

		var act = () => AudienceRegistrationValidator.Validate(services);

		act.Should().NotThrow();
	}

	[Fact]
	public void Validate_EmptySet_DoesNotThrow() {
		var services = new ServiceCollection();

		var act = () => AudienceRegistrationValidator.Validate(services);

		act.Should().NotThrow();
	}

	[Fact]
	public void Validate_IdenticalDuplicate_DoesNotThrow() {
		// Same audience, same scheme — idempotent re-registration is benign.
		var services = Compose(
			new AudienceSchemeRegistration("aud-1", "descope", "Oidc"),
			new AudienceSchemeRegistration("aud-1", "descope", "Oidc"));

		var act = () => AudienceRegistrationValidator.Validate(services);

		act.Should().NotThrow();
	}

	[Fact]
	public void Validate_OneAudienceTwoSchemes_ThrowsNamingBothSides() {
		var services = Compose(
			new AudienceSchemeRegistration("shared-aud", "descope", "Oidc"),
			new AudienceSchemeRegistration("shared-aud", "entraWorkforce", "Entra"));

		var act = () => AudienceRegistrationValidator.Validate(services);

		act.Should().Throw<InvalidOperationException>()
			.WithMessage("*shared-aud*")
			.WithMessage("*descope*")
			.WithMessage("*Oidc*")
			.WithMessage("*entraWorkforce*")
			.WithMessage("*Entra*");
	}

	[Fact]
	public void Validate_ConflictDetection_IsCaseInsensitiveOnAudience() {
		var services = Compose(
			new AudienceSchemeRegistration("Shared-Aud", "descope", "Oidc"),
			new AudienceSchemeRegistration("shared-aud", "entraWorkforce", "Entra"));

		var act = () => AudienceRegistrationValidator.Validate(services);

		act.Should().Throw<InvalidOperationException>();
	}

	[Fact]
	public void Validate_MultipleConflicts_ReportsEveryCollision() {
		var services = Compose(
			new AudienceSchemeRegistration("aud-1", "schemeA", "Oidc"),
			new AudienceSchemeRegistration("aud-1", "schemeB", "Entra"),
			new AudienceSchemeRegistration("aud-2", "schemeC", "Oidc"),
			new AudienceSchemeRegistration("aud-2", "schemeD", "External"));

		var act = () => AudienceRegistrationValidator.Validate(services);

		act.Should().Throw<InvalidOperationException>()
			.WithMessage("*aud-1*")
			.WithMessage("*aud-2*");
	}

	private static ServiceCollection Compose(params AudienceSchemeRegistration[] registrations) {
		var services = new ServiceCollection();
		foreach (var registration in registrations) {
			services.AddSingleton(registration);
		}
		return services;
	}

}
