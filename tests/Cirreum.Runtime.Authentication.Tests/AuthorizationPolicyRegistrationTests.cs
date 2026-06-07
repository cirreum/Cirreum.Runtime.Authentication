namespace Cirreum.Runtime.Authentication.Tests;

using Cirreum.Authentication;
using Cirreum.AuthenticationProvider;
using Cirreum.Authorization;
using Microsoft.AspNetCore.Authorization;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Options;

public sealed class AuthorizationPolicyRegistrationTests {

	private static HostApplicationBuilder BuilderWith(string? primaryScheme) {
		var builder = Host.CreateApplicationBuilder();
		if (primaryScheme is not null) {
			builder.Configuration.AddInMemoryCollection(new Dictionary<string, string?> {
				["Cirreum:Authentication:PrimaryScheme"] = primaryScheme
			});
		}
		return builder;
	}

	private static AuthorizationOptions RegisterAndResolveOptions(string primaryScheme) {
		var builder = BuilderWith(primaryScheme);
		DefaultAuthorizationPolicyRegistration.Register(builder);
		var provider = builder.Services.BuildServiceProvider();
		return provider.GetRequiredService<IOptions<AuthorizationOptions>>().Value;
	}

	[Fact]
	public void A_missing_primary_scheme_throws() {
		var builder = BuilderWith(primaryScheme: null);

		var act = () => DefaultAuthorizationPolicyRegistration.Register(builder);

		act.Should().Throw<InvalidOperationException>().WithMessage("*PrimaryScheme*");
	}

	[Fact]
	public void Returns_an_authorization_builder() {
		var builder = BuilderWith("Primary");

		var authorizationBuilder = DefaultAuthorizationPolicyRegistration.Register(builder);

		authorizationBuilder.Should().NotBeNull();
	}

	[Fact]
	public void Registers_every_predefined_policy() {
		var options = RegisterAndResolveOptions("Primary");

		foreach (var policyName in AuthorizationPolicies.All) {
			options.GetPolicy(policyName).Should().NotBeNull($"policy '{policyName}' should be registered");
		}
	}

	[Fact]
	public void The_system_policy_admits_only_the_primary_scheme() {
		var options = RegisterAndResolveOptions("Primary");

		var system = options.GetPolicy(AuthorizationPolicies.System);

		system.Should().NotBeNull();
		system!.AuthenticationSchemes.Should().ContainSingle().Which.Should().Be("Primary");
	}

	[Fact]
	public void The_core_policies_are_bound_to_the_dynamic_forward_scheme() {
		var options = RegisterAndResolveOptions("Primary");

		var standard = options.GetPolicy(AuthorizationPolicies.Standard);

		standard.Should().NotBeNull();
		standard!.AuthenticationSchemes.Should().Contain(AuthenticationSchemes.Dynamic);
	}

}
