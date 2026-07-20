namespace Cirreum.Authentication;

using Cirreum.AuthenticationProvider;
using Cirreum.Authorization;
using Cirreum.Security;
using Microsoft.AspNetCore.Authorization;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Hosting;

/// <summary>
/// Registers the predefined Cirreum authorization policies (System + Standard family) on a new
/// <see cref="AuthorizationBuilder"/>. The role-based core policies (<c>Standard</c> … <c>StandardAdmin</c>)
/// dispatch through the dynamic forward scheme; the <c>System</c> policy is admitted only through the
/// configured primary scheme (<c>Cirreum:Authentication:PrimaryScheme</c>) so system-level access cannot be
/// obtained via API keys or any other transport.
/// </summary>
internal static class DefaultAuthorizationPolicyRegistration {

	internal static AuthorizationBuilder Register(IHostApplicationBuilder builder) {

		var primaryScheme = builder.Configuration.GetValue<string>("Cirreum:Authentication:PrimaryScheme");
		if (string.IsNullOrWhiteSpace(primaryScheme)) {
			throw new InvalidOperationException(
				"Missing required 'Cirreum:Authentication:PrimaryScheme' configuration. Set it to one of your " +
				"configured authentication scheme names — the 'System' authorization policy admits only this " +
				"scheme, so system-level access cannot be obtained through API keys or other transports.");
		}

		// Scheme-aware boundary classification: primary scheme → Global, other
		// authenticated schemes → Tenant. TryAdd — an application-registered resolver
		// (before AddAuthentication or in its composition callback) wins.
		builder.Services.TryAddSingleton<IAuthenticationBoundaryResolver>(
			new PrimarySchemeAuthenticationBoundaryResolver(primaryScheme));

		var authorizationBuilder = builder.Services.AddAuthorizationBuilder();

		// Core role-based policy bound to the dynamic forward scheme: an authenticated user in any role.
		void ConfigurePolicy(string policyName, params string[] roles) =>
			authorizationBuilder.AddPolicy(policyName, policy => policy
				.AddAuthenticationSchemes(AuthenticationSchemes.Dynamic)
				.RequireAuthenticatedUser()
				.RequireRole(roles));

		// System — restricted to the primary scheme only: system-level access must come through the
		// designated primary IdP, never an API key or other transport.
		authorizationBuilder.AddPolicy(AuthorizationPolicies.System, policy => policy
			.AddAuthenticationSchemes(primaryScheme)
			.RequireAuthenticatedUser()
			.RequireRole(ApplicationRoles.AppSystemRole));

		// Core policies — each admits app:system; the admitted role set narrows as the policy tightens.
		ConfigurePolicy(
			AuthorizationPolicies.Standard,
			ApplicationRoles.AppSystemRole,
			ApplicationRoles.AppAdminRole,
			ApplicationRoles.AppManagerRole,
			ApplicationRoles.AppAgentRole,
			ApplicationRoles.AppInternalRole,
			ApplicationRoles.AppUserRole);

		ConfigurePolicy(
			AuthorizationPolicies.StandardInternal,
			ApplicationRoles.AppSystemRole,
			ApplicationRoles.AppAdminRole,
			ApplicationRoles.AppManagerRole,
			ApplicationRoles.AppInternalRole);

		ConfigurePolicy(
			AuthorizationPolicies.StandardAgent,
			ApplicationRoles.AppSystemRole,
			ApplicationRoles.AppAdminRole,
			ApplicationRoles.AppManagerRole,
			ApplicationRoles.AppAgentRole);

		ConfigurePolicy(
			AuthorizationPolicies.StandardManager,
			ApplicationRoles.AppSystemRole,
			ApplicationRoles.AppAdminRole,
			ApplicationRoles.AppManagerRole);

		ConfigurePolicy(
			AuthorizationPolicies.StandardAdmin,
			ApplicationRoles.AppSystemRole,
			ApplicationRoles.AppAdminRole);

		return authorizationBuilder;
	}

}
