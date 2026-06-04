namespace Microsoft.Extensions.Hosting;

using Cirreum;
using Cirreum.Authentication;
using Cirreum.Authentication.Configuration;
using Cirreum.AuthenticationProvider;
using Cirreum.Providers;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;

/// <summary>
/// App-facing extensions for composing the Cirreum Authentication track.
/// </summary>
public static class HostApplicationBuilderExtensions {

	/// <summary>Marker type for once-per-host idempotency.</summary>
	private sealed class CirreumAuthenticationMarker { }

	/// <summary>
	/// Registers the Cirreum Authentication track end-to-end. Composes every
	/// framework-shipped scheme registrar, the framework-shipped Anonymous /
	/// Ambiguous / Conflict / Audience selectors and handlers, the dynamic forward
	/// <c>PolicyScheme</c>, the audience-routed claims transformer, the predefined
	/// authorization policies, and runs the boot-time Bearer-prefix validator.
	/// </summary>
	/// <param name="builder">The host application builder.</param>
	/// <param name="configure">Optional callback receiving a
	/// <see cref="CirreumAuthenticationBuilder"/>. Apps compose providers
	/// (<c>AddApiKey(...)</c>, <c>AddSignedRequest&lt;T&gt;(...)</c>), register dynamic
	/// resolvers (<c>AddExternalTenantResolver&lt;T&gt;</c>), and per-scheme
	/// application-user resolvers (<c>AddApplicationUserResolver&lt;T&gt;</c>) here.</param>
	/// <param name="authentication">Optional callback for ASP.NET-level
	/// <see cref="AuthenticationOptions"/> overrides.</param>
	/// <returns>The <see cref="CirreumAuthenticationBuilder"/> for further composition.</returns>
	/// <remarks>
	/// <para>
	/// Uses an explicit composition + selector model with a six-stage pipeline.
	/// </para>
	/// <para>
	/// Sequence:
	/// </para>
	/// <list type="number">
	///   <item>Sets <c>ProviderRuntimeType</c> from the host's <c>DomainContext</c> runtime type.</item>
	///   <item>Calls <c>services.AddAuthentication(...)</c> with the dynamic forward scheme as default.</item>
	///   <item>Registers framework-shipped handlers (Anonymous, Ambiguous) + selectors (Conflict sentinel, Audience, Anonymous fallback) + the <see cref="IAudienceSchemeMap"/> default impl.</item>
	///   <item>Registers the dynamic forward <c>PolicyScheme</c> with the <see cref="SchemeResolver.Resolve"/> callback.</item>
	///   <item>Calls <c>services.AddAudienceRoleClaimsTransformation()</c> to wire the claims transformer.</item>
	///   <item>Auto-registers the framework-shipped registrars that still bind from appsettings (Oidc, Entra, External) via the typed <c>RegisterAuthenticationProvider&lt;...&gt;()</c> helper. ApiKey, SignedRequest, and SessionTicket are excluded — the app composes them via <c>auth.AddApiKey(...)</c> / <c>auth.AddSignedRequest&lt;T&gt;(...)</c> / <c>auth.AddSessionTicket(...)</c> in the callback.</item>
	///   <item>Invokes the app's <paramref name="configure"/> callback for provider composition (<c>AddApiKey</c>), dynamic-resolver, and application-user-resolver registrations.</item>
	///   <item>Registers the predefined Cirreum authorization policies (<c>Standard</c>, <c>StandardAdmin</c>, etc.).</item>
	///   <item>Runs the boot-time <see cref="BearerSchemeValidator"/> — fails fast on cross-provider Bearer-prefix collisions.</item>
	/// </list>
	/// <para>
	/// Idempotent — calling multiple times on the same host returns without re-running.
	/// </para>
	/// </remarks>
	public static CirreumAuthenticationBuilder AddAuthentication(
		this IHostApplicationBuilder builder,
		Action<CirreumAuthenticationBuilder>? configure = null,
		Action<AuthenticationOptions>? authentication = null) {

		ArgumentNullException.ThrowIfNull(builder);

		if (builder.Services.IsMarkerTypeRegistered<CirreumAuthenticationMarker>()) {
			throw new InvalidOperationException(
				"AddAuthentication() has already been called for this host. " +
				"Call it once during composition; use the CirreumAuthenticationBuilder " +
				"returned from the first call for any subsequent customization.");
		}
		builder.Services.MarkTypeAsRegistered<CirreumAuthenticationMarker>();

		// 1. Map the host's DomainRuntimeType into ProviderRuntimeType so audience-
		//    based registrars can branch correctly on host-type sensitivity.
		//    Required — no defensible default.
		// TODO: what happens if the app doesn't use Authentication at all and thus
		// doesn't call this method? The runtime type is still required for the
		// provider-side composition, but we won't have this guard in place. We should
		// consider whether there's a better way to enforce that the runtime type
		// is set in that case.
		if (!builder.Properties.TryGetValue(DomainContext.RuntimeTypeKey, out var runtimeTypeBox)
			|| runtimeTypeBox is not DomainRuntimeType runtimeType) {
			throw new InvalidOperationException(
				$"Missing required domain runtime type (set via DomainApplication.CreateBuilder). " +
				$"Cirreum.Authentication requires the host to declare its DomainRuntimeType " +
				$"so audience-based providers can branch between WebApi and WebApp host shapes.");
		}
		var providerType = runtimeType switch {
			DomainRuntimeType.WebApi => ProviderRuntimeType.WebApi,
			DomainRuntimeType.WebApp => ProviderRuntimeType.WebApp,
			_ => throw new InvalidOperationException(
				$"Cirreum.Authentication is supported in WebApi or WebApp runtimes only. " +
				$"Current runtime: {runtimeType}.")
		};
		ProviderContext.SetRuntimeType(providerType);

		// 2. ASP.NET Core authentication services — dynamic forward scheme as default.
		var authBuilder = builder.Services.AddAuthentication(options => {
			options.DefaultScheme = AuthenticationSchemes.Dynamic;
			options.DefaultAuthenticateScheme = AuthenticationSchemes.Dynamic;
			options.DefaultChallengeScheme = AuthenticationSchemes.Dynamic;
			authentication?.Invoke(options);
		});

		// 3. Framework-shipped handlers + selectors + audience map.
		RegisterFrameworkShippedHandlers(authBuilder);
		RegisterFrameworkShippedSelectors(builder.Services);

		// 4. Dynamic forward PolicyScheme — dispatches to the right scheme per request.
		authBuilder.AddPolicyScheme(
			AuthenticationSchemes.Dynamic,
			"Cirreum dynamic forward scheme",
			options => {
				options.ForwardDefaultSelector = SchemeResolver.Resolve;
			});

		// 5. Claims transformer — runs after ASP.NET authentication completes,
		//    dispatches to a per-scheme IApplicationUserResolver registered by the app.
		builder.Services.AddAudienceRoleClaimsTransformation();

		// 6. Compose every framework-shipped registrar. Each call reads its
		//    provider's configuration section and bails appropriately when missing.
		RegisterFrameworkShippedProviders(builder, authBuilder);

		// 7. App-supplied provider composition (e.g. AddApiKey()), dynamic-resolver,
		//    and per-scheme application-user-resolver registrations.
		var cirreumBuilder = new CirreumAuthenticationBuilder(
			builder.Services, authBuilder, builder.Configuration);
		configure?.Invoke(cirreumBuilder);

		// 8. Predefined authorization policies (System + Standard family) —
		//    TODO: re-add when AuthorizationPolicies + ApplicationRoles constants
		//    land in their new home. The legacy Cirreum.Core (which used to host
		//    them) is being archived; the new home is TBD and this umbrella will
		//    register the policies against whatever lands.

		// 9. Boot-time Bearer-prefix uniqueness validation. Builds a throwaway SP to
		//    enumerate IBearerSchemeSelector registrations after every scheme registrar
		//    and the configure callback have contributed.
		// TODO:
		//	 Find a way to not have to build a throwaway SP here. The need to do so is
		//	 a smell that the validation is too tightly coupled to the DI setup; ideally
		//	 we could validate the selectors without having to build an SP and resolve
		//	 them from the container.
		using (var sp = builder.Services.BuildServiceProvider()) {
			var bearerSelectors = sp.GetServices<IBearerSchemeSelector>();
			BearerSchemeValidator.Validate(bearerSelectors);
		}

		return cirreumBuilder;
	}

	private static void RegisterFrameworkShippedHandlers(AuthenticationBuilder authBuilder) {

		authBuilder.AddScheme<AuthenticationSchemeOptions, AnonymousAuthenticationHandler>(
			AuthenticationSchemes.Anonymous, _ => { });

		authBuilder.AddScheme<AmbiguousRequestAuthenticationOptions, AmbiguousRequestAuthenticationHandler>(
			AuthenticationSchemes.Ambiguous, _ => { });
	}

	private static void RegisterFrameworkShippedSelectors(IServiceCollection services) {

		// Audience scheme map — single shared instance, written to by audience-based
		// registrars during their per-instance registration.
		services.TryAddSingleton<IAudienceSchemeMap, DefaultAudienceSchemeMap>();

		// Conflict sentinel — runs first (Priority=0), detects cross-carrier conflicts.
		services.TryAddSingleton<ConflictSentinelSchemeSelector>();
		services.AddSingleton<ISchemeSelector>(sp =>
			sp.GetRequiredService<ConflictSentinelSchemeSelector>());

		// JWT-audience routing selector — Priority=900 (Audience), runs after scheme
		// selectors but before Anonymous fallback.
		services.TryAddSingleton<JwtAudienceSchemeSelector>();
		services.AddSingleton<ISchemeSelector>(sp =>
			sp.GetRequiredService<JwtAudienceSchemeSelector>());

		// Anonymous catch-all — runs last (Priority=999), always claims.
		services.TryAddSingleton<AnonymousAuthenticationSchemeSelector>();
		services.AddSingleton<ISchemeSelector>(sp =>
			sp.GetRequiredService<AnonymousAuthenticationSchemeSelector>());
	}

	private static void RegisterFrameworkShippedProviders(
		IHostApplicationBuilder builder,
		AuthenticationBuilder authBuilder) {

		// ApiKey, SignedRequest, and SessionTicket are composed by the app via
		// auth.AddApiKey(...) / auth.AddSignedRequest<T>(...) / auth.AddSessionTicket(...)
		// inside the configure callback (app-composition model) — they are intentionally
		// NOT auto-registered here. The remaining audience providers still auto-register
		// from their appsettings sections pending their own conversion to the AddXxx()
		// verb shape.
		builder.RegisterAuthenticationProvider<
			OidcAuthenticationRegistrar,
			OidcAuthenticationSettings,
			OidcAuthenticationInstanceSettings>(authBuilder);

		builder.RegisterAuthenticationProvider<
			EntraAuthenticationRegistrar,
			EntraAuthenticationSettings,
			EntraAuthenticationInstanceSettings>(authBuilder);

		builder.RegisterAuthenticationProvider<
			ExternalAuthenticationRegistrar,
			ExternalAuthenticationSettings,
			ExternalAuthenticationInstanceSettings>(authBuilder);
	}

}
