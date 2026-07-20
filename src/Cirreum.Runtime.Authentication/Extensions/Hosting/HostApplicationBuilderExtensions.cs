namespace Microsoft.Extensions.Hosting;

using Cirreum;
using Cirreum.Authentication;
using Cirreum.Authentication.Configuration;
using Cirreum.Authentication.Events;
using Cirreum.AuthenticationProvider;
using Cirreum.Coordination;
using Cirreum.Logging.Deferred;
using Cirreum.Providers;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
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
	/// <returns>The <see cref="AuthorizationBuilder"/> — chain <c>.AddPolicy(...)</c> to register
	/// additional app-specific authorization policies alongside the predefined Cirreum policies.</returns>
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
	///   <item>Registers framework-shipped handlers (Anonymous, Ambiguous) + selectors (Conflict sentinel, Audience, Anonymous fallback).</item>
	///   <item>Registers the dynamic forward <c>PolicyScheme</c> with the <see cref="SchemeResolver.Resolve"/> callback.</item>
	///   <item>Calls <c>services.AddAudienceRoleClaimsTransformation()</c> to wire the claims transformer.</item>
	///   <item>Registers the default in-process <c>IAuthenticationEventPublisher</c> (replaceable via <c>TryAdd</c>); <c>auth.AddEventCoordination()</c> in the callback turns on cross-replica delivery.</item>
	///   <item>Invokes the app's <paramref name="configure"/> callback for provider composition (<c>AddApiKey</c>), dynamic-resolver, and application-user-resolver registrations — deliberately BEFORE audience auto-registration, so app-stashed seams (e.g. the Entra downstream-API callback) are in place when the audience registrars read them.</item>
	///   <item>Auto-registers the framework-shipped registrars that still bind from appsettings (Oidc, Entra, External) via the typed <c>RegisterAuthenticationProvider&lt;...&gt;()</c> helper. ApiKey, SignedRequest, and SessionTicket are excluded — the app composes them via <c>auth.AddApiKey(...)</c> / <c>auth.AddSignedRequest&lt;T&gt;(...)</c> / <c>auth.AddSessionTicket(...)</c> in the callback.</item>
	///   <item>Registers the predefined Cirreum authorization policies (<c>Standard</c>, <c>StandardAdmin</c>, etc.).</item>
	///   <item>Runs the boot-time <see cref="BearerSchemeValidator"/> — fails fast on cross-provider Bearer-prefix collisions.</item>
	/// </list>
	/// <para>
	/// Idempotent — calling multiple times on the same host returns without re-running.
	/// </para>
	/// </remarks>
	public static AuthorizationBuilder AddAuthentication(
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

		// 1. Map the host's DomainRuntimeType (set by the spine via DomainApplication.CreateBuilder) into the
		//    auth track's ProviderRuntimeType so audience-based registrars can branch on host shape
		//    (WebApi vs WebApp). The mapping is deliberate and lives here on purpose: the runtime type is
		//    only consumed by audience-based authentication, so translating DomainContext -> ProviderContext
		//    inside this method keeps the auth track independent of the spine. Required — no defensible default.
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

		// 5a. The auth-event bus default publisher. In-process, ordered
		//     dispatch: consumer handlers first, transport bridges last. A single-replica
		//     app is complete with this alone; auth.AddEventCoordination() in the
		//     configure callback turns on cross-replica delivery by registering the
		//     sender + inbound receiver this publisher composes with. TryAdd —
		//     an app-registered publisher wins.
		builder.Services.TryAddSingleton<IAuthenticationEventPublisher, InProcessAuthenticationEventPublisher>();

		// 6. App-supplied provider composition (e.g. AddApiKey()), dynamic-resolver, and per-scheme
		//    application-user-resolver registrations — runs BEFORE audience auto-registration so any
		//    app-stashed seam (e.g. the Entra downstream-API callback, stashed on the service collection
		//    by auth.EnableDownstreamApi(...)) is in place when the audience registrars read it.
		var cirreumBuilder = new CirreumAuthenticationBuilder(
			builder.Services, authBuilder, builder.Configuration);
		configure?.Invoke(cirreumBuilder);

		// 7. Compose every framework-shipped audience registrar. Each reads its configuration section
		//    (and any app-stashed seam) and bails appropriately when missing.
		RegisterFrameworkShippedProviders(builder, authBuilder);

		// 7a. Validate the complete audience → scheme registration set contributed by the
		//     configure callback and the audience registrars. One audience claimed by two
		//     different schemes fails composition with every collision reported; a clean
		//     set is logged so the live routing table is visible at startup.
		AudienceRegistrationValidator.Validate(builder.Services);

		// 8. Predefined Cirreum authorization policies (System + Standard family). Returns the
		//    AuthorizationBuilder so the app can chain additional .AddPolicy(...) calls.
		var authorizationBuilder = DefaultAuthorizationPolicyRegistration.Register(builder);

		// 9. Coordination posture: a scheme that pulled a coordination requirement (e.g. SignedRequest
		//    strict-nonce) but for which the app never chose a backend fails the host fast here — turning a
		//    silent mis-configuration into a clear startup error instead of a first-request failure. The
		//    sentinel is the signal, so this needs no per-scheme marker.
		CoordinationPostureValidator.Validate(builder.Services);

		// 9a. Advisory: the in-memory replay backend does not coordinate across instances — correct
		//     for single-node / development, but a multi-instance production deployment silently loses replay
		//     protection. The validator above proves only that *a* backend was chosen, not which, so surface a
		//     non-blocking notice when the in-memory backend is selected outside Development. This is Information,
		//     never a fail-fast (a deferred Warning is fatal, and single-node production on the in-memory backend
		//     is legitimate). The internal in-memory type is matched by name across the Cirreum.Coordination
		//     assembly boundary; a non-match just means no advisory — it is never load-bearing.
		var replayGuard = builder.Services.LastOrDefault(d => d.ServiceType == typeof(IReplayGuard));
		if (replayGuard?.ImplementationType?.Name == "InMemoryReplayGuard" && !builder.Environment.IsDevelopment()) {
			Logger.CreateDeferredLogger().LogInformation(
				"Coordination: the in-memory replay backend is selected outside Development. It does not " +
				"coordinate replay across instances — correct for a single-node deployment, but a multi-instance " +
				"deployment must register a distributed backend (Cirreum.Coordination.Redis via " +
				"auth.ConfigureCoordination(c => c.UseRedis())).");
		}

		// 10. Boot-time Bearer-prefix uniqueness validation, after the configure callback and audience
		//    auto-registration have contributed every scheme. Each Bearer-probing scheme registers its
		//    selector as a concrete singleton instance, so the selectors are read straight from the service
		//    collection here — no throwaway ServiceProvider (a second container would duplicate singletons,
		//    break scoped lifetimes, and resolve services before the real application container exists).
		var bearerSelectors = builder.Services
			.Select(descriptor => descriptor.ImplementationInstance)
			.OfType<IBearerSchemeSelector>()
			.Distinct()
			.ToList();
		BearerSchemeValidator.Validate(bearerSelectors);

		return authorizationBuilder;
	}

	private static void RegisterFrameworkShippedHandlers(AuthenticationBuilder authBuilder) {

		authBuilder.AddScheme<AuthenticationSchemeOptions, AnonymousAuthenticationHandler>(
			AuthenticationSchemes.Anonymous, _ => { });

		authBuilder.AddScheme<AmbiguousRequestAuthenticationOptions, AmbiguousRequestAuthenticationHandler>(
			AuthenticationSchemes.Ambiguous, _ => { });
	}

	private static void RegisterFrameworkShippedSelectors(IServiceCollection services) {

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
