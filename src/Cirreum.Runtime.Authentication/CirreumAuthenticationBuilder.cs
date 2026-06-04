namespace Cirreum.Authentication;

using Cirreum;
using Cirreum.AuthenticationProvider;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;

/// <summary>
/// Concrete <see cref="IAuthenticationBuilder"/> implementation passed to the
/// <c>configure</c> callback of <c>AddAuthentication(configure?, authentication?)</c>.
/// Carries the DI service collection and the underlying ASP.NET Core
/// <see cref="AuthenticationBuilder"/> so the scheme extension methods can register schemes,
/// handlers, and selectors against the same composition surface the framework-shipped
/// registrars used.
/// </summary>
/// <remarks>
/// The scheme packages contribute extension methods on <see cref="IAuthenticationBuilder"/>:
/// <list type="bullet">
///   <item><c>AddApiKey(...)</c> — from <c>Cirreum.Authentication.ApiKey</c> (transport declaration + optional dynamic resolver)</item>
///   <item><c>AddSignedRequest&lt;T&gt;(...)</c> — from <c>Cirreum.Authentication.SignedRequest</c></item>
///   <item><c>AddExternalTenantResolver&lt;T&gt;(...)</c> — from <c>Cirreum.Authentication.External</c></item>
///   <item><c>AddApplicationUserResolver&lt;T&gt;(scheme)</c> — registered by this umbrella itself</item>
/// </list>
/// The builder surface is intentionally narrow — provider composition + dynamic
/// resolvers + per-scheme application-user resolvers. All other customization (custom session stores,
/// custom principal binders, custom signed-request algorithms, etc.) goes through
/// plain <c>IServiceCollection</c> registration; framework defaults register via
/// <c>TryAddSingleton</c> so app overrides win.
/// </remarks>
public sealed class CirreumAuthenticationBuilder(
	IServiceCollection services,
	AuthenticationBuilder authBuilder,
	IConfiguration configuration
) : IAuthenticationBuilder {

	/// <inheritdoc/>
	public IServiceCollection Services { get; } = services
		?? throw new ArgumentNullException(nameof(services));

	/// <inheritdoc/>
	public AuthenticationBuilder AuthBuilder { get; } = authBuilder
		?? throw new ArgumentNullException(nameof(authBuilder));

	/// <inheritdoc/>
	public IConfiguration Configuration { get; } = configuration
		?? throw new ArgumentNullException(nameof(configuration));

	/// <summary>
	/// Registers an <see cref="IApplicationUserResolver"/> implementation. May be
	/// called multiple times — one resolver per authentication scheme that needs to
	/// hydrate <see cref="IApplicationUser"/> from the app's data store at request
	/// time.
	/// </summary>
	/// <typeparam name="TResolver">The resolver implementation type. Its
	/// <see cref="IApplicationUserResolver.Scheme"/> property determines which
	/// authentication scheme it handles; the framework's claims transformer
	/// matches the request's
	/// <c>HttpContext.Items[AuthenticationContextKeys.AuthenticatedScheme]</c>
	/// against that value to dispatch. A resolver returning <see langword="null"/>
	/// from <see cref="IApplicationUserResolver.Scheme"/> acts as the default
	/// fallback — only one null-scheme resolver should be registered.</typeparam>
	/// <returns>The builder for chaining.</returns>
	/// <remarks>
	/// <para>
	/// The transformer
	/// (<c>AudienceProviderRoleClaimsTransformer</c> in
	/// <c>Cirreum.Runtime.AuthenticationProvider</c>) is registered automatically by
	/// the <c>AddAuthentication(...)</c> umbrella; calling this method just adds
	/// a resolver to the per-scheme dispatch set. Workforce-only apps that get
	/// roles directly from the IdP's JWT don't need to call this — the transformer
	/// is a no-op when no resolver matches the request's scheme.
	/// </para>
	/// </remarks>
	public CirreumAuthenticationBuilder AddApplicationUserResolver<TResolver>()
		where TResolver : class, IApplicationUserResolver {

		this.Services.AddScoped<IApplicationUserResolver, TResolver>();
		return this;
	}

}
