namespace Cirreum.Runtime.Authentication.Tests;

using Cirreum;
using Cirreum.Authentication;
using Cirreum.AuthenticationProvider;
using Cirreum.Security;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;

/// <summary>
/// End-to-end composition test for the declaration funnel: after <c>AddAuthentication()</c>,
/// an <see cref="ISchemeClaimAuthorityMap"/> is resolvable and already knows the framework's
/// own schemes plus anything the app declared. This is the switch the attribute-authority
/// work turns on — every reader downstream resolves declarations through this registration,
/// and without it they all fall back to pre-declaration behaviour.
/// </summary>
/// <remarks>
/// The host is composed <b>once</b> for the whole class: <c>ProviderContext.SetRuntimeType</c>
/// is process-global and one-shot by design, so a second <c>AddAuthentication()</c> in the
/// same test assembly throws. Conflict and duplicate handling are covered at the unit level
/// in <see cref="SchemeDeclarationTests"/>, which needs no composition.
/// </remarks>
public class AddAuthenticationDeclarationTests {

	private const string AppScheme = "descope";

	private static readonly Lazy<ISchemeClaimAuthorityMap> ComposedMap = new(() => {
		IHostApplicationBuilder builder = Host.CreateApplicationBuilder();
		builder.Properties[DomainContext.RuntimeTypeKey] = DomainRuntimeType.WebApi;
		builder.Configuration.AddInMemoryCollection(new Dictionary<string, string?> {
			["Cirreum:Authentication:PrimaryScheme"] = AppScheme,
		});

		builder.AddAuthentication(auth =>
			auth.DeclareScheme(AppScheme, SubjectKind.Human, roles: ClaimAuthority.ApplicationStore));

		return builder.Services.BuildServiceProvider()
			.GetRequiredService<ISchemeClaimAuthorityMap>();
	}, isThreadSafe: true);

	private static ISchemeClaimAuthorityMap Map => ComposedMap.Value;

	[Fact]
	public void AddAuthentication_registers_the_declaration_map() {
		Map.Should().NotBeNull().And.BeOfType<SchemeClaimAuthorityMap>();
	}

	[Theory]
	[InlineData(AuthenticationSchemes.Anonymous)]
	[InlineData(AuthenticationSchemes.Ambiguous)]
	[InlineData(AuthenticationSchemes.Dynamic)]
	public void The_frameworks_own_schemes_are_declared_Unknown(string scheme) {
		// None of the three authenticates a subject: two mint or reject, and the dynamic
		// scheme forwards to whichever scheme does. Declared rather than left undeclared so
		// they appear in the declaration table an operator reads.
		Map.Get(scheme).SubjectKind.Should().Be(SubjectKind.Unknown);
	}

	[Fact]
	public void An_app_declared_scheme_reaches_the_map() {
		var declaration = Map.Get(AppScheme);

		declaration.SubjectKind.Should().Be(SubjectKind.Human);
		declaration.Roles.Should().Be(ClaimAuthority.ApplicationStore);
	}

	[Fact]
	public void An_undeclared_scheme_resolves_Undeclared() {
		Map.Get("someOtherScheme").Should().Be(SchemeClaimAuthority.Undeclared);
	}

}
