namespace Cirreum.Runtime.Authentication.Tests;

using Cirreum.Authentication;
using Cirreum.Invocation;
using Cirreum.Security;

public sealed class PrimarySchemeAuthenticationBoundaryResolverTests {

	private static IUserState Authenticated(bool authenticated = true) {
		var user = Substitute.For<IUserState>();
		user.IsAuthenticated.Returns(authenticated);
		return user;
	}

	[Fact]
	public void PrimaryScheme_IsGlobal() {
		var resolver = new PrimarySchemeAuthenticationBoundaryResolver("Cirreum.Entra");

		resolver.Resolve(Authenticated(), "cirreum.entra").Should().Be(AuthenticationBoundary.Global);
	}

	[Fact]
	public void HostScheme_IsGlobal() {
		var resolver = new PrimarySchemeAuthenticationBoundaryResolver("Cirreum.Entra");

		resolver.Resolve(Authenticated(), HostInvocationDefaults.Scheme).Should().Be(AuthenticationBoundary.Global);
	}

	[Fact]
	public void OtherScheme_IsTenant() {
		var resolver = new PrimarySchemeAuthenticationBoundaryResolver("Cirreum.Entra");

		resolver.Resolve(Authenticated(), "Cirreum.External").Should().Be(AuthenticationBoundary.Tenant);
	}

	[Fact]
	public void Unauthenticated_IsNone_EvenOnTheHostScheme() {
		var resolver = new PrimarySchemeAuthenticationBoundaryResolver("Cirreum.Entra");

		resolver.Resolve(Authenticated(false), HostInvocationDefaults.Scheme).Should().Be(AuthenticationBoundary.None);
	}

}
