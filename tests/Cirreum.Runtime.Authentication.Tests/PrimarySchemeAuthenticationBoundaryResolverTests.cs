namespace Cirreum.Runtime.Authentication.Tests;

using Cirreum.Authentication;
using Cirreum.Security;

/// <summary>
/// Unit tests for <see cref="PrimarySchemeAuthenticationBoundaryResolver"/> — the
/// scheme-aware boundary classification: primary scheme → Global, any other
/// authenticated scheme → Tenant, unauthenticated → None.
/// </summary>
public class PrimarySchemeAuthenticationBoundaryResolverTests {

	private readonly PrimarySchemeAuthenticationBoundaryResolver _resolver = new("entraWorkforce");

	[Fact]
	public void Resolve_PrimaryScheme_IsGlobal() {
		var boundary = _resolver.Resolve(new TestUserState(isAuthenticated: true), "entraWorkforce");

		boundary.Should().Be(AuthenticationBoundary.Global);
	}

	[Fact]
	public void Resolve_PrimarySchemeMatch_IsCaseInsensitive() {
		var boundary = _resolver.Resolve(new TestUserState(isAuthenticated: true), "ENTRAWORKFORCE");

		boundary.Should().Be(AuthenticationBoundary.Global);
	}

	[Theory]
	[InlineData("descope")]
	[InlineData("entraExternal")]
	[InlineData("ApiKey")]
	[InlineData(null)]
	public void Resolve_NonPrimaryAuthenticatedScheme_IsTenant(string? scheme) {
		var boundary = _resolver.Resolve(new TestUserState(isAuthenticated: true), scheme);

		boundary.Should().Be(AuthenticationBoundary.Tenant);
	}

	[Theory]
	[InlineData("entraWorkforce")]
	[InlineData("descope")]
	[InlineData(null)]
	public void Resolve_Unauthenticated_IsNone(string? scheme) {
		var boundary = _resolver.Resolve(new TestUserState(isAuthenticated: false), scheme);

		boundary.Should().Be(AuthenticationBoundary.None);
	}

	private sealed class TestUserState : UserStateBase {

		public TestUserState(bool isAuthenticated) {
			this._isAuthenticated = isAuthenticated;
		}

		public override bool IsAuthenticationComplete => true;

	}

}
