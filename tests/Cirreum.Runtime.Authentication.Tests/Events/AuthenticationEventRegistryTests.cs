namespace Cirreum.Runtime.Authentication.Tests.Events;

using Cirreum.Authentication.Events;
using Microsoft.Extensions.Logging.Abstractions;

/// <summary>
/// Tests for <see cref="AuthenticationEventRegistry"/> — both lookup directions over the
/// four framework events, and the miss behavior for unknown wire identities.
/// </summary>
public class AuthenticationEventRegistryTests {

	private static async Task<AuthenticationEventRegistry> CreateInitializedAsync() {
		var registry = new AuthenticationEventRegistry(
			NullLogger<AuthenticationEventRegistry>.Instance);
		await registry.InitializeAsync();
		return registry;
	}

	[Theory]
	[InlineData("authentication.credential-revoked", "1", typeof(CredentialRevoked))]
	[InlineData("authentication.user-account-disabled", "1", typeof(UserAccountDisabled))]
	[InlineData("authentication.session-termination-requested", "1", typeof(SessionTerminationRequested))]
	[InlineData("authentication.grants-invalidated", "1", typeof(GrantsInvalidated))]
	public async Task ResolveType_ResolvesEveryFrameworkEvent(
		string identifier, string version, Type expected) {
		var registry = await CreateInitializedAsync();

		var eventType = registry.ResolveType(identifier, version);

		eventType.Should().Be(expected);
	}

	[Fact]
	public async Task ResolveType_UnknownIdentifier_Misses() {
		var registry = await CreateInitializedAsync();

		registry.ResolveType("authentication.not-a-thing", "1").Should().BeNull();
	}

	[Fact]
	public async Task ResolveType_KnownIdentifierUnknownVersion_Misses() {
		var registry = await CreateInitializedAsync();

		registry.ResolveType("authentication.credential-revoked", "999").Should().BeNull();
	}

	[Fact]
	public async Task GetDefinitionFor_ReturnsWireIdentityForOutbound() {
		var registry = await CreateInitializedAsync();

		var definition = registry.GetDefinitionFor(typeof(CredentialRevoked));

		definition.Identifier.Should().Be("authentication.credential-revoked");
		definition.Version.Should().Be("1");
	}

}
