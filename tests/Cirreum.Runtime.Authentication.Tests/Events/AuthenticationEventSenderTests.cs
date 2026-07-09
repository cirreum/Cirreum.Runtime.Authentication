namespace Cirreum.Runtime.Authentication.Tests.Events;

using Cirreum.Authentication.Events;
using Cirreum.Coordination;
using Microsoft.Extensions.Logging.Abstractions;
using System.Text.Json;

/// <summary>
/// Tests for <see cref="AuthenticationEventSender{TEvent}"/> — the outbound wire leg.
/// Verifies the envelope round-trip, the channel constant, and the inbound-dispatch
/// suppression (second line of defense against wire re-entry).
/// </summary>
public class AuthenticationEventSenderTests {

	private static async Task<AuthenticationEventRegistry> CreateInitializedRegistryAsync() {
		var registry = new AuthenticationEventRegistry(
			NullLogger<AuthenticationEventRegistry>.Instance);
		await registry.InitializeAsync();
		return registry;
	}

	[Fact]
	public async Task HandleAsync_PublishesEnvelope_OnTheAuthEventChannel_RoundTrippable() {
		var registry = await CreateInitializedRegistryAsync();
		string? channel = null;
		byte[]? published = null;
		var broadcaster = Substitute.For<ISignalBroadcaster>();
		broadcaster
			.PublishAsync(
				Arg.Do<string>(c => channel = c),
				Arg.Do<ReadOnlyMemory<byte>>(p => published = p.ToArray()),
				Arg.Any<CancellationToken>())
			.Returns(ValueTask.CompletedTask);
		var sender = new AuthenticationEventSender<CredentialRevoked>(registry, broadcaster);
		var evt = new CredentialRevoked("cred-9", "sub-9", DateTimeOffset.UtcNow) {
			CredentialType = "apikey",
			ExpiresAt = DateTimeOffset.UtcNow.AddHours(1),
		};

		await sender.HandleAsync(evt);

		channel.Should().Be("cirreum:_auth-events");
		published.Should().NotBeNull();
		var envelope = JsonSerializer.Deserialize<AuthenticationEventEnvelope>(published)!;
		envelope.Identifier.Should().Be("authentication.credential-revoked");
		envelope.Version.Should().Be("1");
		var roundTripped = envelope.Payload.Deserialize<CredentialRevoked>()!;
		roundTripped.Should().Be(evt);
	}

	[Fact]
	public async Task HandleAsync_DuringInboundDispatch_RefusesToForward() {
		var registry = await CreateInitializedRegistryAsync();
		var broadcaster = Substitute.For<ISignalBroadcaster>();
		var sender = new AuthenticationEventSender<CredentialRevoked>(registry, broadcaster);

		AuthenticationEventDispatchScope.EnterInboundDispatch();
		try {
			await sender.HandleAsync(new CredentialRevoked("cred-1", "sub-1", DateTimeOffset.UtcNow));
		} finally {
			AuthenticationEventDispatchScope.ExitInboundDispatch();
		}

		await broadcaster.DidNotReceiveWithAnyArgs()
			.PublishAsync(default!, default, default);
	}

	[Fact]
	public async Task HandleAsync_UnversionedEventType_ThrowsPermanentConfigurationError() {
		var registry = await CreateInitializedRegistryAsync();
		var broadcaster = Substitute.For<ISignalBroadcaster>();
		var sender = new AuthenticationEventSender<UnversionedEvent>(registry, broadcaster);

		var act = () => sender.HandleAsync(new UnversionedEvent(DateTimeOffset.UtcNow)).AsTask();

		(await act.Should().ThrowAsync<InvalidOperationException>())
			.Which.Message.Should().Contain("permanent configuration error");
		await broadcaster.DidNotReceiveWithAnyArgs().PublishAsync(default!, default, default);
	}

	[Fact]
	public async Task HandleAsync_IsRegisteredAsBridgeMarker() {
		var registry = await CreateInitializedRegistryAsync();
		var sender = new AuthenticationEventSender<CredentialRevoked>(
			registry, Substitute.For<ISignalBroadcaster>());

		sender.Should().BeAssignableTo<IAuthenticationEventTransportBridge>();
		await Task.CompletedTask;
	}

}
