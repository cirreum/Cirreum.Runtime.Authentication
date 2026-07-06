namespace Cirreum.Runtime.Authentication.Tests.Events;

using Cirreum.Authentication.Events;
using Cirreum.Coordination;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging.Abstractions;
using System.Text;
using System.Text.Json;

/// <summary>
/// Tests for <see cref="AuthenticationEventInboundSubscriber"/> — inbound wire dispatch.
/// Uses the real in-process <c>ISignalBroadcaster</c> (via <c>AddCoordination()</c>) so
/// signals flow through the genuine subscribe path. Its in-memory implementation awaits
/// subscribers inline, so a subscriber fault would surface as a throw from
/// <c>PublishAsync</c> — the hostile-input tests assert exactly that it never does.
/// </summary>
public class AuthenticationEventInboundSubscriberTests {

	private sealed class Recorder : IAuthenticationEventHandler<CredentialRevoked> {
		public List<CredentialRevoked> Events { get; } = [];
		public ValueTask HandleAsync(CredentialRevoked evt, CancellationToken cancellationToken = default) {
			this.Events.Add(evt);
			return ValueTask.CompletedTask;
		}
	}

	private sealed class ThrowingRecorder : IAuthenticationEventHandler<CredentialRevoked> {
		public int Invocations;
		public ValueTask HandleAsync(CredentialRevoked evt, CancellationToken cancellationToken = default) {
			this.Invocations++;
			throw new InvalidOperationException("inbound boom");
		}
	}

	private sealed class WireObservingBridge
		: IAuthenticationEventHandler<CredentialRevoked>, IAuthenticationEventTransportBridge {
		public int Invocations;
		public ValueTask HandleAsync(CredentialRevoked evt, CancellationToken cancellationToken = default) {
			this.Invocations++;
			return ValueTask.CompletedTask;
		}
	}

	private static async Task<(ISignalBroadcaster Broadcaster, ServiceProvider Provider)>
		CreateSubscribedAsync(Action<IServiceCollection> configure) {

		var services = new ServiceCollection();
		services.AddCoordination();
		configure(services);
		var provider = services.BuildServiceProvider();

		var registry = new AuthenticationEventRegistry(
			NullLogger<AuthenticationEventRegistry>.Instance);
		await registry.InitializeAsync();

		var subscriber = new AuthenticationEventInboundSubscriber(
			provider.GetRequiredService<ISignalBroadcaster>(),
			registry,
			provider.GetRequiredService<IServiceScopeFactory>(),
			NullLogger<AuthenticationEventInboundSubscriber>.Instance);
		await subscriber.SubscribeAsync();

		return (provider.GetRequiredService<ISignalBroadcaster>(), provider);
	}

	private static byte[] EnvelopeFor(CredentialRevoked evt) =>
		JsonSerializer.SerializeToUtf8Bytes(new AuthenticationEventEnvelope(
			"authentication.credential-revoked",
			"1",
			JsonSerializer.SerializeToElement(evt)));

	[Fact]
	public async Task InboundEnvelope_DispatchesToLocalConsumers_Typed() {
		var recorder = new Recorder();
		var (broadcaster, provider) = await CreateSubscribedAsync(services =>
			services.AddSingleton<IAuthenticationEventHandler<CredentialRevoked>>(recorder));
		using var _ = provider;
		var evt = new CredentialRevoked("cred-7", "sub-7", DateTimeOffset.UtcNow) { Reason = "test" };

		await broadcaster.PublishAsync("cirreum:_auth-events", EnvelopeFor(evt));

		recorder.Events.Should().ContainSingle().Which.Should().Be(evt);
	}

	[Fact]
	public async Task InboundEnvelope_NeverDispatchesToBridges() {
		var recorder = new Recorder();
		var bridge = new WireObservingBridge();
		var (broadcaster, provider) = await CreateSubscribedAsync(services => {
			services.AddSingleton<IAuthenticationEventHandler<CredentialRevoked>>(recorder);
			services.AddSingleton<IAuthenticationEventHandler<CredentialRevoked>>(bridge);
		});
		using var _ = provider;

		await broadcaster.PublishAsync(
			"cirreum:_auth-events",
			EnvelopeFor(new CredentialRevoked("cred-1", "sub-1", DateTimeOffset.UtcNow)));

		recorder.Events.Should().HaveCount(1);
		bridge.Invocations.Should().Be(0);
	}

	[Fact]
	public async Task MalformedJson_IsDroppedWithoutFaultingTheSubscription() {
		var recorder = new Recorder();
		var (broadcaster, provider) = await CreateSubscribedAsync(services =>
			services.AddSingleton<IAuthenticationEventHandler<CredentialRevoked>>(recorder));
		using var _ = provider;

		await broadcaster.PublishAsync("cirreum:_auth-events", Encoding.UTF8.GetBytes("not json {{{{"));
		// The subscription must still be live — a valid envelope after garbage dispatches.
		await broadcaster.PublishAsync(
			"cirreum:_auth-events",
			EnvelopeFor(new CredentialRevoked("cred-2", "sub-2", DateTimeOffset.UtcNow)));

		recorder.Events.Should().HaveCount(1);
	}

	[Fact]
	public async Task EnvelopeWithoutPayload_IsDroppedWithoutFaultingTheSubscription() {
		var recorder = new Recorder();
		var (broadcaster, provider) = await CreateSubscribedAsync(services =>
			services.AddSingleton<IAuthenticationEventHandler<CredentialRevoked>>(recorder));
		using var _ = provider;

		// A syntactically valid envelope with no Payload member: JsonElement's default
		// ValueKind is Undefined, and Deserialize on it throws a NON-JsonException —
		// this must be gated, not escape into the (logger-free, on Redis) pump.
		await broadcaster.PublishAsync(
			"cirreum:_auth-events",
			Encoding.UTF8.GetBytes("""{"Identifier":"authentication.credential-revoked","Version":"1"}"""));

		recorder.Events.Should().BeEmpty();
	}

	[Fact]
	public async Task UnknownIdentity_IsDropped() {
		var recorder = new Recorder();
		var (broadcaster, provider) = await CreateSubscribedAsync(services =>
			services.AddSingleton<IAuthenticationEventHandler<CredentialRevoked>>(recorder));
		using var _ = provider;
		var payload = JsonSerializer.SerializeToUtf8Bytes(new AuthenticationEventEnvelope(
			"authentication.from-the-future", "7", JsonSerializer.SerializeToElement(new { })));

		await broadcaster.PublishAsync("cirreum:_auth-events", payload);

		recorder.Events.Should().BeEmpty();
	}

	[Fact]
	public async Task MismatchedPayload_IsDropped() {
		var recorder = new Recorder();
		var (broadcaster, provider) = await CreateSubscribedAsync(services =>
			services.AddSingleton<IAuthenticationEventHandler<CredentialRevoked>>(recorder));
		using var _ = provider;
		// Known identity, but a payload whose shape can't construct the record.
		var payload = JsonSerializer.SerializeToUtf8Bytes(new AuthenticationEventEnvelope(
			"authentication.credential-revoked", "1",
			JsonSerializer.SerializeToElement(42)));

		await broadcaster.PublishAsync("cirreum:_auth-events", payload);

		recorder.Events.Should().BeEmpty();
	}

	[Fact]
	public async Task ThrowingInboundHandler_IsIsolated_OtherHandlersStillRun() {
		var throwing = new ThrowingRecorder();
		var recorder = new Recorder();
		var (broadcaster, provider) = await CreateSubscribedAsync(services => {
			services.AddSingleton<IAuthenticationEventHandler<CredentialRevoked>>(throwing);
			services.AddSingleton<IAuthenticationEventHandler<CredentialRevoked>>(recorder);
		});
		using var _ = provider;

		await broadcaster.PublishAsync(
			"cirreum:_auth-events",
			EnvelopeFor(new CredentialRevoked("cred-3", "sub-3", DateTimeOffset.UtcNow)));

		throwing.Invocations.Should().Be(1);
		recorder.Events.Should().HaveCount(1);
	}

}
