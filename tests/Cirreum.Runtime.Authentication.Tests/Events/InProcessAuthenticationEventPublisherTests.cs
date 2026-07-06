namespace Cirreum.Runtime.Authentication.Tests.Events;

using Cirreum.Authentication.Events;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging.Abstractions;

/// <summary>
/// Tests for <see cref="InProcessAuthenticationEventPublisher"/> — dispatch order
/// (consumers before bridges), per-handler isolation, and the surface-failures-to-caller
/// contract.
/// </summary>
public class InProcessAuthenticationEventPublisherTests {

	private static CredentialRevoked Event() =>
		new("cred-1", "sub-1", DateTimeOffset.UtcNow);

	private static InProcessAuthenticationEventPublisher CreatePublisher(
		Action<IServiceCollection> configure,
		out ServiceProvider provider) {
		var services = new ServiceCollection();
		configure(services);
		provider = services.BuildServiceProvider();
		return new InProcessAuthenticationEventPublisher(
			provider.GetRequiredService<IServiceScopeFactory>(),
			NullLogger<InProcessAuthenticationEventPublisher>.Instance);
	}

	[Fact]
	public async Task PublishAsync_NoHandlers_Completes() {
		var publisher = CreatePublisher(_ => { }, out var provider);
		using var _ = provider;

		await publisher.PublishAsync(Event());
	}

	[Fact]
	public async Task PublishAsync_DispatchesConsumersBeforeBridges() {
		var order = new List<string>();
		var publisher = CreatePublisher(services => {
			// Register the bridge FIRST so registration order can't be what passes the test.
			services.AddSingleton<IAuthenticationEventHandler<CredentialRevoked>>(
				new RecordingBridge(order));
			services.AddSingleton<IAuthenticationEventHandler<CredentialRevoked>>(
				new RecordingConsumer(order, "consumer-1"));
			services.AddSingleton<IAuthenticationEventHandler<CredentialRevoked>>(
				new RecordingConsumer(order, "consumer-2"));
		}, out var provider);
		using var _ = provider;

		await publisher.PublishAsync(Event());

		order.Should().Equal("consumer-1", "consumer-2", "bridge");
	}

	[Fact]
	public async Task PublishAsync_ThrowingConsumer_IsIsolated_RestStillRun_FailureSurfaced() {
		var order = new List<string>();
		var publisher = CreatePublisher(services => {
			services.AddSingleton<IAuthenticationEventHandler<CredentialRevoked>>(
				new ThrowingConsumer());
			services.AddSingleton<IAuthenticationEventHandler<CredentialRevoked>>(
				new RecordingConsumer(order, "survivor"));
			services.AddSingleton<IAuthenticationEventHandler<CredentialRevoked>>(
				new RecordingBridge(order));
		}, out var provider);
		using var _ = provider;

		var act = () => publisher.PublishAsync(Event()).AsTask();

		var thrown = await act.Should().ThrowAsync<AggregateException>();
		thrown.Which.InnerExceptions.Should().ContainSingle()
			.Which.Should().BeOfType<InvalidOperationException>();
		// The throwing consumer stopped nothing — the surviving consumer AND the
		// bridge both still ran, in order.
		order.Should().Equal("survivor", "bridge");
	}

	[Fact]
	public async Task PublishAsync_ThrowingBridge_FailureSurfaced_AfterConsumersApplied() {
		var order = new List<string>();
		var publisher = CreatePublisher(services => {
			services.AddSingleton<IAuthenticationEventHandler<CredentialRevoked>>(
				new RecordingConsumer(order, "consumer"));
			services.AddSingleton<IAuthenticationEventHandler<CredentialRevoked>>(
				new ThrowingBridge());
		}, out var provider);
		using var _ = provider;

		var act = () => publisher.PublishAsync(Event()).AsTask();

		await act.Should().ThrowAsync<AggregateException>();
		order.Should().Equal("consumer");
	}

	[Fact]
	public async Task PublishAsync_LessDerivedStaticBinding_StillReachesConcreteHandlers() {
		var order = new List<string>();
		var publisher = CreatePublisher(services => {
			services.AddSingleton<IAuthenticationEventHandler<CredentialRevoked>>(
				new RecordingConsumer(order, "concrete"));
		}, out var provider);
		using var _ = provider;

		// Publish through the interface binding — e.g. iterating a heterogeneous
		// List<IAuthenticationEvent>. Dispatch must key on the runtime type.
		IAuthenticationEvent evt = Event();
		await publisher.PublishAsync(evt);

		order.Should().Equal("concrete");
	}

	[Fact]
	public async Task PublishAsync_CallerCancellation_PropagatesAsCancellation() {
		using var cts = new CancellationTokenSource();
		var publisher = CreatePublisher(services => {
			services.AddSingleton<IAuthenticationEventHandler<CredentialRevoked>>(
				new CancellingConsumer(cts));
		}, out var provider);
		using var _ = provider;

		var act = () => publisher.PublishAsync(Event(), cts.Token).AsTask();

		await act.Should().ThrowAsync<OperationCanceledException>();
	}

	private sealed class RecordingConsumer(List<string> order, string name)
		: IAuthenticationEventHandler<CredentialRevoked> {
		public ValueTask HandleAsync(CredentialRevoked evt, CancellationToken cancellationToken = default) {
			order.Add(name);
			return ValueTask.CompletedTask;
		}
	}

	private sealed class RecordingBridge(List<string> order)
		: IAuthenticationEventHandler<CredentialRevoked>, IAuthenticationEventTransportBridge {
		public ValueTask HandleAsync(CredentialRevoked evt, CancellationToken cancellationToken = default) {
			order.Add("bridge");
			return ValueTask.CompletedTask;
		}
	}

	private sealed class ThrowingConsumer : IAuthenticationEventHandler<CredentialRevoked> {
		public ValueTask HandleAsync(CredentialRevoked evt, CancellationToken cancellationToken = default) =>
			throw new InvalidOperationException("consumer boom");
	}

	private sealed class ThrowingBridge
		: IAuthenticationEventHandler<CredentialRevoked>, IAuthenticationEventTransportBridge {
		public ValueTask HandleAsync(CredentialRevoked evt, CancellationToken cancellationToken = default) =>
			throw new InvalidOperationException("bridge boom");
	}

	private sealed class CancellingConsumer(CancellationTokenSource cts)
		: IAuthenticationEventHandler<CredentialRevoked> {
		public ValueTask HandleAsync(CredentialRevoked evt, CancellationToken cancellationToken = default) {
			cts.Cancel();
			cancellationToken.ThrowIfCancellationRequested();
			return ValueTask.CompletedTask;
		}
	}

}
