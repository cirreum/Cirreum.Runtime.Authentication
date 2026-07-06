namespace Cirreum.Runtime.Authentication.Tests.Events;

using Cirreum;
using Cirreum.Authentication;
using Cirreum.Authentication.Events;
using Cirreum.Coordination;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;

/// <summary>
/// Composition tests for <c>auth.AddEventCoordination()</c> and full-loop integration
/// through the real in-process broadcaster — publish, self-echo, and the
/// wire-re-entry guard.
/// </summary>
public class AddEventCoordinationTests {

	private sealed class Recorder<TEvent> : IAuthenticationEventHandler<TEvent>
		where TEvent : IAuthenticationEvent {
		public List<TEvent> Events { get; } = [];
		public ValueTask HandleAsync(TEvent evt, CancellationToken cancellationToken = default) {
			this.Events.Add(evt);
			return ValueTask.CompletedTask;
		}
	}

	private static IServiceCollection CreateServices(
		string applicationName = "TestApp",
		string environmentName = "Production") {

		var services = new ServiceCollection();
		services.AddLogging(logging => logging.ClearProviders());
		var environment = Substitute.For<IDomainEnvironment>();
		environment.ApplicationName.Returns(applicationName);
		environment.EnvironmentName.Returns(environmentName);
		services.AddSingleton(environment);
		return services;
	}

	private static CirreumAuthenticationBuilder AuthBuilderOver(IServiceCollection services) =>
		new(services, new AuthenticationBuilder(services), new ConfigurationBuilder().Build());

	private static async Task<ServiceProvider> BuildAndBootstrapAsync(IServiceCollection services) {
		var provider = services.BuildServiceProvider();
		await new AuthenticationEventCoordinationBootstrap().RunAsync(provider);
		return provider;
	}

	[Fact]
	public void AddEventCoordination_RegistersTheBridge_AmongEventHandlers() {
		var services = CreateServices();
		AuthBuilderOver(services).AddEventCoordination();
		using var provider = services.BuildServiceProvider();

		var handlers = provider.GetServices<IAuthenticationEventHandler<CredentialRevoked>>();

		handlers.Should().ContainSingle(h => h is IAuthenticationEventTransportBridge);
	}

	[Fact]
	public void AddEventCoordination_DefaultsCoordinationScope_ToAppAndEnvironment() {
		var services = CreateServices("MyApp", "Staging");
		AuthBuilderOver(services).AddEventCoordination();
		using var provider = services.BuildServiceProvider();

		provider.GetService<CoordinationScope>()!.Value.Should().Be("MyApp:Staging");
	}

	[Fact]
	public void AddEventCoordination_ExplicitScope_Wins_RegardlessOfOrder() {
		// Explicit AFTER the default.
		var services1 = CreateServices();
		AuthBuilderOver(services1).AddEventCoordination();
		services1.AddCoordination(c => c.WithScope("explicit"));
		using var provider1 = services1.BuildServiceProvider();
		provider1.GetService<CoordinationScope>()!.Value.Should().Be("explicit");

		// Explicit BEFORE the default.
		var services2 = CreateServices();
		services2.AddCoordination(c => c.WithScope("explicit"));
		AuthBuilderOver(services2).AddEventCoordination();
		using var provider2 = services2.BuildServiceProvider();
		provider2.GetService<CoordinationScope>()!.Value.Should().Be("explicit");
	}

	[Fact]
	public void AddEventCoordination_IsIdempotent() {
		var services = CreateServices();
		var auth = AuthBuilderOver(services);
		auth.AddEventCoordination();
		auth.AddEventCoordination();
		using var provider = services.BuildServiceProvider();

		provider.GetServices<IAuthenticationEventHandler<CredentialRevoked>>()
			.Count(h => h is IAuthenticationEventTransportBridge)
			.Should().Be(1);
	}

	[Fact]
	public async Task Bootstrap_NoOps_WhenEventCoordinationWasNeverAdded() {
		using var provider = new ServiceCollection().BuildServiceProvider();

		// Must not throw — the bootstrap is discovered whenever the assembly is loaded,
		// including in apps that never call AddEventCoordination().
		await new AuthenticationEventCoordinationBootstrap().RunAsync(provider);
	}

	[Fact]
	public async Task FullLoop_PublishReachesConsumerDirectly_AndOnceMoreAsSelfEcho() {
		var services = CreateServices();
		var recorder = new Recorder<CredentialRevoked>();
		services.AddSingleton<IAuthenticationEventHandler<CredentialRevoked>>(recorder);
		services.AddSingleton<IAuthenticationEventPublisher, InProcessAuthenticationEventPublisher>();
		AuthBuilderOver(services).AddEventCoordination();
		using var provider = await BuildAndBootstrapAsync(services);
		var evt = new CredentialRevoked("cred-1", "sub-1", DateTimeOffset.UtcNow);

		await provider.GetRequiredService<IAuthenticationEventPublisher>().PublishAsync(evt);

		// Direct in-process dispatch + the loopback self-echo from the in-memory
		// broadcaster (a publishing replica is itself subscribed). Two, not more —
		// the echo's dispatch excludes bridges, so nothing re-enters the wire.
		recorder.Events.Should().HaveCount(2);
		recorder.Events.Should().AllSatisfy(e => e.Should().Be(evt));
	}

	[Fact]
	public async Task FullLoop_HandlerPublishingDuringInboundDispatch_ReachesLocalConsumersOnly() {
		var services = CreateServices();
		var grantsRecorder = new Recorder<GrantsInvalidated>();
		services.AddSingleton<IAuthenticationEventHandler<GrantsInvalidated>>(grantsRecorder);
		// A handler that (against guidance) publishes a follow-on event when it
		// receives CredentialRevoked from the wire.
		services.AddSingleton<IAuthenticationEventHandler<CredentialRevoked>>(sp =>
			new RepublishingHandler(sp.GetRequiredService<IAuthenticationEventPublisher>()));
		services.AddSingleton<IAuthenticationEventPublisher, InProcessAuthenticationEventPublisher>();
		AuthBuilderOver(services).AddEventCoordination();
		using var provider = await BuildAndBootstrapAsync(services);

		await provider.GetRequiredService<IAuthenticationEventPublisher>()
			.PublishAsync(new CredentialRevoked("cred-1", "sub-1", DateTimeOffset.UtcNow));

		// The CredentialRevoked publish reaches the republishing handler twice (direct +
		// self-echo). The direct pass is NOT inbound — its follow-on GrantsInvalidated
		// bridges to the wire and echoes back (2 deliveries). The echo pass IS inbound —
		// its follow-on publish is barred from the wire, so it lands exactly once,
		// locally. 2 + 1 = 3. Were the wire guard absent, the echo pass would also echo
		// (4+); were inbound publishing fully blocked, only 2.
		grantsRecorder.Events.Should().HaveCount(3);
	}

	private sealed class RepublishingHandler(IAuthenticationEventPublisher publisher)
		: IAuthenticationEventHandler<CredentialRevoked> {
		public async ValueTask HandleAsync(CredentialRevoked evt, CancellationToken cancellationToken = default) {
			await publisher.PublishAsync(
				new GrantsInvalidated(evt.Subject, evt.OccurredAt),
				cancellationToken);
		}
	}

}
