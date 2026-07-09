namespace Cirreum.Authentication.Events;

using Cirreum.Startup;
using Microsoft.Extensions.DependencyInjection;

/// <summary>
/// System initializer that initializes the <see cref="AuthenticationEventRegistry"/> and
/// opens the inbound auth-event subscription during host startup.
/// </summary>
/// <remarks>
/// Discovered and registered by the <see cref="ISystemInitializer"/> startup scan
/// whenever this assembly is loaded; resolves the registry lazily and no-ops when
/// <c>auth.AddEventCoordination()</c> was never called. Running in the system-initializer
/// phase — before any <c>IHostedService</c> starts — guarantees the subscription is live
/// before a scheme's boot hydrator (e.g. the ApiKey revocation hydrator) snapshots its
/// store, closing the startup race by construction.
/// </remarks>
internal sealed class AuthenticationEventCoordinationBootstrap : ISystemInitializer {

	/// <inheritdoc/>
	public async ValueTask RunAsync(IServiceProvider serviceProvider) {

		var registry = serviceProvider.GetService<AuthenticationEventRegistry>();
		if (registry is null) {
			return;
		}

		await registry.InitializeAsync().ConfigureAwait(false);

		await serviceProvider
			.GetRequiredService<AuthenticationEventReceiver>()
			.SubscribeAsync()
			.ConfigureAwait(false);
	}

}
