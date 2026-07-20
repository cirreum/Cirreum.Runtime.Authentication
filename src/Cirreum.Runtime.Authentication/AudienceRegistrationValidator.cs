namespace Cirreum.Authentication;

using Cirreum.AuthenticationProvider;
using Cirreum.Logging.Deferred;
using Microsoft.Extensions.DependencyInjection;

/// <summary>
/// Composition-close validation of the <see cref="AudienceSchemeRegistration"/> set
/// contributed by audience-based registrars (and any app-registered entries). One
/// audience claimed by two different schemes fails the host with every collision
/// reported; a clean set is logged so the live audience routing table is visible at
/// startup.
/// </summary>
/// <remarks>
/// Runs against the service collection — entries are instance descriptors, so the
/// complete set is readable without building a container (the same pattern
/// <see cref="BearerSchemeValidator"/> uses for bearer-prefix uniqueness).
/// </remarks>
internal static class AudienceRegistrationValidator {

	internal static void Validate(IServiceCollection services) {

		var registrations = services
			.Select(descriptor => descriptor.ImplementationInstance)
			.OfType<AudienceSchemeRegistration>()
			.Distinct()
			.ToList();

		if (registrations.Count == 0) {
			return;
		}

		var conflicts = registrations
			.GroupBy(r => r.Audience, StringComparer.OrdinalIgnoreCase)
			.Where(group => group.Select(r => r.Scheme).Distinct(StringComparer.Ordinal).Count() > 1)
			.Select(group =>
				$"audience '{group.Key}' is claimed by " +
				string.Join(" and ", group.Select(r => $"scheme '{r.Scheme}' (provider {r.ProviderName})")))
			.ToList();

		if (conflicts.Count > 0) {
			throw new InvalidOperationException(
				"Conflicting audience registrations — each audience must be owned by exactly one " +
				"authentication scheme: " + string.Join("; ", conflicts) + ". Fix the configuration " +
				"so no two provider instances share an Audience.");
		}

		var deferredLogger = Logger.CreateDeferredLogger();
		deferredLogger.LogInformation(
			"Audience routing: {Registrations}.",
			string.Join(", ", registrations
				.OrderBy(r => r.Audience, StringComparer.OrdinalIgnoreCase)
				.Select(r => $"'{r.Audience}' → {r.Scheme} ({r.ProviderName})")));
	}

}
