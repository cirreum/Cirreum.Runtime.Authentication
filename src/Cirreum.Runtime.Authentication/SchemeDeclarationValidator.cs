namespace Cirreum.Authentication;

using Cirreum.Logging.Deferred;
using Cirreum.Security;
using Microsoft.Extensions.DependencyInjection;

/// <summary>
/// Composition-close validation of the <see cref="SchemeClaimAuthorityRegistration"/> set
/// contributed by the scheme registrars (and any app-declared entries). One scheme declared
/// two different ways fails the host with every conflict reported; a clean set is logged so
/// the live declaration table is visible at startup.
/// </summary>
/// <remarks>
/// <para>
/// Identical duplicate declarations are legal and collapse silently: a platform-default
/// scheme is commonly declared by more than one provider, and two providers stating the same
/// thing is agreement, not conflict.
/// </para>
/// <para>
/// An undeclared scheme is also legal. Every reader resolves
/// <see cref="SchemeClaimAuthority.Undeclared"/> for one and applies the behaviour that
/// predates declarations, so a host that declares nothing keeps working.
/// </para>
/// </remarks>
internal static class SchemeDeclarationValidator {

	internal static void Validate(IServiceCollection services) {

		var registrations = services
			.Select(descriptor => descriptor.ImplementationInstance)
			.OfType<SchemeClaimAuthorityRegistration>()
			.Distinct()
			.ToList();

		if (registrations.Count == 0) {
			return;
		}

		// Distinct() above already collapsed identical declarations — the record's value
		// equality is what makes "two providers said the same thing" a non-event. Anything
		// still sharing a scheme name here genuinely disagrees.
		var conflicts = registrations
			.GroupBy(r => r.Scheme, StringComparer.Ordinal)
			.Where(group => group.Skip(1).Any())
			.Select(group =>
				$"scheme '{group.Key}' is declared as " +
				string.Join(" and ", group.Select(Describe)))
			.ToList();

		if (conflicts.Count > 0) {
			throw new InvalidOperationException(
				"Conflicting authentication scheme declarations — each scheme must be declared " +
				"exactly one way: " + string.Join("; ", conflicts) + ". Fix the composition so no " +
				"two declarations of a scheme disagree.");
		}

		var deferredLogger = Logger.CreateDeferredLogger();
		deferredLogger.LogInformation(
			"Scheme declarations: {Registrations}.",
			string.Join(", ", registrations
				.OrderBy(r => r.Scheme, StringComparer.Ordinal)
				.Select(r => $"'{r.Scheme}' → {Describe(r)}")));
	}

	private static string Describe(SchemeClaimAuthorityRegistration registration) =>
		$"{registration.SubjectKind} (profile {registration.Profile}, roles {registration.Roles})";

}
