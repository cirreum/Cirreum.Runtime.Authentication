namespace Cirreum.Authentication;

using Cirreum.Security;
using System.Collections.Frozen;

/// <summary>
/// The composed <see cref="ISchemeClaimAuthorityMap"/>, built once from the
/// <see cref="SchemeClaimAuthorityRegistration"/> entries the authentication providers
/// contributed during composition.
/// </summary>
/// <remarks>
/// <para>
/// Scheme names are compared ordinally, matching how ASP.NET Core keys its own scheme
/// registry: two names differing only by case are two schemes there, so a looser comparison
/// here would resolve a declaration belonging to a different scheme.
/// </para>
/// <para>
/// Identical duplicate registrations are expected — two providers may declare the same
/// platform-default scheme — and collapse to one entry. Conflicting registrations for one
/// scheme are rejected at composition by <see cref="SchemeDeclarationValidator"/>, so this
/// type never has to choose between them.
/// </para>
/// </remarks>
internal sealed class SchemeClaimAuthorityMap : ISchemeClaimAuthorityMap {

	private readonly FrozenDictionary<string, SchemeClaimAuthority> _declarations;

	public SchemeClaimAuthorityMap(IEnumerable<SchemeClaimAuthorityRegistration> registrations) {
		ArgumentNullException.ThrowIfNull(registrations);

		Dictionary<string, SchemeClaimAuthority> declarations = new(StringComparer.Ordinal);
		foreach (var registration in registrations) {
			if (string.IsNullOrWhiteSpace(registration.Scheme)) {
				continue;
			}

			declarations[registration.Scheme] = new SchemeClaimAuthority(
				registration.SubjectKind,
				registration.Profile,
				registration.Roles);
		}

		this._declarations = declarations.ToFrozenDictionary(StringComparer.Ordinal);
	}

	/// <inheritdoc/>
	public SchemeClaimAuthority Get(string? scheme) =>
		!string.IsNullOrWhiteSpace(scheme)
			&& this._declarations.TryGetValue(scheme, out var declaration)
				? declaration
				: SchemeClaimAuthority.Undeclared;

}
