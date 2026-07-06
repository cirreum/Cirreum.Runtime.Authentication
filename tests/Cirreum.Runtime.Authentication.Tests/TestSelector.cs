namespace Cirreum.Runtime.Authentication.Tests;

using Cirreum.AuthenticationProvider;
using Microsoft.AspNetCore.Http;

/// <summary>
/// Hand-rolled <see cref="ISchemeSelector"/> for tests — gives precise control over
/// Priority and TrySelect without mocking the interface. More readable than NSubstitute
/// setups for the simple shape this interface has.
/// </summary>
internal sealed class TestSelector(
	int priority = 0,
	bool matches = false,
	string? schemeName = null
) : ISchemeSelector {

	public int Priority => priority;
	public (bool Matches, string? SchemeName) TrySelect(HttpContext context) => (matches, schemeName);

}
