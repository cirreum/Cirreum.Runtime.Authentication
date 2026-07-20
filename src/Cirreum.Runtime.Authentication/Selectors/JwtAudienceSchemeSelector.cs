namespace Cirreum.Authentication;

using Cirreum.AuthenticationProvider;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.Net.Http.Headers;
using System.Text.Json;

/// <summary>
/// Framework-shipped <see cref="ISchemeSelector"/> that routes JWT bearer requests
/// by inspecting the token's <c>aud</c> claim and looking up the matching scheme
/// in <see cref="IAudienceSchemeMap"/>. Registered at
/// <see cref="SchemeSelectorPriority.Audience"/> (900) so it runs after every
/// Cirreum-shipped scheme selector but before the Anonymous fallback.
/// </summary>
/// <remarks>
/// <para>
/// The selector does NOT validate the JWT —
/// it only routes the request to the right scheme name. The downstream handler
/// (registered by an <see cref="AudienceAuthenticationProviderRegistrar{TSettings, TInstanceSettings}"/>-derived
/// scheme — typically ASP.NET's <c>JwtBearer</c> wired via Microsoft Identity Web) does
/// the actual cryptographic validation.
/// </para>
/// <para>
/// Resolution rules:
/// </para>
/// <list type="number">
///   <item>Inbound has <c>Authorization: Bearer</c> with a JWT-shaped token: parse audience.</item>
///   <item>Audience is mapped via <see cref="IAudienceSchemeMap"/>: route to that scheme.</item>
///   <item>Audience is unmapped AND endpoint is <c>[AllowAnonymous]</c>: route to Anonymous (let the no-result handler run).</item>
///   <item>Audience is unmapped on a protected endpoint: route to Ambiguous (fail closed — genuine JWT, no owner).</item>
/// </list>
/// </remarks>
public sealed class JwtAudienceSchemeSelector(
	IAudienceSchemeMap audienceMap
) : ISchemeSelector {

	private const string BearerPrefixToken = "Bearer ";

	/// <inheritdoc/>
	public int Priority => SchemeSelectorPriority.Audience;

	/// <inheritdoc/>
	public (bool Matches, string? SchemeName) TrySelect(HttpContext context) {

		if (context is null) {
			return (false, null);
		}

		var authHeader = context.Request.Headers[HeaderNames.Authorization].ToString();
		if (string.IsNullOrEmpty(authHeader)
			|| !authHeader.StartsWith(BearerPrefixToken, StringComparison.OrdinalIgnoreCase)) {
			return (false, null);
		}

		var token = authHeader[BearerPrefixToken.Length..].Trim();
		if (string.IsNullOrEmpty(token) || !IsJwtShape(token)) {
			return (false, null);
		}

		var audience = TryExtractAudience(token);
		if (audience is null) {
			return (false, null);
		}

		var scheme = audienceMap.GetSchemeForAudience(audience);
		if (!string.IsNullOrEmpty(scheme)) {
			return (true, scheme);
		}

		// Unrecognized audience. If the endpoint is [AllowAnonymous], let the
		// Anonymous handler return NoResult (so the request proceeds). Otherwise
		// route to Ambiguous for fail-closed rejection — a genuine JWT with no
		// configured scheme owner shouldn't silently fall through to anonymous.
		var endpoint = context.GetEndpoint();
		if (endpoint?.Metadata.GetMetadata<IAllowAnonymous>() is not null) {
			return (true, AuthenticationSchemes.Anonymous);
		}

		// Ambiguous scheme is a special "fail closed" scheme that always rejects the request
		// with a 401 Unauthorized, so the client knows the JWT was valid but not accepted.
		return (true, AuthenticationSchemes.Ambiguous);

	}

	private static bool IsJwtShape(string value) {
		var firstDot = value.IndexOf('.');
		if (firstDot <= 0 || firstDot == value.Length - 1) {
			return false;
		}
		var secondDot = value.IndexOf('.', firstDot + 1);
		return secondDot > firstDot
			&& secondDot < value.Length - 1
			&& value.IndexOf('.', secondDot + 1) == -1;
	}

	private static string? TryExtractAudience(string jwt) {
		try {
			var parts = jwt.Split('.');
			if (parts.Length != 3) {
				return null;
			}
			var payloadBytes = Base64UrlDecode(parts[1]);
			using var doc = JsonDocument.Parse(payloadBytes);
			if (!doc.RootElement.TryGetProperty("aud", out var audElement)) {
				return null;
			}
			return audElement.ValueKind switch {
				JsonValueKind.String => audElement.GetString(),
				JsonValueKind.Array when audElement.GetArrayLength() > 0
					=> audElement[0].GetString(),
				_ => null,
			};
		} catch {
			// Malformed JWT — let the selector pass without claiming. The request
			// will reach a later selector (typically Anonymous), and ASP.NET's
			// authentication pipeline will reject downstream if a protected endpoint
			// is targeted.
			return null;
		}
	}

	private static byte[] Base64UrlDecode(string input) {
		var padded = input.Replace('-', '+').Replace('_', '/');
		switch (padded.Length % 4) {
			case 2:
				padded += "==";
				break;
			case 3:
				padded += "=";
				break;
		}
		return Convert.FromBase64String(padded);
	}

}
