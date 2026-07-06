namespace Cirreum.Authentication.Events;

using System.Text.Json;

/// <summary>
/// The minimal wire shape for a cross-replica auth event: the
/// <c>[MessageVersion]</c> identity that names the schema, plus the serialized event
/// itself. Deliberately not <c>DistributedMessageEnvelope</c> — the auth-event wire is a
/// sealed framework channel with no routing, priority, or delivery-target concerns.
/// </summary>
/// <param name="Identifier">The stable logical identifier from the event type's
/// <c>[MessageVersion]</c> attribute (e.g. <c>"authentication.credential-revoked"</c>).</param>
/// <param name="Version">The schema version from the same attribute.</param>
/// <param name="Payload">The event serialized as JSON. Deserialized against the CLR type
/// the receiving replica resolves for (<paramref name="Identifier"/>,
/// <paramref name="Version"/>) via its <see cref="AuthenticationEventRegistry"/>.</param>
internal sealed record AuthenticationEventEnvelope(
	string Identifier,
	string Version,
	JsonElement Payload);
