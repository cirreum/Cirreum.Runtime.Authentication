namespace Cirreum.Runtime.Authentication.Tests.Events;

using Cirreum.Authentication.Events;

/// <summary>
/// A concrete, public <see cref="IAuthenticationEvent"/> deliberately missing
/// <c>[MessageVersion]</c> — exercises the registry's startup warning and the transport
/// bridge's permanent-configuration-error path.
/// </summary>
public sealed record UnversionedEvent(DateTimeOffset OccurredAt) : IAuthenticationEvent;
