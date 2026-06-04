namespace Cirreum.Authentication.SignedRequest;

/// <summary>
/// Context for a successful signature validation event.
/// </summary>
public sealed class SignatureValidationSucceededContext {

	/// <summary>
	/// Gets the authenticated client.
	/// </summary>
	public required SignedRequestClient Client { get; init; }

	/// <summary>
	/// Gets the credential ID that was used.
	/// </summary>
	public string? CredentialId { get; init; }

	/// <summary>
	/// Gets the remote IP address of the request.
	/// </summary>
	public string? RemoteIpAddress { get; init; }

	/// <summary>
	/// Gets the request path.
	/// </summary>
	public string? RequestPath { get; init; }

	/// <summary>
	/// Gets the HTTP method.
	/// </summary>
	public string? HttpMethod { get; init; }

	/// <summary>
	/// Gets the timestamp of the success.
	/// </summary>
	public DateTimeOffset Timestamp { get; init; } = DateTimeOffset.UtcNow;

}