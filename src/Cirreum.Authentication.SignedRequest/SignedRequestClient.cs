namespace Cirreum.Authentication.SignedRequest;

/// <summary>
/// Represents an authenticated client identified via signed request authentication.
/// </summary>
public sealed record SignedRequestClient {

	/// <summary>
	/// Gets the unique identifier for this client.
	/// </summary>
	public required string ClientId { get; init; }

	/// <summary>
	/// Gets the display name for this client.
	/// </summary>
	public required string ClientName { get; init; }

	/// <summary>
	/// Gets the authentication scheme used (see <see cref="SignedRequestDefaults.AuthenticationScheme"/>).
	/// </summary>
	public string Scheme { get; } = SignedRequestDefaults.AuthenticationScheme;

	/// <summary>
	/// Gets the roles assigned to this client.
	/// </summary>
	public IReadOnlyList<string> Roles { get; init; } = [];

	/// <summary>
	/// Gets optional custom claims to include in the client's identity.
	/// </summary>
	public IReadOnlyDictionary<string, string>? Claims { get; init; }

	/// <summary>
	/// Gets the credential ID that was used for this authentication.
	/// Useful for audit logging which specific key was used.
	/// </summary>
	public string? CredentialId { get; init; }
}
