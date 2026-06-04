namespace Cirreum.Authentication.SignedRequest;

/// <summary>
/// Context for a failed signature validation event.
/// </summary>
public sealed class SignatureValidationFailedContext {

	/// <summary>
	/// Gets the client ID that was attempted (may be null if header was missing).
	/// </summary>
	public string? ClientId { get; init; }

	/// <summary>
	/// Gets the type of failure that occurred.
	/// </summary>
	public required SignatureFailureType FailureType { get; init; }

	/// <summary>
	/// Gets the detailed failure reason.
	/// </summary>
	public required string FailureReason { get; init; }

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
	/// Gets the timestamp of the failure.
	/// </summary>
	public DateTimeOffset Timestamp { get; init; } = DateTimeOffset.UtcNow;

}