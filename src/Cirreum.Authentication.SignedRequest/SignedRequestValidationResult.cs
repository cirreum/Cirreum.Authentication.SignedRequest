namespace Cirreum.Authentication.SignedRequest;

/// <summary>
/// Represents the result of validating a signed request.
/// </summary>
public sealed class SignedRequestValidationResult {

	private SignedRequestValidationResult(
		bool isSuccess,
		SignedRequestClient? client,
		string? failureReason,
		SignatureFailureType failureType) {
		this.IsSuccess = isSuccess;
		this.Client = client;
		this.FailureReason = failureReason;
		this.FailureType = failureType;
	}

	/// <summary>
	/// Gets whether the validation was successful.
	/// </summary>
	public bool IsSuccess { get; }

	/// <summary>
	/// Gets the authenticated client if validation succeeded.
	/// </summary>
	public SignedRequestClient? Client { get; }

	/// <summary>
	/// Gets the failure reason if validation failed.
	/// </summary>
	public string? FailureReason { get; }

	/// <summary>
	/// Gets the type of failure for categorization and rate limiting.
	/// </summary>
	public SignatureFailureType FailureType { get; }

	/// <summary>
	/// Creates a successful result with the authenticated client.
	/// </summary>
	public static SignedRequestValidationResult Success(SignedRequestClient client) =>
		new(true, client, null, SignatureFailureType.None);

	/// <summary>
	/// Creates a failure result indicating the client was not found.
	/// </summary>
	public static SignedRequestValidationResult ClientNotFound() =>
		new(false, null, "Client not found", SignatureFailureType.ClientNotFound);

	/// <summary>
	/// Creates a failure result indicating the signature was invalid.
	/// </summary>
	public static SignedRequestValidationResult InvalidSignature() =>
		new(false, null, "Invalid signature", SignatureFailureType.InvalidSignature);

	/// <summary>
	/// Creates a failure result indicating the timestamp was invalid or expired.
	/// </summary>
	public static SignedRequestValidationResult TimestampExpired() =>
		new(false, null, "Request timestamp expired", SignatureFailureType.TimestampExpired);

	/// <summary>
	/// Creates a failure result indicating the timestamp format was invalid.
	/// </summary>
	public static SignedRequestValidationResult InvalidTimestamp() =>
		new(false, null, "Invalid timestamp format", SignatureFailureType.InvalidTimestamp);

	/// <summary>
	/// Creates a failure result indicating missing required headers.
	/// </summary>
	public static SignedRequestValidationResult MissingHeaders(string details) =>
		new(false, null, $"Missing required headers: {details}", SignatureFailureType.MissingHeaders);

	/// <summary>
	/// Creates a failure result indicating the signature format was invalid.
	/// </summary>
	public static SignedRequestValidationResult InvalidSignatureFormat(string details) =>
		new(false, null, $"Invalid signature format: {details}", SignatureFailureType.InvalidSignatureFormat);

	/// <summary>
	/// Creates a failure result indicating the client credentials are inactive.
	/// </summary>
	public static SignedRequestValidationResult ClientInactive() =>
		new(false, null, "Client credentials inactive", SignatureFailureType.ClientInactive);

	/// <summary>
	/// Creates a generic failure result.
	/// </summary>
	public static SignedRequestValidationResult Failed(string reason) =>
		new(false, null, reason, SignatureFailureType.Other);

}