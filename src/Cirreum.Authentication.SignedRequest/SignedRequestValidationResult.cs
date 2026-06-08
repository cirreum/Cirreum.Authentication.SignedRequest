namespace Cirreum.Authentication.SignedRequest;

/// <summary>
/// Represents the result of validating a signed request.
/// </summary>
public sealed class SignedRequestValidationResult {

	private SignedRequestValidationResult(
		bool isSuccess,
		SignedRequestClient? client,
		string? failureReason,
		SignatureFailureType failureType,
		TimeSpan? replayWindow = null) {
		this.IsSuccess = isSuccess;
		this.Client = client;
		this.FailureReason = failureReason;
		this.FailureType = failureType;
		this.ReplayWindow = replayWindow;
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
	/// On a successful result, the window during which a replay of this exact request would still pass
	/// timestamp validation — i.e. how long a strict-nonce claim must be held. This is the <em>effective</em>
	/// (per-credential) tolerance the resolver applied, which may exceed the global default, so the replay
	/// token never under-covers the accepted window. <see langword="null"/> when the resolver did not report
	/// one — the handler then falls back to the global <c>SignatureValidationOptions</c> tolerances. <b>A custom
	/// resolver that accepts a timestamp window wider than those global tolerances and leaves this
	/// <see langword="null"/> reopens a replay gap</b> (the claim under-covers its acceptance window), so such
	/// resolvers must set this under strict-nonce. The shipped <see cref="DynamicSignedRequestClientResolver"/>
	/// always sets it.
	/// </summary>
	public TimeSpan? ReplayWindow { get; }

	/// <summary>
	/// Creates a successful result with the authenticated client and the effective replay window
	/// (the per-credential timestamp tolerance applied during validation). Pass the window whenever it is
	/// known so strict-nonce sizing matches the accepted timestamp window; omit it to fall back to the
	/// handler's global tolerances.
	/// </summary>
	public static SignedRequestValidationResult Success(SignedRequestClient client, TimeSpan? replayWindow = null) =>
		new(true, client, null, SignatureFailureType.None, replayWindow);

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