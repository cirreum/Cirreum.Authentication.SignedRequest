namespace Cirreum.Authentication.SignedRequest;

/// <summary>
/// Categorizes signature validation failures for rate limiting and monitoring.
/// </summary>
public enum SignatureFailureType {
	/// <summary>No failure (success).</summary>
	None = 0,

	/// <summary>The client ID was not found.</summary>
	ClientNotFound,

	/// <summary>The signature did not match.</summary>
	InvalidSignature,

	/// <summary>The timestamp was outside the allowed window.</summary>
	TimestampExpired,

	/// <summary>The timestamp format was invalid.</summary>
	InvalidTimestamp,

	/// <summary>Required headers were missing.</summary>
	MissingHeaders,

	/// <summary>The signature format was invalid.</summary>
	InvalidSignatureFormat,

	/// <summary>The client exists but credentials are inactive.</summary>
	ClientInactive,

	/// <summary>Other/unspecified failure.</summary>
	Other,

	/// <summary>The request replayed an already-seen signed request (strict-nonce posture).</summary>
	ReplayDetected,

	/// <summary>Replay protection was required but could not run — no coordination backend was registered,
	/// or the backend was unavailable (strict-nonce posture). Distinct from <see cref="ReplayDetected"/> so a
	/// backend outage is observable separately from an actual replay.</summary>
	ReplayProtectionUnavailable
}