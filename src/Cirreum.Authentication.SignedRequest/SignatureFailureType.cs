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
	ReplayProtectionUnavailable,

	/// <summary>The RFC 9421 <c>Signature</c> / <c>Signature-Input</c> headers were absent, malformed, or
	/// described more than one signature.</summary>
	MalformedSignature,

	/// <summary>The signature's <c>alg</c> is not registered / supported.</summary>
	UnsupportedAlgorithm,

	/// <summary>The signed covered-component set omits a required component or names an unsupported one
	/// (e.g. <c>@authority</c>).</summary>
	UnsupportedComponent,

	/// <summary>The request body does not match the signed <c>Content-Digest</c> (RFC 9530).</summary>
	ContentDigestMismatch,

	/// <summary>The strict-nonce posture is enforced but the signature carries no <c>nonce</c> parameter.</summary>
	MissingNonce,

	/// <summary>The <c>nonce</c> is shorter than the configured minimum — too little entropy to be a
	/// single-use replay token (strict-nonce posture).</summary>
	WeakNonce,

	/// <summary>The signature's <c>tag</c> does not match the audience the resolved credential is bound to.</summary>
	AudienceMismatch
}