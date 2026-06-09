namespace Cirreum.Authentication.Configuration;

using Cirreum.SignedRequest;

/// <summary>
/// Options for configuring RFC 9421 signed-request validation behavior.
/// </summary>
public sealed class SignatureValidationOptions {

	/// <summary>
	/// Gets or sets the maximum age of a signature's <c>created</c> time before it is rejected. Default 2 minutes.
	/// </summary>
	/// <remarks>
	/// Combined with <see cref="FutureTimestampTolerance"/> this is the freshness window; under the strict-nonce
	/// posture the replay nonce is held for exactly this window. Longer windows ease clock skew but widen the
	/// replay exposure of the <c>Baseline</c> (no-nonce) posture.
	/// </remarks>
	public TimeSpan TimestampTolerance { get; set; } = TimeSpan.FromMinutes(2);

	/// <summary>
	/// Gets or sets how far a signature's <c>created</c> time may be in the future (client clock ahead of
	/// the server). Default 30 seconds.
	/// </summary>
	public TimeSpan FutureTimestampTolerance { get; set; } = TimeSpan.FromSeconds(30);

	/// <summary>
	/// Gets or sets the covered components a signature MUST include; a signature whose <c>Signature-Input</c>
	/// omits any of these is rejected. Default <c>@method</c>, <c>@path</c>, <c>@query</c>, <c>content-digest</c>
	/// (host-independent — <c>@authority</c> is intentionally not covered, per ADR-0021).
	/// </summary>
	public IReadOnlyList<string> RequiredCoveredComponents { get; set; } = [
		SignatureComponentNames.Method,
		SignatureComponentNames.Path,
		SignatureComponentNames.Query,
		SignatureComponentNames.ContentDigest,
	];

	/// <summary>
	/// Gets or sets whether the strict-nonce replay posture is enforced. When <see langword="true"/>, every
	/// signed request must carry a <c>nonce</c> parameter which is atomically claimed via an <c>IReplayGuard</c>
	/// after the signature verifies, so the same signed request cannot be replayed within the freshness window.
	/// Default <see langword="false"/> (freshness-window protection only — a request can be replayed until the
	/// window lapses).
	/// </summary>
	/// <remarks>
	/// Enabling this requires a coordination backend: call <c>auth.AddCoordination(c =&gt; c.UseInMemory())</c>
	/// (single node) or <c>.UseRedis()</c> (multi-node). The host fails fast at startup if strict-nonce is
	/// enabled without one. (ADR-0021.)
	/// </remarks>
	public bool RequireStrictNonce { get; set; } = false;

	/// <summary>
	/// Gets or sets the minimum length (in characters) of the <c>nonce</c> parameter accepted under the
	/// strict-nonce posture. Default 22 (≈ a 128-bit value in base64url). A shorter nonce is rejected as
	/// <see cref="SignedRequest.SignatureFailureType.WeakNonce"/> — the server cannot trust the client to
	/// supply sufficient entropy, so it enforces a floor.
	/// </summary>
	public int MinimumNonceLength { get; set; } = 22;
}
