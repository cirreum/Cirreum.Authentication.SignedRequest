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
	/// Gets or sets the ceiling on a <em>per-credential</em> <see cref="StoredSigningCredential.TimestampTolerance"/>
	/// override. Default 10 minutes. A per-credential override wider than this is clamped down (with a one-shot
	/// warning), so a single (self-service-registered) credential row cannot silently widen its replay-acceptance
	/// window — and, under strict-nonce, the per-nonce coordination-store retention — without bound. Does NOT clamp
	/// the operator's global <see cref="TimestampTolerance"/>; that is authoritative.
	/// </summary>
	public TimeSpan MaxTimestampTolerance { get; set; } = TimeSpan.FromMinutes(10);

	/// <summary>
	/// Gets or sets the ceiling on a per-credential <see cref="StoredSigningCredential.FutureTimestampTolerance"/>
	/// override. Default 5 minutes. Clamps a customer-influenced override only; the operator's global
	/// <see cref="FutureTimestampTolerance"/> is authoritative.
	/// </summary>
	public TimeSpan MaxFutureTimestampTolerance { get; set; } = TimeSpan.FromMinutes(5);

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
	/// strict-nonce posture. Default 22 (≈ 128 bits at base64 density; the framework client emits a 24-char
	/// standard-base64 nonce, above this floor). A shorter nonce is rejected as
	/// <see cref="SignedRequest.SignatureFailureType.WeakNonce"/> — the server cannot trust the client to
	/// supply sufficient entropy, so it enforces a floor.
	/// </summary>
	public int MinimumNonceLength { get; set; } = 22;

	/// <summary>
	/// The maximum request-body size (bytes) the handler will buffer to verify <c>Content-Digest</c>. A request
	/// whose <c>Content-Length</c> exceeds this is rejected before the body is buffered (H2). Default 1 MiB —
	/// sized for service-to-service / webhook payloads; raise it for larger signed bodies. The body is only read
	/// after the signature verifies, so this bounds an authenticated client's amplification, not an anonymous one.
	/// </summary>
	public long MaxSignedBodyBytes { get; set; } = 1024 * 1024;
}
