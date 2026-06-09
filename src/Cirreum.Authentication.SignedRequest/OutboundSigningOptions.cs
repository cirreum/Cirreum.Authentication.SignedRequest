namespace Cirreum.Authentication.SignedRequest;

using Cirreum.SignedRequest;
using System.Text.Json;

/// <summary>
/// Options for signing outbound HTTP requests (webhooks, service-to-service calls) as RFC 9421 HTTP Message
/// Signatures.
/// </summary>
public sealed class OutboundSigningOptions {

	/// <summary>Default signing options.</summary>
	public static OutboundSigningOptions Default { get; } = new();

	/// <summary>Default JSON serializer options (camelCase) for the JSON-body convenience overload.</summary>
	public static JsonSerializerOptions DefaultJsonOptions { get; } = new() {
		PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
	};

	/// <summary>The RFC 9421 algorithm identifier to sign with. Default <c>hmac-sha256</c> (the only v1 algorithm).</summary>
	public string Algorithm { get; set; } = HmacSha256SignedRequestAlgorithm.Id;

	/// <summary>
	/// The covered components to sign. Default <c>@method</c>, <c>@path</c>, <c>@query</c>, <c>content-digest</c>
	/// (host-independent — no <c>@authority</c>, per ADR-0021).
	/// </summary>
	public IReadOnlyList<string> CoveredComponents { get; set; } = [
		SignatureComponentNames.Method,
		SignatureComponentNames.Path,
		SignatureComponentNames.Query,
		SignatureComponentNames.ContentDigest,
	];

	/// <summary>The signature label used in the <c>Signature</c> / <c>Signature-Input</c> dictionaries. Default <c>sig1</c>.</summary>
	public string SignatureLabel { get; set; } = "sig1";

	/// <summary>
	/// When set, the signature carries an <c>expires</c> of <c>created + ExpiresAfter</c>. Keep it within the
	/// verifier's freshness window — a longer declared validity is rejected by the clamp (ADR-0021).
	/// </summary>
	public TimeSpan? ExpiresAfter { get; set; }

	/// <summary>Whether to emit a random <c>nonce</c> parameter (required by the verifier's strict-nonce posture). Default <see langword="true"/>.</summary>
	public bool IncludeNonce { get; set; } = true;

	/// <summary>The minimum nonce size in bytes (128-bit) accepted for <see cref="NonceBytes"/>.</summary>
	public const int MinimumNonceBytes = 16;

	private int _nonceBytes = MinimumNonceBytes;

	/// <summary>
	/// The number of cryptographically-random bytes in the generated nonce. Default 16 (128-bit). Must be at
	/// least <see cref="MinimumNonceBytes"/> — a nonce below 128 bits cannot give meaningful replay protection,
	/// so a smaller value is rejected rather than silently emitting a weak nonce the verifier would refuse.
	/// </summary>
	public int NonceBytes {
		get => this._nonceBytes;
		set => this._nonceBytes = value >= MinimumNonceBytes
			? value
			: throw new ArgumentOutOfRangeException(nameof(value), value, $"NonceBytes must be at least {MinimumNonceBytes} (128-bit).");
	}

	/// <summary>The optional explicit audience (<c>tag</c>) — required only when the credential is bound to one.</summary>
	public string? Tag { get; set; }

	/// <summary>The JSON serializer options for request bodies. If null, <see cref="DefaultJsonOptions"/> (camelCase) is used.</summary>
	public JsonSerializerOptions? JsonSerializerOptions { get; set; }
}
