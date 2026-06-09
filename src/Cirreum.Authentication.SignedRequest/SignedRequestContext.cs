namespace Cirreum.Authentication.SignedRequest;

/// <summary>
/// The data an <see cref="ISignedRequestClientResolver"/> needs to verify one parsed RFC 9421 signature:
/// the key identifier, algorithm, the already-built signature base, the signature bytes, and the freshness /
/// audience parameters. The handler builds the signature base once (it is request-invariant across a client's
/// credentials) via the shared <c>SignatureBaseBuilder</c> and passes it here, so the resolver only resolves
/// the algorithm, applies per-credential freshness, and verifies the signature.
/// </summary>
public sealed class SignedRequestContext {

	/// <summary>The <c>keyid</c> parameter — selects the presenting client's credential(s).</summary>
	public required string KeyId { get; init; }

	/// <summary>The <c>alg</c> parameter — the RFC 9421 algorithm identifier (e.g. <c>hmac-sha256</c>).</summary>
	public required string Algorithm { get; init; }

	/// <summary>The RFC 9421 signature base bytes the signature is verified against.</summary>
	public required ReadOnlyMemory<byte> SignatureBase { get; init; }

	/// <summary>The decoded signature bytes from the request's <c>Signature</c> header.</summary>
	public required ReadOnlyMemory<byte> Signature { get; init; }

	/// <summary>The <c>created</c> parameter (Unix seconds) — the signature creation time.</summary>
	public required long Created { get; init; }

	/// <summary>The optional <c>expires</c> parameter (Unix seconds) — the signature's hard expiry.</summary>
	public long? Expires { get; init; }

	/// <summary>The optional <c>tag</c> parameter — an explicit audience/context binding.</summary>
	public string? Tag { get; init; }

}
