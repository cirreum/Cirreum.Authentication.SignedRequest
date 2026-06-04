namespace Cirreum.Authentication.SignedRequest;

using Cirreum.AuthenticationProvider.SignedRequest;
using Cirreum.AuthenticationProvider;
using System.Security.Cryptography;

/// <summary>
/// HMAC-SHA256 implementation of the <see cref="ISignedRequestAlgorithm"/>
/// contract. Default algorithm shipped with the SignedRequest
/// scheme. Apps add Ed25519, future post-quantum, etc. by registering additional
/// <see cref="ISignedRequestAlgorithm"/> services.
/// </summary>
public sealed class HmacSha256SignedRequestAlgorithm : ISignedRequestAlgorithm {

	/// <summary>Canonical algorithm identifier — <c>"hmac-sha256"</c>.</summary>
	public const string Id = "hmac-sha256";

	/// <inheritdoc/>
	public string AlgorithmId => Id;

	/// <inheritdoc/>
	public bool Verify(ReadOnlySpan<byte> canonicalInput, ReadOnlySpan<byte> signature, ReadOnlySpan<byte> keyMaterial) {
		Span<byte> expected = stackalloc byte[32];
		HMACSHA256.HashData(keyMaterial, canonicalInput, expected);
		return signature.Length == expected.Length
			&& CryptographicOperations.FixedTimeEquals(expected, signature);
	}

	/// <inheritdoc/>
	public byte[] Sign(ReadOnlySpan<byte> canonicalInput, ReadOnlySpan<byte> keyMaterial) {
		var output = new byte[32];
		HMACSHA256.HashData(keyMaterial, canonicalInput, output);
		return output;
	}

}
