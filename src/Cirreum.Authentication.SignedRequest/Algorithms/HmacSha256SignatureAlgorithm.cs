namespace Cirreum.Authentication.SignedRequest;

using System.Security.Cryptography;

public sealed class HmacSha256SignatureAlgorithm : ILegacySignatureAlgorithm {

	public string Version => SignatureVersions.V1;

	public int SignatureSizeBytes => 32;

	public void Sign(ReadOnlySpan<byte> message, ReadOnlySpan<byte> key, Span<byte> destination) {
		HMACSHA256.HashData(key, message, destination);
	}
}