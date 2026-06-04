namespace Cirreum.Authentication.SignedRequest;

using Cirreum.Authentication.Configuration;
using Microsoft.Extensions.Options;
using System.Buffers;
using System.Security.Cryptography;
using System.Text;

/// <summary>
/// Default implementation of <see cref="ISignatureValidator"/> that delegates cryptographic
/// operations to <see cref="ILegacySignatureAlgorithm"/> implementations resolved by version identifier.
/// </summary>
/// <remarks>
/// <para>
/// Body hashing always uses SHA-256 directly and is not algorithm-dependent. Signature
/// computation and validation dispatch to the registered algorithm matching the requested
/// version.
/// </para>
/// </remarks>
public sealed class DefaultSignatureValidator(
	IOptions<SignatureValidationOptions> options,
	ILegacySignatureAlgorithmResolver algorithmResolver
) : ISignatureValidator {

	private readonly SignatureValidationOptions _options = options.Value;

	/// <summary>
	/// SHA-256 hash of an empty input, lowercase hex-encoded.
	/// </summary>
	public const string EmptyStringHash =
		"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

	/// <summary>
	/// Stackalloc threshold for UTF-8 encoding buffers. Above this size we rent from the array pool.
	/// </summary>
	private const int StackallocThreshold = 512;

	/// <inheritdoc/>
	public string EmptyBodyHash => EmptyStringHash;

	/// <inheritdoc/>
	public bool ValidateSignature(SignedRequestContext context, string signingSecret) {
		var version = context.GetSignatureVersion();
		var providedSignature = context.GetSignatureValue();

		if (string.IsNullOrEmpty(version) || string.IsNullOrEmpty(providedSignature)) {
			return false;
		}

		if (!_options.SupportedSignatureVersions.Contains(version)) {
			return false;
		}

		var algorithm = algorithmResolver.Resolve(version);
		if (algorithm is null) {
			return false;
		}

		// Allocate buffers sized to the algorithm
		var sigSize = algorithm.SignatureSizeBytes;
		Span<byte> providedBytes = stackalloc byte[64]; // Max realistic signature size (Ed25519 = 64, HMAC-SHA256 = 32)
		providedBytes = providedBytes[..sigSize];

		if (!TryParseHex(providedSignature, providedBytes)) {
			return false;
		}

		var canonicalRequest = context.BuildCanonicalRequest();
		Span<byte> expectedBytes = stackalloc byte[64];
		expectedBytes = expectedBytes[..sigSize];

		ComputeSignatureBytes(canonicalRequest, signingSecret, algorithm, expectedBytes);

		return CryptographicOperations.FixedTimeEquals(providedBytes, expectedBytes);
	}

	/// <inheritdoc/>
	public string ComputeSignature(string canonicalRequest, string signingSecret, string version = SignatureVersions.V1) {

		var algorithm = algorithmResolver.Resolve(version)
			?? throw new NotSupportedException($"Signature version '{version}' is not supported");

		Span<byte> signatureBytes = stackalloc byte[64];
		signatureBytes = signatureBytes[..algorithm.SignatureSizeBytes];

		ComputeSignatureBytes(canonicalRequest, signingSecret, algorithm, signatureBytes);

		return $"{version}={Convert.ToHexString(signatureBytes).ToLowerInvariant()}";

	}

	/// <inheritdoc/>
	public bool ValidateTimestamp(long timestamp) {

		var requestTime = DateTimeOffset.FromUnixTimeSeconds(timestamp);
		var now = DateTimeOffset.UtcNow;

		// Too old?
		if (now - requestTime > _options.TimestampTolerance) {
			return false;
		}

		// Too far in the future? (Client clock ahead of ours)
		if (requestTime > now + _options.FutureTimestampTolerance) {
			return false;
		}

		return true;
	}

	/// <inheritdoc/>
	public string ComputeBodyHash(ReadOnlySpan<byte> body) {
		if (body.IsEmpty) {
			return EmptyStringHash;
		}

		Span<byte> hash = stackalloc byte[SHA256.HashSizeInBytes];
		SHA256.HashData(body, hash);
		return Convert.ToHexString(hash).ToLowerInvariant();
	}

	/// <summary>
	/// Computes signature bytes by UTF-8 encoding the inputs and dispatching to the algorithm.
	/// Uses stack allocation for small inputs and pooled buffers for larger ones to minimize allocations.
	/// </summary>
	private static void ComputeSignatureBytes(
		string canonicalRequest,
		string signingSecret,
		ILegacySignatureAlgorithm algorithm,
		Span<byte> destination) {

		var messageByteCount = Encoding.UTF8.GetByteCount(canonicalRequest);
		var keyByteCount = Encoding.UTF8.GetByteCount(signingSecret);

		var rentedMessage = ArrayPool<byte>.Shared.Rent(messageByteCount);
		var rentedKey = ArrayPool<byte>.Shared.Rent(keyByteCount);
		try {
			var messageBytes = rentedMessage.AsSpan(0, messageByteCount);
			var keyBytes = rentedKey.AsSpan(0, keyByteCount);
			Encoding.UTF8.GetBytes(canonicalRequest, messageBytes);
			Encoding.UTF8.GetBytes(signingSecret, keyBytes);
			algorithm.Sign(messageBytes, keyBytes, destination);
		} finally {
			ArrayPool<byte>.Shared.Return(rentedMessage, clearArray: true);
			ArrayPool<byte>.Shared.Return(rentedKey, clearArray: true);
		}

	}

	/// <summary>
	/// Attempts to parse a hexadecimal string into bytes.
	/// </summary>
	/// <param name="hex">Hex string. Length must be exactly twice the destination length.</param>
	/// <param name="destination">Receives the parsed bytes.</param>
	/// <returns>True if parsing succeeded; false if length mismatch or invalid hex characters.</returns>
	private static bool TryParseHex(string hex, Span<byte> destination) {
		if (hex.Length != destination.Length * 2) {
			return false;
		}
		return Convert.FromHexString(hex.AsSpan(), destination, out _, out _)
			== OperationStatus.Done;
	}

}