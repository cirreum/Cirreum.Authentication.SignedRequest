namespace Cirreum.Authentication.SignedRequest;

using Cirreum.Authentication.Configuration;
/// <summary>
/// Provides cryptographic signature validation and generation for signed requests.
/// </summary>
/// <remarks>
/// <para>
/// The validator orchestrates signature computation and verification but delegates
/// the actual cryptographic operations to <see cref="ILegacySignatureAlgorithm"/> implementations
/// resolved by version identifier.
/// </para>
/// <para>
/// Body hash computation uses SHA-256 directly and is not version-dependent.
/// </para>
/// </remarks>
public interface ISignatureValidator {

	/// <summary>
	/// Gets the lowercase hex-encoded SHA-256 hash of an empty body.
	/// </summary>
	/// <remarks>
	/// Use this for requests with no body (GET, HEAD, DELETE) to avoid recomputing
	/// the constant hash on every request.
	/// </remarks>
	string EmptyBodyHash { get; }

	/// <summary>
	/// Validates that the provided signature in the context matches the expected
	/// signature computed from the canonical request and signing secret.
	/// </summary>
	/// <param name="context">The signed request context containing the signature and request data.</param>
	/// <param name="signingSecret">The signing secret associated with the client.</param>
	/// <returns>
	/// <c>true</c> if the signature is valid; <c>false</c> if the signature is missing,
	/// the version is unsupported, the hex format is invalid, or the signature does not match.
	/// </returns>
	/// <remarks>
	/// Uses constant-time comparison to prevent timing attacks. Returns <c>false</c> rather
	/// than throwing for any validation failure, including unsupported versions.
	/// </remarks>
	bool ValidateSignature(SignedRequestContext context, string signingSecret);

	/// <summary>
	/// Computes the wire-format signature for a canonical request.
	/// </summary>
	/// <param name="canonicalRequest">The canonical request string to sign.</param>
	/// <param name="signingSecret">The signing secret to use.</param>
	/// <param name="version">The signature version identifier. Defaults to <see cref="SignatureVersions.V1"/>.</param>
	/// <returns>The signature in <c>"version=hex"</c> format, with hex in lowercase.</returns>
	/// <exception cref="NotSupportedException">
	/// Thrown if no <see cref="ILegacySignatureAlgorithm"/> is registered for the requested version.
	/// </exception>
	string ComputeSignature(string canonicalRequest, string signingSecret, string version = SignatureVersions.V1);

	/// <summary>
	/// Validates that a Unix timestamp falls within the configured tolerance windows.
	/// </summary>
	/// <param name="timestamp">The Unix timestamp (seconds since epoch) from the request.</param>
	/// <returns>
	/// <c>true</c> if the timestamp is within both the past tolerance
	/// (<see cref="SignatureValidationOptions.TimestampTolerance"/>) and the future tolerance
	/// (<see cref="SignatureValidationOptions.FutureTimestampTolerance"/>); otherwise <c>false</c>.
	/// </returns>
	bool ValidateTimestamp(long timestamp);

	/// <summary>
	/// Computes the lowercase hex-encoded SHA-256 hash of the request body.
	/// </summary>
	/// <param name="body">The request body bytes. May be empty.</param>
	/// <returns>
	/// The lowercase hex-encoded SHA-256 hash. Returns <see cref="EmptyBodyHash"/> when
	/// <paramref name="body"/> is empty.
	/// </returns>
	string ComputeBodyHash(ReadOnlySpan<byte> body);
}