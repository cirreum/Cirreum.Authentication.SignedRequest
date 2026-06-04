namespace Cirreum.Authentication.SignedRequest;

/// <summary>
/// Provides context for signed request validation, including all data needed
/// to verify the request signature.
/// </summary>
/// <remarks>
/// Initializes a new instance of the <see cref="SignedRequestContext"/> class.
/// </remarks>
public sealed class SignedRequestContext(
	string clientId,
	string signature,
	long timestamp,
	string httpMethod,
	string path,
	string? bodyHash,
	IReadOnlyDictionary<string, string> headers) {

	/// <summary>
	/// Gets the client ID from the X-Client-Id header.
	/// </summary>
	public string ClientId { get; } = clientId;

	/// <summary>
	/// Gets the signature value from the X-Signature header.
	/// Expected format: "v1=hexstring" where v1 indicates the signature version.
	/// </summary>
	public string Signature { get; } = signature;

	/// <summary>
	/// Gets the Unix timestamp from the X-Timestamp header.
	/// </summary>
	public long Timestamp { get; } = timestamp;

	/// <summary>
	/// Gets the HTTP method (GET, POST, etc.).
	/// </summary>
	public string HttpMethod { get; } = httpMethod;

	/// <summary>
	/// Gets the request path (e.g., "/api/transactions").
	/// </summary>
	public string Path { get; } = path;

	/// <summary>
	/// Gets the SHA256 hash of the request body, or null for bodyless requests.
	/// </summary>
	public string? BodyHash { get; } = bodyHash;

	/// <summary>
	/// Gets additional request headers for reference.
	/// </summary>
	public IReadOnlyDictionary<string, string> Headers { get; } = headers;

	/// <summary>
	/// Gets the timestamp as a DateTimeOffset.
	/// </summary>
	public DateTimeOffset TimestampAsDateTime =>
		DateTimeOffset.FromUnixTimeSeconds(this.Timestamp);

	/// <summary>
	/// Builds the canonical request string that should be signed.
	/// </summary>
	/// <returns>The canonical string: "{timestamp}.{method}.{path}.{bodyHash}"</returns>
	public string BuildCanonicalRequest() {
		var body = this.BodyHash ?? DefaultSignatureValidator.EmptyStringHash;
		return $"{this.Timestamp}.{this.HttpMethod}.{this.Path}.{body}";
	}

	/// <summary>
	/// Parses the signature version from the signature header value.
	/// </summary>
	/// <returns>The version string (e.g., "v1") or null if invalid format.</returns>
	public string? GetSignatureVersion() {
		var eqIndex = this.Signature.IndexOf('=');
		if (eqIndex <= 0) {
			return null;
		}
		return this.Signature[..eqIndex];
	}

	/// <summary>
	/// Gets the signature value without the version prefix.
	/// </summary>
	/// <returns>The hex-encoded signature or null if invalid format.</returns>
	public string? GetSignatureValue() {
		var eqIndex = this.Signature.IndexOf('=');
		if (eqIndex < 0 || eqIndex >= this.Signature.Length - 1) {
			return null;
		}
		return this.Signature[(eqIndex + 1)..];
	}
}
