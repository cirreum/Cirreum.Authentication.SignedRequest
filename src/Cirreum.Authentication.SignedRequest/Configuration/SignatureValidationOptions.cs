namespace Cirreum.Authentication.Configuration;

/// <summary>
/// Options for configuring signature validation behavior.
/// </summary>
public sealed class SignatureValidationOptions {

	/// <summary>
	/// Gets or sets the maximum age of a request timestamp before it's rejected.
	/// Default is 2 minutes.
	/// </summary>
	/// <remarks>
	/// This provides replay protection. Set higher if partners have clock skew issues,
	/// but balance against security (longer windows = more replay opportunity).
	/// </remarks>
	public TimeSpan TimestampTolerance { get; set; } = TimeSpan.FromMinutes(2);

	/// <summary>
	/// Gets or sets whether to allow future timestamps (clock skew in the other direction).
	/// Default is true with a 30 second window.
	/// </summary>
	public TimeSpan FutureTimestampTolerance { get; set; } = TimeSpan.FromSeconds(30);

	/// <summary>
	/// Gets or sets the header name for the client ID.
	/// Default is "X-Client-Id".
	/// </summary>
	public string ClientIdHeaderName { get; set; } = "X-Client-Id";

	/// <summary>
	/// Gets or sets the header name for the signature.
	/// Default is "X-Signature".
	/// </summary>
	public string SignatureHeaderName { get; set; } = "X-Signature";

	/// <summary>
	/// Gets or sets the header name for the timestamp.
	/// Default is "X-Timestamp".
	/// </summary>
	public string TimestampHeaderName { get; set; } = "X-Timestamp";

	/// <summary>
	/// Gets or sets whether to include query string in signature computation.
	/// Default is true for security.
	/// </summary>
	public bool IncludeQueryString { get; set; } = true;

	/// <summary>
	/// Gets or sets the supported signature versions.
	/// Default is ["v1"]. Add new versions when upgrading algorithms.
	/// </summary>
	public IReadOnlySet<string> SupportedSignatureVersions { get; set; } =
		new HashSet<string> { "v1" };
}
