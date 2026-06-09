namespace Cirreum.Authentication.SignedRequest;

/// <summary>
/// Default values for signed request authentication.
/// </summary>
public static class SignedRequestDefaults {
	/// <summary>
	/// The default authentication scheme name for signed request authentication.
	/// </summary>
	public const string AuthenticationScheme = "SignedRequest";

	/// <summary>The RFC 9421 <c>Signature</c> header name.</summary>
	public const string SignatureHeader = "Signature";

	/// <summary>The RFC 9421 <c>Signature-Input</c> header name.</summary>
	public const string SignatureInputHeader = "Signature-Input";

	/// <summary>The RFC 9530 <c>Content-Digest</c> header name.</summary>
	public const string ContentDigestHeader = "Content-Digest";
}