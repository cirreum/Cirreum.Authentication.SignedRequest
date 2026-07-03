namespace Cirreum.Authentication.SignedRequest;

using Cirreum.SignedRequest;

/// <summary>
/// Default values for signed request authentication. The header names forward to the shared
/// <see cref="SignedRequestHeaders"/> in Cirreum.SignedRequest so the signer and verifier can never drift.
/// </summary>
public static class SignedRequestDefaults {
	/// <summary>
	/// The default authentication scheme name for signed request authentication.
	/// </summary>
	public const string AuthenticationScheme = "SignedRequest";

	/// <summary>The RFC 9421 <c>Signature</c> header name.</summary>
	public const string SignatureHeader = SignedRequestHeaders.Signature;

	/// <summary>The RFC 9421 <c>Signature-Input</c> header name.</summary>
	public const string SignatureInputHeader = SignedRequestHeaders.SignatureInput;

	/// <summary>The RFC 9530 <c>Content-Digest</c> header name.</summary>
	public const string ContentDigestHeader = SignedRequestHeaders.ContentDigest;
}