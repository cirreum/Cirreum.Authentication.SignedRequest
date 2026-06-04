namespace Cirreum.Authentication.SignedRequest;

/// <summary>
/// Constants for signature version identifiers.
/// </summary>
public static class SignatureVersions {

	/// <summary>
	/// Version 1: HMAC-SHA256 over the canonical request.
	/// </summary>
	public const string V1 = "v1";

}