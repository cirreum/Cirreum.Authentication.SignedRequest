namespace Cirreum.Authentication;

using Cirreum.Authentication.SignedRequest;

/// <summary>
/// The ASP.NET authentication scheme name(s) for the SignedRequest provider. App authors
/// reference these in policy definitions
/// (<c>.AddAuthenticationSchemes(SignedRequestSchemes.Default)</c>) and anywhere a scheme
/// name is required.
/// </summary>
/// <remarks>
/// SignedRequest is single-scheme (no transport cardinality — signature
/// algorithm versions are resolved within the scheme, not as separate transports), so the
/// surface is a single <see cref="Default"/> constant rather than a transport-keyed family.
/// </remarks>
public static class SignedRequestSchemes {

	/// <summary>The SignedRequest scheme name — <c>SignedRequest</c>.</summary>
	public const string Default = SignedRequestDefaults.AuthenticationScheme;

}
