namespace Cirreum.Authentication.SignedRequest;

using Cirreum.AuthenticationProvider;
using Microsoft.AspNetCore.Http;

/// <summary>
/// <see cref="ISchemeSelector"/> for the SignedRequest scheme. Detects inbound RFC 9421 requests by the
/// presence of both the <c>Signature</c> and <c>Signature-Input</c> headers and routes them to the
/// <c>SignedRequest</c> ASP.NET Core scheme.
/// </summary>
/// <remarks>
/// <para>
/// Registered at <see cref="SchemeSelectorPriority.Signed"/>. The selector is a cheap probe — the presence of
/// the two standard signature headers is sufficient for dispatch; full cryptographic validation happens inside
/// <see cref="SignedRequestAuthenticationHandler"/>.
/// </para>
/// <para>
/// SignedRequest is not a Bearer-transport scheme; it uses RFC 9421 header composition
/// (<see cref="CredentialTransport.HeaderComposition"/>) and so does not implement
/// <see cref="IBearerSchemeSelector"/>.
/// </para>
/// </remarks>
public sealed class SignedRequestAuthenticationSchemeSelector(string schemeName) : ISchemeSelector {

	/// <inheritdoc/>
	public int Priority => SchemeSelectorPriority.Signed;

	/// <inheritdoc/>
	public (bool Matches, string? SchemeName) TrySelect(HttpContext context) {
		if (context is null) {
			return (false, null);
		}

		var headers = context.Request.Headers;
		if (headers.ContainsKey(SignedRequestDefaults.SignatureHeader)
			&& headers.ContainsKey(SignedRequestDefaults.SignatureInputHeader)) {
			return (true, schemeName);
		}

		return (false, null);
	}

}
