namespace Cirreum.Authentication.SignedRequest;

using Cirreum.Authentication.Configuration;
using Cirreum.AuthenticationProvider;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Options;

/// <summary>
/// <see cref="ISchemeSelector"/> for the SignedRequest scheme. Detects inbound
/// requests carrying the configured client-id + timestamp + signature header
/// composition (per <see cref="SignatureValidationOptions"/>) and routes them to
/// the <c>SignedRequest</c> ASP.NET Core scheme.
/// </summary>
/// <remarks>
/// <para>
/// Registered at
/// <see cref="SchemeSelectorPriority.Signed"/>. The selector is a cheap probe —
/// presence of all three signature headers (client-id, timestamp, signature) is
/// sufficient for dispatch. Full cryptographic validation happens inside
/// <see cref="SignedRequestAuthenticationHandler"/>.
/// </para>
/// <para>
/// SignedRequest is not a Bearer-transport scheme; it uses RFC 9421-style header
/// composition (<see cref="CredentialTransport.HeaderComposition"/>) and so does
/// not implement <see cref="IBearerSchemeSelector"/>.
/// </para>
/// </remarks>
public sealed class SignedRequestAuthenticationSchemeSelector(
	string schemeName,
	IOptions<SignatureValidationOptions> validationOptions
) : ISchemeSelector {

	private readonly SignatureValidationOptions _options = validationOptions.Value;

	/// <inheritdoc/>
	public int Priority => SchemeSelectorPriority.Signed;

	/// <inheritdoc/>
	public (bool Matches, string? SchemeName) TrySelect(HttpContext context) {
		if (context is null) {
			return (false, null);
		}

		var hasClientId = context.Request.Headers.ContainsKey(_options.ClientIdHeaderName);
		var hasSignature = context.Request.Headers.ContainsKey(_options.SignatureHeaderName);
		var hasTimestamp = context.Request.Headers.ContainsKey(_options.TimestampHeaderName);

		if (hasClientId && hasSignature && hasTimestamp) {
			return (true, schemeName);
		}

		return (false, null);
	}

}
