namespace Cirreum.Authentication;

using Cirreum.Authentication.Configuration;

/// <summary>
/// Composition options for <c>AddSignedRequest&lt;TClientResolver&gt;(...)</c>. SignedRequest
/// is code-composed (no appsettings section / registrar — per the Cirreum provider model,
/// appsettings and a registrar are a matched pair, and SignedRequest has no per-instance data
/// to configure). Validation behavior is tuned here in code.
/// </summary>
public sealed class SignedRequestOptions {

	internal Action<SignatureValidationOptions>? ValidationConfiguration { get; private set; }

	/// <summary>
	/// Configures signature-validation behavior (timestamp tolerance, required covered components,
	/// strict-nonce posture, etc.). Apps that want config-driven tuning bind their own
	/// configuration here — e.g. <c>o.ConfigureValidation(v =&gt; v.TimestampTolerance = cfg...)</c>.
	/// </summary>
	/// <param name="configure">The configuration action.</param>
	/// <returns>This options instance for chaining.</returns>
	public SignedRequestOptions ConfigureValidation(Action<SignatureValidationOptions> configure) {
		this.ValidationConfiguration = configure ?? throw new ArgumentNullException(nameof(configure));
		return this;
	}

}
