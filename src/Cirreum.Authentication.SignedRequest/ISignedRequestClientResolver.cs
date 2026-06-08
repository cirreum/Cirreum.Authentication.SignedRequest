namespace Cirreum.Authentication.SignedRequest;

/// <summary>
/// Resolves and validates signed request clients from various sources (database, etc.).
/// </summary>
public interface ISignedRequestClientResolver {

	/// <summary>
	/// Resolves and validates a signed request, returning the associated client if valid.
	/// </summary>
	/// <param name="context">The signed request context containing all validation data.</param>
	/// <param name="cancellationToken">A token to cancel the operation.</param>
	/// <returns>A result indicating success with client details, or failure with reason.</returns>
	/// <remarks>
	/// <b>Strict-nonce contract:</b> when the application enables the strict-nonce posture
	/// (<see cref="Configuration.SignatureValidationOptions.RequireStrictNonce"/>) and this resolver performs its
	/// own timestamp validation, a successful result <b>must</b> report the effective acceptance window via
	/// <see cref="SignedRequestValidationResult.ReplayWindow"/> (&gt;= the widest request age it accepts). The replay
	/// nonce is held for exactly that window; omitting it makes the handler fall back to the global
	/// <see cref="Configuration.SignatureValidationOptions"/> tolerances, which under-covers any wider window this
	/// resolver accepts and reopens a replay gap. The shipped <see cref="DynamicSignedRequestClientResolver"/>
	/// reports it automatically.
	/// </remarks>
	Task<SignedRequestValidationResult> ValidateAsync(
		SignedRequestContext context,
		CancellationToken cancellationToken = default);
}
