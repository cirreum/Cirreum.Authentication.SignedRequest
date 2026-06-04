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
	Task<SignedRequestValidationResult> ValidateAsync(
		SignedRequestContext context,
		CancellationToken cancellationToken = default);
}
