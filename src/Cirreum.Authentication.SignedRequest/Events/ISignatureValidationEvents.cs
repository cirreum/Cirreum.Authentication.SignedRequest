namespace Cirreum.Authentication.SignedRequest;

/// <summary>
/// Provides hooks for signature validation events, enabling consumers to implement
/// rate limiting, alerting, and other security controls.
/// </summary>
/// <remarks>
/// <para>
/// Implement this interface to:
/// <list type="bullet">
///   <item>Rate limit failed authentication attempts</item>
///   <item>Alert on suspicious patterns (many failures from same client)</item>
///   <item>Log detailed audit information</item>
///   <item>Block IPs or clients after threshold breaches</item>
/// </list>
/// </para>
/// </remarks>
/// <example>
/// <code>
/// public class RateLimitingValidationEvents : ISignatureValidationEvents {
///     private readonly IRateLimiter _rateLimiter;
///
///     public async Task OnValidationFailedAsync(SignatureValidationFailedContext context) {
///         // Increment failure counter for this client
///         var key = $"sig_fail:{context.ClientId}";
///         var count = await _rateLimiter.IncrementAsync(key, TimeSpan.FromMinutes(15));
///
///         if (count > 10) {
///             // Block client temporarily
///             await _rateLimiter.BlockAsync(context.ClientId, TimeSpan.FromHours(1));
///         }
///     }
/// }
/// </code>
/// </example>
public interface ISignatureValidationEvents {

	/// <summary>
	/// Called when signature validation fails.
	/// </summary>
	/// <param name="context">Details about the failed validation.</param>
	/// <param name="cancellationToken">A token to cancel the operation.</param>
	/// <returns>A task representing the asynchronous operation.</returns>
	Task OnValidationFailedAsync(
		SignatureValidationFailedContext context,
		CancellationToken cancellationToken = default);

	/// <summary>
	/// Called when signature validation succeeds.
	/// </summary>
	/// <param name="context">Details about the successful validation.</param>
	/// <param name="cancellationToken">A token to cancel the operation.</param>
	/// <returns>A task representing the asynchronous operation.</returns>
	Task OnValidationSucceededAsync(
		SignatureValidationSucceededContext context,
		CancellationToken cancellationToken = default);

	/// <summary>
	/// Called before validation to check if the client is blocked.
	/// </summary>
	/// <param name="clientId">The client ID to check.</param>
	/// <param name="cancellationToken">A token to cancel the operation.</param>
	/// <returns>True if the client should be blocked, false to proceed with validation.</returns>
	Task<bool> IsClientBlockedAsync(
		string clientId,
		CancellationToken cancellationToken = default);

}