namespace Cirreum.Authentication.SignedRequest;

/// <summary>
/// A no-op implementation of <see cref="ISignatureValidationEvents"/> for when
/// consumers don't need event handling.
/// </summary>
public sealed class NullSignatureValidationEvents : ISignatureValidationEvents {

	/// <summary>
	/// Gets the singleton instance.
	/// </summary>
	public static NullSignatureValidationEvents Instance { get; } = new();

	private NullSignatureValidationEvents() { }

	/// <inheritdoc/>
	public Task OnValidationFailedAsync(
		SignatureValidationFailedContext context,
		CancellationToken cancellationToken = default) => Task.CompletedTask;

	/// <inheritdoc/>
	public Task OnValidationSucceededAsync(
		SignatureValidationSucceededContext context,
		CancellationToken cancellationToken = default) => Task.CompletedTask;

	/// <inheritdoc/>
	public Task<bool> IsClientBlockedAsync(
		string clientId,
		CancellationToken cancellationToken = default) => Task.FromResult(false);

}