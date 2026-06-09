namespace Cirreum.Authentication.SignedRequest;

using Cirreum.Authentication.Configuration;
using Cirreum.SignedRequest;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using System.Text;

/// <summary>
/// Base class for database-backed or external SignedRequest credential resolvers. Implement
/// <see cref="LookupCredentialsAsync"/> to return the active credentials for a presenting <c>keyid</c>; the
/// base class resolves the RFC 9421 algorithm, applies per-credential freshness (with the strict-nonce replay
/// window), enforces any explicit audience binding, and verifies the signature against the request's signature
/// base.
/// </summary>
/// <remarks>
/// <para>
/// Return all active credentials for the <c>keyid</c>; the base class tries each until one verifies, enabling
/// zero-downtime key rotation. The lookup should hit an index.
/// </para>
/// <example>
/// <code>
/// public sealed class MyResolver(ICredentialRepository repo, ISignedRequestAlgorithmResolver algs,
///         IOptions&lt;SignatureValidationOptions&gt; options, ILogger&lt;MyResolver&gt; logger)
///     : DynamicSignedRequestClientResolver(algs, options, logger) {
///     protected override Task&lt;IEnumerable&lt;StoredSigningCredential&gt;&gt; LookupCredentialsAsync(
///         string keyId, CancellationToken ct) => repo.FindActiveByKeyIdAsync(keyId, ct);
/// }
/// </code>
/// </example>
/// </remarks>
public abstract class DynamicSignedRequestClientResolver(
	ISignedRequestAlgorithmResolver algorithms,
	IOptions<SignatureValidationOptions> options,
	ILogger logger
) : ISignedRequestClientResolver {

	private readonly ISignedRequestAlgorithmResolver _algorithms = algorithms ?? throw new ArgumentNullException(nameof(algorithms));
	private readonly SignatureValidationOptions _options = options?.Value ?? new SignatureValidationOptions();
	private readonly ILogger _logger = logger ?? throw new ArgumentNullException(nameof(logger));

	/// <summary>
	/// Looks up the active signing credentials for a presenting <c>keyid</c> from the database or external
	/// source. Return all active credentials (the base class tries each, supporting key rotation), or an empty
	/// collection if none exist.
	/// </summary>
	protected abstract Task<IEnumerable<StoredSigningCredential>> LookupCredentialsAsync(
		string keyId,
		CancellationToken cancellationToken);

	/// <inheritdoc/>
	public async Task<SignedRequestValidationResult> ValidateAsync(
		SignedRequestContext context,
		CancellationToken cancellationToken = default) {

		ArgumentNullException.ThrowIfNull(context);

		// Resolve the algorithm named on the wire (v1 ships hmac-sha256). An unknown alg is rejected before any
		// credential work — it can never verify.
		var algorithm = this._algorithms.Resolve(context.Algorithm);
		if (algorithm is null) {
			if (this._logger.IsEnabled(LogLevel.Debug)) {
				this._logger.LogDebug("Unsupported signature algorithm {Algorithm} for keyid {KeyId}", context.Algorithm, context.KeyId);
			}
			return SignedRequestValidationResult.Fail(
				SignatureFailureType.UnsupportedAlgorithm, $"Unsupported signature algorithm '{context.Algorithm}'");
		}

		IEnumerable<StoredSigningCredential> credentials;
		try {
			credentials = await this.LookupCredentialsAsync(context.KeyId, cancellationToken);
		} catch (Exception ex) {
			if (this._logger.IsEnabled(LogLevel.Error)) {
				this._logger.LogError(ex, "Error looking up credentials for keyid {KeyId}", context.KeyId);
			}
			return SignedRequestValidationResult.Failed("Credential lookup failed");
		}

		var materialized = credentials as IReadOnlyCollection<StoredSigningCredential> ?? [.. credentials];

		StoredSigningCredential? matched = null;
		TimeSpan matchedTolerance = default;
		TimeSpan matchedFutureTolerance = default;
		var audienceMismatch = false;

		foreach (var credential in materialized) {
			if (!credential.IsActive) {
				continue;
			}

			if (credential.ExpiresAt is { } credentialExpiry && credentialExpiry < DateTimeOffset.UtcNow) {
				continue;
			}

			// Per-credential algorithm restriction (null => any registered algorithm is acceptable).
			if (credential.SupportedAlgorithms is { } allowed && !allowed.Contains(context.Algorithm)) {
				continue;
			}

			var tolerance = credential.TimestampTolerance ?? this._options.TimestampTolerance;
			var futureTolerance = credential.FutureTimestampTolerance ?? this._options.FutureTimestampTolerance;

			if (!ValidateFreshness(context.Created, context.Expires, tolerance, futureTolerance)) {
				continue;
			}

			// Audience: a credential bound to an explicit audience requires the matching tag (the shared-credential
			// defense). When null the keyid is the implicit audience and no tag is required.
			if (credential.Audience is { } audience && !string.Equals(audience, context.Tag, StringComparison.Ordinal)) {
				audienceMismatch = true;
				continue;
			}

			if (algorithm.Verify(context.SignatureBase.Span, context.Signature.Span, Encoding.UTF8.GetBytes(credential.SigningSecret))) {
				matched = credential;
				matchedTolerance = tolerance;
				matchedFutureTolerance = futureTolerance;
				break;
			}
		}

		if (matched is null) {
			if (materialized.Count == 0) {
				return SignedRequestValidationResult.ClientNotFound();
			}

			if (audienceMismatch) {
				return SignedRequestValidationResult.Fail(SignatureFailureType.AudienceMismatch, "Audience (tag) mismatch");
			}

			return SignedRequestValidationResult.InvalidSignature();
		}

		// Report the effective replay window (the per-credential tolerances applied) so the strict-nonce claim is
		// held for exactly as long as a replay of this request would still pass freshness validation. A
		// per-credential override may exceed the global default, so the global value alone would under-cover it.
		var replayWindow = matchedTolerance + matchedFutureTolerance;
		return SignedRequestValidationResult.Success(matched.ToClient(), replayWindow);
	}

	private static bool ValidateFreshness(long created, long? expires, TimeSpan tolerance, TimeSpan futureTolerance) {
		var now = DateTimeOffset.UtcNow;
		var createdTime = DateTimeOffset.FromUnixTimeSeconds(created);

		if (now - createdTime > tolerance) {
			return false; // too old
		}

		if (createdTime > now + futureTolerance) {
			return false; // too far in the future (client clock ahead)
		}

		if (expires is { } expiresSeconds) {
			var expiresTime = DateTimeOffset.FromUnixTimeSeconds(expiresSeconds);
			if (now > expiresTime) {
				return false; // already expired
			}

			// Clamp: a client-declared validity wider than the server's freshness window is rejected, so the
			// replay nonce TTL (= tolerance + futureTolerance) always covers the accepted window. (ADR-0021.)
			if (expiresTime - createdTime > tolerance + futureTolerance) {
				return false;
			}
		}

		return true;
	}

}
