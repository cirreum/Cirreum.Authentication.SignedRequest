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

	// A credential that declares no algorithms is pinned to the v1 default (hmac-sha256) — see the per-credential
	// algorithm pin in ValidateAsync. An asymmetric credential must opt in via StoredSigningCredential.SupportedAlgorithms.
	private static readonly IReadOnlySet<string> DefaultAlgorithms =
		new HashSet<string>(StringComparer.Ordinal) { HmacSha256SignedRequestAlgorithm.Id };

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

			// Reject a credential whose secret is below the minimum strength — an operator misconfiguration
			// (empty / trivially short secret) must never produce a verifiable MAC. Fail closed and surface it.
			if (!SignedRequestSecret.MeetsFloor(credential.SigningSecret)) {
				if (this._logger.IsEnabled(LogLevel.Warning)) {
					this._logger.LogWarning(
						"Signing credential {CredentialId} for keyid {KeyId} has a signing secret shorter than the " +
						"{Minimum}-byte minimum; skipping it.", credential.CredentialId, context.KeyId, SignedRequestSecret.MinimumBytes);
				}

				continue;
			}

			// Per-credential algorithm pin. A credential that does not declare its algorithms is pinned to the
			// v1 default (hmac-sha256), NOT "any registered algorithm" — so adding an asymmetric algorithm later
			// can never let a request name hmac-sha256 against a key provisioned for asymmetric verification (the
			// alg-confusion / public-key-as-HMAC-key attack). An asymmetric credential opts in explicitly.
			var allowedAlgorithms = credential.SupportedAlgorithms is { Count: > 0 } declared ? declared : DefaultAlgorithms;
			if (!allowedAlgorithms.Contains(context.Algorithm)) {
				continue;
			}

			// A per-credential tolerance override is customer-influenced (self-service-registered) and is clamped
			// to the operator's ceiling, so one credential row cannot widen its replay-acceptance window — and the
			// strict-nonce coordination-store retention sized from it — without bound (D1). The operator's global
			// tolerance (used when a credential declares no override) is authoritative and is never clamped.
			var tolerance = this.ClampOverride(
				credential.TimestampTolerance, this._options.TimestampTolerance, this._options.MaxTimestampTolerance,
				context.KeyId, nameof(StoredSigningCredential.TimestampTolerance));
			var futureTolerance = this.ClampOverride(
				credential.FutureTimestampTolerance, this._options.FutureTimestampTolerance, this._options.MaxFutureTimestampTolerance,
				context.KeyId, nameof(StoredSigningCredential.FutureTimestampTolerance));

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
				// Fail closed on an anomalous identity even though the secret verified: a (self-service-registered)
				// store row with a blank ClientId/ClientName would mint a principal authorization cannot name (C1).
				if (string.IsNullOrWhiteSpace(credential.ClientId) || string.IsNullOrWhiteSpace(credential.ClientName)) {
					if (this._logger.IsEnabled(LogLevel.Warning)) {
						this._logger.LogWarning(
							"Signing credential {CredentialId} for keyid {KeyId} verified but has a blank client id/name; " +
							"skipping it.", credential.CredentialId, context.KeyId);
					}

					continue;
				}

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

	// Process-wide one-shot guard so the per-credential-tolerance clamp advisory logs at most once.
	private static int _warnedClamp;

	// Returns the operator global when the credential declares no override; otherwise the override clamped to the
	// configured ceiling (warning once when a clamp actually happens). Bounds a customer-influenced override so it
	// cannot widen the replay-acceptance window / strict-nonce TTL without limit (D1).
	private TimeSpan ClampOverride(TimeSpan? credentialOverride, TimeSpan operatorGlobal, TimeSpan ceiling, string keyId, string knob) {
		if (credentialOverride is not { } value) {
			return operatorGlobal;
		}

		if (value <= ceiling) {
			return value;
		}

		if (this._logger.IsEnabled(LogLevel.Warning) && Interlocked.CompareExchange(ref _warnedClamp, 1, 0) == 0) {
			this._logger.LogWarning(
				"A signed-request credential for keyid {KeyId} declared a {Knob} of {Override} exceeding the configured " +
				"ceiling {Ceiling}; clamping it. A per-credential tolerance cannot widen the replay-acceptance window " +
				"(or the strict-nonce nonce TTL) beyond SignatureValidationOptions.Max*. (Logged once.)",
				keyId, knob, value, ceiling);
		}

		return ceiling;
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
