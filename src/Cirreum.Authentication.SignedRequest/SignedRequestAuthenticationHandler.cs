namespace Cirreum.Authentication.SignedRequest;

using Cirreum.Authentication.Configuration;
using Cirreum.SignedRequest;
using Cirreum.Coordination;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.IO;
using System.Security.Claims;
using System.Text.Encodings.Web;
using System.Threading;

/// <summary>
/// Authentication handler that validates RFC 9421 HTTP Message Signatures.
/// </summary>
/// <remarks>
/// <para>
/// The request carries <c>Signature</c> and <c>Signature-Input</c> (RFC 8941 structured fields) plus a
/// <c>Content-Digest</c> (RFC 9530). The handler parses them, reconstructs the byte-identical signature base
/// via the shared <c>SignatureBaseBuilder</c> (ADR-0021 §8), and asks the
/// <see cref="ISignedRequestClientResolver"/> to resolve the <c>keyid</c> credential and verify the signature.
/// It then binds the body via <c>Content-Digest</c> and, under the strict-nonce posture, claims the <c>nonce</c>
/// for single-use replay protection.
/// </para>
/// <para>
/// Audience is the per-service credential (the <c>keyid</c>); transport host/scheme/IP are not signed and not
/// consulted (host-independent, per the 2026-06-08 redesign).
/// </para>
/// </remarks>
public class SignedRequestAuthenticationHandler(
	IOptionsMonitor<SignedRequestAuthenticationOptions> options,
	ILoggerFactory logger,
	UrlEncoder encoder,
	ISignedRequestClientResolver clientResolver,
	IOptions<SignatureValidationOptions> validationOptions,
	RecyclableMemoryStreamManager streamManager,
	ISignatureValidationEvents? events = null
) : AuthenticationHandler<SignedRequestAuthenticationOptions>(options, logger, encoder) {

	private readonly ISignatureValidationEvents _events = events ?? NullSignatureValidationEvents.Instance;
	private readonly SignatureValidationOptions _validationOptions = validationOptions?.Value ?? new SignatureValidationOptions();
	private readonly RecyclableMemoryStreamManager _streamManager = streamManager;

	// Process-wide one-shot guard so the strict-nonce "resolver reported no replay window" advisory is logged
	// at most once (the handler is transient — a new instance per request).
	private static int _warnedNullReplayWindow;

	/// <inheritdoc/>
	protected override async Task<AuthenticateResult> HandleAuthenticateAsync() {

		var signatureInput = this.GetHeader(SignedRequestDefaults.SignatureInputHeader);
		var signature = this.GetHeader(SignedRequestDefaults.SignatureHeader);

		// No signature headers at all — let other handlers run.
		if (string.IsNullOrEmpty(signatureInput) && string.IsNullOrEmpty(signature)) {
			return AuthenticateResult.NoResult();
		}

		if (string.IsNullOrEmpty(signatureInput) || string.IsNullOrEmpty(signature)) {
			return await this.FailAsync(null, SignatureFailureType.MalformedSignature,
				"Both Signature and Signature-Input headers are required");
		}

		// RFC 9421 wire parse. v1 requires exactly one signature; multiple labels are ambiguous for a single
		// authentication decision and are rejected.
		if (!SignatureWireParser.TryParse(signatureInput, signature, out var entries) || entries.Count != 1) {
			return await this.FailAsync(null, SignatureFailureType.MalformedSignature,
				"Malformed or ambiguous Signature / Signature-Input headers");
		}

		var entry = entries[0];

		// Every required covered component must be present, else the signature does not bind what the server
		// relies on (RFC 9421 §7.2.1 — coverage is declared, never opportunistic).
		foreach (var required in this._validationOptions.RequiredCoveredComponents) {
			if (!entry.CoveredComponents.Contains(required)) {
				return await this.FailAsync(entry.KeyId, SignatureFailureType.UnsupportedComponent,
					$"Signature does not cover required component '{required}'");
			}
		}

		// Anti-abuse hook (consumer-supplied), keyed on the credential identifier.
		if (await this._events.IsClientBlockedAsync(entry.KeyId, this.Context.RequestAborted)) {
			return await this.FailAsync(entry.KeyId, SignatureFailureType.Other, "Client blocked");
		}

		// Reconstruct the signature base from the request via the shared §8 builder. The covered field values
		// (e.g. Content-Digest) come from the request headers; derived components from the request line.
		var fields = this.BuildCoveredFields(entry.CoveredComponents);
		var components = SignatureBaseComponents.FromRequest(
			this.Request.Method, this.Request.Path.ToUriComponent(), this.Request.QueryString.Value, fields);

		byte[] signatureBase;
		try {
			signatureBase = SignatureBaseBuilder.BuildBase(components, entry.CoveredComponents, entry.SignatureParamsValue);
		} catch (InvalidOperationException ex) {
			// An unsupported derived component (e.g. @authority) or a covered field absent from the request.
			return await this.FailAsync(entry.KeyId, SignatureFailureType.UnsupportedComponent, ex.Message);
		}

		var context = new SignedRequestContext {
			KeyId = entry.KeyId,
			Algorithm = entry.Algorithm,
			SignatureBase = signatureBase,
			Signature = entry.Signature,
			Created = entry.Created,
			Expires = entry.Expires,
			Tag = entry.Tag,
		};

		var result = await clientResolver.ValidateAsync(context, this.Context.RequestAborted);
		if (!result.IsSuccess || result.Client is null) {
			return await this.FailAsync(entry.KeyId, result.FailureType, result.FailureReason ?? "Invalid signature", warn: true);
		}

		var client = result.Client;

		// Fail closed on an anomalous identity: a verified signature proves the SECRET, not that the resolved
		// subject is meaningful. A (self-service-registered) credential row with a blank ClientId/ClientName
		// would otherwise mint a principal with an empty NameIdentifier that authorization cannot name (C1).
		if (string.IsNullOrWhiteSpace(client.ClientId) || string.IsNullOrWhiteSpace(client.ClientName)) {
			return await this.FailAsync(entry.KeyId, SignatureFailureType.Other,
				"Resolved signing credential has a blank client id or name", error: true);
		}

		// Content-Digest binds the body (RFC 9530): the signature proved the digest STRING; now prove that string
		// matches the actual body. And if the signature does NOT cover content-digest yet the request carries a
		// body (or a Content-Digest header the signer chose not to bind), that body is unauthenticated and
		// swappable — fail closed regardless of RequiredCoveredComponents (H1), so dropping content-digest from
		// the required set can only relax a genuinely bodyless surface, never silently unbind a body.
		var coversDigest = entry.CoveredComponents.Contains(SignatureComponentNames.ContentDigest);
		var digestHeader = this.GetHeader(SignedRequestDefaults.ContentDigestHeader);

		// Bound the body buffered to verify the digest (H2). The signature has already verified, so this caps an
		// authenticated client's memory amplification; a Content-Length over the cap is refused before buffering.
		if (this.Request.ContentLength is { } contentLength && contentLength > this._validationOptions.MaxSignedBodyBytes) {
			return await this.FailAsync(entry.KeyId, SignatureFailureType.Other,
				"Request body exceeds the maximum signed body size", warn: true);
		}

		var body = await this.ReadBodyAsync();
		if (coversDigest) {
			if (!ContentDigest.Verify(digestHeader, body)) {
				return await this.FailAsync(entry.KeyId, SignatureFailureType.ContentDigestMismatch,
					"Content-Digest does not match the request body");
			}
		} else if (body.Length > 0 || digestHeader is not null) {
			return await this.FailAsync(entry.KeyId, SignatureFailureType.ContentDigestMismatch,
				"Request carries a body the signature does not bind (content-digest is not a covered component)", warn: true);
		}

		// Strict-nonce replay protection (ADR-0021): claim the RFC 9421 nonce now the signature is proven valid.
		if (this._validationOptions.RequireStrictNonce) {
			var replayFailure = await this.ClaimNonceAsync(entry, result.ReplayWindow);
			if (replayFailure is not null) {
				return replayFailure;
			}
		}

		var ticket = this.BuildTicket(client);

		await this._events.OnValidationSucceededAsync(new SignatureValidationSucceededContext {
			Client = client,
			CredentialId = client.CredentialId,
			RemoteIpAddress = this.Context.Connection.RemoteIpAddress?.ToString(),
			RequestPath = this.Request.Path,
			HttpMethod = this.Request.Method,
		}, this.Context.RequestAborted);

		if (this.Logger.IsEnabled(LogLevel.Debug)) {
			this.Logger.LogDebug(
				"Signed request authenticated for keyid {KeyId} ({ClientName})", client.ClientId, client.ClientName);
		}

		return AuthenticateResult.Success(ticket);
	}

	/// <inheritdoc/>
	protected override Task HandleChallengeAsync(AuthenticationProperties properties) {
		this.Response.StatusCode = 401;
		// Deliberately uniform: one stable realm, no per-cause `error` parameter. RFC 9421 defines no standard
		// WWW-Authenticate vocabulary for HTTP Message Signatures, and an undifferentiated challenge denies an
		// attacker a probing oracle (unknown-keyid vs bad-signature). The realm is a fixed constant rather than
		// the deployment-specific scheme name (H3); precise failure categories are on ISignatureValidationEvents.
		this.Response.Headers.WWWAuthenticate = $"SignedRequest realm=\"{ChallengeRealm}\"";
		return Task.CompletedTask;
	}

	private const string ChallengeRealm = "SignedRequest";

	/// <inheritdoc/>
	protected override Task HandleForbiddenAsync(AuthenticationProperties properties) {
		this.Response.StatusCode = 403;
		return Task.CompletedTask;
	}

	// Returns a failure AuthenticateResult on a strict-nonce problem, or null when the nonce was claimed.
	private async Task<AuthenticateResult?> ClaimNonceAsync(ParsedSignature entry, TimeSpan? replayWindow) {
		var nonce = entry.Nonce;
		if (string.IsNullOrEmpty(nonce)) {
			return await this.FailAsync(entry.KeyId, SignatureFailureType.MissingNonce,
				"A nonce is required under the strict-nonce posture", error: true);
		}

		if (nonce.Length < this._validationOptions.MinimumNonceLength) {
			return await this.FailAsync(entry.KeyId, SignatureFailureType.WeakNonce,
				"The nonce is shorter than the required minimum", warn: true);
		}

		IReplayGuard? replayGuard;
		try {
			replayGuard = this.Context.RequestServices.GetService<IReplayGuard>();
		} catch (Exception ex) when (ex is not OperationCanceledException) {
			// The backend's DI factory threw during activation (e.g. a Redis multiplexer constructed lazily
			// during an outage). Fail closed — a clean 401, not an unhandled 500.
			return await this.ReplayBackendUnavailableAsync(entry.KeyId, ex);
		}

		if (replayGuard is null) {
			// Strict-nonce on but no coordination backend chosen. The umbrella's CoordinationPostureValidator
			// should have failed startup; this is the request-time failsafe. Fail closed.
			return await this.FailAsync(entry.KeyId, SignatureFailureType.ReplayProtectionUnavailable,
				"Replay protection is required but no coordination backend is registered", error: true);
		}

		// Hold the claim for exactly as long as a replay would still pass freshness validation — the effective
		// (per-credential) window the resolver reported. Fall back to the global tolerances when it reports none.
		if (replayWindow is null
			&& this.Logger.IsEnabled(LogLevel.Warning)
			&& Interlocked.CompareExchange(ref _warnedNullReplayWindow, 1, 0) == 0) {
			this.Logger.LogWarning(
				"Strict-nonce is enabled but the signed-request resolver returned no effective replay window; " +
				"the nonce TTL is sized from the global timestamp tolerances. A custom {Resolver} that accepts a " +
				"timestamp window wider than the global SignatureValidationOptions must report it via " +
				"SignedRequestValidationResult.ReplayWindow, or a replay gap reopens. (Logged once.)",
				nameof(ISignedRequestClientResolver));
		}

		var ttl = (replayWindow
			?? (this._validationOptions.TimestampTolerance + this._validationOptions.FutureTimestampTolerance))
			+ TimeSpan.FromSeconds(1); // +1s closes the sub-second slit at the boundary from second-rounded `created` (D2).

		bool claimed;
		try {
			claimed = await replayGuard.TryClaimAsync(nonce, ttl, this.Context.RequestAborted);
		} catch (Exception ex) when (ex is not OperationCanceledException) {
			// Backend unreachable (e.g. Redis down). Fail closed gracefully — a clean authentication failure
			// rather than an unhandled 500. (Cancellation propagates: that is a normal client disconnect.)
			return await this.ReplayBackendUnavailableAsync(entry.KeyId, ex);
		}

		if (!claimed) {
			return await this.FailAsync(entry.KeyId, SignatureFailureType.ReplayDetected, "Replayed signed request", warn: true);
		}

		return null;
	}

	// Fail closed (clean 401) when the replay backend is unavailable — whether it could not be activated from
	// DI or threw while claiming the nonce — rather than letting the exception surface as an unhandled 500.
	private async Task<AuthenticateResult> ReplayBackendUnavailableAsync(string keyId, Exception ex) {
		if (this.Logger.IsEnabled(LogLevel.Error)) {
			this.Logger.LogError(ex, "Replay protection backend unavailable for keyid {KeyId}", keyId);
		}

		await this.RaiseFailureAsync(keyId, SignatureFailureType.ReplayProtectionUnavailable,
			"Replay protection backend is unavailable");
		return AuthenticateResult.Fail("Replay protection is temporarily unavailable");
	}

	/// <summary>
	/// Claim types the handler emits itself from the resolved client's first-class fields. A store-supplied
	/// custom claim for one of these is dropped (with a warning) so a (self-service-registered) credential row
	/// cannot shadow identity, role, the credential-type marker, the scheme, or the credential id that an
	/// authorization policy relies on — the same A7/M-2 reserved-claim guard ApiKey and SessionTicket carry (C2).
	/// </summary>
	private static readonly HashSet<string> ReservedClaimTypes = new(StringComparer.OrdinalIgnoreCase) {
		ClaimTypes.NameIdentifier,
		ClaimTypes.Name,
		ClaimTypes.Role,
		"client_type",
		"auth_scheme",
		"credential_id",
	};

	private AuthenticationTicket BuildTicket(SignedRequestClient client) {
		var claims = new List<Claim> {
			new(ClaimTypes.NameIdentifier, client.ClientId),
			new(ClaimTypes.Name, client.ClientName),
			new("client_type", "signed_request"),
			new("auth_scheme", client.Scheme),
		};

		if (!string.IsNullOrEmpty(client.CredentialId)) {
			claims.Add(new Claim("credential_id", client.CredentialId));
		}

		// Roles from a (self-service / semi-trusted) store are de-duplicated and screened for control characters
		// before projection, so a malformed/hostile credential row can neither bloat the principal with repeats
		// nor smuggle CR/LF into a downstream sink that re-emits a claim value (C3/N13, RFC 9110 §5.5).
		foreach (var role in client.Roles.Distinct(StringComparer.Ordinal)) {
			if (IsSafeClaimValue(role)) {
				claims.Add(new Claim(ClaimTypes.Role, role));
			} else {
				this.WarnUnsafeClaim(client.ClientId, ClaimTypes.Role);
			}
		}

		if (client.Claims is not null) {
			foreach (var (claimType, claimValue) in client.Claims) {
				if (ReservedClaimTypes.Contains(claimType)) {
					// A store-supplied custom claim must never shadow a framework claim the handler emits —
					// dropping it keeps identity / role / client_type / auth_scheme / credential_id authoritative.
					if (this.Logger.IsEnabled(LogLevel.Warning)) {
						this.Logger.LogWarning(
							"Signed-request client {ClientId} declared a reserved claim '{ClaimType}'; ignoring it.",
							client.ClientId, claimType);
					}
					continue;
				}
				if (!IsSafeClaimValue(claimValue)) {
					this.WarnUnsafeClaim(client.ClientId, claimType);
					continue;
				}
				claims.Add(new Claim(claimType, claimValue));
			}
		}

		var identity = new ClaimsIdentity(claims, this.Scheme.Name);
		return new AuthenticationTicket(new ClaimsPrincipal(identity), this.Scheme.Name);
	}

	// Whether a claim value is safe to project — rejecting C0/C1 control characters (CR/LF/NUL/…) that could
	// corrupt a downstream sink re-emitting it (audit record, header echo, non-structured log). RFC 9110 §5.5.
	private static bool IsSafeClaimValue(string? value) {
		if (string.IsNullOrEmpty(value)) {
			return true;
		}
		foreach (var c in value) {
			if (char.IsControl(c)) {
				return false;
			}
		}
		return true;
	}

	private void WarnUnsafeClaim(string clientId, string claimType) {
		if (this.Logger.IsEnabled(LogLevel.Warning)) {
			this.Logger.LogWarning(
				"Signed-request client {ClientId} supplied claim '{ClaimType}' with an unsafe (control-character) value; dropping it.",
				clientId, claimType);
		}
	}

	// Collects the covered HTTP field values from the request (derived '@' components are not fields). A covered
	// field that is absent from the request is left out, so BuildBase rejects the signature as incomplete.
	private Dictionary<string, string> BuildCoveredFields(IReadOnlyList<string> coveredComponents) {
		var fields = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);

		foreach (var component in coveredComponents) {
			if (component.Length == 0 || component[0] == '@') {
				continue;
			}

			var value = this.GetHeader(component);
			if (value is not null) {
				fields[component] = value;
			}
		}

		return fields;
	}

	private string? GetHeader(string headerName) =>
		this.Request.Headers.TryGetValue(headerName, out var values) ? values.ToString() : null;

	private async Task<byte[]> ReadBodyAsync() {
		if (!this.Request.Body.CanSeek) {
			this.Request.EnableBuffering();
		}

		var originalPosition = this.Request.Body.Position;
		try {
			this.Request.Body.Position = 0;
			await using var memoryStream = this._streamManager.GetStream();
			await this.Request.Body.CopyToAsync(memoryStream, this.Context.RequestAborted);
			return memoryStream.ToArray();
		} finally {
			this.Request.Body.Position = originalPosition;
		}
	}

	private async Task<AuthenticateResult> FailAsync(
		string? keyId, SignatureFailureType failureType, string reason, bool warn = false, bool error = false) {

		await this.RaiseFailureAsync(keyId, failureType, reason);

		if (error && this.Logger.IsEnabled(LogLevel.Error)) {
			this.Logger.LogError("Signed request rejected for keyid {KeyId}: {Reason}", keyId, reason);
		} else if (warn && this.Logger.IsEnabled(LogLevel.Warning)) {
			this.Logger.LogWarning("Signed request rejected for keyid {KeyId}: {Reason}", keyId, reason);
		}

		return AuthenticateResult.Fail(reason);
	}

	private Task RaiseFailureAsync(string? keyId, SignatureFailureType failureType, string reason) =>
		this._events.OnValidationFailedAsync(new SignatureValidationFailedContext {
			ClientId = keyId,
			FailureType = failureType,
			FailureReason = reason,
			RemoteIpAddress = this.Context.Connection.RemoteIpAddress?.ToString(),
			RequestPath = this.Request.Path,
			HttpMethod = this.Request.Method,
		}, this.Context.RequestAborted);
}
