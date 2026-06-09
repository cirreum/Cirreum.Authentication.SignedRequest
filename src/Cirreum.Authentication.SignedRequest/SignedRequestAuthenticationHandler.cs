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

		// Content-Digest binds the body (RFC 9530): the signature proved the digest STRING; now prove that string
		// matches the actual body. Required on every method — a bodyless request signs the empty-body digest.
		if (entry.CoveredComponents.Contains(SignatureComponentNames.ContentDigest)) {
			var digestHeader = this.GetHeader(SignedRequestDefaults.ContentDigestHeader);
			var body = await this.ReadBodyAsync();
			if (!ContentDigest.Verify(digestHeader, body)) {
				return await this.FailAsync(entry.KeyId, SignatureFailureType.ContentDigestMismatch,
					"Content-Digest does not match the request body");
			}
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
		this.Response.Headers.WWWAuthenticate = $"SignedRequest realm=\"{this.Scheme.Name}\"";
		return Task.CompletedTask;
	}

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

		var replayGuard = this.Context.RequestServices.GetService<IReplayGuard>();
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

		var ttl = replayWindow
			?? (this._validationOptions.TimestampTolerance + this._validationOptions.FutureTimestampTolerance);

		bool claimed;
		try {
			claimed = await replayGuard.TryClaimAsync(nonce, ttl, this.Context.RequestAborted);
		} catch (Exception ex) when (ex is not OperationCanceledException) {
			// Backend unreachable (e.g. Redis down). Fail closed gracefully — a clean authentication failure
			// rather than an unhandled 500 — logged and surfaced through the event sink. (Cancellation
			// propagates: that is a normal client disconnect.)
			if (this.Logger.IsEnabled(LogLevel.Error)) {
				this.Logger.LogError(ex, "Replay protection backend unavailable for keyid {KeyId}", entry.KeyId);
			}
			await this.RaiseFailureAsync(entry.KeyId, SignatureFailureType.ReplayProtectionUnavailable,
				"Replay protection backend is unavailable");
			return AuthenticateResult.Fail("Replay protection is temporarily unavailable");
		}

		if (!claimed) {
			return await this.FailAsync(entry.KeyId, SignatureFailureType.ReplayDetected, "Replayed signed request", warn: true);
		}

		return null;
	}

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

		foreach (var role in client.Roles) {
			claims.Add(new Claim(ClaimTypes.Role, role));
		}

		if (client.Claims is not null) {
			foreach (var (claimType, claimValue) in client.Claims) {
				claims.Add(new Claim(claimType, claimValue));
			}
		}

		var identity = new ClaimsIdentity(claims, this.Scheme.Name);
		return new AuthenticationTicket(new ClaimsPrincipal(identity), this.Scheme.Name);
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
