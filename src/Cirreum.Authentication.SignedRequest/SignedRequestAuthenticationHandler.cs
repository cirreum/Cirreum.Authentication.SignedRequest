namespace Cirreum.Authentication.SignedRequest;

using Cirreum.Authentication.Configuration;
using Cirreum.Coordination;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.IO;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using System.Text.Encodings.Web;

/// <summary>
/// Authentication handler that validates signed requests using HMAC signatures.
/// </summary>
/// <remarks>
/// <para>
/// This handler reads the following headers:
/// <list type="bullet">
///   <item><c>X-Client-Id</c> - Public client identifier for database lookup</item>
///   <item><c>X-Timestamp</c> - Unix timestamp for replay protection</item>
///   <item><c>X-Signature</c> - HMAC signature in format "v1=hexstring"</item>
/// </list>
/// </para>
/// <para>
/// The signature is computed over: {timestamp}.{method}.{path}.{bodyHash}
/// </para>
/// </remarks>
/// <remarks>
/// Initializes a new instance of the <see cref="SignedRequestAuthenticationHandler"/> class.
/// </remarks>
public class SignedRequestAuthenticationHandler(
	IOptionsMonitor<SignedRequestAuthenticationOptions> options,
	ILoggerFactory logger,
	UrlEncoder encoder,
	ISignedRequestClientResolver clientResolver,
	ISignatureValidator signatureValidator,
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

		// 1. Extract required headers
		var clientId = this.GetHeaderValue(this._validationOptions.ClientIdHeaderName);
		var signature = this.GetHeaderValue(this._validationOptions.SignatureHeaderName);
		var timestampStr = this.GetHeaderValue(this._validationOptions.TimestampHeaderName);

		// Check for missing headers
		var missingHeaders = new List<string>();
		if (string.IsNullOrEmpty(clientId)) {
			missingHeaders.Add(this._validationOptions.ClientIdHeaderName);
		}

		if (string.IsNullOrEmpty(signature)) {
			missingHeaders.Add(this._validationOptions.SignatureHeaderName);
		}

		if (string.IsNullOrEmpty(timestampStr)) {
			missingHeaders.Add(this._validationOptions.TimestampHeaderName);
		}

		if (missingHeaders.Count > 0) {
			// If no auth headers at all, return NoResult to allow other handlers
			if (missingHeaders.Count == 3) {
				return AuthenticateResult.NoResult();
			}

			// Partial headers = bad request
			await this.RaiseFailureEventAsync(clientId, SignatureFailureType.MissingHeaders,
				$"Missing: {string.Join(", ", missingHeaders)}");
			return AuthenticateResult.Fail($"Missing required headers: {string.Join(", ", missingHeaders)}");
		}

		// 2. Parse timestamp
		if (!long.TryParse(timestampStr, out var timestamp)) {
			await this.RaiseFailureEventAsync(clientId, SignatureFailureType.InvalidTimestamp, "Invalid timestamp format");
			return AuthenticateResult.Fail("Invalid timestamp format");
		}

		// 3. Check if client is blocked (rate limiting)
		if (await this._events.IsClientBlockedAsync(clientId!, this.Context.RequestAborted)) {
			await this.RaiseFailureEventAsync(clientId, SignatureFailureType.Other, "Client blocked");
			return AuthenticateResult.Fail("Client temporarily blocked");
		}

		// 4. Compute body hash
		var bodyHash = await this.ComputeBodyHashAsync();

		// 5. Build request path
		var path = this._validationOptions.IncludeQueryString
			? this.Request.Path + this.Request.QueryString
			: this.Request.Path.ToString();

		// 6. Build context
		var context = new SignedRequestContext(
			clientId: clientId!,
			signature: signature!,
			timestamp: timestamp,
			httpMethod: this.Request.Method,
			path: path,
			bodyHash: bodyHash,
			headers: this.BuildHeadersDictionary());

		// 7. Validate
		var result = await clientResolver.ValidateAsync(context, this.Context.RequestAborted);

		if (!result.IsSuccess || result.Client is null) {
			await this.RaiseFailureEventAsync(clientId, result.FailureType, result.FailureReason ?? "Validation failed");

			if (this.Logger.IsEnabled(LogLevel.Warning)) {
				this.Logger.LogWarning(
					"Signed request validation failed for client {ClientId}: {Reason}",
					clientId,
					result.FailureReason ?? "Unknown");
			}
			return AuthenticateResult.Fail(result.FailureReason ?? "Invalid signature");
		}

		// 8. Build claims principal
		var client = result.Client;

		// 8a. Strict-nonce replay protection (ADR-0021): the signature is now proven valid, so atomically
		//     claim its digest. The same signed request is single-use within the timestamp window; a replay
		//     loses the claim and is rejected. All failure paths fail closed.
		if (this._validationOptions.RequireStrictNonce) {
			var replayGuard = this.Context.RequestServices.GetService<IReplayGuard>();

			if (replayGuard is null) {
				// Misconfiguration: strict-nonce is on but no coordination backend was chosen. The umbrella
				// boot validator (CoordinationPostureValidator) should have failed startup; this is the
				// request-time failsafe. Fail closed — never authenticate replay-exposed.
				const string reason = "Replay protection is required but no coordination backend is registered";
				await this.RaiseFailureEventAsync(clientId, SignatureFailureType.ReplayProtectionUnavailable, reason);
				if (this.Logger.IsEnabled(LogLevel.Error)) {
					this.Logger.LogError("Signed request rejected for client {ClientId}: {Reason}", clientId, reason);
				}
				return AuthenticateResult.Fail(reason);
			}

			// Hold the claim for exactly as long as a replay of this request would still pass timestamp
			// validation. That is the effective (per-credential) tolerance the resolver applied — using the
			// global default would under-cover a client granted a wider tolerance and re-open a replay window.
			// Fall back to the global tolerances when the resolver did not report an effective window.
			if (result.ReplayWindow is null
				&& this.Logger.IsEnabled(LogLevel.Warning)
				&& System.Threading.Interlocked.CompareExchange(ref _warnedNullReplayWindow, 1, 0) == 0) {
				// The shipped DynamicSignedRequestClientResolver always reports the window. A custom resolver that
				// withholds it forces this global fallback — safe only if that resolver also validates within the
				// global tolerances. If it accepts a WIDER per-credential window, the nonce under-covers it and a
				// replay gap reopens; the handler cannot detect that, so warn once. (ADR-0021.)
				this.Logger.LogWarning(
					"Strict-nonce is enabled but the signed-request resolver returned no effective replay window; " +
					"the nonce TTL is sized from the global timestamp tolerances. A custom {Resolver} that accepts a " +
					"timestamp window wider than the global SignatureValidationOptions must report it via " +
					"SignedRequestValidationResult.ReplayWindow, or a replay gap reopens. (Logged once.)",
					nameof(ISignedRequestClientResolver));
			}

			var ttl = result.ReplayWindow
				?? (this._validationOptions.TimestampTolerance + this._validationOptions.FutureTimestampTolerance);
			var token = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(signature!)));

			bool claimed;
			try {
				claimed = await replayGuard.TryClaimAsync(token, ttl, this.Context.RequestAborted);
			} catch (Exception ex) when (ex is not OperationCanceledException) {
				// Backend unreachable (e.g. Redis down). Fail closed gracefully — a clean authentication
				// failure rather than an unhandled 500 — logged and surfaced through the event sink so the
				// outage stays observable. (Cancellation propagates: that is a normal client disconnect.)
				const string reason = "Replay protection backend is unavailable";
				await this.RaiseFailureEventAsync(clientId, SignatureFailureType.ReplayProtectionUnavailable, reason);
				if (this.Logger.IsEnabled(LogLevel.Error)) {
					this.Logger.LogError(ex, "Signed request rejected for client {ClientId}: {Reason}", clientId, reason);
				}
				return AuthenticateResult.Fail("Replay protection is temporarily unavailable");
			}

			if (!claimed) {
				const string reason = "Replayed signed request";
				await this.RaiseFailureEventAsync(clientId, SignatureFailureType.ReplayDetected, reason);
				if (this.Logger.IsEnabled(LogLevel.Warning)) {
					this.Logger.LogWarning("Signed request rejected for client {ClientId}: {Reason}", clientId, reason);
				}
				return AuthenticateResult.Fail(reason);
			}
		}

		var claims = new List<Claim> {
			new(ClaimTypes.NameIdentifier, client.ClientId),
			new(ClaimTypes.Name, client.ClientName),
			new("client_type", "signed_request"),
			new("auth_scheme", client.Scheme)
		};

		if (!string.IsNullOrEmpty(client.CredentialId)) {
			claims.Add(new Claim("credential_id", client.CredentialId));
		}

		// Add roles
		foreach (var role in client.Roles) {
			claims.Add(new Claim(ClaimTypes.Role, role));
		}

		// Add custom claims
		if (client.Claims is not null) {
			foreach (var (claimType, claimValue) in client.Claims) {
				claims.Add(new Claim(claimType, claimValue));
			}
		}

		var identity = new ClaimsIdentity(claims, this.Scheme.Name);
		var principal = new ClaimsPrincipal(identity);
		var ticket = new AuthenticationTicket(principal, this.Scheme.Name);

		// Raise success event
		await this._events.OnValidationSucceededAsync(new SignatureValidationSucceededContext {
			Client = client,
			CredentialId = client.CredentialId,
			RemoteIpAddress = this.Context.Connection.RemoteIpAddress?.ToString(),
			RequestPath = path,
			HttpMethod = this.Request.Method
		}, this.Context.RequestAborted);

		if (this.Logger.IsEnabled(LogLevel.Debug)) {
			this.Logger.LogDebug(
				"Signed request authenticated for client {ClientId} ({ClientName})",
				client.ClientId,
				client.ClientName);
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

	private string? GetHeaderValue(string headerName) {
		if (this.Request.Headers.TryGetValue(headerName, out var values)) {
			return values.FirstOrDefault();
		}
		return null;
	}

	private async Task<string?> ComputeBodyHashAsync() {
		if (this.Request.Method is "GET" or "HEAD" or "DELETE" or "OPTIONS") {
			return null;
		}

		if (!this.Request.Body.CanSeek) {
			this.Request.EnableBuffering();
		}

		var originalPosition = this.Request.Body.Position;
		try {
			this.Request.Body.Position = 0;
			await using var memoryStream = this._streamManager.GetStream();
			await this.Request.Body.CopyToAsync(memoryStream, this.Context.RequestAborted);

			return signatureValidator.ComputeBodyHash(
				memoryStream.GetBuffer().AsSpan(0, (int)memoryStream.Length));

		} finally {
			this.Request.Body.Position = originalPosition;
		}
	}

	private Dictionary<string, string> BuildHeadersDictionary() {
		var headers = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);

		foreach (var header in this.Request.Headers) {
			// Skip auth headers from context (they're already extracted)
			if (string.Equals(header.Key, this._validationOptions.ClientIdHeaderName, StringComparison.OrdinalIgnoreCase) ||
				string.Equals(header.Key, this._validationOptions.SignatureHeaderName, StringComparison.OrdinalIgnoreCase) ||
				string.Equals(header.Key, this._validationOptions.TimestampHeaderName, StringComparison.OrdinalIgnoreCase)) {
				continue;
			}

			var value = header.Value.FirstOrDefault();
			if (!string.IsNullOrEmpty(value)) {
				headers[header.Key] = value;
			}
		}

		return headers;
	}

	private Task RaiseFailureEventAsync(string? clientId, SignatureFailureType failureType, string reason) {
		return this._events.OnValidationFailedAsync(new SignatureValidationFailedContext {
			ClientId = clientId,
			FailureType = failureType,
			FailureReason = reason,
			RemoteIpAddress = this.Context.Connection.RemoteIpAddress?.ToString(),
			RequestPath = this.Request.Path,
			HttpMethod = this.Request.Method
		}, this.Context.RequestAborted);
	}
}
