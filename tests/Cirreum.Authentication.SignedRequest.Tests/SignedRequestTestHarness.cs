namespace Cirreum.Authentication.SignedRequest.Tests;

using Cirreum.Authentication.Configuration;
using Cirreum.SignedRequest;
using Cirreum.Coordination;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Microsoft.IO;
using System.Text;
using System.Text.Encodings.Web;

/// <summary>
/// Shared helpers for the SignedRequest tests: builds genuine RFC 9421 signed requests through the same §8
/// <see cref="SignatureBaseBuilder"/> + <see cref="HmacSha256SignedRequestAlgorithm"/> the server uses (so a
/// test request verifies byte-identically), and runs them through the authentication handler.
/// </summary>
internal static class SignedRequestTestHarness {

	public const string KeyId = "svc-a";
	public const string Secret = "super-secret-signing-key";
	public const string Algorithm = "hmac-sha256";

	// A 24-char base64 value (>= the default MinimumNonceLength of 22) — a well-formed strict-nonce value.
	public const string Nonce = "Zm9vYmFyMTIzNDU2Nzg5MGFi";

	public static readonly IReadOnlyList<string> DefaultCovered = [
		SignatureComponentNames.Method,
		SignatureComponentNames.Path,
		SignatureComponentNames.Query,
		SignatureComponentNames.ContentDigest,
	];

	/// <summary>A fully-formed, ready-to-present RFC 9421 signed request.</summary>
	public sealed record SignedMessage {
		public required string Method { get; init; }
		public required string Path { get; init; }
		public required string Query { get; init; }
		public required byte[] Body { get; init; }
		public required string ContentDigest { get; init; }
		public required string SignatureInput { get; init; }
		public required string Signature { get; init; }
	}

	public static SignedMessage Sign(
		string keyId = KeyId,
		string secret = Secret,
		string method = "GET",
		string path = "/api/x",
		string query = "",
		byte[]? body = null,
		string? nonce = Nonce,
		long? created = null,
		long? expires = null,
		string? tag = null,
		IReadOnlyList<string>? covered = null,
		string algorithm = Algorithm,
		string signatureLabel = "sig1") {

		body ??= [];
		covered ??= DefaultCovered;
		created ??= DateTimeOffset.UtcNow.ToUnixTimeSeconds();

		var contentDigest = ContentDigest.Compute(body);
		var components = SignatureBaseComponents.FromRequest(
			method, path, query, [new KeyValuePair<string, string>(SignatureComponentNames.ContentDigest, contentDigest)]);

		var parameters = new SignatureParameters {
			CoveredComponents = covered,
			KeyId = keyId,
			Algorithm = algorithm,
			Created = created.Value,
			Expires = expires,
			Nonce = nonce,
			Tag = tag,
		};

		var result = SignatureBaseBuilder.BuildForSigning(components, parameters);
		var signatureBytes = new HmacSha256SignedRequestAlgorithm().Sign(result.SignatureBase, Encoding.UTF8.GetBytes(secret));

		return new SignedMessage {
			Method = method,
			Path = path,
			Query = query,
			Body = body,
			ContentDigest = contentDigest,
			SignatureInput = $"{signatureLabel}={result.SignatureParamsValue}",
			Signature = $"{signatureLabel}=:{Convert.ToBase64String(signatureBytes)}:",
		};
	}

	/// <summary>Builds a <see cref="SignedRequestContext"/> directly (for resolver-level tests).</summary>
	public static SignedRequestContext Context(
		string keyId = KeyId,
		string secret = Secret,
		string method = "GET",
		string path = "/api/x",
		string query = "",
		byte[]? body = null,
		long? created = null,
		long? expires = null,
		string? tag = null,
		string algorithm = Algorithm) {

		body ??= [];
		var createdSeconds = created ?? DateTimeOffset.UtcNow.ToUnixTimeSeconds();
		var contentDigest = ContentDigest.Compute(body);
		var components = SignatureBaseComponents.FromRequest(
			method, path, query, [new KeyValuePair<string, string>(SignatureComponentNames.ContentDigest, contentDigest)]);

		var parameters = new SignatureParameters {
			CoveredComponents = DefaultCovered,
			KeyId = keyId,
			Algorithm = algorithm,
			Created = createdSeconds,
			Expires = expires,
			Tag = tag,
		};

		var result = SignatureBaseBuilder.BuildForSigning(components, parameters);
		var signatureBytes = new HmacSha256SignedRequestAlgorithm().Sign(result.SignatureBase, Encoding.UTF8.GetBytes(secret));

		return new SignedRequestContext {
			KeyId = keyId,
			Algorithm = algorithm,
			SignatureBase = result.SignatureBase,
			Signature = signatureBytes,
			Created = createdSeconds,
			Expires = expires,
			Tag = tag,
		};
	}

	public static SignedRequestAlgorithmResolver Algorithms() => new([new HmacSha256SignedRequestAlgorithm()]);

	public static HttpContext BuildHttpContext(SignedMessage message, IServiceProvider requestServices) {
		var context = new DefaultHttpContext { RequestServices = requestServices };
		context.Request.Method = message.Method;
		context.Request.Path = message.Path;
		if (!string.IsNullOrEmpty(message.Query)) {
			context.Request.QueryString = new QueryString(message.Query);
		}

		context.Request.Body = new MemoryStream(message.Body, writable: false);
		context.Request.ContentLength = message.Body.Length;
		context.Request.Headers[SignedRequestDefaults.ContentDigestHeader] = message.ContentDigest;
		context.Request.Headers[SignedRequestDefaults.SignatureInputHeader] = message.SignatureInput;
		context.Request.Headers[SignedRequestDefaults.SignatureHeader] = message.Signature;
		return context;
	}

	public static async Task<(AuthenticateResult Result, ISignatureValidationEvents Events)> RunAsync(
		HttpContext context,
		SignatureValidationOptions options,
		ISignedRequestClientResolver resolver,
		ISignatureValidationEvents? events = null) {

		events ??= Substitute.For<ISignatureValidationEvents>();

		var optionsMonitor = Substitute.For<IOptionsMonitor<SignedRequestAuthenticationOptions>>();
		optionsMonitor.Get(Arg.Any<string>()).Returns(new SignedRequestAuthenticationOptions());

		var handler = new SignedRequestAuthenticationHandler(
			optionsMonitor,
			NullLoggerFactory.Instance,
			UrlEncoder.Default,
			resolver,
			Options.Create(options),
			new RecyclableMemoryStreamManager(),
			events);

		var scheme = new AuthenticationScheme(
			SignedRequestSchemes.Default, SignedRequestSchemes.Default, typeof(SignedRequestAuthenticationHandler));
		await handler.InitializeAsync(scheme, context);
		return (await handler.AuthenticateAsync(), events);
	}

	public static Task<(AuthenticateResult Result, ISignatureValidationEvents Events)> RunAsync(
		SignedMessage message,
		SignatureValidationOptions options,
		ISignedRequestClientResolver resolver,
		IServiceProvider requestServices,
		ISignatureValidationEvents? events = null) =>
		RunAsync(BuildHttpContext(message, requestServices), options, resolver, events);

	public static ISignedRequestClientResolver ResolverReturning(SignedRequestValidationResult result) {
		var resolver = Substitute.For<ISignedRequestClientResolver>();
		resolver.ValidateAsync(Arg.Any<SignedRequestContext>(), Arg.Any<CancellationToken>()).Returns(result);
		return resolver;
	}

	public static SignedRequestValidationResult Success(TimeSpan? replayWindow) =>
		SignedRequestValidationResult.Success(
			new SignedRequestClient { ClientId = KeyId, ClientName = "Service A", CredentialId = "cred-1" }, replayWindow);

	public static IServiceProvider Empty() => new ServiceCollection().BuildServiceProvider();

	public static IServiceProvider With(IReplayGuard guard) =>
		new ServiceCollection().AddSingleton(guard).BuildServiceProvider();

	public static IServiceProvider Coordinated() =>
		new ServiceCollection().AddCoordination(c => c.UseInMemory()).BuildServiceProvider();

	// Captures the TTL the handler hands the backend, so a test can prove it matches the effective window.
	public sealed class CapturingReplayGuard : IReplayGuard {
		public TimeSpan? CapturedTtl { get; private set; }
		public ValueTask<bool> TryClaimAsync(string token, TimeSpan ttl, CancellationToken cancellationToken = default) {
			this.CapturedTtl = ttl;
			return ValueTask.FromResult(true);
		}
	}

	// Simulates an unreachable backend (e.g. Redis down).
	public sealed class ThrowingReplayGuard : IReplayGuard {
		public ValueTask<bool> TryClaimAsync(string token, TimeSpan ttl, CancellationToken cancellationToken = default) =>
			throw new InvalidOperationException("coordination backend unavailable");
	}

	// Simulates a client disconnect mid-claim (RequestAborted fired).
	public sealed class CancellingReplayGuard : IReplayGuard {
		public ValueTask<bool> TryClaimAsync(string token, TimeSpan ttl, CancellationToken cancellationToken = default) =>
			throw new OperationCanceledException();
	}

	// A real resolver over an in-memory credential set, exercising the full verify path.
	public sealed class RealResolver(IEnumerable<StoredSigningCredential> credentials)
		: DynamicSignedRequestClientResolver(Algorithms(), Options.Create(new SignatureValidationOptions()), NullLogger.Instance) {
		protected override Task<IEnumerable<StoredSigningCredential>> LookupCredentialsAsync(
			string keyId, CancellationToken cancellationToken) => Task.FromResult(credentials);
	}

	public static StoredSigningCredential Credential(string secret = Secret, string? audience = null) => new() {
		CredentialId = "cred-1",
		ClientId = KeyId,
		ClientName = "Service A",
		SigningSecret = secret,
		Audience = audience,
	};
}
