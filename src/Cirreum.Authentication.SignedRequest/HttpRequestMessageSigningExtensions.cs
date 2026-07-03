namespace System.Net.Http;

using Cirreum.Authentication.SignedRequest;
using Cirreum.SignedRequest;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

/// <summary>
/// Extension methods for signing outbound HTTP requests as RFC 9421 HTTP Message Signatures (RFC 9530
/// <c>Content-Digest</c> for the body). Use when sending webhooks or service-to-service requests. The signing
/// base is built with the shared <c>SignatureBaseBuilder</c> (ADR-0021 §8), so an outbound-signed request
/// verifies byte-identically on the server.
/// </summary>
public static class HttpRequestMessageSigningExtensions {

	/// <summary>
	/// Signs the request, adding <c>Content-Digest</c>, <c>Signature-Input</c>, and <c>Signature</c> headers.
	/// </summary>
	/// <param name="request">The HTTP request to sign.</param>
	/// <param name="keyId">The credential identifier (<c>keyid</c>) the verifier resolves the secret by.</param>
	/// <param name="signingSecret">The shared secret for the HMAC signature.</param>
	/// <param name="options">Optional signing options.</param>
	/// <param name="cancellationToken">Cancellation token.</param>
	/// <returns>The request, for chaining.</returns>
	public static async Task<HttpRequestMessage> SignRequestAsync(
		this HttpRequestMessage request,
		string keyId,
		string signingSecret,
		OutboundSigningOptions? options = null,
		CancellationToken cancellationToken = default) {

		ArgumentNullException.ThrowIfNull(request);
		ArgumentException.ThrowIfNullOrWhiteSpace(keyId);
		ArgumentException.ThrowIfNullOrWhiteSpace(signingSecret);
		// Refuse to emit a signature under a sub-floor key — fail fast at the signer rather than ship a weak MAC (E3).
		SignedRequestSecret.EnsureFloor(signingSecret, nameof(signingSecret));

		// The signer must sign the exact absolute wire path. A relative RequestUri cannot be resolved here (the
		// HttpClient.BaseAddress prefix is not visible), so a relative target would silently sign an under-bound
		// @path. SendSignedAsync resolves against BaseAddress first; the request-only SignRequestAsync cannot.
		if (request.RequestUri is not { IsAbsoluteUri: true }) {
			throw new InvalidOperationException(
				"SignRequestAsync requires an absolute RequestUri. A relative URI cannot be resolved to the wire " +
				"path the server signs over. Use SendSignedAsync (which resolves against HttpClient.BaseAddress) " +
				"or set an absolute RequestUri before signing.");
		}

		options ??= OutboundSigningOptions.Default;

		var algorithm = ResolveAlgorithm(options.Algorithm);

		var body = request.Content is null
			? []
			: await request.Content.ReadAsByteArrayAsync(cancellationToken).ConfigureAwait(false);
		var contentDigest = ContentDigest.Compute(body);

		// RequestUri is guaranteed absolute by the guard above, so AbsolutePath/Query are already the isolated,
		// percent-encoded wire components.
		var uri = request.RequestUri!;
		var components = SignatureBaseComponents.FromRequest(
			request.Method.Method,
			uri.AbsolutePath,
			uri.Query,
			[new KeyValuePair<string, string>(SignatureComponentNames.ContentDigest, contentDigest)]);

		var created = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
		long? expires = options.ExpiresAfter is { } window ? created + (long)window.TotalSeconds : null;
		var nonce = options.IncludeNonce
			? Convert.ToBase64String(RandomNumberGenerator.GetBytes(options.NonceBytes))
			: null;

		var parameters = new SignatureParameters {
			CoveredComponents = options.CoveredComponents,
			KeyId = keyId,
			Algorithm = options.Algorithm,
			Created = created,
			Expires = expires,
			Nonce = nonce,
			Tag = options.Tag,
		};

		var result = SignatureBaseBuilder.BuildForSigning(components, parameters);
		var signatureBytes = algorithm.Sign(result.SignatureBase, Encoding.UTF8.GetBytes(signingSecret));

		request.Headers.Remove(SignedRequestDefaults.ContentDigestHeader);
		request.Headers.Remove(SignedRequestDefaults.SignatureInputHeader);
		request.Headers.Remove(SignedRequestDefaults.SignatureHeader);

		request.Headers.TryAddWithoutValidation(SignedRequestDefaults.ContentDigestHeader, contentDigest);
		request.Headers.TryAddWithoutValidation(
			SignedRequestDefaults.SignatureInputHeader, $"{options.SignatureLabel}={result.SignatureParamsValue}");
		request.Headers.TryAddWithoutValidation(
			SignedRequestDefaults.SignatureHeader, $"{options.SignatureLabel}=:{Convert.ToBase64String(signatureBytes)}:");

		return request;
	}

	/// <summary>Signs and sends a request.</summary>
	public static async Task<HttpResponseMessage> SendSignedAsync(
		this HttpClient client,
		HttpRequestMessage request,
		string keyId,
		string signingSecret,
		OutboundSigningOptions? options = null,
		CancellationToken cancellationToken = default) {

		ArgumentNullException.ThrowIfNull(client);
		ArgumentNullException.ThrowIfNull(request);

		// Resolve a relative RequestUri against the client's BaseAddress BEFORE signing, so the signer signs
		// the SAME absolute wire path HttpClient will actually send.
		ResolveAgainstBaseAddress(request, client.BaseAddress);
		await request.SignRequestAsync(keyId, signingSecret, options, cancellationToken).ConfigureAwait(false);
		return await client.SendAsync(request, cancellationToken).ConfigureAwait(false);
	}

	/// <summary>Signs and sends a request with a JSON body.</summary>
	public static Task<HttpResponseMessage> SendSignedAsync<TContent>(
		this HttpClient client,
		HttpMethod method,
		string requestUri,
		string keyId,
		string signingSecret,
		TContent? content = default,
		OutboundSigningOptions? options = null,
		CancellationToken cancellationToken = default) {

		ArgumentNullException.ThrowIfNull(client);

		var request = new HttpRequestMessage(method, requestUri);

		if (content is not null) {
			var json = JsonSerializer.Serialize(
				content, options?.JsonSerializerOptions ?? OutboundSigningOptions.DefaultJsonOptions);
			request.Content = new StringContent(json, Encoding.UTF8, "application/json");
		}

		return client.SendSignedAsync(request, keyId, signingSecret, options, cancellationToken);
	}

	private static ISignedRequestAlgorithm ResolveAlgorithm(string algorithmId) =>
		string.Equals(algorithmId, HmacSha256SignedRequestAlgorithm.Id, StringComparison.Ordinal)
			? new HmacSha256SignedRequestAlgorithm()
			: throw new NotSupportedException(
				$"Outbound signing algorithm '{algorithmId}' is not supported (v1 ships hmac-sha256).");

	// Resolve a relative RequestUri against the client's BaseAddress so the signer signs the absolute wire path
	// HttpClient will actually send. A relative URI with no BaseAddress is unsignable and fails fast.
	private static void ResolveAgainstBaseAddress(HttpRequestMessage request, Uri? baseAddress) {
		if (request.RequestUri is { IsAbsoluteUri: false } relative) {
			request.RequestUri = baseAddress is not null
				? new Uri(baseAddress, relative)
				: throw new InvalidOperationException(
					"Cannot sign a request with a relative RequestUri when HttpClient.BaseAddress is not set. " +
					"Set BaseAddress or use an absolute RequestUri.");
		}
	}
}
