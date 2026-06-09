namespace Cirreum.Authentication.SignedRequest.Tests;

using Cirreum.Authentication.Configuration;
using Cirreum.Coordination;
using Cirreum.SignedRequest;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;

/// <summary>
/// Adversarial-review hardening tests for the SignedRequest server scheme: cross-surface canonicalization
/// parity (review item 1), the algorithm-to-credential pin (4), the secret-strength floor (5), and the
/// fail-closed replay-backend activation path (3) — plus a known-answer vector that locks the RFC 9421 wire
/// signature base byte-for-byte (the same vector the Common package and the client SDK assert).
/// </summary>
public sealed class SignedRequestHardeningTests {

	private static SignatureParameters Params() => new() {
		CoveredComponents = ["@method", "@path", "@query", "content-digest"],
		KeyId = "svc-a",
		Algorithm = "hmac-sha256",
		Created = 1_718_000_000,
		Nonce = "nonce-xyz-0123456789",
	};

	// --- ① Cross-surface parity: the client's Uri-based extraction and the server's ASP.NET
	//        FromUriComponent -> ToUriComponent pipeline produce the byte-identical signature base for the
	//        same wire URL (the real APIs, not a simulation). ---

	[Theory]
	[InlineData("https://h/files/a%20b")]                 // percent-encoded space
	[InlineData("https://h/r%C3%A9sum%C3%A9")]            // percent-encoded UTF-8
	[InlineData("https://h/api/orders")]                  // plain
	[InlineData("https://h/v1/widgets-7_3.2/123")]        // typical id path
	[InlineData("https://h/api/orders?page=1&q=a%20b")]   // query with an encoded space
	public void Client_Uri_and_server_HttpRequest_extraction_yield_one_signature_base(string url) {
		var uri = new Uri(url);
		KeyValuePair<string, string>[] fields = [new("content-digest", "sha-256=:abc:")];

		// Client outbound signer extraction.
		var client = SignatureBaseComponents.FromRequest("POST", uri.AbsolutePath, uri.Query, fields);

		// Server handler extraction: ASP.NET decodes the wire URL exactly as Kestrel does, then the handler
		// re-encodes via ToUriComponent / reads QueryString.Value.
		var serverPath = PathString.FromUriComponent(uri).ToUriComponent();
		var serverQuery = QueryString.FromUriComponent(uri).Value;
		var server = SignatureBaseComponents.FromRequest("POST", serverPath, serverQuery, fields);

		SignatureBaseBuilder.BuildForSigning(client, Params()).SignatureBase
			.Should().Equal(SignatureBaseBuilder.BuildForSigning(server, Params()).SignatureBase);
	}

	// --- Known-answer vector (locks the wire format identically across Common, server, and client). ---

	[Fact]
	public void Known_answer_signature_base_is_byte_stable() {
		var components = SignatureBaseComponents.FromRequest(
			"POST", "/api/orders", "?page=1", [new("content-digest", "sha-256=:abc:")]);

		var signed = SignatureBaseBuilder.BuildForSigning(components, Params());

		var expected =
			"\"@method\": POST\n" +
			"\"@path\": /api/orders\n" +
			"\"@query\": ?page=1\n" +
			"\"content-digest\": sha-256=:abc:\n" +
			"\"@signature-params\": (\"@method\" \"@path\" \"@query\" \"content-digest\")" +
			";created=1718000000;keyid=\"svc-a\";alg=\"hmac-sha256\";nonce=\"nonce-xyz-0123456789\"";

		System.Text.Encoding.UTF8.GetString(signed.SignatureBase).Should().Be(expected);
	}

	// --- ④ The algorithm is pinned to the credential: a credential that declares no algorithms defaults to
	//        hmac-sha256 (NOT "any registered"), and a credential pinned to a different algorithm is rejected. ---

	[Fact]
	public async Task Credential_with_no_declared_algorithms_is_pinned_to_hmac_and_verifies() {
		var message = SignedRequestTestHarness.Sign();
		var resolver = new SignedRequestTestHarness.RealResolver([SignedRequestTestHarness.Credential()]);

		var (result, _) = await SignedRequestTestHarness.RunAsync(
			message, new SignatureValidationOptions(), resolver, SignedRequestTestHarness.Empty());

		result.Succeeded.Should().BeTrue();
	}

	[Fact]
	public async Task Credential_pinned_to_a_different_algorithm_rejects_an_hmac_request() {
		var message = SignedRequestTestHarness.Sign();
		var credential = SignedRequestTestHarness.Credential() with {
			SupportedAlgorithms = new HashSet<string> { "ed25519" },
		};
		var resolver = new SignedRequestTestHarness.RealResolver([credential]);

		var (result, _) = await SignedRequestTestHarness.RunAsync(
			message, new SignatureValidationOptions(), resolver, SignedRequestTestHarness.Empty());

		result.Succeeded.Should().BeFalse();
	}

	// --- ⑤ A credential whose secret is below the strength floor is skipped — even though its signature
	//        would otherwise verify (an operator misconfiguration must never authenticate). ---

	[Fact]
	public async Task Credential_with_a_secret_below_the_floor_is_skipped_and_fails_closed() {
		var message = SignedRequestTestHarness.Sign(secret: "short");        // 5 bytes < the 16-byte floor
		var credential = SignedRequestTestHarness.Credential(secret: "short");
		var resolver = new SignedRequestTestHarness.RealResolver([credential]);

		var (result, _) = await SignedRequestTestHarness.RunAsync(
			message, new SignatureValidationOptions(), resolver, SignedRequestTestHarness.Empty());

		result.Succeeded.Should().BeFalse();
	}

	// --- ③ A replay backend that throws while being activated from DI fails closed (clean 401), not 500. ---

	[Fact]
	public async Task Replay_backend_activation_failure_fails_closed_without_throwing() {
		var message = SignedRequestTestHarness.Sign();
		var options = new SignatureValidationOptions { RequireStrictNonce = true };
		var resolver = new SignedRequestTestHarness.RealResolver([SignedRequestTestHarness.Credential()]);
		var services = new ServiceCollection()
			.AddSingleton<IReplayGuard>(_ => throw new InvalidOperationException("backend activation failed"))
			.BuildServiceProvider();

		// RunAsync would surface an unhandled exception if the handler did not catch the activation failure.
		var (result, _) = await SignedRequestTestHarness.RunAsync(message, options, resolver, services);

		result.Succeeded.Should().BeFalse();
		result.Failure!.Message.Should().Contain("Replay protection");
	}

	// --- ⑥ The credential ToString redacts the signing secret (no leak through logging / interpolation). ---

	[Fact]
	public void StoredSigningCredential_ToString_redacts_the_secret() {
		var credential = SignedRequestTestHarness.Credential(secret: "super-secret-signing-key");

		credential.ToString().Should().NotContain("super-secret-signing-key").And.Contain("[redacted]");
	}

	// --- ⑦ The outbound signer's NonceBytes floor (parity with the client SDK). ---

	[Fact]
	public void OutboundSigningOptions_NonceBytes_below_128_bit_is_rejected() {
		var act = () => new OutboundSigningOptions { NonceBytes = 8 };

		act.Should().Throw<ArgumentOutOfRangeException>();
	}

}
