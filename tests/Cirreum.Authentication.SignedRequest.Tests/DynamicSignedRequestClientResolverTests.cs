namespace Cirreum.Authentication.SignedRequest.Tests;

using Cirreum.Authentication.Configuration;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;

/// <summary>
/// Proves the resolver reports the <em>effective</em> replay window — the per-credential tolerances it
/// actually applied — so the handler can size the strict-nonce claim to exactly the window the request was
/// accepted under (H1). Without this, a credential granted a wider-than-global tolerance would leave a
/// replay gap between nonce-expiry and timestamp-window-expiry.
/// </summary>
public sealed class DynamicSignedRequestClientResolverTests {

	private static SignedRequestContext ContextAtNow() =>
		new(
			clientId: "client-1",
			signature: "v1=deadbeef",
			timestamp: DateTimeOffset.UtcNow.ToUnixTimeSeconds(),
			httpMethod: "GET",
			path: "/api/x",
			bodyHash: null,
			headers: new Dictionary<string, string>());

	private static ISignatureValidator AcceptingValidator() {
		var validator = Substitute.For<ISignatureValidator>();
		validator.ValidateSignature(Arg.Any<SignedRequestContext>(), Arg.Any<string>()).Returns(true);
		return validator;
	}

	[Fact]
	public async Task Success_reports_the_effective_per_credential_window_when_the_credential_widens_it() {
		var options = new SignatureValidationOptions {
			TimestampTolerance = TimeSpan.FromMinutes(2),
			FutureTimestampTolerance = TimeSpan.FromSeconds(30),
		};
		var credential = new StoredSigningCredential {
			CredentialId = "cred-1",
			ClientId = "client-1",
			ClientName = "Client One",
			SigningSecret = "secret",
			TimestampTolerance = TimeSpan.FromMinutes(10),      // wider than global
			FutureTimestampTolerance = TimeSpan.FromMinutes(1), // wider than global
		};
		var resolver = new TestResolver([credential], AcceptingValidator(), Options.Create(options));

		var result = await resolver.ValidateAsync(ContextAtNow());

		result.IsSuccess.Should().BeTrue();
		result.ReplayWindow.Should().Be(TimeSpan.FromMinutes(10) + TimeSpan.FromMinutes(1));
		// Specifically NOT the global sum — that under-coverage is the replay gap (H1).
		result.ReplayWindow.Should().NotBe(options.TimestampTolerance + options.FutureTimestampTolerance);
	}

	[Fact]
	public async Task Success_falls_back_to_global_tolerances_when_the_credential_does_not_override() {
		var options = new SignatureValidationOptions {
			TimestampTolerance = TimeSpan.FromMinutes(3),
			FutureTimestampTolerance = TimeSpan.FromSeconds(45),
		};
		var credential = new StoredSigningCredential {
			CredentialId = "cred-1",
			ClientId = "client-1",
			ClientName = "Client One",
			SigningSecret = "secret",
			// no per-credential tolerance overrides -> global applies
		};
		var resolver = new TestResolver([credential], AcceptingValidator(), Options.Create(options));

		var result = await resolver.ValidateAsync(ContextAtNow());

		result.IsSuccess.Should().BeTrue();
		result.ReplayWindow.Should().Be(options.TimestampTolerance + options.FutureTimestampTolerance);
	}

	private sealed class TestResolver(
		IEnumerable<StoredSigningCredential> credentials,
		ISignatureValidator validator,
		IOptions<SignatureValidationOptions> options)
		: DynamicSignedRequestClientResolver(validator, options, NullLogger.Instance) {

		protected override Task<IEnumerable<StoredSigningCredential>> LookupCredentialsAsync(
			string clientId, CancellationToken cancellationToken) => Task.FromResult(credentials);
	}

}
