namespace Cirreum.Authentication.SignedRequest.Tests;

using Cirreum.Authentication.Configuration;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;

/// <summary>
/// Resolver-level proofs over the RFC 9421 verify loop: algorithm resolution, per-credential freshness with
/// the <c>expires</c> clamp, the audience (<c>tag</c>) binding, and the effective replay-window the handler
/// sizes the strict-nonce claim from (H1).
/// </summary>
public sealed class DynamicSignedRequestClientResolverTests {

	private sealed class TestResolver(
		IEnumerable<StoredSigningCredential> credentials,
		IOptions<SignatureValidationOptions> options)
		: DynamicSignedRequestClientResolver(SignedRequestTestHarness.Algorithms(), options, NullLogger.Instance) {

		protected override Task<IEnumerable<StoredSigningCredential>> LookupCredentialsAsync(
			string keyId, CancellationToken cancellationToken) => Task.FromResult(credentials);
	}

	private static TestResolver Resolver(
		IEnumerable<StoredSigningCredential> credentials, SignatureValidationOptions? options = null) =>
		new(credentials, Options.Create(options ?? new SignatureValidationOptions()));

	[Fact]
	public async Task Success_reports_the_effective_per_credential_window_when_the_credential_widens_it() {
		var options = new SignatureValidationOptions {
			TimestampTolerance = TimeSpan.FromMinutes(2),
			FutureTimestampTolerance = TimeSpan.FromSeconds(30),
		};
		var credential = SignedRequestTestHarness.Credential() with {
			TimestampTolerance = TimeSpan.FromMinutes(10),     // wider than global
			FutureTimestampTolerance = TimeSpan.FromMinutes(1), // wider than global
		};

		var result = await Resolver([credential], options).ValidateAsync(SignedRequestTestHarness.Context());

		result.IsSuccess.Should().BeTrue();
		result.ReplayWindow.Should().Be(TimeSpan.FromMinutes(10) + TimeSpan.FromMinutes(1));
		// NOT the global sum — that under-coverage is the replay gap (H1).
		result.ReplayWindow.Should().NotBe(options.TimestampTolerance + options.FutureTimestampTolerance);
	}

	[Fact]
	public async Task Success_falls_back_to_the_global_tolerances_when_the_credential_does_not_override() {
		var options = new SignatureValidationOptions {
			TimestampTolerance = TimeSpan.FromMinutes(3),
			FutureTimestampTolerance = TimeSpan.FromSeconds(45),
		};

		var result = await Resolver([SignedRequestTestHarness.Credential()], options)
			.ValidateAsync(SignedRequestTestHarness.Context());

		result.IsSuccess.Should().BeTrue();
		result.ReplayWindow.Should().Be(options.TimestampTolerance + options.FutureTimestampTolerance);
	}

	// --- D1: a per-credential tolerance override is clamped to the operator's ceiling so a single (self-service)
	//         credential row cannot widen the replay window / strict-nonce TTL without bound. ---

	[Fact]
	public async Task A_per_credential_tolerance_override_above_the_ceiling_is_clamped_D1() {
		var credential = SignedRequestTestHarness.Credential() with {
			TimestampTolerance = TimeSpan.FromMinutes(30), // wants 30 min; default MaxTimestampTolerance is 10 min
		};
		// A request 15 minutes old: within the 30-min override, but BEYOND the 10-min ceiling it clamps to.
		var staleContext = SignedRequestTestHarness.Context(
			created: DateTimeOffset.UtcNow.AddMinutes(-15).ToUnixTimeSeconds());

		var result = await Resolver([credential]).ValidateAsync(staleContext);

		result.IsSuccess.Should().BeFalse("the 30-min override clamps to the 10-min ceiling, so a 15-min-old request is too old");
	}

	[Fact]
	public async Task The_clamped_tolerance_sizes_the_reported_replay_window_D1() {
		var credential = SignedRequestTestHarness.Credential() with {
			TimestampTolerance = TimeSpan.FromMinutes(30),       // clamps to MaxTimestampTolerance (10 min)
			FutureTimestampTolerance = TimeSpan.FromMinutes(20), // clamps to MaxFutureTimestampTolerance (5 min)
		};

		var result = await Resolver([credential]).ValidateAsync(SignedRequestTestHarness.Context());

		result.IsSuccess.Should().BeTrue();
		result.ReplayWindow.Should().Be(TimeSpan.FromMinutes(10) + TimeSpan.FromMinutes(5),
			"the strict-nonce TTL is sized from the clamped window, not the unbounded override");
	}

	[Fact]
	public async Task An_unsupported_algorithm_is_rejected_before_any_credential_work() {
		var result = await Resolver([SignedRequestTestHarness.Credential()])
			.ValidateAsync(SignedRequestTestHarness.Context(algorithm: "ed25519"));

		result.IsSuccess.Should().BeFalse();
		result.FailureType.Should().Be(SignatureFailureType.UnsupportedAlgorithm);
	}

	[Fact]
	public async Task An_unknown_keyid_is_client_not_found() {
		var result = await Resolver([]).ValidateAsync(SignedRequestTestHarness.Context());

		result.FailureType.Should().Be(SignatureFailureType.ClientNotFound);
	}

	[Fact]
	public async Task A_wrong_secret_is_an_invalid_signature() {
		var resolver = Resolver([SignedRequestTestHarness.Credential(secret: "a-different-secret")]);

		var result = await resolver.ValidateAsync(SignedRequestTestHarness.Context(secret: SignedRequestTestHarness.Secret));

		result.IsSuccess.Should().BeFalse();
		result.FailureType.Should().Be(SignatureFailureType.InvalidSignature);
	}

	[Fact]
	public async Task A_stale_created_time_is_rejected() {
		var options = new SignatureValidationOptions { TimestampTolerance = TimeSpan.FromMinutes(1) };
		var staleCreated = DateTimeOffset.UtcNow.AddMinutes(-10).ToUnixTimeSeconds();

		var result = await Resolver([SignedRequestTestHarness.Credential()], options)
			.ValidateAsync(SignedRequestTestHarness.Context(created: staleCreated));

		result.IsSuccess.Should().BeFalse();
	}

	[Fact]
	public async Task A_declared_validity_wider_than_the_server_window_is_rejected_by_the_clamp() {
		var options = new SignatureValidationOptions {
			TimestampTolerance = TimeSpan.FromMinutes(2),
			FutureTimestampTolerance = TimeSpan.FromSeconds(30), // total window 2.5 min
		};
		var now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();

		// expires is an hour out — far wider than the 2.5-minute window the nonce TTL would cover.
		var result = await Resolver([SignedRequestTestHarness.Credential()], options)
			.ValidateAsync(SignedRequestTestHarness.Context(created: now, expires: now + 3600));

		result.IsSuccess.Should().BeFalse();
	}

	[Fact]
	public async Task A_credential_bound_to_an_audience_requires_the_matching_tag() {
		var resolver = Resolver([SignedRequestTestHarness.Credential(audience: "orders-api")]);

		var withoutTag = await resolver.ValidateAsync(SignedRequestTestHarness.Context(tag: null));
		withoutTag.IsSuccess.Should().BeFalse();
		withoutTag.FailureType.Should().Be(SignatureFailureType.AudienceMismatch);

		var withTag = await resolver.ValidateAsync(SignedRequestTestHarness.Context(tag: "orders-api"));
		withTag.IsSuccess.Should().BeTrue();
	}

	[Fact]
	public async Task An_inactive_credential_is_skipped() {
		var resolver = Resolver([SignedRequestTestHarness.Credential() with { IsActive = false }]);

		var result = await resolver.ValidateAsync(SignedRequestTestHarness.Context());

		result.IsSuccess.Should().BeFalse();
	}

}
