namespace Cirreum.Authentication.SignedRequest.Tests;

using Cirreum.Authentication.Configuration;
using Cirreum.AuthenticationProvider.SignedRequest;
using Microsoft.AspNetCore.Http;
using System.Text;
using Harness = SignedRequestTestHarness;

/// <summary>
/// Handler-level proofs for the RFC 9421 verify path: end-to-end authentication, Content-Digest body binding,
/// covered-set / wire-format rejection, and the strict-nonce posture (ADR-0021) — replay rejection, the claim
/// TTL tracking the effective per-credential window (H1), fail-closed on a missing/throwing backend (H2), and
/// the nonce entropy gates.
/// </summary>
public sealed class SignedRequestHandlerTests {

	private static SignatureValidationOptions Strict() => new() { RequireStrictNonce = true };

	// Reads the failure type from the recorded OnValidationFailedAsync call (the substitute records it during the
	// act; Arg.Do callbacks would not fire retroactively during a Received() assertion).
	private static Task<SignatureFailureType?> CapturedFailureAsync(ISignatureValidationEvents events) {
		foreach (var call in events.ReceivedCalls()) {
			if (call.GetMethodInfo().Name == nameof(ISignatureValidationEvents.OnValidationFailedAsync)) {
				var context = (SignatureValidationFailedContext)call.GetArguments()[0]!;
				return Task.FromResult<SignatureFailureType?>(context.FailureType);
			}
		}

		return Task.FromResult<SignatureFailureType?>(null);
	}

	// ---- End-to-end real verify path ----

	[Fact]
	public async Task A_correctly_signed_request_authenticates() {
		var resolver = new Harness.RealResolver([Harness.Credential()]);

		var (result, _) = await Harness.RunAsync(
			Harness.Sign(nonce: null), new SignatureValidationOptions(), resolver, Harness.Empty());

		result.Succeeded.Should().BeTrue();
	}

	[Fact]
	public async Task The_end_to_end_real_path_enforces_single_use_under_strict_nonce() {
		var resolver = new Harness.RealResolver([Harness.Credential()]);
		var provider = Harness.Coordinated();
		var signed = Harness.Sign();

		var (first, _) = await Harness.RunAsync(signed, Strict(), resolver, provider);
		first.Succeeded.Should().BeTrue("a correctly signed request authenticates through the real path");

		var (second, _) = await Harness.RunAsync(signed, Strict(), resolver, provider);
		second.Succeeded.Should().BeFalse("the identical signed request is single-use under strict-nonce");
		second.Failure!.Message.Should().Contain("Replayed");
	}

	[Fact]
	public async Task A_body_that_does_not_match_the_signed_content_digest_is_rejected() {
		var resolver = new Harness.RealResolver([Harness.Credential()]);
		var signed = Harness.Sign(method: "POST", body: Encoding.UTF8.GetBytes("the real body"), nonce: null);
		var tampered = signed with { Body = Encoding.UTF8.GetBytes("a tampered body") };

		var (result, events) = await Harness.RunAsync(tampered, new SignatureValidationOptions(), resolver, Harness.Empty());

		result.Succeeded.Should().BeFalse();
		(await CapturedFailureAsync(events)).Should().Be(SignatureFailureType.ContentDigestMismatch);
	}

	[Fact]
	public async Task An_unsupported_algorithm_is_rejected() {
		var resolver = new Harness.RealResolver([Harness.Credential()]);

		var (result, events) = await Harness.RunAsync(
			Harness.Sign(algorithm: "ed25519", nonce: null), new SignatureValidationOptions(), resolver, Harness.Empty());

		result.Succeeded.Should().BeFalse();
		(await CapturedFailureAsync(events)).Should().Be(SignatureFailureType.UnsupportedAlgorithm);
	}

	// ---- Wire-format / covered-set ----

	[Fact]
	public async Task A_request_with_no_signature_headers_returns_no_result() {
		var context = new DefaultHttpContext { RequestServices = Harness.Empty() };
		context.Request.Method = "GET";

		var (result, _) = await Harness.RunAsync(
			context, new SignatureValidationOptions(), Harness.ResolverReturning(Harness.Success(null)));

		result.None.Should().BeTrue();
	}

	[Fact]
	public async Task Only_one_of_the_two_signature_headers_is_malformed() {
		var context = new DefaultHttpContext { RequestServices = Harness.Empty() };
		context.Request.Method = "GET";
		context.Request.Headers[SignedRequestDefaults.SignatureHeader] = "sig1=:YWJj:";

		var (result, events) = await Harness.RunAsync(
			context, new SignatureValidationOptions(), Harness.ResolverReturning(Harness.Success(null)));

		result.Succeeded.Should().BeFalse();
		(await CapturedFailureAsync(events)).Should().Be(SignatureFailureType.MalformedSignature);
	}

	[Fact]
	public async Task Garbled_signature_headers_are_malformed() {
		var context = new DefaultHttpContext { RequestServices = Harness.Empty() };
		context.Request.Method = "GET";
		context.Request.Headers[SignedRequestDefaults.SignatureHeader] = "not a signature";
		context.Request.Headers[SignedRequestDefaults.SignatureInputHeader] = "not an input";

		var (result, events) = await Harness.RunAsync(
			context, new SignatureValidationOptions(), Harness.ResolverReturning(Harness.Success(null)));

		result.Succeeded.Should().BeFalse();
		(await CapturedFailureAsync(events)).Should().Be(SignatureFailureType.MalformedSignature);
	}

	[Fact]
	public async Task A_signature_missing_a_required_covered_component_is_rejected() {
		var signed = Harness.Sign(
			nonce: null,
			covered: [SignatureComponentNames.Method, SignatureComponentNames.Path, SignatureComponentNames.Query]);

		var (result, events) = await Harness.RunAsync(
			signed, new SignatureValidationOptions(), Harness.ResolverReturning(Harness.Success(null)), Harness.Empty());

		result.Succeeded.Should().BeFalse();
		(await CapturedFailureAsync(events)).Should().Be(SignatureFailureType.UnsupportedComponent);
	}

	// ---- Strict-nonce posture (H1/H2 + entropy gates) ----

	[Fact]
	public async Task A_valid_request_authenticates_then_its_exact_replay_is_rejected() {
		var provider = Harness.Coordinated();
		var signed = Harness.Sign();

		var (first, _) = await Harness.RunAsync(signed, Strict(), Harness.ResolverReturning(Harness.Success(TimeSpan.FromMinutes(5))), provider);
		first.Succeeded.Should().BeTrue();

		var (second, events) = await Harness.RunAsync(signed, Strict(), Harness.ResolverReturning(Harness.Success(TimeSpan.FromMinutes(5))), provider);
		second.Succeeded.Should().BeFalse();
		(await CapturedFailureAsync(events)).Should().Be(SignatureFailureType.ReplayDetected);
	}

	[Fact]
	public async Task The_nonce_ttl_tracks_the_effective_per_credential_window_not_the_global_default() {
		var options = new SignatureValidationOptions {
			RequireStrictNonce = true,
			TimestampTolerance = TimeSpan.FromMinutes(2),
			FutureTimestampTolerance = TimeSpan.FromSeconds(30),
		};
		var effectiveWindow = TimeSpan.FromMinutes(10);
		var guard = new Harness.CapturingReplayGuard();

		var (result, _) = await Harness.RunAsync(
			Harness.Sign(), options, Harness.ResolverReturning(Harness.Success(effectiveWindow)), Harness.With(guard));

		result.Succeeded.Should().BeTrue();
		guard.CapturedTtl.Should().Be(effectiveWindow);
		guard.CapturedTtl.Should().NotBe(options.TimestampTolerance + options.FutureTimestampTolerance);
	}

	[Fact]
	public async Task When_the_resolver_reports_no_window_the_ttl_falls_back_to_the_global_tolerances() {
		var options = new SignatureValidationOptions {
			RequireStrictNonce = true,
			TimestampTolerance = TimeSpan.FromMinutes(3),
			FutureTimestampTolerance = TimeSpan.FromSeconds(45),
		};
		var guard = new Harness.CapturingReplayGuard();

		var (result, _) = await Harness.RunAsync(
			Harness.Sign(), options, Harness.ResolverReturning(Harness.Success(replayWindow: null)), Harness.With(guard));

		result.Succeeded.Should().BeTrue();
		guard.CapturedTtl.Should().Be(options.TimestampTolerance + options.FutureTimestampTolerance);
	}

	[Fact]
	public async Task A_throwing_coordination_backend_fails_closed_without_surfacing_a_500() {
		var (result, events) = await Harness.RunAsync(
			Harness.Sign(), Strict(), Harness.ResolverReturning(Harness.Success(TimeSpan.FromMinutes(5))),
			Harness.With(new Harness.ThrowingReplayGuard()));

		result.Succeeded.Should().BeFalse();
		(await CapturedFailureAsync(events)).Should().Be(SignatureFailureType.ReplayProtectionUnavailable);
	}

	[Fact]
	public async Task Strict_nonce_with_no_backend_registered_fails_closed() {
		var (result, events) = await Harness.RunAsync(
			Harness.Sign(), Strict(), Harness.ResolverReturning(Harness.Success(TimeSpan.FromMinutes(5))), Harness.Empty());

		result.Succeeded.Should().BeFalse();
		(await CapturedFailureAsync(events)).Should().Be(SignatureFailureType.ReplayProtectionUnavailable);
	}

	[Fact]
	public async Task With_strict_nonce_off_no_coordination_backend_is_required() {
		var (result, _) = await Harness.RunAsync(
			Harness.Sign(nonce: null),
			new SignatureValidationOptions { RequireStrictNonce = false },
			Harness.ResolverReturning(Harness.Success(replayWindow: null)),
			Harness.Empty());

		result.Succeeded.Should().BeTrue();
	}

	[Fact]
	public async Task Cancellation_from_the_backend_propagates_and_is_not_swallowed_as_a_failure() {
		var act = async () => await Harness.RunAsync(
			Harness.Sign(), Strict(), Harness.ResolverReturning(Harness.Success(TimeSpan.FromMinutes(5))),
			Harness.With(new Harness.CancellingReplayGuard()));

		await act.Should().ThrowAsync<OperationCanceledException>();
	}

	[Fact]
	public async Task A_missing_nonce_under_strict_nonce_is_rejected() {
		var (result, events) = await Harness.RunAsync(
			Harness.Sign(nonce: null), Strict(), Harness.ResolverReturning(Harness.Success(TimeSpan.FromMinutes(5))), Harness.Empty());

		result.Succeeded.Should().BeFalse();
		(await CapturedFailureAsync(events)).Should().Be(SignatureFailureType.MissingNonce);
	}

	[Fact]
	public async Task A_weak_nonce_under_strict_nonce_is_rejected() {
		var (result, events) = await Harness.RunAsync(
			Harness.Sign(nonce: "short"), Strict(), Harness.ResolverReturning(Harness.Success(TimeSpan.FromMinutes(5))), Harness.Empty());

		result.Succeeded.Should().BeFalse();
		(await CapturedFailureAsync(events)).Should().Be(SignatureFailureType.WeakNonce);
	}

}
