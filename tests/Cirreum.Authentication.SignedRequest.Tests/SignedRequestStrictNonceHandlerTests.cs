namespace Cirreum.Authentication.SignedRequest.Tests;

using Cirreum.Authentication.Configuration;
using Cirreum.Coordination;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Microsoft.IO;
using System.Text.Encodings.Web;

/// <summary>
/// Handler-level proofs for the strict-nonce posture (ADR-0021): that the scheme consumes
/// <see cref="IReplayGuard"/> correctly — replay is rejected, the claim TTL tracks the effective
/// per-credential window (H1), and a missing or throwing backend fails closed without a 500 (H2).
/// The primitive's own concurrency/atomicity is proven in Cirreum.Coordination; these tests prove
/// the handler's <em>use</em> of it.
/// </summary>
public sealed class SignedRequestStrictNonceHandlerTests {

	private const string Signature = "v1=deadbeefdeadbeefdeadbeefdeadbeef";

	// The resolver is stubbed, so the signature value itself is irrelevant — these tests exercise the
	// handler's strict-nonce stage, which runs only after validation has already succeeded.
	private static SignedRequestValidationResult SuccessResult(TimeSpan? replayWindow) =>
		SignedRequestValidationResult.Success(
			new SignedRequestClient { ClientId = "client-1", ClientName = "Client One", CredentialId = "cred-1" },
			replayWindow);

	private static ISignedRequestClientResolver ResolverReturning(SignedRequestValidationResult result) {
		var resolver = Substitute.For<ISignedRequestClientResolver>();
		resolver.ValidateAsync(Arg.Any<SignedRequestContext>(), Arg.Any<CancellationToken>()).Returns(result);
		return resolver;
	}

	private static IServiceProvider RequestServicesWith(IReplayGuard guard) =>
		new ServiceCollection().AddSingleton(guard).BuildServiceProvider();

	private static async Task<(AuthenticateResult result, ISignatureValidationEvents events)> RunAsync(
		SignatureValidationOptions validationOptions,
		ISignedRequestClientResolver resolver,
		IServiceProvider requestServices) {

		var events = Substitute.For<ISignatureValidationEvents>();

		var optionsMonitor = Substitute.For<IOptionsMonitor<SignedRequestAuthenticationOptions>>();
		optionsMonitor.Get(Arg.Any<string>()).Returns(new SignedRequestAuthenticationOptions());

		var handler = new SignedRequestAuthenticationHandler(
			optionsMonitor,
			NullLoggerFactory.Instance,
			UrlEncoder.Default,
			resolver,
			Substitute.For<ISignatureValidator>(),
			Options.Create(validationOptions),
			new RecyclableMemoryStreamManager(),
			events);

		var context = new DefaultHttpContext { RequestServices = requestServices };
		context.Request.Method = "GET";
		context.Request.Headers["X-Client-Id"] = "client-1";
		context.Request.Headers["X-Signature"] = Signature;
		context.Request.Headers["X-Timestamp"] = DateTimeOffset.UtcNow.ToUnixTimeSeconds().ToString();

		var scheme = new AuthenticationScheme(
			SignedRequestSchemes.Default, SignedRequestSchemes.Default, typeof(SignedRequestAuthenticationHandler));
		await handler.InitializeAsync(scheme, context);

		return (await handler.AuthenticateAsync(), events);
	}

	[Fact]
	public async Task A_valid_request_authenticates_then_its_exact_replay_is_rejected() {
		var options = new SignatureValidationOptions { RequireStrictNonce = true };
		// A real in-memory coordination backend so the second claim genuinely loses the race. The provider
		// (and therefore the singleton guard) is shared across both presentations.
		var provider = new ServiceCollection().AddCoordination(c => c.UseInMemory()).BuildServiceProvider();

		var (first, _) = await RunAsync(options, ResolverReturning(SuccessResult(TimeSpan.FromMinutes(5))), provider);
		first.Succeeded.Should().BeTrue("the first presentation claims the nonce and authenticates");

		var (second, events) = await RunAsync(options, ResolverReturning(SuccessResult(TimeSpan.FromMinutes(5))), provider);
		second.Succeeded.Should().BeFalse("the exact same signed request is single-use within the window");
		second.Failure!.Message.Should().Contain("Replayed");
		await events.Received(1).OnValidationFailedAsync(
			Arg.Is<SignatureValidationFailedContext>(c => c.FailureType == SignatureFailureType.ReplayDetected),
			Arg.Any<CancellationToken>());
	}

	[Fact]
	public async Task The_nonce_ttl_tracks_the_effective_per_credential_window_not_the_global_default() {
		// Global window is small; the resolver reports a much larger effective (per-credential) window.
		var options = new SignatureValidationOptions {
			RequireStrictNonce = true,
			TimestampTolerance = TimeSpan.FromMinutes(2),
			FutureTimestampTolerance = TimeSpan.FromSeconds(30),
		};
		var effectiveWindow = TimeSpan.FromMinutes(10);
		var guard = new CapturingReplayGuard();

		var (result, _) = await RunAsync(
			options, ResolverReturning(SuccessResult(effectiveWindow)), RequestServicesWith(guard));

		result.Succeeded.Should().BeTrue();
		// H1: the claim is held for the window the request was actually accepted under (10 min), NOT the
		// 2.5 min global sum — otherwise a client granted a wider tolerance would have a replay gap.
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
		var guard = new CapturingReplayGuard();

		var (result, _) = await RunAsync(
			options, ResolverReturning(SuccessResult(replayWindow: null)), RequestServicesWith(guard));

		result.Succeeded.Should().BeTrue();
		guard.CapturedTtl.Should().Be(options.TimestampTolerance + options.FutureTimestampTolerance);
	}

	[Fact]
	public async Task A_throwing_coordination_backend_fails_closed_without_surfacing_a_500() {
		var options = new SignatureValidationOptions { RequireStrictNonce = true };

		var (result, events) = await RunAsync(
			options,
			ResolverReturning(SuccessResult(TimeSpan.FromMinutes(5))),
			RequestServicesWith(new ThrowingReplayGuard()));

		// Fail closed: a clean authentication failure, NOT a propagated exception (which would become a 500).
		result.Succeeded.Should().BeFalse();
		result.Failure.Should().NotBeNull();
		await events.Received(1).OnValidationFailedAsync(
			Arg.Is<SignatureValidationFailedContext>(c => c.FailureType == SignatureFailureType.ReplayProtectionUnavailable),
			Arg.Any<CancellationToken>());
	}

	[Fact]
	public async Task Strict_nonce_with_no_backend_registered_fails_closed() {
		var options = new SignatureValidationOptions { RequireStrictNonce = true };
		// Empty request services: GetService<IReplayGuard>() returns null. The umbrella boot validator should
		// have caught this; the handler is the request-time failsafe.
		var provider = new ServiceCollection().BuildServiceProvider();

		var (result, events) = await RunAsync(
			options, ResolverReturning(SuccessResult(TimeSpan.FromMinutes(5))), provider);

		result.Succeeded.Should().BeFalse();
		await events.Received(1).OnValidationFailedAsync(
			Arg.Is<SignatureValidationFailedContext>(c => c.FailureType == SignatureFailureType.ReplayProtectionUnavailable),
			Arg.Any<CancellationToken>());
	}

	[Fact]
	public async Task With_strict_nonce_off_no_coordination_backend_is_required() {
		var options = new SignatureValidationOptions { RequireStrictNonce = false };
		var provider = new ServiceCollection().BuildServiceProvider(); // no IReplayGuard at all

		var (result, _) = await RunAsync(
			options, ResolverReturning(SuccessResult(replayWindow: null)), provider);

		result.Succeeded.Should().BeTrue();
	}

	// Captures the TTL the handler hands the backend, so a test can prove it matches the effective window.
	private sealed class CapturingReplayGuard : IReplayGuard {
		public TimeSpan? CapturedTtl { get; private set; }
		public ValueTask<bool> TryClaimAsync(string token, TimeSpan ttl, CancellationToken cancellationToken = default) {
			this.CapturedTtl = ttl;
			return ValueTask.FromResult(true);
		}
	}

	// Simulates an unreachable backend (e.g. Redis down).
	private sealed class ThrowingReplayGuard : IReplayGuard {
		public ValueTask<bool> TryClaimAsync(string token, TimeSpan ttl, CancellationToken cancellationToken = default) =>
			throw new InvalidOperationException("coordination backend unavailable");
	}

}
