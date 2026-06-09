namespace Cirreum.Authentication;

using Cirreum.Authentication.Configuration;
using Cirreum.Authentication.SignedRequest;
using Cirreum.AuthenticationProvider;
using Cirreum.AuthenticationProvider.SignedRequest;
using Cirreum.Coordination;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Options;
using Microsoft.IO;

/// <summary>
/// The <c>AddSignedRequest&lt;TClientResolver&gt;(...)</c> composition verb contributed by the
/// SignedRequest package. Available inside the <c>configure</c> callback of
/// <c>AddAuthentication(...)</c> on the umbrella package.
/// </summary>
/// <remarks>
/// <para>
/// SignedRequest is <b>code-composed</b> — there is no appsettings section or registrar (per
/// the Cirreum provider model, appsettings and a registrar are a matched pair, and SignedRequest
/// has no per-instance data). The client resolver is a <b>required</b> type parameter because it
/// is the sole source of signing credentials: the scheme validates HMAC-signed requests by
/// looking up the presenting client's secret via <see cref="ISignedRequestClientResolver"/>
/// (typically a database). Without a resolver the scheme can never authenticate anything, so it
/// is mandatory at the call site — unlike ApiKey, where a resolver is additive on top of
/// appsettings-configured clients.
/// </para>
/// </remarks>
public static class SignedRequestAuthenticationBuilderExtensions {

	private sealed class SignedRequestComposedMarker { }

	/// <summary>
	/// Composes the SignedRequest authentication scheme using the supplied client resolver.
	/// Registers the signature validator + algorithm resolvers + event sink, the resolver, and
	/// the <see cref="SignedRequestSchemes.Default"/> scheme + selector.
	/// </summary>
	/// <typeparam name="TClientResolver">The app's <see cref="ISignedRequestClientResolver"/>
	/// implementation — resolves the signing credential for a presenting client (e.g. from a
	/// database). Inherit <see cref="DynamicSignedRequestClientResolver"/> for the common case.</typeparam>
	/// <param name="builder">The Cirreum authentication builder.</param>
	/// <param name="configure">Optional callback to tune signature validation via
	/// <see cref="SignedRequestOptions.ConfigureValidation"/>.</param>
	/// <returns>The builder for chaining.</returns>
	public static IAuthenticationBuilder AddSignedRequest<TClientResolver>(
		this IAuthenticationBuilder builder,
		Action<SignedRequestOptions>? configure = null)
		where TClientResolver : class, ISignedRequestClientResolver {

		ArgumentNullException.ThrowIfNull(builder);

		var services = builder.Services;
		if (services.Any(d => d.ServiceType == typeof(SignedRequestComposedMarker))) {
			throw new InvalidOperationException(
				"AddSignedRequest() has already been called for this host. Call it once during composition.");
		}
		services.AddSingleton<SignedRequestComposedMarker>();

		var options = new SignedRequestOptions();
		configure?.Invoke(options);

		// Validation behavior — code-first. Defaults (from SignatureValidationOptions's own
		// initializers) apply when not configured; IOptions provides a default instance.
		if (options.ValidationConfiguration is not null) {
			services.Configure(options.ValidationConfiguration);
		}

		// Strict-nonce posture (ADR-0021) needs a coordination backend: pull the requirement so the umbrella's
		// CoordinationPostureValidator fails the host fast at startup if the app never chooses one. Probe the
		// configured options here (rather than reading bound IOptions) so it stays ordering-independent.
		var validationProbe = new SignatureValidationOptions();
		options.ValidationConfiguration?.Invoke(validationProbe);
		if (validationProbe.RequireStrictNonce) {
			services.AddCoordination();
		}

		// Supporting services — RFC 9421 algorithm contracts (HMAC-SHA256 default + pluggable resolver),
		// the body-buffering stream manager (for Content-Digest verification), and the no-op event sink.
		services.TryAddSingleton<ISignedRequestAlgorithm, HmacSha256SignedRequestAlgorithm>();
		services.TryAddSingleton<ISignedRequestAlgorithmResolver, SignedRequestAlgorithmResolver>();
		services.TryAddSingleton<RecyclableMemoryStreamManager>();
		services.TryAddSingleton<ISignatureValidationEvents>(_ => NullSignatureValidationEvents.Instance);

		// Required client resolver — the sole source of signing credentials. Scoped so app
		// implementations can inject per-request dependencies (repositories, etc.).
		services.TryAddScoped<TClientResolver>();
		services.TryAddScoped<ISignedRequestClientResolver>(sp => sp.GetRequiredService<TClientResolver>());

		// Single scheme + selector.
		var schemeName = SignedRequestSchemes.Default;
		builder.AuthBuilder.AddScheme<SignedRequestAuthenticationOptions, SignedRequestAuthenticationHandler>(
			schemeName,
			_ => { });
		services.AddSingleton(new SignedRequestAuthenticationSchemeSelector(schemeName));
		services.AddSingleton<ISchemeSelector>(sp =>
			sp.GetRequiredService<SignedRequestAuthenticationSchemeSelector>());

		return builder;
	}

}
