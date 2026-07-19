namespace Cirreum.Authentication.SignedRequest.Tests;

using Cirreum.Authentication.Configuration;
using Cirreum.AuthenticationProvider;
using Cirreum.SignedRequest;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Microsoft.IO;

/// <summary>
/// Composition-path proofs for <c>AddSignedRequest&lt;TClientResolver&gt;()</c>: the full registration
/// graph must compose on a bare host and yield a resolvable container. Guards the untested-composition-verb
/// escape vector behind Cirreum.Authentication.ApiKey issue #1, where the provider's composition verb threw
/// unconditionally through five published versions because no test ever invoked it.
/// </summary>
public sealed class AddSignedRequestCompositionTests {

	private static IAuthenticationBuilder CreateBuilder(IServiceCollection services) {
		var builder = Substitute.For<IAuthenticationBuilder>();
		builder.Services.Returns(services);
		builder.AuthBuilder.Returns(new AuthenticationBuilder(services));
		builder.Configuration.Returns(new ConfigurationBuilder().Build());
		return builder;
	}

	[Fact]
	public void AddSignedRequest_composes_without_throwing_and_resolves_the_registered_graph() {
		var services = new ServiceCollection();
		var builder = CreateBuilder(services);

		builder.AddSignedRequest<StubClientResolver>();

		using var provider = services.BuildServiceProvider(new ServiceProviderOptions {
			ValidateScopes = true,
		});
		provider.GetRequiredService<ISignedRequestAlgorithmResolver>().Should().NotBeNull();
		provider.GetRequiredService<ISignatureValidationEvents>().Should().NotBeNull();
		provider.GetRequiredService<RecyclableMemoryStreamManager>().Should().NotBeNull();
		provider.GetRequiredService<ISchemeSelector>().Should().NotBeNull();

		// The client resolver is scoped (so app implementations can inject per-request dependencies).
		using var scope = provider.CreateScope();
		scope.ServiceProvider.GetRequiredService<ISignedRequestClientResolver>()
			.Should().BeOfType<StubClientResolver>();
	}

	[Fact]
	public void AddSignedRequest_applies_the_validation_configuration() {
		var services = new ServiceCollection();
		var builder = CreateBuilder(services);

		builder.AddSignedRequest<StubClientResolver>(o =>
			o.ConfigureValidation(v => v.TimestampTolerance = TimeSpan.FromMinutes(7)));

		using var provider = services.BuildServiceProvider();
		provider.GetRequiredService<IOptions<SignatureValidationOptions>>()
			.Value.TimestampTolerance.Should().Be(TimeSpan.FromMinutes(7));
	}

	[Fact]
	public void AddSignedRequest_called_twice_throws_the_composition_guard() {
		var services = new ServiceCollection();
		var builder = CreateBuilder(services);
		builder.AddSignedRequest<StubClientResolver>();

		var act = () => builder.AddSignedRequest<StubClientResolver>();

		act.Should().Throw<InvalidOperationException>()
			.WithMessage("*already been called*");
	}

	private sealed class StubClientResolver : ISignedRequestClientResolver {
		public Task<SignedRequestValidationResult> ValidateAsync(
			SignedRequestContext context,
			CancellationToken cancellationToken = default) => throw new NotSupportedException();
	}
}
