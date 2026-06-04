namespace Cirreum.Authentication.SignedRequest;

using System.Collections.Frozen;

public sealed class LegacySignatureAlgorithmResolver(
	IEnumerable<ILegacySignatureAlgorithm> algorithms
) : ILegacySignatureAlgorithmResolver {

	private readonly FrozenDictionary<string, ILegacySignatureAlgorithm> _algorithms = algorithms.ToFrozenDictionary(
			a => a.Version,
			StringComparer.Ordinal);

	public ILegacySignatureAlgorithm? Resolve(string version) {
		return _algorithms.TryGetValue(version, out var algorithm) ? algorithm : null;
	}

}

// TODO: Add built-in algorithms and register them in DI
//services.AddSingleton<ILegacySignatureAlgorithm, HmacSha256SignatureAlgorithm>();
//services.AddSingleton<ILegacySignatureAlgorithmResolver, LegacySignatureAlgorithmResolver>();
