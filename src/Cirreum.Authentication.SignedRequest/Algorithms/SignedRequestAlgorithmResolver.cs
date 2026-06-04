namespace Cirreum.Authentication.SignedRequest;

using Cirreum.AuthenticationProvider.SignedRequest;
using Cirreum.AuthenticationProvider;
/// <summary>
/// Resolves <see cref="ISignedRequestAlgorithm"/> implementations by canonical
/// algorithm identifier. Iterates all registered services and returns the first
/// whose <see cref="ISignedRequestAlgorithm.AlgorithmId"/> matches.
/// </summary>
/// <remarks>
/// Apps register additional algorithms by adding more
/// <see cref="ISignedRequestAlgorithm"/> services to DI; the resolver picks them
/// up automatically with no registry edits.
/// </remarks>
public sealed class SignedRequestAlgorithmResolver(IEnumerable<ISignedRequestAlgorithm> algorithms)
	: ISignedRequestAlgorithmResolver {

	private readonly IReadOnlyList<ISignedRequestAlgorithm> _algorithms = [.. algorithms];

	/// <inheritdoc/>
	public ISignedRequestAlgorithm? Resolve(string algorithmId) {
		foreach (var algorithm in _algorithms) {
			if (string.Equals(algorithm.AlgorithmId, algorithmId, StringComparison.Ordinal)) {
				return algorithm;
			}
		}
		return null;
	}

}
