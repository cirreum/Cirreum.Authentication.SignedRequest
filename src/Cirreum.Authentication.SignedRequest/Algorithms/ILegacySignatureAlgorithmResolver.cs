namespace Cirreum.Authentication.SignedRequest;

/// <summary>
/// Defines a mechanism for resolving signature algorithms based on a version identifier.
/// </summary>
/// <remarks>Implementations of this interface provide a way to map version strings to specific signature
/// algorithm instances. This is typically used to support multiple algorithm versions or to enable algorithm
/// negotiation in cryptographic systems.</remarks>
public interface ILegacySignatureAlgorithmResolver {

	/// <summary>
	/// Resolves an algorithm by its version identifier, or null if unsupported.
	/// </summary>
	ILegacySignatureAlgorithm? Resolve(string version);
}