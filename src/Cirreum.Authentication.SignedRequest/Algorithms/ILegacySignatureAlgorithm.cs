namespace Cirreum.Authentication.SignedRequest;

/// <summary>
/// Defines the contract for a cryptographic signature algorithm capable of producing digital signatures for messages.
/// </summary>
/// <remarks>Implementations of this interface provide methods to generate digital signatures using a specified
/// key and message. The interface exposes properties to identify the algorithm version and the size of the generated
/// signature. This interface is intended for use in scenarios where message authenticity and integrity must be verified
/// using digital signatures.</remarks>
public interface ILegacySignatureAlgorithm {

	/// <summary>
	/// The wire-format version identifier (e.g., "v1").
	/// </summary>
	string Version { get; }

	/// <summary>
	/// Size of the signature output in bytes.
	/// </summary>
	int SignatureSizeBytes { get; }

	/// <summary>
	/// Computes the signature into the destination buffer.
	/// </summary>
	void Sign(ReadOnlySpan<byte> message, ReadOnlySpan<byte> key, Span<byte> destination);

}