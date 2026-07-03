namespace Cirreum.Authentication.SignedRequest;

using Cirreum.Authentication.Configuration;
/// <summary>
/// Represents stored signing credentials retrieved from a database or external source.
/// Used by <see cref="DynamicSignedRequestClientResolver"/> to validate signed requests.
/// </summary>
/// <remarks>
/// <para>
/// Each client can have multiple active credentials to support zero-downtime key rotation.
/// When rotating keys:
/// <list type="number">
///   <item>Add new credential with <see cref="IsActive"/> = true</item>
///   <item>Update partner systems to use new key</item>
///   <item>Set old credential <see cref="IsActive"/> = false</item>
/// </list>
/// </para>
/// </remarks>
public sealed record StoredSigningCredential {

	/// <summary>
	/// Gets the unique identifier for this specific credential.
	/// Useful for audit logging which key was used.
	/// </summary>
	public required string CredentialId { get; init; }

	/// <summary>
	/// Gets the client ID this credential belongs to.
	/// </summary>
	public required string ClientId { get; init; }

	/// <summary>
	/// Gets the display name for this client.
	/// </summary>
	public required string ClientName { get; init; }

	/// <summary>
	/// Gets the signing secret used to compute HMAC signatures.
	/// </summary>
	/// <remarks>
	/// Store it encrypted at rest (the consuming application owns encryption/decryption). It must be at least
	/// <c>SignedRequestSecret.MinimumBytes</c> (16) UTF-8 bytes — a <em>byte</em> floor, not an entropy measure,
	/// so 128-bit strength requires that many <em>random</em> bytes (NIST SP 800-107 recommends ≥ 32). Provision it
	/// with <c>SigningSecretGenerator.Generate()</c> rather than a hand-chosen passphrase; a credential whose secret
	/// is below the floor is skipped at verification (E1).
	/// </remarks>
	public required string SigningSecret { get; init; }

	/// <summary>
	/// Gets whether this credential is currently active.
	/// Inactive credentials will not be used for validation.
	/// </summary>
	public bool IsActive { get; init; } = true;

	/// <summary>
	/// Gets the optional expiration time for this credential.
	/// </summary>
	public DateTimeOffset? ExpiresAt { get; init; }

	/// <summary>
	/// Gets the roles assigned to this client.
	/// </summary>
	public IReadOnlyList<string> Roles { get; init; } = [];

	/// <summary>
	/// Gets optional custom claims to include in the client's identity.
	/// </summary>
	public IReadOnlyDictionary<string, string>? Claims { get; init; }

	/// <summary>
	/// Gets an optional per-client timestamp tolerance that overrides <see cref="SignatureValidationOptions.TimestampTolerance"/>.
	/// If null, the application's default is used.
	/// </summary>
	/// <remarks>
	/// Set this for clients with known clock skew issues to allow older requests.
	/// </remarks>
	public TimeSpan? TimestampTolerance { get; init; }

	/// <summary>
	/// Gets an optional per-client future timestamp tolerance that overrides <see cref="SignatureValidationOptions.FutureTimestampTolerance"/>.
	/// If null, the application's default is used.
	/// </summary>
	/// <remarks>
	/// Set this for clients with clocks running ahead to allow future-dated requests.
	/// </remarks>
	public TimeSpan? FutureTimestampTolerance { get; init; }

	/// <summary>
	/// Gets the optional set of permitted RFC 9421 algorithm identifiers (e.g. <c>hmac-sha256</c>) for this
	/// credential. When <see langword="null"/> or empty the credential is pinned to the v1 default
	/// (<c>hmac-sha256</c>) — NOT "any registered algorithm" — so a future asymmetric algorithm can never be
	/// used against a key provisioned for HMAC. A credential for any non-default algorithm MUST list it here.
	/// </summary>
	public IReadOnlySet<string>? SupportedAlgorithms { get; init; }

	/// <summary>
	/// Gets the optional explicit audience this credential is bound to (the RFC 9421 <c>tag</c>). When set, a
	/// request signed with this credential must carry a matching <c>tag</c> or it is rejected — the defense for
	/// a credential deliberately shared across more than one audience (ADR-0021). When <see langword="null"/>
	/// the credential (<c>keyid</c>) is itself the implicit audience.
	/// </summary>
	public string? Audience { get; init; }

	/// <summary>
	/// Converts this stored credential to a <see cref="SignedRequestClient"/> for authentication.
	/// </summary>
	/// <returns>A signed request client with the credential's properties.</returns>
	public SignedRequestClient ToClient() => new() {
		ClientId = this.ClientId,
		ClientName = this.ClientName,
		Roles = this.Roles,
		Claims = this.Claims,
		CredentialId = this.CredentialId
	};

	/// <summary>
	/// Redacts the signing secret from the synthesized record string, so a credential cannot leak its secret
	/// through logging or string interpolation.
	/// </summary>
	public override string ToString() =>
		$"{nameof(StoredSigningCredential)} {{ CredentialId = {this.CredentialId}, ClientId = {this.ClientId}, ClientName = {this.ClientName}, SigningSecret = [redacted] }}";

}