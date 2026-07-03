namespace Cirreum.Authentication.SignedRequest.Tests;

using Cirreum.Authentication.Configuration;
using Cirreum.SignedRequest;
using System.Security.Claims;
using Harness = SignedRequestTestHarness;

/// <summary>
/// Identity / claims integrity proofs (C1–C3): a verified signature over a blank-identity (self-service) store
/// row does not authenticate, store-supplied claims cannot shadow the framework claims, and roles are
/// de-duplicated + screened for control characters before projection.
/// </summary>
public sealed class SignedRequestIdentityTests {

	private static SignatureValidationOptions Lax() => new(); // strict-nonce off

	[Fact]
	public async Task A_credential_with_a_blank_client_id_does_not_authenticate_C1() {
		var blank = new StoredSigningCredential {
			CredentialId = "cred-1", ClientId = "  ", ClientName = "X", SigningSecret = Harness.Secret,
		};
		var resolver = new Harness.RealResolver([blank]);
		var message = Harness.Sign(nonce: null);

		var (result, _) = await Harness.RunAsync(message, Lax(), resolver, Harness.Empty());

		result.Succeeded.Should().BeFalse("a verified signature over a blank-identity credential must not authenticate");
	}

	[Fact]
	public async Task The_handler_rejects_a_resolver_success_with_a_blank_client_id_C1() {
		var resolver = Harness.ResolverReturning(
			SignedRequestValidationResult.Success(new SignedRequestClient { ClientId = "", ClientName = "X" }));
		var message = Harness.Sign(nonce: null);

		var (result, _) = await Harness.RunAsync(message, Lax(), resolver, Harness.Empty());

		result.Succeeded.Should().BeFalse("the non-replaceable handler fail-closes a blank subject even if a resolver returns Success");
	}

	[Fact]
	public async Task Store_claims_cannot_shadow_reserved_claim_types_C2() {
		var client = new SignedRequestClient {
			ClientId = "svc-a",
			ClientName = "Service A",
			Roles = ["reader"],
			Claims = new Dictionary<string, string> {
				[ClaimTypes.Role] = "admin",      // reserved — must be ignored (no privilege escalation)
				["auth_scheme"] = "spoofed",      // reserved — must be ignored
				["credential_id"] = "spoofed",    // reserved — must be ignored
				["department"] = "engineering",   // ordinary — must pass through
			},
		};
		var resolver = Harness.ResolverReturning(SignedRequestValidationResult.Success(client));
		var message = Harness.Sign(nonce: null);

		var (result, _) = await Harness.RunAsync(message, Lax(), resolver, Harness.Empty());

		result.Succeeded.Should().BeTrue();
		var principal = result.Principal!;
		principal.FindAll(ClaimTypes.Role).Select(c => c.Value).Should().Contain("reader").And.NotContain("admin");
		principal.FindAll("auth_scheme").Select(c => c.Value).Should().ContainSingle().Which.Should().Be("SignedRequest");
		principal.FindFirstValue("department").Should().Be("engineering");
	}

	[Fact]
	public async Task Roles_are_de_duplicated_and_control_characters_screened_C3() {
		var client = new SignedRequestClient {
			ClientId = "svc-a",
			ClientName = "Service A",
			Roles = ["reader", "reader", "ad\r\nmin"], // a duplicate + a CRLF-bearing role
		};
		var resolver = Harness.ResolverReturning(SignedRequestValidationResult.Success(client));
		var message = Harness.Sign(nonce: null);

		var (result, _) = await Harness.RunAsync(message, Lax(), resolver, Harness.Empty());

		result.Principal!.FindAll(ClaimTypes.Role).Select(c => c.Value)
			.Should().ContainSingle().Which.Should().Be("reader", "the duplicate collapses and the CRLF-bearing role is dropped");
	}
}
