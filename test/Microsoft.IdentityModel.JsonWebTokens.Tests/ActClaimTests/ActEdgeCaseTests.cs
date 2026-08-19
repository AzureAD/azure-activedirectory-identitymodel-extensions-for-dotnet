// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;
using Microsoft.IdentityModel.TestUtils;
using Microsoft.IdentityModel.Tokens;
using Xunit;
using Xunit.Abstractions;

namespace Microsoft.IdentityModel.JsonWebTokens.Tests.ActClaimTests
{
    /// <summary>
    /// Edge-case tests describing the CORRECT expected behavior of the "act" claim.
    /// Three of these currently FAIL against the implementation in PR #3571; the
    /// canonical-delegation test passes and is included as the contrast case.
    /// </summary>
    [Collection("ActClaimTests")]
    public class ActEdgeCaseTests : IDisposable
    {
        private readonly ITestOutputHelper _output;
        private readonly int _originalMaxChainLength = JsonWebTokenHandler.MaxActorChainLength;

        /// <summary>
        /// Members that legitimately identify an actor inside "act". RFC 8693 section 4.1 shows
        /// "sub" (the actor), a nested "act" (progressively earlier actors), and "iss" (used to
        /// qualify an actor from a different issuer in the cross-domain example). Lifetime and
        /// audience claims are not meaningful inside "act".
        /// </summary>
        private static readonly HashSet<string> ActorIdentifyingClaims =
            new HashSet<string>(StringComparer.Ordinal) { "sub", "act", "iss" };

        public ActEdgeCaseTests(ITestOutputHelper output) => _output = output;

        public void Dispose() => JsonWebTokenHandler.MaxActorChainLength = _originalMaxChainLength;

        private static TokenValidationParameters ValidationParameters => new TokenValidationParameters
        {
            IssuerSigningKey = KeyingMaterial.DefaultSymmetricSecurityKey_256,
            ValidIssuer = Default.Issuer,
            ValidAudience = Default.Audience,
            ValidateLifetime = false,
        };

        private static string IssueToken(ClaimsIdentity subject) =>
            new JsonWebTokenHandler().CreateToken(new SecurityTokenDescriptor
            {
                Subject = subject,
                Issuer = Default.Issuer,
                Audience = Default.Audience,
                SigningCredentials = KeyingMaterial.DefaultSymmetricSigningCreds_256_Sha2
            });

        private static JsonElement PayloadOf(string jwt) =>
            JsonDocument.Parse(Encoding.UTF8.GetString(
                Base64UrlEncoder.DecodeBytes(new JsonWebToken(jwt).EncodedPayload))).RootElement;

        private static JsonElement ActClaimOf(string jwt) => PayloadOf(jwt).GetProperty("act");

        // JsonElement.EnumerateObject preserves duplicate members, so this counts real wire duplicates.
        private static int CountMembers(JsonElement obj, string name) =>
            obj.EnumerateObject().Count(p => p.Name == name);

        private static string RawJson(JsonElement e) => e.GetRawText();

        /// <summary>
        /// Builds an inbound token whose subject is "user", acted on by "svc-A".
        /// </summary>
        private static string CreateInboundDelegationToken()
        {
            var actor = new CaseSensitiveClaimsIdentity(new List<Claim> { new Claim("sub", "svc-A") });
            var subject = new CaseSensitiveClaimsIdentity(new List<Claim> { new Claim("sub", "user") });
            subject.Actor = actor;

            return IssueToken(subject);
        }

        /// <summary>
        /// FINDING #2. A JSON object must never contain the same member name twice. When a validated
        /// ClaimsIdentity (which by design carries BOTH identity.Actor and a retained literal "act"
        /// claim) is used as the actor of a new token, WriteIdentityClaims emits the literal "act"
        /// claim and WriteActorObject separately emits the structural "act" - producing two "act"
        /// members in one signed object.
        /// </summary>
        [Fact]
        public async Task ReissuedToken_ValidatedIdentityUsedAsActor_EmitsExactlyOneActMember()
        {
            // Arrange - an ordinary single-level actor token at the DEFAULT MaxActorChainLength of 1.
            string inboundToken = CreateInboundDelegationToken();

            var handler = new JsonWebTokenHandler();
            TokenValidationResult result = await handler.ValidateTokenAsync(inboundToken, ValidationParameters);
            Assert.True(result.IsValid);

            // Act - the validated caller identity becomes the actor of the outgoing token.
            var newSubject = new CaseSensitiveClaimsIdentity(new List<Claim> { new Claim("sub", "downstream") });
            newSubject.Actor = result.ClaimsIdentity;
            string reissuedToken = IssueToken(newSubject);

            // Assert - the emitted "act" object must contain exactly one nested "act" member.
            JsonElement actObject = ActClaimOf(reissuedToken);
            int nestedActCount = CountMembers(actObject, "act");

            Assert.True(
                nestedActCount == 1,
                $"Expected exactly 1 nested 'act' member but found {nestedActCount}. " +
                $"The signed 'act' object is ambiguous: first-wins and last-wins JSON parsers will " +
                $"resolve different delegation actors.{Environment.NewLine}" +
                $"Emitted act = {RawJson(actObject)}");
        }

        /// <summary>
        /// FINDING #3. Duplicate JSON members must resolve identically wherever they appear. The outer
        /// payload collapses duplicates last-wins (Dictionary indexer assignment in
        /// JsonWebToken.PayloadClaimSet), but CreateActorClaimsIdentityFromJsonElement enumerates the
        /// raw JsonElement and AddClaim's every duplicate, making "act" effectively first-wins.
        /// </summary>
        [Fact]
        public async Task ActorIdentity_DuplicateSubMembersInAct_ResolveLastWinsLikeOuterPayload()
        {
            // Arrange - one signed token carrying the SAME duplicate construct at both levels.
            string payload =
                "{\"iss\":\"" + Default.Issuer + "\",\"aud\":\"" + Default.Audience + "\"," +
                "\"sub\":\"outer-first\",\"sub\":\"outer-last\"," +
                "\"act\":{\"sub\":\"actor-first\",\"sub\":\"actor-last\"}}";

            var handler = new JsonWebTokenHandler();
            string token = handler.CreateToken(payload, KeyingMaterial.DefaultSymmetricSigningCreds_256_Sha2);

            // Act
            TokenValidationResult result = await handler.ValidateTokenAsync(token, ValidationParameters);
            Assert.True(result.IsValid);

            ClaimsIdentity outerIdentity = result.ClaimsIdentity;
            ClaimsIdentity actorIdentity = outerIdentity.Actor;
            Assert.NotNull(actorIdentity);

            int outerSubCount = outerIdentity.Claims.Count(c => c.Type == "sub");
            int actorSubCount = actorIdentity.Claims.Count(c => c.Type == "sub");

            // Assert 1 - the actor must collapse duplicates to a single claim, exactly like the outer payload.
            Assert.True(
                actorSubCount == outerSubCount,
                $"Duplicate-member resolution is inconsistent: the outer payload produced {outerSubCount} " +
                $"'sub' claim(s) but the 'act' object produced {actorSubCount}. The actor now carries " +
                $"multiple conflicting identities; Claims.Single(...) throws and FindFirst is first-wins " +
                $"while the outer payload is last-wins.{Environment.NewLine}" +
                $"actor 'sub' claims = [{string.Join(", ", actorIdentity.Claims.Where(c => c.Type == "sub").Select(c => c.Value))}]");

            // Assert 2 - and it must pick the SAME duplicate the outer payload picks (last-wins).
            Assert.Equal("actor-last", actorIdentity.FindFirst("sub").Value);

            // Assert 3 - re-serializing must not coalesce duplicates into an RFC 8693-invalid array 'sub'.
            var newSubject = new CaseSensitiveClaimsIdentity(new List<Claim> { new Claim("sub", "downstream") });
            newSubject.Actor = actorIdentity;
            JsonElement reissuedAct = ActClaimOf(IssueToken(newSubject));
            JsonValueKind subKind = reissuedAct.GetProperty("sub").ValueKind;

            Assert.True(
                subKind == JsonValueKind.String,
                $"RFC 8693 section 4.1 requires 'sub' inside 'act' to be a StringOrURI, but it was " +
                $"serialized as {subKind}.{Environment.NewLine}Emitted act = {RawJson(reissuedAct)}");
        }

        /// <summary>
        /// A signed JSON object must never repeat a member name. A validated ClaimsIdentity carries
        /// BOTH identity.Actor and the retained literal "act" claim, so using it as the actor of a new
        /// token made WriteIdentityClaims emit the literal "act" while WriteActorObject separately
        /// emitted the structural one.
        /// <para>
        /// This test also REPORTS the non-actor claims ("aud"/"exp"/"iat"/"nbf") that a validated
        /// identity drags into "act", but deliberately does not assert on them: per
        /// ActorToken_WithCallerProvidedNonIdentityClaims_AreWrittenVerbatim the writer intentionally
        /// serializes the actor identity as-is and only refrains from injecting its OWN defaults.
        /// Stripping them here would be silent data loss. They appear only because the caller reused a
        /// validated identity as an actor; see ActObject_CanonicalDelegation_ContainsOnlyActorClaims
        /// for the delegation shape that avoids this entirely.
        /// </para>
        /// </summary>
        [Fact]
        public async Task ActObject_FromValidatedIdentity_ContainsNoDuplicateMembers()
        {
            // Arrange
            JsonWebTokenHandler.MaxActorChainLength = 3;
            string inboundToken = CreateInboundDelegationToken();

            var handler = new JsonWebTokenHandler();
            TokenValidationResult result = await handler.ValidateTokenAsync(inboundToken, ValidationParameters);
            Assert.True(result.IsValid);

            _output.WriteLine("=== Claims on the validated ClaimsIdentity (the future actor) ===");
            foreach (Claim claim in result.ClaimsIdentity.Claims)
                _output.WriteLine($"  {claim.Type,-6} = {claim.Value}");

            // Act - use the validated identity as the actor of a new token.
            var downstreamSubject = new CaseSensitiveClaimsIdentity(new List<Claim> { new Claim("sub", "downstream") });
            downstreamSubject.Actor = result.ClaimsIdentity;
            JsonElement actObject = ActClaimOf(IssueToken(downstreamSubject));

            _output.WriteLine(string.Empty);
            _output.WriteLine("=== Members actually written into \"act\" ===");

            var carried = new List<string>();
            var duplicates = new List<string>();
            var seen = new HashSet<string>(StringComparer.Ordinal);

            foreach (JsonProperty member in actObject.EnumerateObject())
            {
                bool isDuplicate = !seen.Add(member.Name);
                bool isNonActor = !ActorIdentifyingClaims.Contains(member.Name);

                _output.WriteLine($"  [{(isDuplicate ? "DUPLICATE" : isNonActor ? "carried" : "expected"),-9}] " +
                                  $"\"{member.Name}\" : {RawJson(member.Value)}");

                if (isDuplicate)
                    duplicates.Add(member.Name);
                else if (isNonActor)
                    carried.Add(member.Name);
            }

            _output.WriteLine(string.Empty);
            _output.WriteLine("=== Raw act value ===");
            _output.WriteLine("  " + RawJson(actObject));
            _output.WriteLine(string.Empty);
            _output.WriteLine($"Carried non-actor claims (reported, by design not stripped) : " +
                              $"{(carried.Count == 0 ? "(none)" : string.Join(", ", carried))}");
            _output.WriteLine($"Duplicate members (asserted)                                : " +
                              $"{(duplicates.Count == 0 ? "(none)" : string.Join(", ", duplicates))}");

            // Assert - no member name may appear twice in the signed "act" object.
            Assert.True(
                duplicates.Count == 0,
                $"The emitted 'act' object contains duplicate JSON members: {string.Join(", ", duplicates)}. " +
                $"First-wins and last-wins JSON parsers will resolve different delegation actors." +
                $"{Environment.NewLine}Emitted act = {RawJson(actObject)}");
        }
    }
}
