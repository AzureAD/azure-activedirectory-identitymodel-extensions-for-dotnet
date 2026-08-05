// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System;
using System.Collections.Generic;
using System.Security.Claims;
using System.Text.Json;
using Microsoft.IdentityModel.TestUtils;
using Microsoft.IdentityModel.Tokens;
using Xunit;
namespace Microsoft.IdentityModel.JsonWebTokens.Tests.ActClaimTests
{
    // MaxActorChainLength is a process-wide static shared by the act-claim serialization and
    // deserialization tests; disable parallelization so mutating it can't race other collections.
    [CollectionDefinition("ActClaimTests", DisableParallelization = true)]
    public class ActClaimTestsCollection { }

    [Collection("ActClaimTests")]
    public class ActClaimSerializationTests : IDisposable
    {
        // Reset the process-wide MaxActorChainLength after every test for isolation.
        public void Dispose() => JsonWebTokenHandler.MaxActorChainLength = 1;

        [Fact]
        public void MaxActorChainLength_DefaultIsOne()
        {
            // Arrange / Act / Assert
            Assert.Equal(1, JsonWebTokenHandler.MaxActorChainLength);
        }

        [Fact]
        public void MaxActorChainLength_LessThanOne_Throws()
        {
            // Arrange / Act / Assert
            var ex = Assert.Throws<ArgumentOutOfRangeException>(() => JsonWebTokenHandler.MaxActorChainLength = 0);
            Assert.Contains("IDX14317", ex.Message);
        }

        [Fact]
        public void ActorToken_IsRfcCompliant_ActObjectHasNoNonIdentityClaims()
        {
            // RFC 8693 section 4.1: the "act" claim holds only identity claims; the handler must not
            // INJECT its own default temporal claims (exp, nbf, iat) into "act" the way it does for the
            // top-level payload. This is the regression guard for the original bug, where reusing
            // WriteJwsPayload for actors leaked default exp/iat/nbf into every "act" object.
            var actorIdentity = new CaseSensitiveClaimsIdentity("ActorAuth");
            actorIdentity.AddClaim(new Claim("sub", "actor-subject-id"));
            actorIdentity.AddClaim(new Claim("name", "Actor Name"));

            var mainIdentity = new CaseSensitiveClaimsIdentity("Bearer");
            mainIdentity.AddClaim(new Claim("sub", "main-subject-id"));
            mainIdentity.Actor = actorIdentity;

            var handler = new JsonWebTokenHandler();
            var tokenDescriptor = new SecurityTokenDescriptor
            {
                Subject = mainIdentity,
                Issuer = "https://example.com",
                Audience = "https://api.example.com",
                SigningCredentials = Default.AsymmetricSigningCredentials,
            };
            var token = handler.CreateToken(tokenDescriptor);
            var decoded = handler.ReadJsonWebToken(token);

            // The top-level payload DOES receive the default temporal claims that CreateToken injects.
            // Asserting this first is what makes the "act" asserts below non-trivial: it proves the
            // default-time injection actually runs for this token, yet does not reach the "act" object.
            Assert.True(decoded.Payload.HasClaim("exp"), "top-level payload should contain 'exp'");
            Assert.True(decoded.Payload.HasClaim("nbf"), "top-level payload should contain 'nbf'");
            Assert.True(decoded.Payload.HasClaim("iat"), "top-level payload should contain 'iat'");

            // The "act" object carries the actor's identity claims and NONE of the injected temporal
            // claims. (Caller-provided non-identity claims are a separate concern - see the
            // ActorToken_WithCallerProvidedNonIdentityClaims_AreWrittenVerbatim test - here the actor
            // has none, so any exp/nbf/iat present could only have come from injection.)
            var act = decoded.Payload.GetValue<JsonElement>("act");
            Assert.Equal("actor-subject-id", act.GetProperty("sub").GetString());
            Assert.Equal("Actor Name", act.GetProperty("name").GetString());
            Assert.False(act.TryGetProperty("exp", out _), "act must not contain an injected 'exp'");
            Assert.False(act.TryGetProperty("nbf", out _), "act must not contain an injected 'nbf'");
            Assert.False(act.TryGetProperty("iat", out _), "act must not contain an injected 'iat'");
        }

        [Fact]
        public void ActorToken_WithCallerProvidedNonIdentityClaims_AreWrittenVerbatim()
        {
            // By design the actor ClaimsIdentity is serialized as-is. RFC 8693 section 4.1 says
            // non-identity claims (exp/nbf/iat/aud/iss) are "not used" within "act", but it does not
            // require a serializer to strip caller-provided ones. We deliberately do NOT strip: whatever
            // the caller puts on the actor identity is written verbatim (no silent data loss). The handler
            // only refrains from injecting its OWN default temporal claims (asserted in the test above).
            var actorIdentity = new CaseSensitiveClaimsIdentity("ActorAuth");
            actorIdentity.AddClaim(new Claim("sub", "actor-subject-id"));
            actorIdentity.AddClaim(new Claim("exp", "9999999999"));
            actorIdentity.AddClaim(new Claim("aud", "https://actor.example.com"));

            var mainIdentity = new CaseSensitiveClaimsIdentity("Bearer");
            mainIdentity.AddClaim(new Claim("sub", "main-subject-id"));
            mainIdentity.Actor = actorIdentity;

            var handler = new JsonWebTokenHandler();
            var token = handler.CreateToken(new SecurityTokenDescriptor
            {
                Subject = mainIdentity,
                Issuer = "https://example.com",
                Audience = "https://api.example.com",
                SigningCredentials = Default.AsymmetricSigningCredentials,
            });

            // Caller-provided non-identity claims survive verbatim in "act" (not stripped, not rejected).
            var act = handler.ReadJsonWebToken(token).Payload.GetValue<JsonElement>("act");
            Assert.Equal("actor-subject-id", act.GetProperty("sub").GetString());
            Assert.Equal("9999999999", act.GetProperty("exp").GetString());
            Assert.Equal("https://actor.example.com", act.GetProperty("aud").GetString());
        }

        [Fact]
        public void ActClaim_NonClaimsIdentityValueInClaims_WithSubjectActor_WritesSingleActMember()
        {
            // Regression (PR #3560 review): when the "act" entry in the Claims dictionary is NOT a
            // ClaimsIdentity (e.g. a plain string) AND Subject.Actor is also set, the claim loop writes
            // "act" verbatim while WriteActor could ALSO emit an "act" object from Subject.Actor, producing
            // two "act" members (a duplicate/ambiguous key, since Utf8JsonWriter does not dedupe property
            // names). The Claims "act" key must take precedence and exactly one "act" must be written.
            var subjectActor = new CaseSensitiveClaimsIdentity("ActorAuth");
            subjectActor.AddClaim(new Claim("sub", "subject-actor-id"));

            var mainIdentity = new CaseSensitiveClaimsIdentity("Bearer");
            mainIdentity.AddClaim(new Claim("sub", "main-subject-id"));
            mainIdentity.Actor = subjectActor;

            var handler = new JsonWebTokenHandler();
            var tokenDescriptor = new SecurityTokenDescriptor
            {
                Subject = mainIdentity,
                Issuer = "https://example.com",
                Audience = "https://api.example.com",
                SigningCredentials = Default.AsymmetricSigningCredentials,
                Claims = new Dictionary<string, object> { { "act", "raw-act-string" } },
            };

            var token = handler.CreateToken(tokenDescriptor);
            var decoded = handler.ReadJsonWebToken(token);

            // Exactly one top-level "act" member. JsonDocument preserves duplicate property names, so a
            // second "act" (the bug) would be counted here.
            using var payloadDoc = JsonDocument.Parse(Base64UrlEncoder.Decode(decoded.EncodedPayload));
            int actCount = 0;
            foreach (JsonProperty property in payloadDoc.RootElement.EnumerateObject())
            {
                if (property.NameEquals("act"))
                    actCount++;
            }

            Assert.Equal(1, actCount);

            // The Claims "act" value wins verbatim; Subject.Actor is not emitted as a second "act".
            JsonElement singleAct = payloadDoc.RootElement.GetProperty("act");
            Assert.Equal(JsonValueKind.String, singleAct.ValueKind);
            Assert.Equal("raw-act-string", singleAct.GetString());
        }

        [Fact]
        public void ActClaim_NonClaimsIdentityValueInClaims_NoSubjectActor_IsWrittenVerbatimAsOrdinaryClaim()
        {
            // Backward compatibility: before actor support, an "act" entry in the Claims dictionary was
            // just an ordinary claim written verbatim. That must be unchanged when its value is NOT a
            // ClaimsIdentity and there is no Subject.Actor - the actor feature must not intercept it.
            var mainIdentity = new CaseSensitiveClaimsIdentity("Bearer");
            mainIdentity.AddClaim(new Claim("sub", "main-subject-id"));

            var handler = new JsonWebTokenHandler();
            var tokenDescriptor = new SecurityTokenDescriptor
            {
                Subject = mainIdentity,
                Issuer = "https://example.com",
                Audience = "https://api.example.com",
                SigningCredentials = Default.AsymmetricSigningCredentials,
                Claims = new Dictionary<string, object> { { "act", "raw-act-string" } },
            };

            var token = handler.CreateToken(tokenDescriptor);
            var decoded = handler.ReadJsonWebToken(token);

            // Exactly one top-level "act" member (WriteActor is not invoked: no ClaimsIdentity actor and
            // no Subject.Actor), written verbatim as the caller supplied it.
            using var payloadDoc = JsonDocument.Parse(Base64UrlEncoder.Decode(decoded.EncodedPayload));
            int actCount = 0;
            foreach (JsonProperty property in payloadDoc.RootElement.EnumerateObject())
            {
                if (property.NameEquals("act"))
                    actCount++;
            }

            Assert.Equal(1, actCount);

            JsonElement singleAct = payloadDoc.RootElement.GetProperty("act");
            Assert.Equal(JsonValueKind.String, singleAct.ValueKind);
            Assert.Equal("raw-act-string", singleAct.GetString());
        }

        [Fact]
        public void ActClaim_SubjectActorAndLiteralActClaimOnSubject_WritesSingleStructuredActMember()
        {
            // A ClaimsIdentity can carry BOTH a structural Actor and a raw "act" claim - notably after a
            // round-trip, since deserialization sets identity.Actor AND retains the raw "act" claim. On
            // re-serialization WriteActor emits "act" from Subject.Actor while AddSubjectClaims would emit
            // the raw "act" claim too, producing a duplicate "act". The structural actor must win and
            // exactly one "act" (a JSON object) must be written. The Claims dictionary has no "act" here, so
            // the existing dictionary-based skip does not apply - this exercises the Subject.Actor guard.
            var actor = new CaseSensitiveClaimsIdentity("ActorAuth");
            actor.AddClaim(new Claim("sub", "actor-id"));

            var mainIdentity = new CaseSensitiveClaimsIdentity("Bearer");
            mainIdentity.AddClaim(new Claim("sub", "main-subject-id"));
            mainIdentity.AddClaim(new Claim("act", "literal-act-on-subject"));
            mainIdentity.Actor = actor;

            var handler = new JsonWebTokenHandler();
            var token = handler.CreateToken(new SecurityTokenDescriptor
            {
                Subject = mainIdentity,
                Issuer = "https://example.com",
                Audience = "https://api.example.com",
                SigningCredentials = Default.AsymmetricSigningCredentials,
            });
            var decoded = handler.ReadJsonWebToken(token);

            using var payloadDoc = JsonDocument.Parse(Base64UrlEncoder.Decode(decoded.EncodedPayload));
            int actCount = 0;
            foreach (JsonProperty property in payloadDoc.RootElement.EnumerateObject())
            {
                if (property.NameEquals("act"))
                    actCount++;
            }

            Assert.Equal(1, actCount);

            // The single "act" is the structural actor object (from Subject.Actor), not the raw string.
            JsonElement act = payloadDoc.RootElement.GetProperty("act");
            Assert.Equal(JsonValueKind.Object, act.ValueKind);
            Assert.Equal("actor-id", act.GetProperty("sub").GetString());
        }

        [Fact]
        public void ActorChain_CyclicClaimsIdentityActor_IsRejectedByClaimsIdentity()
        {
            // The actor-serialization recursion (WriteActorObject / WriteActorAsJsonString, the latter
            // expanding with int.MaxValue) terminates on a null Actor and therefore relies on the
            // ClaimsIdentity.Actor chain being finite and acyclic. ClaimsIdentity enforces exactly that:
            // its Actor setter throws InvalidOperationException on any circular reference, so a cycle can
            // never reach the serializer. This test documents the guarantee the recursion depends on.

            // Self reference.
            var self = new CaseSensitiveClaimsIdentity("Self");
            Assert.Throws<InvalidOperationException>(() => self.Actor = self);

            // Mutual reference.
            var first = new CaseSensitiveClaimsIdentity("First");
            var second = new CaseSensitiveClaimsIdentity("Second");
            first.Actor = second;
            Assert.Throws<InvalidOperationException>(() => second.Actor = first);
        }

        [Fact]
        public void NestedActorToken_IsRfcCompliant_EveryActObjectHasNoNonIdentityClaims()
        {
            // RFC 8693 section 4.1: every actor object in a nested delegation chain is identity-only.
            JsonWebTokenHandler.MaxActorChainLength = 2;

            var nestedActor = new CaseSensitiveClaimsIdentity("NestedActorAuth");
            nestedActor.AddClaim(new Claim("sub", "nested-actor-id"));

            var actorIdentity = new CaseSensitiveClaimsIdentity("ActorAuth");
            actorIdentity.AddClaim(new Claim("sub", "actor-subject-id"));
            actorIdentity.Actor = nestedActor;

            var mainIdentity = new CaseSensitiveClaimsIdentity("Bearer");
            mainIdentity.AddClaim(new Claim("sub", "main-subject-id"));
            mainIdentity.Actor = actorIdentity;

            var handler = new JsonWebTokenHandler();
            var token = handler.CreateToken(new SecurityTokenDescriptor
            {
                Subject = mainIdentity,
                Issuer = "https://example.com",
                Audience = "https://api.example.com",
                SigningCredentials = Default.AsymmetricSigningCredentials,
            });
            var decoded = handler.ReadJsonWebToken(token);

            var act = decoded.Payload.GetValue<JsonElement>("act");
            AssertActorObjectIsIdentityOnly(act, "actor-subject-id");

            Assert.True(act.TryGetProperty("act", out var nestedAct));
            AssertActorObjectIsIdentityOnly(nestedAct, "nested-actor-id");
        }

        private static void AssertActorObjectIsIdentityOnly(JsonElement act, string expectedSub)
        {
            Assert.Equal(JsonValueKind.Object, act.ValueKind);
            Assert.Equal(expectedSub, act.GetProperty("sub").GetString());
            Assert.False(act.TryGetProperty("exp", out _), "act must not contain 'exp'");
            Assert.False(act.TryGetProperty("nbf", out _), "act must not contain 'nbf'");
            Assert.False(act.TryGetProperty("iat", out _), "act must not contain 'iat'");
        }

        [Fact]
        public void ActorToken_InClaimsDictionary_IsCorrectlySerialized()
        {
            var context = new CompareContext($"{this}.ActorToken_InClaimsDictionary_IsCorrectlySerialized");
            string actorname = "act";
            try
            {
                // Create a ClaimsIdentity for the actor
                var actorIdentity = new CaseSensitiveClaimsIdentity("ActorAuth");
                actorIdentity.AddClaim(new Claim("sub", "actor-subject-id"));
                actorIdentity.AddClaim(new Claim("name", "Actor Name"));
                actorIdentity.AddClaim(new Claim("role", "admin"));

                // Create the main identity
                var mainIdentity = new CaseSensitiveClaimsIdentity("Bearer");
                mainIdentity.AddClaim(new Claim("sub", "main-subject-id"));
                mainIdentity.AddClaim(new Claim("name", "Main User"));

                // Create a token with JsonWebTokenHandler where actor is in Claims dictionary
                var tokenHandler = new JsonWebTokenHandler();
                var tokenDescriptor = new SecurityTokenDescriptor
                {
                    Subject = mainIdentity,
                    Issuer = "https://example.com",
                    Audience = "https://api.example.com",
                    Expires = DateTime.UtcNow.AddHours(1),
                    SigningCredentials = Default.AsymmetricSigningCredentials,
                    Claims = new Dictionary<string, object>
                    {
                        { actorname, actorIdentity }
                    },
                };
                var token = tokenHandler.CreateToken(tokenDescriptor);
                JsonWebToken decodedToken = tokenHandler.ReadJsonWebToken(token);

                // Verify actor claim exists in the token
                Assert.True(decodedToken.Payload.HasClaim("act"), "JWT token should contain 'act' claim");
                // Verify the actor object directly
                var actorObject = decodedToken.Payload.GetValue<JsonElement>("act");
                Assert.Equal(JsonValueKind.Object, actorObject.ValueKind);

                // Verify actor claims directly from the JSON object
                Assert.Equal("actor-subject-id", actorObject.GetProperty("sub").GetString());
                Assert.Equal("Actor Name", actorObject.GetProperty("name").GetString());
                Assert.Equal("admin", actorObject.GetProperty("role").GetString());
                TestUtilities.AssertFailIfErrors(context);
            }
            catch (Exception ex)
            {
                context.Diffs.Add($"Exception: {ex}");
            }
        }

        [Fact]
        public void ActorToken_AsSubject_IsCorrectlySerialized()
        {
            var context = new CompareContext($"{this}.ActorToken_AsSubject_IsCorrectlySerialized");
            try
            {
                // Create actor identity
                var actorIdentity = new CaseSensitiveClaimsIdentity("ActorAuth");
                actorIdentity.AddClaim(new Claim("sub", "actor-subject-id"));
                actorIdentity.AddClaim(new Claim("name", "Actor Name"));
                actorIdentity.AddClaim(new Claim("role", "admin"));

                // Create the main identity with Actor set via Identity.Actor
                var mainIdentity = new CaseSensitiveClaimsIdentity("Bearer");
                mainIdentity.AddClaim(new Claim("sub", "main-subject-id"));
                mainIdentity.AddClaim(new Claim("name", "Main User"));
                mainIdentity.Actor = actorIdentity;

                // Create a token with JsonWebTokenHandler
                var tokenHandler = new JsonWebTokenHandler();
                var tokenDescriptor = new SecurityTokenDescriptor
                {
                    Subject = mainIdentity,
                    Issuer = "https://example.com",
                    Audience = "https://api.example.com",
                    Expires = DateTime.UtcNow.AddHours(1),
                    SigningCredentials = Default.AsymmetricSigningCredentials,
                };
                var token = tokenHandler.CreateToken(tokenDescriptor);
                JsonWebToken decodedToken = tokenHandler.ReadJsonWebToken(token);

                // Verify actor claim exists in the token
                Assert.True(decodedToken.Payload.HasClaim("act"), "JWT token should contain 'act' claim");

                // Verify the actor object directly
                var actorObject = decodedToken.Payload.GetValue<JsonElement>("act");
                Assert.Equal(JsonValueKind.Object, actorObject.ValueKind);

                // Verify actor claims directly from the JSON object
                Assert.Equal("actor-subject-id", actorObject.GetProperty("sub").GetString());
                Assert.Equal("Actor Name", actorObject.GetProperty("name").GetString());
                Assert.Equal("admin", actorObject.GetProperty("role").GetString());
                TestUtilities.AssertFailIfErrors(context);
            }
            catch (Exception ex)
            {
                context.Diffs.Add($"Exception: {ex}");
            }
        }

        [Fact]
        public void ActorToken_InBothClaimsAndSubject_PrefersClaimsValue()
        {
            var context = new CompareContext($"{this}.ActorToken_InBothClaimsAndSubject_PrefersClaimsValue");
            string actorname = "act";

            try
            {
                // Create actor identity for Subject.Actor (should be ignored)
                var subjectActorIdentity = new CaseSensitiveClaimsIdentity("ActorAuth");
                subjectActorIdentity.AddClaim(new Claim("sub", "subject-actor-id"));
                subjectActorIdentity.AddClaim(new Claim("name", "Subject Actor"));

                // Create actor identity for Claims dictionary (should be used)
                var claimsActorIdentity = new CaseSensitiveClaimsIdentity("ClaimsActorAuth");
                claimsActorIdentity.AddClaim(new Claim("sub", "claims-actor-id"));
                claimsActorIdentity.AddClaim(new Claim("name", "Claims Actor"));

                // Create the main identity
                var mainIdentity = new CaseSensitiveClaimsIdentity("Bearer");
                mainIdentity.AddClaim(new Claim("sub", "main-subject-id"));
                mainIdentity.AddClaim(new Claim("name", "Main User"));
                mainIdentity.Actor = subjectActorIdentity; // Set the actor that should be ignored

                // Create a token with JsonWebTokenHandler
                var tokenHandler = new JsonWebTokenHandler();
                var tokenDescriptor = new SecurityTokenDescriptor
                {
                    Subject = mainIdentity,
                    Issuer = "https://example.com",
                    Audience = "https://api.example.com",
                    Expires = DateTime.UtcNow.AddHours(1),
                    SigningCredentials = Default.AsymmetricSigningCredentials,
                    // Add Claims actor that should take precedence
                    Claims = new Dictionary<string, object>
                    {
                        { actorname, claimsActorIdentity }
                    },
                };
                var token = tokenHandler.CreateToken(tokenDescriptor);
                JsonWebToken decodedToken = tokenHandler.ReadJsonWebToken(token);

                // Verify actor claim exists
                Assert.True(decodedToken.Payload.HasClaim(actorname), "JWT token should contain actor claim");

                // Verify actor claim exists and is a JSON object
                var actorObject = decodedToken.Payload.GetValue<JsonElement>("act");
                Assert.Equal(JsonValueKind.Object, actorObject.ValueKind);

                // Verify Claims dictionary actor was used, not Subject.Actor
                Assert.Equal("claims-actor-id", actorObject.GetProperty("sub").GetString());
                Assert.Equal("Claims Actor", actorObject.GetProperty("name").GetString());
                Assert.NotEqual("subject-actor-id", actorObject.GetProperty("sub").GetString());
                TestUtilities.AssertFailIfErrors(context);
            }
            catch (Exception ex)
            {
                context.Diffs.Add($"Exception: {ex}");
            }
        }

        [Fact]
        public void NestedActorToken_InClaimsDictionary_IsCorrectlySerialized()
        {
            var context = new CompareContext($"{this}.NestedActorToken_InClaimsDictionary_IsCorrectlySerialized");

            try
            {
                // Two object levels needed: the actor and its nested actor.
                JsonWebTokenHandler.MaxActorChainLength = 2;

                // Create nested actor identity
                var nestedActorIdentity = new CaseSensitiveClaimsIdentity("NestedActorAuth");
                nestedActorIdentity.AddClaim(new Claim("sub", "nested-actor-id"));
                nestedActorIdentity.AddClaim(new Claim("name", "Nested Actor"));

                // Create actor identity with nested actor
                var actorIdentity = new CaseSensitiveClaimsIdentity("ActorAuth");
                actorIdentity.AddClaim(new Claim("sub", "actor-subject-id"));
                actorIdentity.AddClaim(new Claim("name", "Actor Name"));
                actorIdentity.Actor = nestedActorIdentity;  // Set nested actor

                // Create the main identity
                var mainIdentity = new CaseSensitiveClaimsIdentity("Bearer");
                mainIdentity.AddClaim(new Claim("sub", "main-subject-id"));
                mainIdentity.AddClaim(new Claim("name", "Main User"));

                // Create a token with JsonWebTokenHandler where actor is in Claims dictionary
                var tokenHandler = new JsonWebTokenHandler();
                var tokenDescriptor = new SecurityTokenDescriptor
                {
                    Subject = mainIdentity,
                    Issuer = "https://example.com",
                    Audience = "https://api.example.com",
                    Expires = DateTime.UtcNow.AddHours(1),
                    SigningCredentials = Default.AsymmetricSigningCredentials,
                    Claims = new Dictionary<string, object>
                    {
                        { "act", actorIdentity }
                    },
                };
                var token = tokenHandler.CreateToken(tokenDescriptor);
                JsonWebToken decodedToken = tokenHandler.ReadJsonWebToken(token);

                // Verify actor claim exists
                Assert.True(decodedToken.Payload.HasClaim("act"), "JWT token should contain 'act' claim");

                // Verify the actor object
                var actorObject = decodedToken.Payload.GetValue<JsonElement>("act");
                Assert.Equal(JsonValueKind.Object, actorObject.ValueKind);

                // Verify main actor claims directly from JSON object
                Assert.Equal("actor-subject-id", actorObject.GetProperty("sub").GetString());
                Assert.Equal("Actor Name", actorObject.GetProperty("name").GetString());

                // Verify nested actor exists and is a JSON object
                Assert.True(actorObject.TryGetProperty("act", out var nestedActorElement));
                Assert.Equal(JsonValueKind.Object, nestedActorElement.ValueKind);

                // Verify nested actor claims directly from JSON object
                Assert.Equal("nested-actor-id", nestedActorElement.GetProperty("sub").GetString());
                Assert.Equal("Nested Actor", nestedActorElement.GetProperty("name").GetString());
                TestUtilities.AssertFailIfErrors(context);
            }
            catch (Exception ex)
            {
                context.Diffs.Add($"Exception: {ex}");
            }
        }

        [Fact]
        public void NestedActorToken_AsSubject_IsCorrectlySerialized()
        {
            var context = new CompareContext($"{this}.NestedActorToken_AsSubject_IsCorrectlySerialized");

            // Two object levels needed: the actor and its nested actor.
            JsonWebTokenHandler.MaxActorChainLength = 2;

            // Create nested actor
            var nestedActorIdentity = new CaseSensitiveClaimsIdentity("NestedActorAuth");
            nestedActorIdentity.AddClaim(new Claim("sub", "nested-actor-id"));
            nestedActorIdentity.AddClaim(new Claim("name", "Nested Actor"));

            // Create actor identity with nested actor
            var actorIdentity = new CaseSensitiveClaimsIdentity("ActorAuth");
            actorIdentity.AddClaim(new Claim("sub", "actor-subject-id"));
            actorIdentity.AddClaim(new Claim("name", "Actor Name"));
            actorIdentity.Actor = nestedActorIdentity;

            // Create the main identity with Actor set
            var mainIdentity = new CaseSensitiveClaimsIdentity("Bearer");
            mainIdentity.AddClaim(new Claim("sub", "main-subject-id"));
            mainIdentity.AddClaim(new Claim("name", "Main User"));
            mainIdentity.Actor = actorIdentity;

            // Create a token with JsonWebTokenHandler
            var tokenHandler = new JsonWebTokenHandler();
            var tokenDescriptor = new SecurityTokenDescriptor
            {
                Subject = mainIdentity,
                Issuer = "https://example.com",
                Audience = "https://api.example.com",
                Expires = DateTime.UtcNow.AddHours(1),
                SigningCredentials = Default.AsymmetricSigningCredentials,
            };
            var token = tokenHandler.CreateToken(tokenDescriptor);
            JsonWebToken decodedToken = tokenHandler.ReadJsonWebToken(token);

            // Verify actor claim exists
            Assert.True(decodedToken.Payload.HasClaim("act"), "JWT token should contain 'act' claim");

            // Verify the actor object structure
            var actorObject = decodedToken.Payload.GetValue<JsonElement>("act");
            Assert.Equal(JsonValueKind.Object, actorObject.ValueKind);

            // Verify main actor claims directly from JSON object
            Assert.Equal("actor-subject-id", actorObject.GetProperty("sub").GetString());
            Assert.Equal("Actor Name", actorObject.GetProperty("name").GetString());

            // Verify nested actor exists and is a JSON object
            Assert.True(actorObject.TryGetProperty("act", out var nestedActorElement));
            Assert.Equal(JsonValueKind.Object, nestedActorElement.ValueKind);

            // Verify nested actor claims directly from JSON object
            Assert.Equal("nested-actor-id", nestedActorElement.GetProperty("sub").GetString());
            Assert.Equal("Nested Actor", nestedActorElement.GetProperty("name").GetString());
            TestUtilities.AssertFailIfErrors(context);
        }

        [Fact]
        public void NestedActorChain_ExceedingDefaultMaxChainLength_Subject_DegradesToJsonString()
        {
            // Default MaxActorChainLength is 1: only the immediate actor is a JSON object; deeper
            // actors degrade to a JSON-text string instead of throwing.
            var handler = new JsonWebTokenHandler();

            var level6Actor = new CaseSensitiveClaimsIdentity("Level6Auth");
            level6Actor.AddClaim(new Claim("sub", "level6-actor"));

            var level5Actor = new CaseSensitiveClaimsIdentity("Level5Auth");
            level5Actor.AddClaim(new Claim("sub", "level5-actor"));
            level5Actor.Actor = level6Actor;

            var level4Actor = new CaseSensitiveClaimsIdentity("Level4Auth");
            level4Actor.AddClaim(new Claim("sub", "level4-actor"));
            level4Actor.Actor = level5Actor;

            var level3Actor = new CaseSensitiveClaimsIdentity("Level3Auth");
            level3Actor.AddClaim(new Claim("sub", "level3-actor"));
            level3Actor.Actor = level4Actor;

            var level2Actor = new CaseSensitiveClaimsIdentity("Level2Auth");
            level2Actor.AddClaim(new Claim("sub", "level2-actor"));
            level2Actor.Actor = level3Actor;

            var level1Actor = new CaseSensitiveClaimsIdentity("Level1Auth");
            level1Actor.AddClaim(new Claim("sub", "level1-actor"));
            level1Actor.Actor = level2Actor;

            var mainIdentity = new CaseSensitiveClaimsIdentity("Bearer");
            mainIdentity.AddClaim(new Claim("sub", "main-subject-id"));
            mainIdentity.Actor = level1Actor;

            var tokenDescriptor = new SecurityTokenDescriptor
            {
                Subject = mainIdentity,
                Issuer = "https://example.com",
                Audience = "https://api.example.com",
                SigningCredentials = Default.AsymmetricSigningCredentials,
            };

            // No throw: the immediate actor is written as an object; the deeper chain degrades.
            var token = handler.CreateToken(tokenDescriptor);
            var decodedToken = handler.ReadJsonWebToken(token);

            var actorObject = decodedToken.Payload.GetValue<JsonElement>("act");
            Assert.Equal(JsonValueKind.Object, actorObject.ValueKind);
            Assert.Equal("level1-actor", actorObject.GetProperty("sub").GetString());

            // The nested actor beyond the limit is a JSON-text string, not a nested object.
            Assert.True(actorObject.TryGetProperty("act", out var nestedActor));
            Assert.Equal(JsonValueKind.String, nestedActor.ValueKind);

            // The string is valid JSON whose remaining subtree is fully expanded (level2 -> level3 ...).
            using var nestedDoc = JsonDocument.Parse(nestedActor.GetString());
            Assert.Equal("level2-actor", nestedDoc.RootElement.GetProperty("sub").GetString());
            Assert.Equal(JsonValueKind.Object, nestedDoc.RootElement.GetProperty("act").ValueKind);
        }

        [Fact]
        public void NestedActorChain_ExceedingDefaultMaxChainLength_ClaimsDictionary_DegradesToJsonString()
        {
            // Default MaxActorChainLength is 1: the immediate actor from the Claims dictionary is a
            // JSON object; deeper actors degrade to a JSON-text string instead of throwing.
            var handler = new JsonWebTokenHandler();

            var level6Actor = new CaseSensitiveClaimsIdentity("Level6Auth");
            level6Actor.AddClaim(new Claim("sub", "level6-actor"));

            var level5Actor = new CaseSensitiveClaimsIdentity("Level5Auth");
            level5Actor.AddClaim(new Claim("sub", "level5-actor"));
            level5Actor.Actor = level6Actor;

            var level4Actor = new CaseSensitiveClaimsIdentity("Level4Auth");
            level4Actor.AddClaim(new Claim("sub", "level4-actor"));
            level4Actor.Actor = level5Actor;

            var level3Actor = new CaseSensitiveClaimsIdentity("Level3Auth");
            level3Actor.AddClaim(new Claim("sub", "level3-actor"));
            level3Actor.Actor = level4Actor;

            var level2Actor = new CaseSensitiveClaimsIdentity("Level2Auth");
            level2Actor.AddClaim(new Claim("sub", "level2-actor"));
            level2Actor.Actor = level3Actor;

            var level1Actor = new CaseSensitiveClaimsIdentity("Level1Auth");
            level1Actor.AddClaim(new Claim("sub", "level1-actor"));
            level1Actor.Actor = level2Actor;

            var mainIdentity = new CaseSensitiveClaimsIdentity("Bearer");
            mainIdentity.AddClaim(new Claim("sub", "main-subject-id"));

            var tokenDescriptor = new SecurityTokenDescriptor
            {
                Subject = mainIdentity,
                Issuer = "https://example.com",
                Audience = "https://api.example.com",
                SigningCredentials = Default.AsymmetricSigningCredentials,
                Claims = new Dictionary<string, object>
                {
                    { "act", level1Actor }
                },
            };

            // No throw: the immediate actor is written as an object; the deeper chain degrades.
            var token = handler.CreateToken(tokenDescriptor);
            var decodedToken = handler.ReadJsonWebToken(token);

            var actorObject = decodedToken.Payload.GetValue<JsonElement>("act");
            Assert.Equal(JsonValueKind.Object, actorObject.ValueKind);
            Assert.Equal("level1-actor", actorObject.GetProperty("sub").GetString());

            // The nested actor beyond the limit is a JSON-text string, not a nested object.
            Assert.True(actorObject.TryGetProperty("act", out var nestedActor));
            Assert.Equal(JsonValueKind.String, nestedActor.ValueKind);

            using var nestedDoc = JsonDocument.Parse(nestedActor.GetString());
            Assert.Equal("level2-actor", nestedDoc.RootElement.GetProperty("sub").GetString());
            Assert.Equal(JsonValueKind.Object, nestedDoc.RootElement.GetProperty("act").ValueKind);
        }

        [Fact]
        public void NestedActorTokens_AtExactlyMaxDepthOf5_Succeeds()
        {
            // Configure 5 object levels (main -> level1 -> ... -> level5) and verify all serialize as objects.
            JsonWebTokenHandler.MaxActorChainLength = 5;
            var handler = new JsonWebTokenHandler();

            var level5Actor = new CaseSensitiveClaimsIdentity("Level5Auth");
            level5Actor.AddClaim(new Claim("sub", "level5-actor"));

            var level4Actor = new CaseSensitiveClaimsIdentity("Level4Auth");
            level4Actor.AddClaim(new Claim("sub", "level4-actor"));
            level4Actor.Actor = level5Actor;

            var level3Actor = new CaseSensitiveClaimsIdentity("Level3Auth");
            level3Actor.AddClaim(new Claim("sub", "level3-actor"));
            level3Actor.Actor = level4Actor;

            var level2Actor = new CaseSensitiveClaimsIdentity("Level2Auth");
            level2Actor.AddClaim(new Claim("sub", "level2-actor"));
            level2Actor.Actor = level3Actor;

            var level1Actor = new CaseSensitiveClaimsIdentity("Level1Auth");
            level1Actor.AddClaim(new Claim("sub", "level1-actor"));
            level1Actor.Actor = level2Actor;

            var mainIdentity = new CaseSensitiveClaimsIdentity("Bearer");
            mainIdentity.AddClaim(new Claim("sub", "main-subject-id"));
            mainIdentity.Actor = level1Actor;

            var tokenDescriptor = new SecurityTokenDescriptor
            {
                Subject = mainIdentity,
                Issuer = "https://example.com",
                Audience = "https://api.example.com",
                SigningCredentials = Default.AsymmetricSigningCredentials,
            };

            var token = handler.CreateToken(tokenDescriptor);
            var decodedToken = handler.ReadJsonWebToken(token);

            Assert.True(decodedToken.Payload.HasClaim("act"));
            var actorObject = decodedToken.Payload.GetValue<JsonElement>("act");
            Assert.Equal("level1-actor", actorObject.GetProperty("sub").GetString());

            Assert.True(actorObject.TryGetProperty("act", out var level2));
            Assert.Equal("level2-actor", level2.GetProperty("sub").GetString());

            Assert.True(level2.TryGetProperty("act", out var level3));
            Assert.Equal("level3-actor", level3.GetProperty("sub").GetString());

            Assert.True(level3.TryGetProperty("act", out var level4));
            Assert.Equal("level4-actor", level4.GetProperty("sub").GetString());

            Assert.True(level4.TryGetProperty("act", out var level5));
            Assert.Equal("level5-actor", level5.GetProperty("sub").GetString());

            Assert.False(level5.TryGetProperty("act", out _));
        }
    }
}
