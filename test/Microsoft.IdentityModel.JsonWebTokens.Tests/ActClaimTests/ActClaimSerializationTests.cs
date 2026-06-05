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
    public class ActClaimSerializationTests
    {
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
                Assert.True(decodedToken.Payload.HasClaim(tokenDescriptor.ActorClaimType), "JWT token should contain 'actort' claim");
                // Verify the actor object directly
                var actorObject = decodedToken.Payload.GetValue<JsonElement>(tokenDescriptor.ActorClaimType);
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
                Assert.True(decodedToken.Payload.HasClaim(tokenDescriptor.ActorClaimType), "JWT token should contain 'act' claim");

                // Verify actor claim exists in the token
                Assert.True(decodedToken.Payload.HasClaim(tokenDescriptor.ActorClaimType), "JWT token should contain actor claim");

                // Verify the actor object directly
                var actorObject = decodedToken.Payload.GetValue<JsonElement>(tokenDescriptor.ActorClaimType);
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
        public void ActorToken_InClaimsDictionary_AsNonClaimsIdentity_IsNotDropped()
        {
            // Regression test: a value placed under the actor claim type that is NOT a ClaimsIdentity
            // (e.g. a pre-serialized JSON object) must be serialized verbatim, not silently dropped.
            // Before the fix the write loop skipped the claim and CreateActorTokenDescriptor refused
            // to emit a non-ClaimsIdentity value, so the 'act' claim vanished with only an IDX14315 warning.
            var actorValue = new Dictionary<string, object>
            {
                { "sub", "actor-subject-id" },
                { "name", "Actor Name" }
            };

            var mainIdentity = new CaseSensitiveClaimsIdentity("Bearer");
            mainIdentity.AddClaim(new Claim("sub", "main-subject-id"));

            var tokenHandler = new JsonWebTokenHandler();
            var tokenDescriptor = new SecurityTokenDescriptor
            {
                Subject = mainIdentity,
                Issuer = "https://example.com",
                Audience = "https://api.example.com",
                Expires = DateTime.UtcNow.AddHours(1),
                SigningCredentials = Default.AsymmetricSigningCredentials,
                Claims = new Dictionary<string, object> { { "act", actorValue } },
            };

            var token = tokenHandler.CreateToken(tokenDescriptor);
            JsonWebToken decodedToken = tokenHandler.ReadJsonWebToken(token);

            Assert.True(decodedToken.Payload.HasClaim("act"), "The 'act' claim was dropped from the serialized token.");

            var actorObject = decodedToken.Payload.GetValue<JsonElement>("act");
            Assert.Equal(JsonValueKind.Object, actorObject.ValueKind);
            Assert.Equal("actor-subject-id", actorObject.GetProperty("sub").GetString());
            Assert.Equal("Actor Name", actorObject.GetProperty("name").GetString());
        }

        [Fact]
        public void ActorToken_NonClaimsIdentityInClaims_WithSubjectActor_DoesNotLoseActClaim()
        {
            var actorValue = new Dictionary<string, object> { { "sub", "claims-actor-id" } };

            var subjectActor = new CaseSensitiveClaimsIdentity("SubjectActorAuth");
            subjectActor.AddClaim(new Claim("sub", "subject-actor-id"));

            var mainIdentity = new CaseSensitiveClaimsIdentity("Bearer");
            mainIdentity.AddClaim(new Claim("sub", "main-subject-id"));
            mainIdentity.Actor = subjectActor;

            var tokenHandler = new JsonWebTokenHandler();
            var tokenDescriptor = new SecurityTokenDescriptor
            {
                Subject = mainIdentity,
                Issuer = "https://example.com",
                Audience = "https://api.example.com",
                SigningCredentials = Default.AsymmetricSigningCredentials,
                Claims = new Dictionary<string, object> { { "act", actorValue } },
            };

            var token = tokenHandler.CreateToken(tokenDescriptor);
            JsonWebToken decodedToken = tokenHandler.ReadJsonWebToken(token);

            Assert.True(decodedToken.Payload.HasClaim("act"));
            var actorObject = decodedToken.Payload.GetValue<JsonElement>("act");
            Assert.Equal("claims-actor-id", actorObject.GetProperty("sub").GetString());
        }

        [Fact]
        public void NestedActorToken_InClaimsDictionary_IsCorrectlySerialized()
        {
            var context = new CompareContext($"{this}.NestedActorToken_InClaimsDictionary_IsCorrectlySerialized");

            try
            {
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
                Assert.True(decodedToken.Payload.HasClaim("act"), "JWT token should contain 'actort' claim");

                // Verify the actor object
                var actorObject = decodedToken.Payload.GetValue<JsonElement>("act");
                Assert.Equal(JsonValueKind.Object, actorObject.ValueKind);

                // Verify main actor claims directly from JSON object
                Assert.Equal("actor-subject-id", actorObject.GetProperty("sub").GetString());
                Assert.Equal("Actor Name", actorObject.GetProperty("name").GetString());

                // Verify nested actor exists and is a JSON object
                Assert.True(actorObject.TryGetProperty(tokenDescriptor.ActorClaimType, out var nestedActorElement));
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
                ActorClaimType = "act",
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
            Assert.True(actorObject.TryGetProperty(tokenDescriptor.ActorClaimType, out var nestedActorElement));
            Assert.Equal(JsonValueKind.Object, nestedActorElement.ValueKind);

            // Verify nested actor claims directly from JSON object
            Assert.Equal("nested-actor-id", nestedActorElement.GetProperty("sub").GetString());
            Assert.Equal("Nested Actor", nestedActorElement.GetProperty("name").GetString());
            TestUtilities.AssertFailIfErrors(context);
        }

        [Fact]
        public void NestedActorTokens_ExceedingFixedMaxDepthOf5_ThrowsSecurityTokenException()
        {
            // MaxActorChainLength is fixed at 5 (1 top-level + 4 nested actors).
            // 6 actor levels (main -> level1 -> ... -> level6) should exceed the limit.
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
                ActorClaimType = "act",
            };

            var exception = Assert.Throws<SecurityTokenException>(() => handler.CreateToken(tokenDescriptor));
            Assert.Contains("IDX14313", exception.Message);
        }

        [Fact]
        public void NestedActorTokens_InClaimsDictionary_ExceedingFixedMaxDepthOf5_ThrowsSecurityTokenException()
        {
            // MaxActorChainLength is fixed at 5 (1 top-level + 4 nested actors).
            // 6 actor levels via Claims dictionary should exceed the limit.
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
                ActorClaimType = "act",
            };

            var exception = Assert.Throws<SecurityTokenException>(() => handler.CreateToken(tokenDescriptor));
            Assert.Contains("IDX14313", exception.Message);
        }

        [Fact]
        public void NestedActorTokens_AtExactlyMaxDepthOf5_Succeeds()
        {
            // MaxActorChainLength is fixed at 5 (1 top-level + 4 nested actors).
            // 5 actor levels (main -> level1 -> ... -> level5) should succeed at exactly the limit.
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
                ActorClaimType = "act",
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
