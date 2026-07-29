// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Text.Json;
using System.Threading.Tasks;
using Microsoft.IdentityModel.TestUtils;
using Microsoft.IdentityModel.Tokens;
using Xunit;

namespace Microsoft.IdentityModel.JsonWebTokens.Tests.ActClaimTests
{
    [Collection("ActClaimTests")]
    public class ActClaimDeserializationTests : IDisposable
    {
        // Reset the process-wide MaxActorChainLength after every test for isolation.
        public void Dispose() => JsonWebTokenHandler.MaxActorChainLength = 1;

        [Fact]
        public void CreateActorClaimsIdentity_BasicJsonElement_CreatesClaimsIdentityCorrectly()
        {
            // Create a simple JSON Element that represents an actor token
            string actorJson = @"{
                ""sub"": ""actor-subject-id"",
                ""name"": ""Actor Name"",
                ""role"": ""admin""
            }";

            var jsonElement = JsonDocument.Parse(actorJson).RootElement;
            var validationParameters = new TokenValidationParameters()
            {
            };

            // Create ClaimsIdentity from JsonElement
            var identity = JsonWebTokenHandler.CreateActorClaimsIdentityFromJsonElement(
                jsonElement,
                validationParameters);

            // Assert
            Assert.NotNull(identity);
            Assert.Null(identity.AuthenticationType);  // Default constructor doesn't set AuthenticationType
            Assert.IsType<CaseSensitiveClaimsIdentity>(identity);

            // Verify claims values
            Assert.Equal("actor-subject-id", identity.Claims.First(c => c.Type == "sub").Value);
            Assert.Equal("Actor Name", identity.Claims.First(c => c.Type == "name").Value);
            Assert.Equal("admin", identity.Claims.First(c => c.Type == "role").Value);
        }

        [Fact]
        public void CreateActorClaimsIdentity_NestedActorInJsonElement_CreatesNestedClaimsIdentity()
        {
            // One nested actor level requires a chain length of 2.
            JsonWebTokenHandler.MaxActorChainLength = 2;

            // Create nested actor JSON structure
            string actorJson = @"{
                ""sub"": ""actor-subject-id"",
                ""name"": ""Actor Name"",
                ""act"": {
                    ""sub"": ""nested-actor-id"",
                    ""name"": ""Nested Actor""
                }
            }";

            var jsonElement = JsonDocument.Parse(actorJson).RootElement;
            var tokenValidationParameters = new TokenValidationParameters
            {
            };

            // Create ClaimsIdentity from JsonElement
            var identity = JsonWebTokenHandler.CreateActorClaimsIdentityFromJsonElement(
                jsonElement,
                tokenValidationParameters);

            // Verify main identity
            Assert.NotNull(identity);
            Assert.Equal("actor-subject-id", identity.Claims.First(c => c.Type == "sub").Value);
            Assert.Equal("Actor Name", identity.Claims.First(c => c.Type == "name").Value);

            // Verify nested actor identity
            Assert.NotNull(identity.Actor);
            Assert.Equal("nested-actor-id", identity.Actor.Claims.First(c => c.Type == "sub").Value);
            Assert.Equal("Nested Actor", identity.Actor.Claims.First(c => c.Type == "name").Value);
        }

        [Fact]
        public void CreateActorClaimsIdentity_MultiLevelNestedActorJson_HandlesProperDepth()
        {
            // Two nested actor levels require a chain length of 3.
            JsonWebTokenHandler.MaxActorChainLength = 3;

            // Create a three-level nested actor JSON structure
            string actorJson = @"{
                ""sub"": ""level1-subject"",
                ""name"": ""Level 1 Actor"",
                ""act"": {
                    ""sub"": ""level2-subject"",
                    ""name"": ""Level 2 Actor"",
                    ""act"": {
                        ""sub"": ""level3-subject"",
                        ""name"": ""Level 3 Actor""
                    }
                }
            }";

            var jsonElement = JsonDocument.Parse(actorJson).RootElement;
            var tokenValidationParameters = new TokenValidationParameters
            {
            };

            // Create ClaimsIdentity from JsonElement
            var identity = JsonWebTokenHandler.CreateActorClaimsIdentityFromJsonElement(
                jsonElement,
                tokenValidationParameters);

            // Verify level 1
            Assert.NotNull(identity);
            Assert.Equal("level1-subject", identity.Claims.First(c => c.Type == "sub").Value);
            Assert.Equal("Level 1 Actor", identity.Claims.First(c => c.Type == "name").Value);

            // Verify level 2
            Assert.NotNull(identity.Actor);
            Assert.Equal("level2-subject", identity.Actor.Claims.First(c => c.Type == "sub").Value);
            Assert.Equal("Level 2 Actor", identity.Actor.Claims.First(c => c.Type == "name").Value);

            // Verify level 3
            Assert.NotNull(identity.Actor.Actor);
            Assert.Equal("level3-subject", identity.Actor.Actor.Claims.First(c => c.Type == "sub").Value);
            Assert.Equal("Level 3 Actor", identity.Actor.Actor.Claims.First(c => c.Type == "name").Value);

            // No level 4
            Assert.Null(identity.Actor.Actor.Actor);
        }

        [Fact]
        public void CreateActorClaimsIdentity_JsonElementWithArrayValues_ProcessesCorrectly()
        {
            // Create JSON with array value
            string actorJson = @"{
                ""sub"": ""actor-subject-id"",
                ""name"": ""Actor Name"",
                ""roles"": [""admin"", ""user"", ""manager""]
            }";

            var jsonElement = JsonDocument.Parse(actorJson).RootElement;
            var tokenValidationParameters = new TokenValidationParameters
            {
            };

            // Create ClaimsIdentity from JsonElement
            var identity = JsonWebTokenHandler.CreateActorClaimsIdentityFromJsonElement(
                jsonElement,
                tokenValidationParameters);

            // Verify identity and simple claims
            Assert.NotNull(identity);
            Assert.Equal("actor-subject-id", identity.Claims.First(c => c.Type == "sub").Value);
            Assert.Equal("Actor Name", identity.Claims.First(c => c.Type == "name").Value);

            // Verify array values were processed into multiple claims
            var roleClaims = identity.Claims.Where(c => c.Type == "roles").ToList();
            Assert.Equal(3, roleClaims.Count);
            Assert.Contains(roleClaims, c => c.Value == "admin");
            Assert.Contains(roleClaims, c => c.Value == "user");
            Assert.Contains(roleClaims, c => c.Value == "manager");
        }

        [Fact]
        public void CreateActorClaimsIdentity_JsonElementWithComplexTypes_HandlesCorrectly()
        {
            // Create JSON with complex types (objects)
            string actorJson = @"{
                ""sub"": ""actor-subject-id"",
                ""name"": ""Actor Name"",
                ""metadata"": {
                    ""created"": ""2023-10-15"",
                    ""system"": ""test-system""
                },
                ""numbers"": [1, 2, 3]
            }";

            var jsonElement = JsonDocument.Parse(actorJson).RootElement;
            var tokenValidationParameters = new TokenValidationParameters
            {
            };

            // Create ClaimsIdentity from JsonElement
            var identity = JsonWebTokenHandler.CreateActorClaimsIdentityFromJsonElement(
                jsonElement,
                tokenValidationParameters);

            // Verify identity and simple claims
            Assert.NotNull(identity);
            Assert.Equal("actor-subject-id", identity.Claims.First(c => c.Type == "sub").Value);
            Assert.Equal("Actor Name", identity.Claims.First(c => c.Type == "name").Value);

            // Verify the JSON object was serialized to a claim
            var metadataClaim = identity.Claims.First(c => c.Type == "metadata");
            Assert.NotNull(metadataClaim);
            Assert.Contains("created", metadataClaim.Value);
            Assert.Contains("test-system", metadataClaim.Value);

            // Verify number array was handled
            var numberClaims = identity.Claims.Where(c => c.Type == "numbers").ToList();
            Assert.Equal(3, numberClaims.Count);
            Assert.Contains(numberClaims, c => c.Value == "1");
            Assert.Contains(numberClaims, c => c.Value == "2");
            Assert.Contains(numberClaims, c => c.Value == "3");
        }

        [Fact]
        public void CreateActorClaimsIdentity_NonObjectJsonElement_ReturnsNullAndWarns()
        {
            // Create a non-object JSON Element (string)
            string actorJson = @"""This is just a string, not an object""";
            var jsonElement = JsonDocument.Parse(actorJson).RootElement;

            var tokenValidationParameters = new TokenValidationParameters
            {
            };

            // Act: a non-object "act" cannot be expanded into an Actor chain; it warns and returns
            // null instead of throwing.
            var identity = JsonWebTokenHandler.CreateActorClaimsIdentityFromJsonElement(
                jsonElement,
                tokenValidationParameters);

            // Assert
            Assert.Null(identity);
        }

        [Fact]
        public void CreateActorClaimsIdentity_NullValidationParameters_ThrowsArgumentNullException()
        {
            // Create a simple JSON Element
            string actorJson = @"{ ""sub"": ""actor-subject-id"" }";
            var jsonElement = JsonDocument.Parse(actorJson).RootElement;

            // Act & Assert
            var exception = Assert.Throws<ArgumentNullException>(() =>
                JsonWebTokenHandler.CreateActorClaimsIdentityFromJsonElement(
                    jsonElement,
                    null));

            Assert.Equal("tokenValidationParameters", exception.ParamName);
        }

        [Fact]
        public void CreateActorClaimsIdentity_WithNestedActor_DoesNotMutateStaticChainLength()
        {
            // One nested actor level requires a chain length of 2.
            JsonWebTokenHandler.MaxActorChainLength = 2;

            // Create actor JSON with nested actor
            string actorJson = @"{
                ""sub"": ""actor-subject-id"",
                ""name"": ""Actor Name"",
                ""act"": {
                    ""sub"": ""nested-actor-id"",
                    ""name"": ""Nested Actor""
                }
            }";

            var jsonElement = JsonDocument.Parse(actorJson).RootElement;
            var tokenValidationParameters = new TokenValidationParameters
            {
            };

            // Create ClaimsIdentity from JsonElement
            var identity = JsonWebTokenHandler.CreateActorClaimsIdentityFromJsonElement(
                jsonElement,
                tokenValidationParameters);

            // The configured chain length is not mutated by reading nested actors.
            Assert.Equal(2, JsonWebTokenHandler.MaxActorChainLength);

            // Verify both levels of actors exist
            Assert.NotNull(identity);
            Assert.NotNull(identity.Actor);
        }

        [Fact]
        public async Task ValidateTokenAsync_WithActorInToken_ReturnsActorClaimsIdentity()
        {
            // Create a token with an actor claim
            var handler = new JsonWebTokenHandler();

            var actorIdentity = new CaseSensitiveClaimsIdentity("ActorAuth");
            actorIdentity.AddClaim(new Claim("sub", "actor-subject-id"));
            actorIdentity.AddClaim(new Claim("name", "Actor Name"));
            actorIdentity.AddClaim(new Claim("role", "admin"));

            var mainIdentity = new CaseSensitiveClaimsIdentity("Bearer");
            mainIdentity.AddClaim(new Claim("sub", "main-subject-id"));
            mainIdentity.AddClaim(new Claim("name", "Main User"));

            var tokenDescriptor = new SecurityTokenDescriptor
            {
                Subject = mainIdentity,
                Issuer = "https://example.com",
                Audience = "https://api.example.com",
                Expires = DateTime.UtcNow.AddHours(1),
                SigningCredentials = Default.AsymmetricSigningCredentials,
                Claims = new Dictionary<string, object>
                {
                    { "act", actorIdentity}
                },
            };
            string token = handler.CreateToken(tokenDescriptor);
            handler.MapInboundClaims = true;

            // Validate token
            var validationParameters = new TokenValidationParameters
            {
                ValidateIssuer = false,
                ValidateAudience = false,
                ValidateLifetime = false,
                IssuerSigningKey = Default.AsymmetricSigningKey,
                ValidateIssuerSigningKey = true,
            };

            var result = await handler.ValidateTokenAsync(token, validationParameters);

            // Verify validation succeeded
            Assert.True(result.IsValid);
            Assert.NotNull(result.SecurityToken);
            Assert.NotNull(result.ClaimsIdentity);

            // Verify main claims
            var mainClaim = result.ClaimsIdentity.Claims.FirstOrDefault(c => c.Type == "name");
            Assert.NotNull(mainClaim);
            Assert.Equal("Main User", mainClaim.Value);

            // Verify actor claims identity
            Assert.NotNull(result.ClaimsIdentity.Actor);
            var actorSubClaim = result.ClaimsIdentity.Actor.Claims.FirstOrDefault(c => c.Type == "sub");
            var actorNameClaim = result.ClaimsIdentity.Actor.Claims.FirstOrDefault(c => c.Type == "name");
            var actorRoleClaim = result.ClaimsIdentity.Actor.Claims.FirstOrDefault(c => c.Type == "role");
            Assert.NotNull(actorSubClaim);
            Assert.NotNull(actorNameClaim);
            Assert.NotNull(actorRoleClaim);

            Assert.Equal("actor-subject-id", actorSubClaim.Value);
            Assert.Equal("Actor Name", actorNameClaim.Value);
            Assert.Equal("admin", actorRoleClaim.Value);
        }

        [Fact]
        public async Task ValidateTokenAsync_CustomDelegate_ProcessesSimpleAndNestedActors()
        {
            // Two actor levels: require a chain length of 2 so the nested actor serializes as an object.
            JsonWebTokenHandler.MaxActorChainLength = 2;

            int delegateCallCount = 0;
            ClaimsIdentity CustomDelegate(JsonElement element, TokenValidationParameters tokenValidationParameters = null)
            {
                delegateCallCount++;
                var id = new CaseSensitiveClaimsIdentity("CustomActorAuth");
                if (element.TryGetProperty("sub", out var sub))
                    id.AddClaim(new Claim("sub", sub.GetString()));
                if (element.TryGetProperty("name", out var name))
                    id.AddClaim(new Claim("name", name.GetString()));
                if (element.TryGetProperty("act", out var nested) && nested.ValueKind == JsonValueKind.Object)
                    id.Actor = CustomDelegate(nested);
                return id;
            }

            var nestedActor = new CaseSensitiveClaimsIdentity("NestedActorAuth");
            nestedActor.AddClaim(new Claim("sub", "nested-actor-id"));
            nestedActor.AddClaim(new Claim("name", "Nested Actor"));

            var actor = new CaseSensitiveClaimsIdentity("ActorAuth");
            actor.AddClaim(new Claim("sub", "actor-subject-id"));
            actor.AddClaim(new Claim("name", "Actor Name"));
            actor.Actor = nestedActor;

            var mainIdentity = new CaseSensitiveClaimsIdentity("Bearer");
            mainIdentity.AddClaim(new Claim("sub", "main-subject-id"));
            mainIdentity.AddClaim(new Claim("name", "Main User"));

            var handler = new JsonWebTokenHandler();
            var tokenDescriptor = new SecurityTokenDescriptor
            {
                Subject = mainIdentity,
                Issuer = "https://example.com",
                Audience = "https://api.example.com",
                Expires = DateTime.UtcNow.AddHours(1),
                SigningCredentials = Default.AsymmetricSigningCredentials,
                Claims = new Dictionary<string, object> { { "act", actor } },
            };
            var token = handler.CreateToken(tokenDescriptor);

            var validationParameters = new TokenValidationParameters
            {
                ValidateIssuer = false,
                ValidateAudience = false,
                ValidateLifetime = false,
                IssuerSigningKey = Default.AsymmetricSigningKey,
                ValidateIssuerSigningKey = true,
                ActClaimRetriever = CustomDelegate,
            };

            var result = await handler.ValidateTokenAsync(token, validationParameters);

            Assert.True(result.IsValid);
            Assert.NotNull(result.ClaimsIdentity.Actor);
            Assert.Equal("actor-subject-id", result.ClaimsIdentity.Actor.Claims.First(c => c.Type == "sub").Value);
            Assert.NotNull(result.ClaimsIdentity.Actor.Actor);
            Assert.Equal("nested-actor-id", result.ClaimsIdentity.Actor.Actor.Claims.First(c => c.Type == "sub").Value);
            Assert.True(delegateCallCount >= 2);
        }

        [Fact]
        public async Task ValidateTokenAsync_NestedActors_DefaultDelegate_CreatesProperClaimsIdentity()
        {
            // Two actor levels: require a chain length of 2.
            JsonWebTokenHandler.MaxActorChainLength = 2;

            var nestedActor = new CaseSensitiveClaimsIdentity("NestedActorAuth");
            nestedActor.AddClaim(new Claim("sub", "nested-actor-id"));
            nestedActor.AddClaim(new Claim("name", "Nested Actor"));

            var actor = new CaseSensitiveClaimsIdentity("ActorAuth");
            actor.AddClaim(new Claim("sub", "actor-subject-id"));
            actor.AddClaim(new Claim("name", "Actor Name"));
            actor.Actor = nestedActor;

            var mainIdentity = new CaseSensitiveClaimsIdentity("Bearer");
            mainIdentity.AddClaim(new Claim("sub", "main-subject-id"));
            mainIdentity.AddClaim(new Claim("name", "Main User"));

            var handler = new JsonWebTokenHandler();
            var tokenDescriptor = new SecurityTokenDescriptor
            {
                Subject = mainIdentity,
                Issuer = "https://example.com",
                Audience = "https://api.example.com",
                Expires = DateTime.UtcNow.AddHours(1),
                SigningCredentials = Default.AsymmetricSigningCredentials,
                Claims = new Dictionary<string, object> { { "act", actor } },
            };
            var token = handler.CreateToken(tokenDescriptor);

            var validationParameters = new TokenValidationParameters
            {
                ValidateIssuer = false,
                ValidateAudience = false,
                ValidateLifetime = false,
                IssuerSigningKey = Default.AsymmetricSigningKey,
                ValidateIssuerSigningKey = true,
            };

            var result = await handler.ValidateTokenAsync(token, validationParameters);

            Assert.True(result.IsValid);
            Assert.NotNull(result.ClaimsIdentity.Actor);
            Assert.Equal("actor-subject-id", result.ClaimsIdentity.Actor.Claims.First(c => c.Type == "sub").Value);
            Assert.NotNull(result.ClaimsIdentity.Actor.Actor);
            Assert.Equal("nested-actor-id", result.ClaimsIdentity.Actor.Actor.Claims.First(c => c.Type == "sub").Value);
        }



        [Fact]
        public async Task ValidateTokenAsync_CustomDelegate_WhenDelegateFails_ThrowsOnClaimsIdentityAccess()
        {
            // When a custom delegate throws an exception, validation succeeds but accessing
            // ClaimsIdentity throws because it's lazily evaluated
            ClaimsIdentity CustomDelegate(JsonElement element, TokenValidationParameters tokenValidationParameters = null)
            {
                throw new InvalidOperationException("Delegate failure");
            }

            var actor = new CaseSensitiveClaimsIdentity("ActorAuth");
            actor.AddClaim(new Claim("sub", "actor-subject-id"));

            var mainIdentity = new CaseSensitiveClaimsIdentity("Bearer");
            mainIdentity.AddClaim(new Claim("sub", "main-subject-id"));

            var handler = new JsonWebTokenHandler();
            var tokenDescriptor = new SecurityTokenDescriptor
            {
                Subject = mainIdentity,
                Issuer = "https://example.com",
                Audience = "https://api.example.com",
                Expires = DateTime.UtcNow.AddHours(1),
                SigningCredentials = Default.AsymmetricSigningCredentials,
                Claims = new Dictionary<string, object> { { "act", actor } },
            };
            var token = handler.CreateToken(tokenDescriptor);

            var validationParameters = new TokenValidationParameters
            {
                ValidateIssuer = false,
                ValidateAudience = false,
                ValidateLifetime = false,
                IssuerSigningKey = Default.AsymmetricSigningKey,
                ValidateIssuerSigningKey = true,
                ActClaimRetriever = CustomDelegate,
            };

            var result = await handler.ValidateTokenAsync(token, validationParameters);

            // Validation succeeds
            Assert.True(result.IsValid);

            // But accessing ClaimsIdentity throws because the delegate fails during lazy evaluation
            var exception = Assert.Throws<SecurityTokenException>(
                () => result.ClaimsIdentity);

            Assert.Contains("IDX14314", exception.Message);
        }

        [Fact]
        public async Task ValidateTokenAsync_ActorAsSubjectAndClaimsDictionary_ProcessesWithDefaultAndCustomDelegate()
        {
            ClaimsIdentity CustomDelegate(JsonElement element, TokenValidationParameters tokenValidationParameters = null)
            {
                var id = new CaseSensitiveClaimsIdentity("CustomActorAuth");
                if (element.TryGetProperty("sub", out var sub))
                    id.AddClaim(new Claim("sub", sub.GetString()));
                return id;
            }

            // Actor as Subject
            var actorAsSubject = new CaseSensitiveClaimsIdentity("ActorAuth");
            actorAsSubject.AddClaim(new Claim("sub", "actor-subject-id"));

            var mainIdentity = new CaseSensitiveClaimsIdentity("Bearer");
            mainIdentity.AddClaim(new Claim("sub", "main-subject-id"));
            mainIdentity.Actor = actorAsSubject;

            var handler = new JsonWebTokenHandler();
            var tokenDescriptor = new SecurityTokenDescriptor
            {
                Subject = mainIdentity,
                Issuer = "https://example.com",
                Audience = "https://api.example.com",
                Expires = DateTime.UtcNow.AddHours(1),
                SigningCredentials = Default.AsymmetricSigningCredentials,
            };
            var token = handler.CreateToken(tokenDescriptor);

            var validationParameters = new TokenValidationParameters
            {
                ValidateIssuer = false,
                ValidateAudience = false,
                ValidateLifetime = false,
                IssuerSigningKey = Default.AsymmetricSigningKey,
                ValidateIssuerSigningKey = true,
            };

            // Default delegate
            var result = await handler.ValidateTokenAsync(token, validationParameters);
            Assert.True(result.IsValid);
            Assert.NotNull(result.ClaimsIdentity.Actor);
            Assert.Equal("actor-subject-id", result.ClaimsIdentity.Actor.Claims.First(c => c.Type == "sub").Value);

            // Custom delegate
            validationParameters.ActClaimRetriever = CustomDelegate;
            var result2 = await handler.ValidateTokenAsync(token, validationParameters);
            Assert.True(result2.IsValid);
            Assert.NotNull(result2.ClaimsIdentity.Actor);
            Assert.Equal("actor-subject-id", result2.ClaimsIdentity.Actor.Claims.First(c => c.Type == "sub").Value);

            // Actor in both Subject and Claims dictionary, Claims dictionary should take precedence
            var subjectActor = new CaseSensitiveClaimsIdentity("SubjectActorAuth");
            subjectActor.AddClaim(new Claim("sub", "subject-actor-id"));

            var claimsActor = new CaseSensitiveClaimsIdentity("ClaimsActorAuth");
            claimsActor.AddClaim(new Claim("sub", "claims-actor-id"));

            var mainIdentity2 = new CaseSensitiveClaimsIdentity("Bearer");
            mainIdentity2.AddClaim(new Claim("sub", "main-subject-id"));
            mainIdentity2.Actor = subjectActor;

            var tokenDescriptor2 = new SecurityTokenDescriptor
            {
                Subject = mainIdentity2,
                Issuer = "https://example.com",
                Audience = "https://api.example.com",
                Expires = DateTime.UtcNow.AddHours(1),
                SigningCredentials = Default.AsymmetricSigningCredentials,
                Claims = new Dictionary<string, object> { { "act", claimsActor } },
            };
            var token2 = handler.CreateToken(tokenDescriptor2);

            var result3 = await handler.ValidateTokenAsync(token2, validationParameters);
            Assert.True(result3.IsValid);
            Assert.NotNull(result3.ClaimsIdentity.Actor);
            Assert.Equal("claims-actor-id", result3.ClaimsIdentity.Actor.Claims.First(c => c.Type == "sub").Value);
        }

        [Fact]
        public async Task ValidateTokenAsync_WithBothActAndActort_ActTakesPrecedence()
        {
            // ARRANGE
            // Build a legacy "actort" JWT string with a distinguishable actor subject.
            var innerHandler = new JsonWebTokenHandler();
            var actortActorIdentity = new CaseSensitiveClaimsIdentity("ActortAuth");
            actortActorIdentity.AddClaim(new Claim("sub", "actort-actor-id"));
            string actortJwtString = innerHandler.CreateToken(new SecurityTokenDescriptor
            {
                Subject = actortActorIdentity,
                Issuer = "https://actor.example.com",
                Audience = "https://api.example.com",
                SigningCredentials = Default.AsymmetricSigningCredentials
            });

            // The modern RFC 8693 "act" actor (JSON object) with a different, distinguishable subject.
            var actActorIdentity = new CaseSensitiveClaimsIdentity("ActAuth");
            actActorIdentity.AddClaim(new Claim("sub", "act-actor-id"));

            var mainIdentity = new CaseSensitiveClaimsIdentity("Bearer");
            mainIdentity.AddClaim(new Claim("sub", "main-subject-id"));

            var handler = new JsonWebTokenHandler();
            // Token carries BOTH: "act" (JSON object) and legacy "actort" (JWT string).
            string mainToken = handler.CreateToken(new SecurityTokenDescriptor
            {
                Subject = mainIdentity,
                Issuer = "https://example.com",
                Audience = "https://api.example.com",
                Expires = DateTime.UtcNow.AddHours(1),
                SigningCredentials = Default.AsymmetricSigningCredentials,
                Claims = new Dictionary<string, object>
                {
                    { "act", actActorIdentity },
                    { "actort", actortJwtString }
                }
            });

            var validationParameters = new TokenValidationParameters
            {
                ValidateIssuer = false,
                ValidateAudience = false,
                ValidateLifetime = false,
                IssuerSigningKey = Default.AsymmetricSigningKey,
                ValidateIssuerSigningKey = true
            };

            // ACT
            var result = await handler.ValidateTokenAsync(mainToken, validationParameters);

            // ASSERT
            // No duplicate-actor exception is thrown, and "act" wins over legacy "actort".
            Assert.True(result.IsValid);
            Assert.NotNull(result.ClaimsIdentity.Actor);
            Assert.Equal("act-actor-id", result.ClaimsIdentity.Actor.Claims.First(c => c.Type == "sub").Value);
            Assert.DoesNotContain(result.ClaimsIdentity.Actor.Claims, c => c.Value == "actort-actor-id");
        }

        [Fact]
        public async Task ValidateTokenAsync_WithActortClaim_HandlesJwtStringNotJson()
        {
            // ARRANGE
            // First create a JWT token to use as the actor token string
            var innerHandler = new JsonWebTokenHandler();
            var actorJwtIdentity = new CaseSensitiveClaimsIdentity("ActorAuth");
            actorJwtIdentity.AddClaim(new Claim("sub", "actor-subject-id"));
            actorJwtIdentity.AddClaim(new Claim("name", "Actor Name"));

            var actorJwtDescriptor = new SecurityTokenDescriptor
            {
                Subject = actorJwtIdentity,
                Issuer = "https://actor.example.com",
                Audience = "https://api.example.com",
                SigningCredentials = Default.AsymmetricSigningCredentials
            };

            // Create the actor token as a JWT string
            string actorJwtString = innerHandler.CreateToken(actorJwtDescriptor);

            // Now create the main token with the actort claim containing the JWT string
            var mainIdentity = new CaseSensitiveClaimsIdentity("Bearer");
            mainIdentity.AddClaim(new Claim("sub", "main-subject-id"));
            mainIdentity.AddClaim(new Claim("name", "Main User"));

            var handler = new JsonWebTokenHandler();
            var mainTokenDescriptor = new SecurityTokenDescriptor
            {
                Subject = mainIdentity,
                Issuer = "https://example.com",
                Audience = "https://api.example.com",
                Expires = DateTime.UtcNow.AddHours(1),
                SigningCredentials = Default.AsymmetricSigningCredentials,
                Claims = new Dictionary<string, object>
                {
                    // Use actort claim with JWT string
                    { "actort", actorJwtString }
                }
            };

            // Create the main token
            string mainToken = handler.CreateToken(mainTokenDescriptor);

            // ACT
            // Validate the token with actort claim type
            var validationParameters = new TokenValidationParameters
            {
                ValidateIssuer = false,
                ValidateAudience = false,
                ValidateLifetime = false,
                IssuerSigningKey = Default.AsymmetricSigningKey,
                ValidateIssuerSigningKey = true
            };

            var result = await handler.ValidateTokenAsync(mainToken, validationParameters);

            // ASSERT
            // Verify validation succeeded
            Assert.True(result.IsValid);
            Assert.NotNull(result.ClaimsIdentity);

            // Verify actor is processed as a JWT
            Assert.NotNull(result.ClaimsIdentity.Actor);

            // The actor should have claims from the JWT token
            var actorSubClaim = result.ClaimsIdentity.Actor.Claims.FirstOrDefault(c => c.Type == "sub");
            var actorNameClaim = result.ClaimsIdentity.Actor.Claims.FirstOrDefault(c => c.Type == "name");

            Assert.NotNull(actorSubClaim);
            Assert.NotNull(actorNameClaim);
            Assert.Equal("actor-subject-id", actorSubClaim.Value);
            Assert.Equal("Actor Name", actorNameClaim.Value);

            // For comparison, create another token with 'act' claim as JSON
            var jsonActor = new CaseSensitiveClaimsIdentity("ActorAuth");
            jsonActor.AddClaim(new Claim("sub", "json-actor-id"));
            jsonActor.AddClaim(new Claim("name", "JSON Actor"));

            var jsonTokenDescriptor = new SecurityTokenDescriptor
            {
                Subject = mainIdentity,
                Issuer = "https://example.com",
                Audience = "https://api.example.com",
                Expires = DateTime.UtcNow.AddHours(1),
                SigningCredentials = Default.AsymmetricSigningCredentials,
                Claims = new Dictionary<string, object>
                {
                    { "act", jsonActor }
                },
            };

            string jsonToken = handler.CreateToken(jsonTokenDescriptor);
            var jsonResult = await handler.ValidateTokenAsync(jsonToken, validationParameters);

            // Verify different processing method
            Assert.NotNull(jsonResult.ClaimsIdentity.Actor);
            Assert.Equal("json-actor-id", jsonResult.ClaimsIdentity.Actor.Claims.First(c => c.Type == "sub").Value);
        }

        [Fact]
        public async Task ValidateTokenAsync_MapInboundClaimsTrue_MapsMainClaimsButNotActorClaims()
        {
            // When MapInboundClaims is true, short claim names in the main identity are mapped to long URIs,
            // but actor claims remain in short form because they are deserialized directly from JSON
            var handler = new JsonWebTokenHandler();
            handler.MapInboundClaims = true;

            var actorIdentity = new CaseSensitiveClaimsIdentity("ActorAuth");
            actorIdentity.AddClaim(new Claim("sub", "actor-subject-id"));
            actorIdentity.AddClaim(new Claim("email", "actor@example.com"));
            actorIdentity.AddClaim(new Claim("given_name", "ActorFirstName"));

            var mainIdentity = new CaseSensitiveClaimsIdentity("Bearer");
            mainIdentity.AddClaim(new Claim("sub", "main-subject-id"));
            mainIdentity.AddClaim(new Claim("email", "main@example.com"));

            var tokenDescriptor = new SecurityTokenDescriptor
            {
                Subject = mainIdentity,
                Issuer = "https://example.com",
                Audience = "https://api.example.com",
                Expires = DateTime.UtcNow.AddHours(1),
                SigningCredentials = Default.AsymmetricSigningCredentials,
                Claims = new Dictionary<string, object> { { "act", actorIdentity } },
            };
            string token = handler.CreateToken(tokenDescriptor);

            var validationParameters = new TokenValidationParameters
            {
                ValidateIssuer = false,
                ValidateAudience = false,
                ValidateLifetime = false,
                IssuerSigningKey = Default.AsymmetricSigningKey,
                ValidateIssuerSigningKey = true,
            };

            var result = await handler.ValidateTokenAsync(token, validationParameters);

            Assert.True(result.IsValid);
            Assert.NotNull(result.ClaimsIdentity.Actor);

            // Verify main identity claims are mapped to long form
            var mainSubClaim = result.ClaimsIdentity.Claims.FirstOrDefault(c => c.Type == ClaimTypes.NameIdentifier);
            var mainEmailClaim = result.ClaimsIdentity.Claims.FirstOrDefault(c => c.Type == ClaimTypes.Email);
            Assert.NotNull(mainSubClaim);
            Assert.NotNull(mainEmailClaim);
            Assert.Equal("main-subject-id", mainSubClaim.Value);
            Assert.Equal("main@example.com", mainEmailClaim.Value);

            // Actor claims remain in short form (not mapped) because they are deserialized directly from JSON
            var actorSubClaim = result.ClaimsIdentity.Actor.Claims.FirstOrDefault(c => c.Type == "sub");
            var actorEmailClaim = result.ClaimsIdentity.Actor.Claims.FirstOrDefault(c => c.Type == "email");
            var actorGivenNameClaim = result.ClaimsIdentity.Actor.Claims.FirstOrDefault(c => c.Type == "given_name");
            Assert.NotNull(actorSubClaim);
            Assert.NotNull(actorEmailClaim);
            Assert.NotNull(actorGivenNameClaim);
            Assert.Equal("actor-subject-id", actorSubClaim.Value);
            Assert.Equal("actor@example.com", actorEmailClaim.Value);
            Assert.Equal("ActorFirstName", actorGivenNameClaim.Value);

            // Long-form claims don't exist in actor identity
            Assert.Null(result.ClaimsIdentity.Actor.Claims.FirstOrDefault(c => c.Type == ClaimTypes.NameIdentifier));
            Assert.Null(result.ClaimsIdentity.Actor.Claims.FirstOrDefault(c => c.Type == ClaimTypes.Email));
        }

        [Fact]
        public async Task ValidateTokenAsync_MapInboundClaimsFalse_KeepsActorClaimsInShortForm()
        {
            // When MapInboundClaims is false (default), short claim names should remain as-is
            var handler = new JsonWebTokenHandler();
            handler.MapInboundClaims = false;

            var actorIdentity = new CaseSensitiveClaimsIdentity("ActorAuth");
            actorIdentity.AddClaim(new Claim("sub", "actor-subject-id"));
            actorIdentity.AddClaim(new Claim("email", "actor@example.com"));
            actorIdentity.AddClaim(new Claim("given_name", "ActorFirstName"));

            var mainIdentity = new CaseSensitiveClaimsIdentity("Bearer");
            mainIdentity.AddClaim(new Claim("sub", "main-subject-id"));
            mainIdentity.AddClaim(new Claim("email", "main@example.com"));

            var tokenDescriptor = new SecurityTokenDescriptor
            {
                Subject = mainIdentity,
                Issuer = "https://example.com",
                Audience = "https://api.example.com",
                Expires = DateTime.UtcNow.AddHours(1),
                SigningCredentials = Default.AsymmetricSigningCredentials,
                Claims = new Dictionary<string, object> { { "act", actorIdentity } },
            };
            string token = handler.CreateToken(tokenDescriptor);

            var validationParameters = new TokenValidationParameters
            {
                ValidateIssuer = false,
                ValidateAudience = false,
                ValidateLifetime = false,
                IssuerSigningKey = Default.AsymmetricSigningKey,
                ValidateIssuerSigningKey = true,
            };

            var result = await handler.ValidateTokenAsync(token, validationParameters);

            Assert.True(result.IsValid);
            Assert.NotNull(result.ClaimsIdentity.Actor);

            // Verify main identity claims remain in short form
            var mainSubClaim = result.ClaimsIdentity.Claims.FirstOrDefault(c => c.Type == "sub");
            var mainEmailClaim = result.ClaimsIdentity.Claims.FirstOrDefault(c => c.Type == "email");
            Assert.NotNull(mainSubClaim);
            Assert.NotNull(mainEmailClaim);
            Assert.Equal("main-subject-id", mainSubClaim.Value);
            Assert.Equal("main@example.com", mainEmailClaim.Value);

            // Verify actor claims remain in short form
            var actorSubClaim = result.ClaimsIdentity.Actor.Claims.FirstOrDefault(c => c.Type == "sub");
            var actorEmailClaim = result.ClaimsIdentity.Actor.Claims.FirstOrDefault(c => c.Type == "email");
            var actorGivenNameClaim = result.ClaimsIdentity.Actor.Claims.FirstOrDefault(c => c.Type == "given_name");
            Assert.NotNull(actorSubClaim);
            Assert.NotNull(actorEmailClaim);
            Assert.NotNull(actorGivenNameClaim);
            Assert.Equal("actor-subject-id", actorSubClaim.Value);
            Assert.Equal("actor@example.com", actorEmailClaim.Value);
            Assert.Equal("ActorFirstName", actorGivenNameClaim.Value);

            // Verify long-form claims don't exist when mapping is disabled
            Assert.Null(result.ClaimsIdentity.Actor.Claims.FirstOrDefault(c => c.Type == ClaimTypes.NameIdentifier));
            Assert.Null(result.ClaimsIdentity.Actor.Claims.FirstOrDefault(c => c.Type == ClaimTypes.Email));
        }

        [Fact]
        public async Task ValidateTokenAsync_MapInboundClaimsTrue_WithActortClaim_DetectsActorCorrectly()
        {
            // When MapInboundClaims is true, "actort" gets mapped to the long URI ClaimTypes.Actor.
            // The actor detection must use the raw claim type (not mapped) to correctly identify actor claims.
            var handler = new JsonWebTokenHandler();
            handler.MapInboundClaims = true;

            // Create a token with "actort" claim (legacy unsigned JWT format)
            var innerHandler = new JsonWebTokenHandler();
            var actorDescriptor = new SecurityTokenDescriptor
            {
                Claims = new Dictionary<string, object>
                {
                    { "sub", "actor-subject-id" },
                    { "name", "Actor Name" },
                },
            };
            // Create unsigned actor JWT (actort is a JWT string)
            string actorJwt = innerHandler.CreateToken(actorDescriptor);

            var mainIdentity = new CaseSensitiveClaimsIdentity("Bearer");
            mainIdentity.AddClaim(new Claim("sub", "main-subject-id"));

            // Put "actort" in the claims dictionary as a raw JWT string
            var tokenDescriptor = new SecurityTokenDescriptor
            {
                Subject = mainIdentity,
                Issuer = "https://example.com",
                Audience = "https://api.example.com",
                Expires = DateTime.UtcNow.AddHours(1),
                SigningCredentials = Default.AsymmetricSigningCredentials,
                Claims = new Dictionary<string, object> { { "actort", actorJwt } },
            };
            string token = handler.CreateToken(tokenDescriptor);

            var validationParameters = new TokenValidationParameters
            {
                ValidateIssuer = false,
                ValidateAudience = false,
                ValidateLifetime = false,
                IssuerSigningKey = Default.AsymmetricSigningKey,
                ValidateIssuerSigningKey = true,
            };

            var result = await handler.ValidateTokenAsync(token, validationParameters);

            Assert.True(result.IsValid);
            Assert.NotNull(result.ClaimsIdentity.Actor);
            Assert.Equal("actor-subject-id", result.ClaimsIdentity.Actor.Claims.First(c => c.Type == "sub").Value);
        }

        [Fact]
        public void CreateActorClaimsIdentity_ExceedingMaxChainLength_KeepsRemainderAsClaim()
        {
            // With the default chain length of 1, only the top actor is expanded; deeper actors are
            // retained as an "act" claim instead of throwing.
            // Create a 6-level nested actor JSON structure (exceeds the limit)
            string actorJson = @"{
                ""sub"": ""level1-subject"",
                ""act"": {
                    ""sub"": ""level2-subject"",
                    ""act"": {
                        ""sub"": ""level3-subject"",
                        ""act"": {
                            ""sub"": ""level4-subject"",
                            ""act"": {
                                ""sub"": ""level5-subject"",
                                ""act"": {
                                    ""sub"": ""level6-subject""
                                }
                            }
                        }
                    }
                }
            }";

            var jsonElement = JsonDocument.Parse(actorJson).RootElement;
            var tokenValidationParameters = new TokenValidationParameters
            {
            };

            var identity = JsonWebTokenHandler.CreateActorClaimsIdentityFromJsonElement(
                jsonElement,
                tokenValidationParameters);

            Assert.NotNull(identity);
            Assert.Equal("level1-subject", identity.Claims.First(c => c.Type == "sub").Value);
            // The nested actor beyond the limit is kept as a raw "act" claim, not expanded into Actor.
            Assert.Null(identity.Actor);
            Assert.Contains(identity.Claims, c => c.Type == "act");
        }

        [Fact]
        public void CreateActorClaimsIdentity_AtExactlyMaxDepthOf5_Succeeds()
        {
            // Configure a chain length of 5 and provide exactly 5 nested actor levels.
            JsonWebTokenHandler.MaxActorChainLength = 5;

            // Create exactly 5 levels of nested actors (at the limit)
            string actorJson = @"{
                ""sub"": ""level1-subject"",
                ""act"": {
                    ""sub"": ""level2-subject"",
                    ""act"": {
                        ""sub"": ""level3-subject"",
                        ""act"": {
                            ""sub"": ""level4-subject"",
                            ""act"": {
                                ""sub"": ""level5-subject""
                            }
                        }
                    }
                }
            }";

            var jsonElement = JsonDocument.Parse(actorJson).RootElement;
            var tokenValidationParameters = new TokenValidationParameters
            {
            };

            var identity = JsonWebTokenHandler.CreateActorClaimsIdentityFromJsonElement(
                jsonElement,
                tokenValidationParameters);

            Assert.NotNull(identity);
            Assert.Equal("level1-subject", identity.Claims.First(c => c.Type == "sub").Value);

            Assert.NotNull(identity.Actor);
            Assert.Equal("level2-subject", identity.Actor.Claims.First(c => c.Type == "sub").Value);

            Assert.NotNull(identity.Actor.Actor);
            Assert.Equal("level3-subject", identity.Actor.Actor.Claims.First(c => c.Type == "sub").Value);

            Assert.NotNull(identity.Actor.Actor.Actor);
            Assert.Equal("level4-subject", identity.Actor.Actor.Actor.Claims.First(c => c.Type == "sub").Value);

            Assert.NotNull(identity.Actor.Actor.Actor.Actor);
            Assert.Equal("level5-subject", identity.Actor.Actor.Actor.Actor.Claims.First(c => c.Type == "sub").Value);

            Assert.Null(identity.Actor.Actor.Actor.Actor.Actor);
        }

        [Fact]
        public async Task LegacyActort_NestedJwtChain_ExceedingMaxChainLength_StopsExpanding()
        {
            // Legacy "actort" JWT-string actor chains are depth-limited during validation: beyond the
            // configured chain length the chain stops expanding (no throw) rather than recursing without bound.
            var handler = new JsonWebTokenHandler();
            var signingCredentials = Default.AsymmetricSigningCredentials;

            // Build a chain of nested actort JWTs exceeding MaxActorChainLength (5).
            // Create the innermost actor JWT first, then wrap each level.
            string currentActorToken = null;

            // Create 6 levels of nested actort tokens (exceeds limit of 5)
            for (int i = 6; i >= 1; i--)
            {
                var actorIdentity = new CaseSensitiveClaimsIdentity("Bearer");
                actorIdentity.AddClaim(new Claim("sub", $"level{i}-actor"));

                var descriptor = new SecurityTokenDescriptor
                {
                    Subject = actorIdentity,
                    Issuer = "https://example.com",
                    Audience = "https://api.example.com",
                    SigningCredentials = signingCredentials,
                };

                if (currentActorToken != null)
                {
                    descriptor.Claims = new Dictionary<string, object>
                    {
                        { "actort", currentActorToken }
                    };
                }

                currentActorToken = handler.CreateToken(descriptor);
            }

            // Create the main token with the deeply nested actort chain
            var mainIdentity = new CaseSensitiveClaimsIdentity("Bearer");
            mainIdentity.AddClaim(new Claim("sub", "main-subject-id"));

            var mainDescriptor = new SecurityTokenDescriptor
            {
                Subject = mainIdentity,
                Issuer = "https://example.com",
                Audience = "https://api.example.com",
                SigningCredentials = signingCredentials,
                Claims = new Dictionary<string, object>
                {
                    { "actort", currentActorToken }
                },
            };

            var mainToken = handler.CreateToken(mainDescriptor);

            var validationParameters = new TokenValidationParameters
            {
                ValidateIssuer = false,
                ValidateAudience = false,
                ValidateLifetime = false,
                IssuerSigningKey = Default.AsymmetricSigningKey,
            };

            var result = await handler.ValidateTokenAsync(mainToken, validationParameters);
            Assert.True(result.IsValid);

            // With the default chain length of 1 the immediate actor is expanded and the chain stops there.
            var identity = result.ClaimsIdentity;
            Assert.NotNull(identity.Actor);
            Assert.Equal("level1-actor", identity.Actor.FindFirst("sub")?.Value);
            Assert.Null(identity.Actor.Actor);
        }

        [Fact]
        public async Task LegacyActort_NestedJwtChain_WithinMaxDepth_Succeeds()
        {
            // Validates that legacy "actort" JWT-string actor chains within the depth limit
            // are processed successfully during token validation.
            // The chain has 4 actor levels; configure the chain length to expand all of them.
            JsonWebTokenHandler.MaxActorChainLength = 4;

            var handler = new JsonWebTokenHandler();
            var signingCredentials = Default.AsymmetricSigningCredentials;

            // Build a chain of 4 nested actort JWTs (within limit of 5).
            string currentActorToken = null;

            for (int i = 4; i >= 1; i--)
            {
                var actorIdentity = new CaseSensitiveClaimsIdentity("Bearer");
                actorIdentity.AddClaim(new Claim("sub", $"level{i}-actor"));

                var descriptor = new SecurityTokenDescriptor
                {
                    Subject = actorIdentity,
                    Issuer = "https://example.com",
                    Audience = "https://api.example.com",
                    SigningCredentials = signingCredentials,
                };

                if (currentActorToken != null)
                {
                    descriptor.Claims = new Dictionary<string, object>
                    {
                        { "actort", currentActorToken }
                    };
                }

                currentActorToken = handler.CreateToken(descriptor);
            }

            // Create the main token with nested actort chain
            var mainIdentity = new CaseSensitiveClaimsIdentity("Bearer");
            mainIdentity.AddClaim(new Claim("sub", "main-subject-id"));

            var mainDescriptor = new SecurityTokenDescriptor
            {
                Subject = mainIdentity,
                Issuer = "https://example.com",
                Audience = "https://api.example.com",
                SigningCredentials = signingCredentials,
                Claims = new Dictionary<string, object>
                {
                    { "actort", currentActorToken }
                },
            };

            var mainToken = handler.CreateToken(mainDescriptor);

            var validationParameters = new TokenValidationParameters
            {
                ValidateIssuer = false,
                ValidateAudience = false,
                ValidateLifetime = false,
                IssuerSigningKey = Default.AsymmetricSigningKey,
            };

            var result = await handler.ValidateTokenAsync(mainToken, validationParameters);
            Assert.True(result.IsValid, $"Token validation failed: {result.Exception?.Message}");

            // ClaimsIdentity is lazily created — accessing it triggers actor chain processing
            var identity = result.ClaimsIdentity;

            // Verify the actor chain was created
            Assert.NotNull(identity.Actor);
            Assert.Equal("level1-actor", identity.Actor.FindFirst("sub")?.Value);
            Assert.NotNull(identity.Actor.Actor);
            Assert.Equal("level2-actor", identity.Actor.Actor.FindFirst("sub")?.Value);
        }

        // ---------------------------------------------------------------------------------------
        // End-to-end tests: create a token, inspect the raw serialized payload to show exactly
        // where "act" / "actort" land, then validate the token round-trip and assert the Actor.
        // ---------------------------------------------------------------------------------------

        [Fact]
        public async Task EndToEnd_ActFromSubjectActor_SerializedAsJsonObject_AndRoundTrips()
        {
            // ARRANGE: a subject carrying an actor via ClaimsIdentity.Actor.
            var handler = new JsonWebTokenHandler();
            var actor = new CaseSensitiveClaimsIdentity(new[] { new Claim("sub", "service-A"), new Claim("role", "worker") });
            var subject = new CaseSensitiveClaimsIdentity(new[] { new Claim("sub", "user-1") }) { Actor = actor };

            string token = handler.CreateToken(new SecurityTokenDescriptor
            {
                Subject = subject,
                Issuer = "https://example.com",
                Audience = "https://api.example.com",
                Expires = DateTime.UtcNow.AddHours(1),
                SigningCredentials = Default.AsymmetricSigningCredentials
            });

            // ASSERT (serialization): the actor is written under the "act" claim as a JSON OBJECT,
            // and there is no "actort" claim.
            var decoded = handler.ReadJsonWebToken(token);
            Assert.True(decoded.Payload.HasClaim("act"), "payload should contain 'act'");
            Assert.False(decoded.Payload.HasClaim("actort"), "payload should NOT contain 'actort'");
            var act = decoded.Payload.GetValue<JsonElement>("act");
            Assert.Equal(JsonValueKind.Object, act.ValueKind);
            Assert.Equal("service-A", act.GetProperty("sub").GetString());

            // ACT + ASSERT (deserialization round-trip): the actor is read back onto ClaimsIdentity.Actor.
            var result = await handler.ValidateTokenAsync(token, new TokenValidationParameters
            {
                ValidateIssuer = false,
                ValidateAudience = false,
                ValidateLifetime = false,
                IssuerSigningKey = Default.AsymmetricSigningKey,
                ValidateIssuerSigningKey = true
            });

            Assert.True(result.IsValid);
            Assert.NotNull(result.ClaimsIdentity.Actor);
            Assert.Equal("service-A", result.ClaimsIdentity.Actor.FindFirst("sub")?.Value);
            Assert.Equal("worker", result.ClaimsIdentity.Actor.FindFirst("role")?.Value);
        }

        [Fact]
        public async Task EndToEnd_NestedActors_SerializedAsNestedActObjects_AndRoundTrip()
        {
            // Two actor levels: require a chain length of 2.
            JsonWebTokenHandler.MaxActorChainLength = 2;

            // ARRANGE: a delegation chain user-1 <- service-A <- service-B.
            var handler = new JsonWebTokenHandler();
            var inner = new CaseSensitiveClaimsIdentity(new[] { new Claim("sub", "service-B") });
            var outer = new CaseSensitiveClaimsIdentity(new[] { new Claim("sub", "service-A") }) { Actor = inner };
            var subject = new CaseSensitiveClaimsIdentity(new[] { new Claim("sub", "user-1") }) { Actor = outer };

            string token = handler.CreateToken(new SecurityTokenDescriptor
            {
                Subject = subject,
                Issuer = "https://example.com",
                Audience = "https://api.example.com",
                Expires = DateTime.UtcNow.AddHours(1),
                SigningCredentials = Default.AsymmetricSigningCredentials
            });

            // ASSERT (serialization): "act" nests another "act" (RFC 8693 delegation chain).
            var decoded = handler.ReadJsonWebToken(token);
            var act = decoded.Payload.GetValue<JsonElement>("act");
            Assert.Equal("service-A", act.GetProperty("sub").GetString());
            Assert.True(act.TryGetProperty("act", out var nestedAct), "'act' should contain a nested 'act'");
            Assert.Equal("service-B", nestedAct.GetProperty("sub").GetString());

            // ACT + ASSERT (deserialization round-trip): both levels of Actor are populated.
            var result = await handler.ValidateTokenAsync(token, new TokenValidationParameters
            {
                ValidateIssuer = false,
                ValidateAudience = false,
                ValidateLifetime = false,
                IssuerSigningKey = Default.AsymmetricSigningKey,
                ValidateIssuerSigningKey = true
            });

            Assert.True(result.IsValid);
            Assert.Equal("service-A", result.ClaimsIdentity.Actor?.FindFirst("sub")?.Value);
            Assert.Equal("service-B", result.ClaimsIdentity.Actor?.Actor?.FindFirst("sub")?.Value);
        }

        [Fact]
        public async Task EndToEnd_LegacyActortJwtString_SerializedAsString_AndRoundTrips()
        {
            // ARRANGE: the handler never *writes* actort; a caller supplies it as a JWT string
            // in the Claims dictionary (this is what legacy JwtSecurityTokenHandler tokens look like).
            var handler = new JsonWebTokenHandler();
            string actorJwt = handler.CreateToken(new SecurityTokenDescriptor
            {
                Subject = new CaseSensitiveClaimsIdentity(new[] { new Claim("sub", "legacy-actor") }),
                SigningCredentials = Default.AsymmetricSigningCredentials
            });

            string token = handler.CreateToken(new SecurityTokenDescriptor
            {
                Subject = new CaseSensitiveClaimsIdentity(new[] { new Claim("sub", "user-1") }),
                Issuer = "https://example.com",
                Audience = "https://api.example.com",
                Expires = DateTime.UtcNow.AddHours(1),
                SigningCredentials = Default.AsymmetricSigningCredentials,
                Claims = new Dictionary<string, object> { { "actort", actorJwt } }
            });

            // ASSERT (serialization): the actor is present under "actort" as a JWT STRING, not "act".
            var decoded = handler.ReadJsonWebToken(token);
            Assert.True(decoded.Payload.HasClaim("actort"), "payload should contain 'actort'");
            Assert.False(decoded.Payload.HasClaim("act"), "payload should NOT contain 'act'");
            // "actort" is a JWT string (not a JSON object), so it reads back as a string.
            Assert.Equal(actorJwt, decoded.Payload.GetValue<string>("actort"));

            // ACT + ASSERT (deserialization round-trip): the legacy actort JWT is parsed onto Actor.
            var result = await handler.ValidateTokenAsync(token, new TokenValidationParameters
            {
                ValidateIssuer = false,
                ValidateAudience = false,
                ValidateLifetime = false,
                IssuerSigningKey = Default.AsymmetricSigningKey,
                ValidateIssuerSigningKey = true
            });

            Assert.True(result.IsValid);
            Assert.NotNull(result.ClaimsIdentity.Actor);
            Assert.Equal("legacy-actor", result.ClaimsIdentity.Actor.FindFirst("sub")?.Value);
        }
    }
}
