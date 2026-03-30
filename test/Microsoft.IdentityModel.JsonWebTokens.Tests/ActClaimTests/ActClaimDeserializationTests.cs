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
    public class ActClaimDeserializationTests
    {
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
                ActorClaimType = "act",
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
                ActorClaimType = "act",
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
                ActorClaimType = "act",
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
                ActorClaimType = "act",
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
                ActorClaimType = "act",
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
        public void CreateActorClaimsIdentity_NonObjectJsonElement_ThrowsArgumentException()
        {
            // Create a non-object JSON Element (string)
            string actorJson = @"""This is just a string, not an object""";
            var jsonElement = JsonDocument.Parse(actorJson).RootElement;

            var tokenValidationParameters = new TokenValidationParameters
            {
                ActorClaimType = "act",
            };

            // Act & Assert
            var exception = Assert.Throws<ArgumentException>(() =>
                JsonWebTokenHandler.CreateActorClaimsIdentityFromJsonElement(
                    jsonElement,
                    tokenValidationParameters));

            Assert.Contains("Actor token must be a JSON object", exception.Message);
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
        public void CreateActorClaimsIdentity_CustomActorClaimName_IsRespected()
        {
            // Create JSON with custom actor claim name
            string actorJson = @"{
                ""sub"": ""actor-subject-id"",
                ""name"": ""Actor Name"",
                ""custom_act"": {
                    ""sub"": ""nested-actor-id"",
                    ""name"": ""Nested Actor""
                }
            }";

            var jsonElement = JsonDocument.Parse(actorJson).RootElement;
            var tokenValidationParameters = new TokenValidationParameters
            {
                ActorClaimType = "custom_act",
            };

            // Create ClaimsIdentity from JsonElement
            var identity = JsonWebTokenHandler.CreateActorClaimsIdentityFromJsonElement(
                jsonElement,
                tokenValidationParameters);

            // Verify main identity
            Assert.NotNull(identity);
            Assert.Equal("actor-subject-id", identity.Claims.First(c => c.Type == "sub").Value);
            Assert.Equal("Actor Name", identity.Claims.First(c => c.Type == "name").Value);

            // Verify nested actor was found using custom claim name
            Assert.NotNull(identity.Actor);
            Assert.Equal("nested-actor-id", identity.Actor.Claims.First(c => c.Type == "sub").Value);
            Assert.Equal("Nested Actor", identity.Actor.Claims.First(c => c.Type == "name").Value);
        }

        [Fact]
        public void CreateActorClaimsIdentity_WithNestedActor_IncrementsActorChainDepth()
        {
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
                ActorClaimType = "act",
                ActorChainDepth = 2,
            };

            // Create ClaimsIdentity from JsonElement
            var identity = JsonWebTokenHandler.CreateActorClaimsIdentityFromJsonElement(
                jsonElement,
                tokenValidationParameters);

            // Verify depth was incremented (2 + 1 = 3)
            Assert.Equal(3, tokenValidationParameters.ActorChainDepth);

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
                ActorClaimType = "act",
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
                ActorClaimType = "act",
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
                ActorClaimType = "act",
                ActClaimRetrieverDelegate = CustomDelegate,
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
                ActorClaimType = "act",
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
                ActorClaimType = "act",
                ActClaimRetrieverDelegate = CustomDelegate,
            };

            var result = await handler.ValidateTokenAsync(token, validationParameters);

            // Validation succeeds
            Assert.True(result.IsValid);

            // But accessing ClaimsIdentity throws because the delegate fails during lazy evaluation
            var exception = Assert.Throws<SecurityTokenDecryptionFailedException>(
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
                ActorClaimType = "act",
            };

            // Default delegate
            var result = await handler.ValidateTokenAsync(token, validationParameters);
            Assert.True(result.IsValid);
            Assert.NotNull(result.ClaimsIdentity.Actor);
            Assert.Equal("actor-subject-id", result.ClaimsIdentity.Actor.Claims.First(c => c.Type == "sub").Value);

            // Custom delegate
            validationParameters.ActClaimRetrieverDelegate = CustomDelegate;
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
                    { "actor_claim_name", jsonActor }
                },
                ActorClaimType = "actor_claim_name",
            };

            string jsonToken = handler.CreateToken(jsonTokenDescriptor);
            validationParameters.ActorClaimType = "actor_claim_name";
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
                ActorClaimType = "act",
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
                ActorClaimType = "act",
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
        public void CreateActorClaimsIdentity_ExceedingFixedMaxDepthOf4_ThrowsSecurityTokenException()
        {
            // The MaxActorChainLength is fixed at 4 and not configurable.
            // Create a 5-level nested actor JSON structure (exceeds the limit)
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
                ActorClaimType = "act",
            };

            var exception = Assert.Throws<SecurityTokenException>(() =>
                JsonWebTokenHandler.CreateActorClaimsIdentityFromJsonElement(
                    jsonElement,
                    tokenValidationParameters));

            Assert.Contains("IDX14313", exception.Message);
        }

        [Fact]
        public void CreateActorClaimsIdentity_AtExactlyMaxDepthOf4_Succeeds()
        {
            // The MaxActorChainLength is fixed at 4.
            // Create exactly 4 levels of nested actors (at the limit)
            string actorJson = @"{
                ""sub"": ""level1-subject"",
                ""act"": {
                    ""sub"": ""level2-subject"",
                    ""act"": {
                        ""sub"": ""level3-subject"",
                        ""act"": {
                            ""sub"": ""level4-subject""
                        }
                    }
                }
            }";

            var jsonElement = JsonDocument.Parse(actorJson).RootElement;
            var tokenValidationParameters = new TokenValidationParameters
            {
                ActorClaimType = "act",
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

            Assert.Null(identity.Actor.Actor.Actor.Actor);
        }
    }
}
