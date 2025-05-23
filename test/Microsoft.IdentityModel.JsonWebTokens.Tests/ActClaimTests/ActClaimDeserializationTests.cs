// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System;
using System.Collections.Generic;
using System.Security.Claims;
using System.Text.Json;
using Microsoft.IdentityModel.TestUtils;
using Microsoft.IdentityModel.Tokens;
using Xunit;
using System.Threading.Tasks;
using System.Linq;
namespace Microsoft.IdentityModel.JsonWebTokens.Tests.ActClaimTests
{
    public class ActClaimDeserializationTests
    {
        // Tests for creating ClaimsIdentity from JsonElement
        [ResetAppContextSwitches]
        [Fact]
        public void BasicJsonElementShouldCreateClaimsIdentityCorrectly()
        {
            var context = new CompareContext($"{this}.BasicJsonElementShouldCreateClaimsIdentityCorrectly");
            bool switchValue = false;
            AppContext.TryGetSwitch(AppContextSwitches.EnableActClaimSupportSwitch, out switchValue);
            AppContext.SetSwitch(AppContextSwitches.EnableActClaimSupportSwitch, true);
            try
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
                    ActorClaimType = "act"
                };

                // Create ClaimsIdentity from JsonElement
                var identity = JsonWebTokenHandler.CreateActorClaimsIdentityFromJsonElement(
                    jsonElement,
                    validationParameters);

                // Assert
                Assert.NotNull(identity);
                Assert.Equal("Actor", identity.AuthenticationType);
                Assert.IsType<CaseSensitiveClaimsIdentity>(identity);

                // Verify claims values
                Assert.Equal("actor-subject-id", identity.Claims.First(c => c.Type == "sub").Value);
                Assert.Equal("Actor Name", identity.Claims.First(c => c.Type == "name").Value);
                Assert.Equal("admin", identity.Claims.First(c => c.Type == "role").Value);

                TestUtilities.AssertFailIfErrors(context);
            }
            catch (Exception ex)
            {
                context.Diffs.Add($"Exception: {ex}");
            }
            finally
            {
                AppContext.SetSwitch(AppContextSwitches.EnableActClaimSupportSwitch, false);
            }
        }

        [ResetAppContextSwitches]
        [Fact]
        public void NestedActorInJsonElementShouldCreateNestedClaimsIdentity()
        {
            var context = new CompareContext($"{this}.NestedActorInJsonElementShouldCreateNestedClaimsIdentity");
            bool switchValue = false;
            AppContext.TryGetSwitch(AppContextSwitches.EnableActClaimSupportSwitch, out switchValue);
            AppContext.SetSwitch(AppContextSwitches.EnableActClaimSupportSwitch, true);
            try
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
                    ActorClaimType = "act"
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

                TestUtilities.AssertFailIfErrors(context);
            }
            catch (Exception ex)
            {
                context.Diffs.Add($"Exception: {ex}");
            }
            finally
            {
                AppContext.SetSwitch(AppContextSwitches.EnableActClaimSupportSwitch, false);
            }
        }

        [ResetAppContextSwitches]
        [Fact]
        public void MultiLevelNestedActorJsonShouldHandleProperDepth()
        {
            var context = new CompareContext($"{this}.MultiLevelNestedActorJsonShouldHandleProperDepth");
            bool switchValue = false;
            AppContext.TryGetSwitch(AppContextSwitches.EnableActClaimSupportSwitch, out switchValue);
            AppContext.SetSwitch(AppContextSwitches.EnableActClaimSupportSwitch, true);
            try
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
                    MaxActorChainLength = 3  // Allow up to 3 levels
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

                TestUtilities.AssertFailIfErrors(context);
            }
            catch (Exception ex)
            {
                context.Diffs.Add($"Exception: {ex}");
            }
            finally
            {
                AppContext.SetSwitch(AppContextSwitches.EnableActClaimSupportSwitch, false);
            }
        }

        [ResetAppContextSwitches]
        [Fact]
        public void NestedActorExceedingMaxDepth_ThrowsException()
        {
            var context = new CompareContext($"{this}.NestedActorExceedingMaxDepth_ThrowsException");
            bool switchValue = false;
            AppContext.TryGetSwitch(AppContextSwitches.EnableActClaimSupportSwitch, out switchValue);
            AppContext.SetSwitch(AppContextSwitches.EnableActClaimSupportSwitch, true);
            try
            {
                // Create a three-level nested actor but set max depth to 2
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
                    MaxActorChainLength = 2,  // Only allow 2 levels, but JSON has 3
                    ActorChainDepth = 1      // Start at depth 1 to simulate being in an ongoing chain
                };

                // Act - This should throw a SecurityTokenException
                var identity = JsonWebTokenHandler.CreateActorClaimsIdentityFromJsonElement(
                    jsonElement,
                    tokenValidationParameters);

                context.Diffs.Add("Expected exception was not thrown.");
                TestUtilities.AssertFailIfErrors(context);
            }
            catch (SecurityTokenException ex)
            {
                // Assert - Verify the exception message contains the expected content
                if (!ex.Message.Contains("IDX14313"))
                {
                    context.Diffs.Add($"Exception message does not contain expected content. Message: {ex.Message}");
                }
                TestUtilities.AssertFailIfErrors(context);
            }
            catch (Exception ex)
            {
                // Unexpected exception type
                context.Diffs.Add($"Unexpected exception type: {ex.GetType()}, Message: {ex.Message}");
                TestUtilities.AssertFailIfErrors(context);
            }
            finally
            {
                AppContext.SetSwitch(AppContextSwitches.EnableActClaimSupportSwitch, false);
            }
        }

        [ResetAppContextSwitches]
        [Fact]
        public void JsonElementWithArrayValuesShouldProcessCorrectly()
        {
            var context = new CompareContext($"{this}.JsonElementWithArrayValuesShouldProcessCorrectly");
            bool switchValue = false;
            AppContext.TryGetSwitch(AppContextSwitches.EnableActClaimSupportSwitch, out switchValue);
            AppContext.SetSwitch(AppContextSwitches.EnableActClaimSupportSwitch, true);
            try
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
                    ActorClaimType = "act"
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

                TestUtilities.AssertFailIfErrors(context);
            }
            catch (Exception ex)
            {
                context.Diffs.Add($"Exception: {ex}");
            }
            finally
            {
                AppContext.SetSwitch(AppContextSwitches.EnableActClaimSupportSwitch, false);
            }
        }

        [ResetAppContextSwitches]
        [Fact]
        public void JsonElementWithComplexTypesShouldHandleCorrectly()
        {
            var context = new CompareContext($"{this}.JsonElementWithComplexTypesShouldHandleCorrectly");
            bool switchValue = false;
            AppContext.TryGetSwitch(AppContextSwitches.EnableActClaimSupportSwitch, out switchValue);
            AppContext.SetSwitch(AppContextSwitches.EnableActClaimSupportSwitch, true);
            try
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
                    ActorClaimType = "act"
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

                TestUtilities.AssertFailIfErrors(context);
            }
            catch (Exception ex)
            {
                context.Diffs.Add($"Exception: {ex}");
            }
            finally
            {
                AppContext.SetSwitch(AppContextSwitches.EnableActClaimSupportSwitch, false);
            }
        }

        [ResetAppContextSwitches]
        [Fact]
        public void NonObjectJsonElement_ThrowsException()
        {
            var context = new CompareContext($"{this}.NonObjectJsonElement_ThrowsException");
            bool switchValue = false;
            AppContext.TryGetSwitch(AppContextSwitches.EnableActClaimSupportSwitch, out switchValue);
            AppContext.SetSwitch(AppContextSwitches.EnableActClaimSupportSwitch, true);
            try
            {
                // Create a non-object JSON Element (string)
                string actorJson = @"""This is just a string, not an object""";
                var jsonElement = JsonDocument.Parse(actorJson).RootElement;

                var tokenValidationParameters = new TokenValidationParameters
                {
                    ActorClaimType = "act"
                };

                // Act - This should throw an ArgumentException
                var identity = JsonWebTokenHandler.CreateActorClaimsIdentityFromJsonElement(
                    jsonElement,
                    tokenValidationParameters);

                context.Diffs.Add("Expected exception was not thrown.");
                TestUtilities.AssertFailIfErrors(context);
            }
            catch (ArgumentException ex)
            {
                // Expected exception type
                Assert.Contains("Actor token must be a JSON object", ex.Message);
            }
            catch (Exception ex)
            {
                // Unexpected exception type
                context.Diffs.Add($"Unexpected exception type: {ex.GetType()}, Message: {ex.Message}");
                TestUtilities.AssertFailIfErrors(context);
            }
            finally
            {
                AppContext.SetSwitch(AppContextSwitches.EnableActClaimSupportSwitch, false);
            }
        }

        [ResetAppContextSwitches]
        [Fact]
        public void NullValidationParameters_ThrowsException()
        {
            var context = new CompareContext($"{this}.NullValidationParameters_ThrowsException");
            bool switchValue = false;
            AppContext.TryGetSwitch(AppContextSwitches.EnableActClaimSupportSwitch, out switchValue);
            AppContext.SetSwitch(AppContextSwitches.EnableActClaimSupportSwitch, true);
            try
            {
                // Create a simple JSON Element
                string actorJson = @"{ ""sub"": ""actor-subject-id"" }";
                var jsonElement = JsonDocument.Parse(actorJson).RootElement;

                // Act - This should throw an ArgumentNullException
                var identity = JsonWebTokenHandler.CreateActorClaimsIdentityFromJsonElement(
                    jsonElement,
                    null);  // Null validation parameters

                context.Diffs.Add("Expected exception was not thrown.");
                TestUtilities.AssertFailIfErrors(context);
            }
            catch (ArgumentNullException ex)
            {
                // Expected exception type
                Assert.Equal("tokenValidationParameters", ex.ParamName);
            }
            catch (Exception ex)
            {
                // Unexpected exception type
                context.Diffs.Add($"Unexpected exception type: {ex.GetType()}, Message: {ex.Message}");
                TestUtilities.AssertFailIfErrors(context);
            }
            finally
            {
                AppContext.SetSwitch(AppContextSwitches.EnableActClaimSupportSwitch, false);
            }
        }

        [ResetAppContextSwitches]
        [Fact]
        public void CustomActorClaimNameShouldBeRespected()
        {
            var context = new CompareContext($"{this}.CustomActorClaimNameShouldBeRespected");
            bool switchValue = false;
            AppContext.TryGetSwitch(AppContextSwitches.EnableActClaimSupportSwitch, out switchValue);
            AppContext.SetSwitch(AppContextSwitches.EnableActClaimSupportSwitch, true);
            try
            {
                // Create JSON with custom actor claim name
                string actorJson = @"{
                    ""sub"": ""actor-subject-id"",
                    ""name"": ""Actor Name"",
                    ""actort"": {
                        ""sub"": ""nested-actor-id"",
                        ""name"": ""Nested Actor""
                    }
                }";

                var jsonElement = JsonDocument.Parse(actorJson).RootElement;
                var tokenValidationParameters = new TokenValidationParameters
                {
                    ActorClaimType = "actort"  // Custom actor claim name
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

                TestUtilities.AssertFailIfErrors(context);
            }
            catch (Exception ex)
            {
                context.Diffs.Add($"Exception: {ex}");
            }
            finally
            {
                AppContext.SetSwitch(AppContextSwitches.EnableActClaimSupportSwitch, false);
            }
        }

        [ResetAppContextSwitches]
        [Fact]
        public void ActorChainDepthShouldBeIncremented()
        {
            var context = new CompareContext($"{this}.ActorChainDepthShouldBeIncremented");
            bool switchValue = false;
            AppContext.TryGetSwitch(AppContextSwitches.EnableActClaimSupportSwitch, out switchValue);
            AppContext.SetSwitch(AppContextSwitches.EnableActClaimSupportSwitch, true);
            try
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
                    MaxActorChainLength = 4,
                    ActorChainDepth = 2  // Start at depth 2
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

                TestUtilities.AssertFailIfErrors(context);
            }
            catch (Exception ex)
            {
                context.Diffs.Add($"Exception: {ex}");
            }
            finally
            {
                AppContext.SetSwitch(AppContextSwitches.EnableActClaimSupportSwitch, false);
            }
        }

        [ResetAppContextSwitches]
        [Fact]
        public async Task ValidateTokenAsync_WithActorInToken_ProvidesActorClaimsIdentity()
        {
            var context = new CompareContext($"{this}.ValidateTokenAsync_WithActorInToken_ProvidesActorClaimsIdentity");
            bool switchValue = false;
            AppContext.TryGetSwitch(AppContextSwitches.EnableActClaimSupportSwitch, out switchValue);
            AppContext.SetSwitch(AppContextSwitches.EnableActClaimSupportSwitch, true);
            try
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
                    MaxActorChainLength = 4
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
                Console.WriteLine($"Verified main claims");

                // Verify actor claims identity
                Assert.NotNull(result.ClaimsIdentity.Actor);
                var actorSubClaim = result.ClaimsIdentity.Actor.Claims.FirstOrDefault(c => c.Type == "sub");
                var actorNameClaim = result.ClaimsIdentity.Actor.Claims.FirstOrDefault(c => c.Type == "name");
                var actorRoleClaim = result.ClaimsIdentity.Actor.Claims.FirstOrDefault(c => c.Type == "role");
                Assert.NotNull(actorSubClaim);
                Assert.NotNull(actorNameClaim);
                Assert.NotNull(actorRoleClaim);
                Console.WriteLine($"Verified actor claim");

                Assert.Equal("actor-subject-id", actorSubClaim.Value);
                Assert.Equal("Actor Name", actorNameClaim.Value);
                Assert.Equal("admin", actorRoleClaim.Value);

                TestUtilities.AssertFailIfErrors(context);
            }
            catch (Exception ex)
            {
                context.Diffs.Add($"Exception: {ex}");
                TestUtilities.AssertFailIfErrors(context);
            }
            finally
            {
                AppContext.SetSwitch(AppContextSwitches.EnableActClaimSupportSwitch, false);
            }
        }
        [ResetAppContextSwitches]
        [Fact]
        public async Task ValidateTokenAsync_CustomDelegate_WorksWithSimpleAndNestedActors()
        {
            var context = new CompareContext($"{this}.ValidateTokenAsync_CustomDelegate_WorksWithSimpleAndNestedActors");
            AppContext.SetSwitch(AppContextSwitches.EnableActClaimSupportSwitch, true);

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

            try
            {
                // Nested actor
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
                    Claims = new Dictionary<string, object> { { "act", actor } }
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
                    MaxActorChainLength = 3,
                    ActClaimRetrieverDelegate = CustomDelegate
                };

                var result = await handler.ValidateTokenAsync(token, validationParameters);
                Assert.True(result.IsValid);
                Assert.NotNull(result.ClaimsIdentity.Actor);
                Assert.Equal("actor-subject-id", result.ClaimsIdentity.Actor.Claims.First(c => c.Type == "sub").Value);
                Assert.NotNull(result.ClaimsIdentity.Actor.Actor);
                Assert.Equal("nested-actor-id", result.ClaimsIdentity.Actor.Actor.Claims.First(c => c.Type == "sub").Value);
                Assert.True(delegateCallCount >= 2);

                TestUtilities.AssertFailIfErrors(context);
            }
            finally
            {
                AppContext.SetSwitch(AppContextSwitches.EnableActClaimSupportSwitch, false);
            }
        }

        [ResetAppContextSwitches]
        [Fact]
        public async Task ValidateTokenAsync_NestedActors_DefaultDelegate_CreatesProperClaimsIdentity()
        {
            var context = new CompareContext($"{this}.ValidateTokenAsync_NestedActors_DefaultDelegate_CreatesProperClaimsIdentity");
            AppContext.SetSwitch(AppContextSwitches.EnableActClaimSupportSwitch, true);

            try
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
                    Claims = new Dictionary<string, object> { { "act", actor } }
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
                    MaxActorChainLength = 2
                };

                var result = await handler.ValidateTokenAsync(token, validationParameters);
                Assert.True(result.IsValid);
                Assert.NotNull(result.ClaimsIdentity.Actor);
                Assert.Equal("actor-subject-id", result.ClaimsIdentity.Actor.Claims.First(c => c.Type == "sub").Value);
                Assert.NotNull(result.ClaimsIdentity.Actor.Actor);
                Assert.Equal("nested-actor-id", result.ClaimsIdentity.Actor.Actor.Claims.First(c => c.Type == "sub").Value);

                TestUtilities.AssertFailIfErrors(context);
            }
            finally
            {
                AppContext.SetSwitch(AppContextSwitches.EnableActClaimSupportSwitch, false);
            }
        }

        [ResetAppContextSwitches]
        [Fact]
        public async Task ValidateTokenAsync_NestingBeyondMaxActorChain_ThrowsException()
        {
            var context = new CompareContext($"{this}.ValidateTokenAsync_NestingBeyondMaxActorChain_ThrowsException");
            AppContext.SetSwitch(AppContextSwitches.EnableActClaimSupportSwitch, true);

            try
            {
                var level3Actor = new CaseSensitiveClaimsIdentity("Level3Auth");
                level3Actor.AddClaim(new Claim("sub", "level3-actor"));

                var level2Actor = new CaseSensitiveClaimsIdentity("Level2Auth");
                level2Actor.AddClaim(new Claim("sub", "level2-actor"));
                level2Actor.Actor = level3Actor;

                var level1Actor = new CaseSensitiveClaimsIdentity("Level1Auth");
                level1Actor.AddClaim(new Claim("sub", "level1-actor"));
                level1Actor.Actor = level2Actor;

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
                    Claims = new Dictionary<string, object> { { "act", level1Actor } }
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
                    MaxActorChainLength = 2
                };
                handler.MapInboundClaims = true;
                var result = await handler.ValidateTokenAsync(token, validationParameters);
                Assert.Null(result.ClaimsIdentity.Actor);
                TestUtilities.AssertFailIfErrors(context);
            }
            catch (Exception ex)
            {
                Assert.Contains("IDX14313", ex.ToString());
            }
            finally
            {
                AppContext.SetSwitch(AppContextSwitches.EnableActClaimSupportSwitch, false);
            }
        }

        [ResetAppContextSwitches]
        [Fact]
        public async Task ValidateTokenAsync_CustomDelegate_ThrowsExceptionIfDelegateFails()
        {
            var context = new CompareContext($"{this}.ValidateTokenAsync_CustomDelegate_ThrowsIfDelegateFails");
            AppContext.SetSwitch(AppContextSwitches.EnableActClaimSupportSwitch, true);

            ClaimsIdentity CustomDelegate(JsonElement element, TokenValidationParameters tokenValidationParameters = null)
            {
                throw new InvalidOperationException("Delegate failure");
            }

            try
            {
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
                    Claims = new Dictionary<string, object> { { "act", actor } }
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
                    MaxActorChainLength = 2,
                    ActClaimRetrieverDelegate = CustomDelegate
                };

                var result = await handler.ValidateTokenAsync(token, validationParameters);
                Assert.Null(result.ClaimsIdentity.Actor);
                TestUtilities.AssertFailIfErrors(context);
            }
            catch (Exception ex)
            {
                Assert.Contains("IDX14314", ex.ToString());
            }
            finally
            {
                AppContext.SetSwitch(AppContextSwitches.EnableActClaimSupportSwitch, false);
            }
        }

        [ResetAppContextSwitches]
        [Fact]
        public async Task ValidateTokenAsync_ActorAsSubjectAndClaimsDictionary_DefaultAndCustomDelegate()
        {
            var context = new CompareContext($"{this}.ValidateTokenAsync_ActorAsSubjectAndClaimsDictionary_DefaultAndCustomDelegate");
            AppContext.SetSwitch(AppContextSwitches.EnableActClaimSupportSwitch, true);

            ClaimsIdentity CustomDelegate(JsonElement element, TokenValidationParameters tokenValidationParameters = null)
            {
                var id = new CaseSensitiveClaimsIdentity("CustomActorAuth");
                if (element.TryGetProperty("sub", out var sub))
                    id.AddClaim(new Claim("sub", sub.GetString()));
                return id;
            }

            try
            {
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
                    SigningCredentials = Default.AsymmetricSigningCredentials
                };
                var token = handler.CreateToken(tokenDescriptor);

                var validationParameters = new TokenValidationParameters
                {
                    ValidateIssuer = false,
                    ValidateAudience = false,
                    ValidateLifetime = false,
                    IssuerSigningKey = Default.AsymmetricSigningKey,
                    ValidateIssuerSigningKey = true,
                    ActorClaimType = "act"
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
                    Claims = new Dictionary<string, object> { { "act", claimsActor } }
                };
                var token2 = handler.CreateToken(tokenDescriptor2);

                var result3 = await handler.ValidateTokenAsync(token2, validationParameters);
                Assert.True(result3.IsValid);
                Assert.NotNull(result3.ClaimsIdentity.Actor);
                Assert.Equal("claims-actor-id", result3.ClaimsIdentity.Actor.Claims.First(c => c.Type == "sub").Value);

                TestUtilities.AssertFailIfErrors(context);
            }
            finally
            {
                AppContext.SetSwitch(AppContextSwitches.EnableActClaimSupportSwitch, false);
            }
        }

    }
}
