// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System;
using System.Collections.Generic;
using System.Security.Claims;
using System.Text.Json;
using Microsoft.IdentityModel.TestUtils;
using Microsoft.IdentityModel.Tokens;
using Microsoft.IdentityModel.JsonWebTokens;
using Xunit;
using System.Threading.Tasks;
namespace Microsoft.IdentityModel.Tests
{
    public class ActorClaimsTests
    {
        [ResetAppContextSwitches]
        [Fact]
        public void ActorTokenInClaimsDictionaryShouldBeProperlySerialized()
        {
            var context = new CompareContext($"{this}.ActorTokenInClaimsDictionaryShouldBeProperlySerialized");
            bool switchValue = false;
            AppContext.TryGetSwitch(AppContextSwitches.EnableActClaimSupportSwitch, out switchValue);
            AppContext.SetSwitch(AppContextSwitches.EnableActClaimSupportSwitch, true);
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
                    }
                };
                var token = tokenHandler.CreateToken(tokenDescriptor);
                JsonWebToken decodedToken = tokenHandler.ReadJsonWebToken(token);

                // Verify actor claim exists in the token
                Assert.True(decodedToken.Payload.HasClaim(tokenDescriptor.ActorClaimName), "JWT token should contain 'actort' claim");
                // Verify the actor object directly
                var actorObject = decodedToken.Payload.GetValue<JsonElement>(tokenDescriptor.ActorClaimName);
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
            finally
            {
                AppContext.SetSwitch(AppContextSwitches.EnableActClaimSupportSwitch, false);
            }
        }

        [ResetAppContextSwitches]
        [Fact]
        public void ActorTokenAsSubjectShouldBeProperlySerialized()
        {
            var context = new CompareContext($"{this}.ActorTokenAsSubjectShouldBeProperlySerialized");
            bool switchValue = false;
            AppContext.TryGetSwitch(AppContextSwitches.EnableActClaimSupportSwitch, out switchValue);
            AppContext.SetSwitch(AppContextSwitches.EnableActClaimSupportSwitch, true);
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
                    SigningCredentials = Default.AsymmetricSigningCredentials
                };
                var token = tokenHandler.CreateToken(tokenDescriptor);
                JsonWebToken decodedToken = tokenHandler.ReadJsonWebToken(token);

                // Verify actor claim exists in the token
                Assert.True(decodedToken.Payload.HasClaim(tokenDescriptor.ActorClaimName), "JWT token should contain 'act' claim");

                // Verify actor claim exists in the token
                Assert.True(decodedToken.Payload.HasClaim(tokenDescriptor.ActorClaimName), "JWT token should contain actor claim");

                // Verify the actor object directly
                var actorObject = decodedToken.Payload.GetValue<JsonElement>(tokenDescriptor.ActorClaimName);
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
            finally
            {
                AppContext.SetSwitch(AppContextSwitches.EnableActClaimSupportSwitch, false);
            }
        }

        [ResetAppContextSwitches]
        [Fact]
        public void ActorTokenInBothClaimsAndSubjectShouldPreferClaimsValue()
        {
            var context = new CompareContext($"{this}.ActorTokenInBothClaimsAndSubjectShouldPreferClaimsValue");
            bool switchValue = false;
            string actorname = "act";
            AppContext.TryGetSwitch(AppContextSwitches.EnableActClaimSupportSwitch, out switchValue);
            AppContext.SetSwitch(AppContextSwitches.EnableActClaimSupportSwitch, true);
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
                    }
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
            finally
            {
                AppContext.SetSwitch(AppContextSwitches.EnableActClaimSupportSwitch, false);
            }
        }

        [ResetAppContextSwitches]
        [Fact]
        public void NestedActorTokenInClaimsDictionaryShouldBeProperlySerialized()
        {
            var context = new CompareContext($"{this}.NestedActorTokenInClaimsDictionaryShouldBeProperlySerialized");
            bool switchValue = false;
            AppContext.TryGetSwitch(AppContextSwitches.EnableActClaimSupportSwitch, out switchValue);
            AppContext.SetSwitch(AppContextSwitches.EnableActClaimSupportSwitch, true);
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
                    }
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
                Assert.True(actorObject.TryGetProperty(tokenDescriptor.ActorClaimName, out var nestedActorElement));
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
            finally
            {
                AppContext.SetSwitch(AppContextSwitches.EnableActClaimSupportSwitch, false);
            }
        }
        [ResetAppContextSwitches]
        [Fact]
        public void NestedActorTokenAsSubjectShouldBeProperlySerialized()
        {
            var context = new CompareContext($"{this}.NestedActorTokenAsSubjectShouldBeProperlySerialized");
            bool switchValue = false;
            AppContext.TryGetSwitch(AppContextSwitches.EnableActClaimSupportSwitch, out switchValue);
            try
            {
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
                    ActorClaimName = "act",
                };
                AppContext.SetSwitch(AppContextSwitches.EnableActClaimSupportSwitch, true);
                var token = tokenHandler.CreateToken(tokenDescriptor);
                JsonWebToken decodedToken = tokenHandler.ReadJsonWebToken(token);

                // Verify actor claim exists
                Assert.True(decodedToken.Payload.HasClaim("act"), "JWT token should contain 'act' claim");

                // Verify the actor object structure
                var actorObject = decodedToken.Payload.GetValue<JsonElement>("act");
                Console.WriteLine("actor token created: " + actorObject.ToString());

                Assert.Equal(JsonValueKind.Object, actorObject.ValueKind);

                // Verify main actor claims directly from JSON object
                Assert.Equal("actor-subject-id", actorObject.GetProperty("sub").GetString());
                Assert.Equal("Actor Name", actorObject.GetProperty("name").GetString());

                // Verify nested actor exists and is a JSON object
                Assert.True(actorObject.TryGetProperty(tokenDescriptor.ActorClaimName, out var nestedActorElement));
                Assert.Equal(JsonValueKind.Object, nestedActorElement.ValueKind);
                Console.WriteLine("nested token created: " + nestedActorElement.ToString());

                // Verify nested actor claims directly from JSON object
                Assert.Equal("nested-actor-id", nestedActorElement.GetProperty("sub").GetString());
                Assert.Equal("Nested Actor", nestedActorElement.GetProperty("name").GetString());
                TestUtilities.AssertFailIfErrors(context);
            }
            finally
            {
                AppContext.SetSwitch(AppContextSwitches.EnableActClaimSupportSwitch, false);
            }
        }
        [ResetAppContextSwitches]
        [Fact]
        public void MaxActorChainLength_RejectsNegativeValues()
        {
            bool switchValue = false;
            AppContext.TryGetSwitch(AppContextSwitches.EnableActClaimSupportSwitch, out switchValue);

            // Arrange
            SecurityTokenDescriptor tokenDescriptor = new SecurityTokenDescriptor
            {
                Subject = null,
                Issuer = "https://example.com",
                Audience = "https://api.example.com",
                SigningCredentials = Default.AsymmetricSigningCredentials
            };
            AppContext.SetSwitch(AppContextSwitches.EnableActClaimSupportSwitch, true);
            tokenDescriptor.ActorClaimName = "act"; // Set the actor claim name to "act" for testing
            int originalValue = tokenDescriptor.MaxActorChainLength;
            try
            {
                tokenDescriptor.ActorClaimName = "act"; // Set the actor claim name to "act" for testing
                // Act & Assert - Valid value 0 should not throw
                tokenDescriptor.MaxActorChainLength = 0;
                Assert.Equal(0, tokenDescriptor.MaxActorChainLength);

                // Act & Assert - Negative value
                var ex = Assert.Throws<ArgumentOutOfRangeException>(() =>
                    tokenDescriptor.MaxActorChainLength = -5);
                Assert.Contains("IDX11027", ex.Message);

                // Act & Assert - Valid value 1 should not throw
                tokenDescriptor.MaxActorChainLength = 1;
                Assert.Equal(1, tokenDescriptor.MaxActorChainLength);

                ex = Assert.Throws<ArgumentOutOfRangeException>(() =>
                    tokenDescriptor.MaxActorChainLength = 10);
                Assert.Contains("IDX11027", ex.Message);
            }
            finally
            {
                // Restore to original value
                tokenDescriptor.MaxActorChainLength = originalValue;
                AppContext.SetSwitch(AppContextSwitches.EnableActClaimSupportSwitch, false);
            }
        }

        [ResetAppContextSwitches]
        [Fact]
        public void NestedSubjectActorTokens_ExceedingMaxDepth_ThrowsException()
        {
            var context = new CompareContext($"{this}.NestedActorTokens_ExceedingMaxDepth_ThrowsException");
            bool switchValue = false;
            AppContext.TryGetSwitch(AppContextSwitches.EnableActClaimSupportSwitch, out switchValue);
            AppContext.SetSwitch(AppContextSwitches.EnableActClaimSupportSwitch, true);
            try
            {
                // Arrange
                var handler = new JsonWebTokenHandler();

                // Create nested actor identities (3 levels, but we'll set MaxActorChainLength to 2)
                var level3Actor = new CaseSensitiveClaimsIdentity("Level3Auth");
                level3Actor.AddClaim(new Claim("sub", "level3-actor"));
                level3Actor.AddClaim(new Claim("name", "Level 3 Actor"));

                var level2Actor = new CaseSensitiveClaimsIdentity("Level2Auth");
                level2Actor.AddClaim(new Claim("sub", "level2-actor"));
                level2Actor.AddClaim(new Claim("name", "Level 2 Actor"));
                level2Actor.Actor = level3Actor; // This will cause exception due to MaxActorChainLength=2

                var level1Actor = new CaseSensitiveClaimsIdentity("Level1Auth");
                level1Actor.AddClaim(new Claim("sub", "level1-actor"));
                level1Actor.AddClaim(new Claim("name", "Level 1 Actor"));
                level1Actor.Actor = level2Actor;

                // Create the main identity
                var mainIdentity = new CaseSensitiveClaimsIdentity("Bearer");
                mainIdentity.AddClaim(new Claim("sub", "main-subject-id"));
                mainIdentity.AddClaim(new Claim("name", "Main User"));
                mainIdentity.Actor = level1Actor;

                // Create token descriptor
                var tokenDescriptor = new SecurityTokenDescriptor
                {
                    Subject = mainIdentity,
                    Issuer = "https://example.com",
                    Audience = "https://api.example.com",
                    SigningCredentials = Default.AsymmetricSigningCredentials,
                    ActorClaimName = "act",
                    MaxActorChainLength = 2
                };

                // Act - This should throw a SecurityTokenException
                var token = handler.CreateToken(tokenDescriptor);
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
            }
            catch (Exception ex)
            {
                // Unexpected exception type
                context.Diffs.Add($"Unexpected exception type: {ex.GetType()}, Message: {ex.Message}");
            }
            finally
            {
                AppContext.SetSwitch(AppContextSwitches.EnableActClaimSupportSwitch, false);
            }

        }

        [Fact]
        public void NestedClaimsDictionaryActorTokens_ExceedingMaxDepth_ThrowsException()
        {
            var context = new CompareContext($"{this}.NestedClaimsDictionaryActorTokens_ExceedingMaxDepth_ThrowsException");
            bool switchValue = false;
            AppContext.TryGetSwitch(AppContextSwitches.EnableActClaimSupportSwitch, out switchValue);
            AppContext.SetSwitch(AppContextSwitches.EnableActClaimSupportSwitch, true);
            try
            {
                // Arrange
                var handler = new JsonWebTokenHandler();
                string actorname = "act";
                // Create nested actor identities
                var nestedActorIdentity = new CaseSensitiveClaimsIdentity("NestedActorAuth");
                nestedActorIdentity.AddClaim(new Claim("sub", "nested-actor-id"));
                nestedActorIdentity.AddClaim(new Claim("name", "Nested Actor"));

                // Create actor identity with nested actor
                var actorIdentity = new CaseSensitiveClaimsIdentity("ActorAuth");
                actorIdentity.AddClaim(new Claim("sub", "actor-subject-id"));
                actorIdentity.AddClaim(new Claim("name", "Actor Name"));
                actorIdentity.Actor = nestedActorIdentity; // This should be ignored due to MaxActorChainLength

                // Create the main identity
                var mainIdentity = new CaseSensitiveClaimsIdentity("Bearer");
                mainIdentity.AddClaim(new Claim("sub", "main-subject-id"));
                mainIdentity.AddClaim(new Claim("name", "Main User"));

                // Create token with actor in Claims dictionary
                var tokenDescriptor = new SecurityTokenDescriptor
                {
                    Subject = mainIdentity,
                    Issuer = "https://example.com",
                    Audience = "https://api.example.com",
                    SigningCredentials = Default.AsymmetricSigningCredentials,
                    Claims = new Dictionary<string, object>
                    {
                        { actorname, actorIdentity }
                    },
                    ActorClaimName = actorname,
                    MaxActorChainLength = 1
                };

                // Act
                var token = handler.CreateToken(tokenDescriptor);
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
            }
            catch (Exception ex)
            {
                // Unexpected exception type
                context.Diffs.Add($"Unexpected exception type: {ex.GetType()}, Message: {ex.Message}");
            }
            finally
            {
                AppContext.SetSwitch(AppContextSwitches.EnableActClaimSupportSwitch, false);
            }
        }
        [ResetAppContextSwitches]
        [Fact]
        public void ActorTokens_MixedSourceRespectMaxActorChainLength()
        {
            AppContext.SetSwitch(AppContextSwitches.EnableActClaimSupportSwitch, true);
            try
            {
                // Arrange
                var handler = new JsonWebTokenHandler();
                string actorname = "act";
                // Create level 2 actor (will be in claims dictionary)
                var level2Actor = new CaseSensitiveClaimsIdentity("Level2Auth");
                level2Actor.AddClaim(new Claim("sub", "level2-actor"));
                level2Actor.AddClaim(new Claim("name", "Level 2 Actor"));

                // Create nested actors that should be truncated
                var level3Actor = new CaseSensitiveClaimsIdentity("Level3Auth");
                level3Actor.AddClaim(new Claim("sub", "level3-actor"));
                level3Actor.AddClaim(new Claim("name", "Level 3 Actor"));

                // Create level 1 actor with nested actor
                var level1Actor = new CaseSensitiveClaimsIdentity("Level1Auth");
                level1Actor.AddClaim(new Claim("sub", "level1-actor"));
                level1Actor.AddClaim(new Claim("name", "Level 1 Actor"));
                level1Actor.Actor = level3Actor; // This should be ignored due to MaxActorChainLength

                // Create the main identity
                var mainIdentity = new CaseSensitiveClaimsIdentity("Bearer");
                mainIdentity.AddClaim(new Claim("sub", "main-subject-id"));
                mainIdentity.AddClaim(new Claim("name", "Main User"));
                mainIdentity.Actor = level1Actor;

                // Create a token with additional actor in Claims dictionary
                var tokenDescriptor = new SecurityTokenDescriptor
                {
                    Subject = mainIdentity,
                    Issuer = "https://example.com",
                    Audience = "https://api.example.com",
                    SigningCredentials = Default.AsymmetricSigningCredentials,
                    // Add level 2 actor in claims dictionary to replace level 1's actor
                    Claims = new Dictionary<string, object>
                    {
                        { actorname, level2Actor }
                    },
                    ActorClaimName = actorname,
                    MaxActorChainLength = 1
                };

                var token = handler.CreateToken(tokenDescriptor);
                var jwtToken = handler.ReadJsonWebToken(token);

                // Assert - Check actor object structure
                Assert.True(jwtToken.Payload.HasClaim(actorname), "JWT token should contain 'act' claim");
                var actorObject = jwtToken.Payload.GetValue<JsonElement>(tokenDescriptor.ActorClaimName);

                Assert.Equal(JsonValueKind.Object, actorObject.ValueKind);

                // Verify we get the actor from Claims dictionary (should be level2Actor)
                Assert.Equal("level2-actor", actorObject.GetProperty("sub").GetString());
                Assert.Equal("Level 2 Actor", actorObject.GetProperty("name").GetString());

                // There should be no nested actor because we're already at max depth
                Assert.False(actorObject.TryGetProperty("act", out _), "There should be no nested actor claim due to MaxActorChainLength");
            }
            finally
            {
                AppContext.SetSwitch(AppContextSwitches.EnableActClaimSupportSwitch, false);
            }
        }
        [ResetAppContextSwitches]
        [Fact]
        public void NestedClaimTokens_ExceedingMaxDepth_ThrowsException()
        {
            var context = new CompareContext($"{this}.NestedActorTokens_ExceedingMaxDepth_ThrowsException");
            bool switchValue = false;
            AppContext.TryGetSwitch(AppContextSwitches.EnableActClaimSupportSwitch, out switchValue);
            var actorname = "act";
            try
            {
                // Arrange
                var handler = new JsonWebTokenHandler();

                // Create nested actor identities (3 levels, but we'll set MaxActorChainLength to 2)
                var level3Actor = new CaseSensitiveClaimsIdentity("Level3Auth");
                level3Actor.AddClaim(new Claim("sub", "level3-actor"));
                level3Actor.AddClaim(new Claim("name", "Level 3 Actor"));

                var level2Actor = new CaseSensitiveClaimsIdentity("Level2Auth");
                level2Actor.AddClaim(new Claim("sub", "level2-actor"));
                level2Actor.AddClaim(new Claim("name", "Level 2 Actor"));
                level2Actor.Actor = level3Actor; // This will cause exception due to MaxActorChainLength=2

                var level1Actor = new CaseSensitiveClaimsIdentity("Level1Auth");
                level1Actor.AddClaim(new Claim("sub", "level1-actor"));
                level1Actor.AddClaim(new Claim("name", "Level 1 Actor"));
                level1Actor.Actor = level2Actor;

                // Create the main identity
                var mainIdentity = new CaseSensitiveClaimsIdentity("Bearer");
                mainIdentity.AddClaim(new Claim("sub", "main-subject-id"));
                mainIdentity.AddClaim(new Claim("name", "Main User"));
                // Create token descriptor
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
                    ActorClaimName = actorname,
                    MaxActorChainLength = 1
                };
                AppContext.SetSwitch(AppContextSwitches.EnableActClaimSupportSwitch, true);

                // Act - This should throw a SecurityTokenException
                var token = handler.CreateToken(tokenDescriptor);
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
            }
            catch (Exception ex)
            {
                // Unexpected exception type
                context.Diffs.Add($"Unexpected exception type: {ex.GetType()}, Message: {ex.Message}");
            }
            finally
            {
                AppContext.SetSwitch(AppContextSwitches.EnableActClaimSupportSwitch, false);
            }
        }
    }
}
