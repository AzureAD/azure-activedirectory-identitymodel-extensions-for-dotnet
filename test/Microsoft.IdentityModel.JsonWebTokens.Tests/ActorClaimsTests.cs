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
using System.Linq;
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
                    ActorClaimName = "act"
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
                    ActorClaimName = "act"
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
                    ActorClaimName = "act",
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
                    ActorClaimName = "act",
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
                    ActorClaimName = "act"
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
                    ActorClaimName = "act"
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
                    ActorClaimName = "act"
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
                    ActorClaimName = "actort"  // Custom actor claim name
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
        public void DifferentIssuerShouldBeAppliedToAllClaims()
        {
            var context = new CompareContext($"{this}.DifferentIssuerShouldBeAppliedToAllClaims");
            bool switchValue = false;
            AppContext.TryGetSwitch(AppContextSwitches.EnableActClaimSupportSwitch, out switchValue);
            AppContext.SetSwitch(AppContextSwitches.EnableActClaimSupportSwitch, true);
            try
            {
                // Create simple actor JSON
                string actorJson = @"{
                    ""sub"": ""actor-subject-id"",
                    ""name"": ""Actor Name""
                }";

                var jsonElement = JsonDocument.Parse(actorJson).RootElement;
                var tokenValidationParameters = new TokenValidationParameters
                {
                    ActorClaimName = "act"
                };

                string customIssuer = "https://custom-issuer.example.com";

                // Create ClaimsIdentity with custom issuer
                var identity = JsonWebTokenHandler.CreateActorClaimsIdentityFromJsonElement(
                    jsonElement,
                    tokenValidationParameters,
                    customIssuer);

                // Verify all claims have custom issuer
                foreach (var claim in identity.Claims)
                {
                    Assert.Equal(customIssuer, claim.Issuer);
                    Assert.Equal(customIssuer, claim.OriginalIssuer);
                }

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
        public void CustomAuthenticationTypeShouldBeRespected()
        {
            var context = new CompareContext($"{this}.CustomAuthenticationTypeShouldBeRespected");
            bool switchValue = false;
            AppContext.TryGetSwitch(AppContextSwitches.EnableActClaimSupportSwitch, out switchValue);
            AppContext.SetSwitch(AppContextSwitches.EnableActClaimSupportSwitch, true);
            try
            {
                // Create simple actor JSON
                string actorJson = @"{
                    ""sub"": ""actor-subject-id"",
                    ""name"": ""Actor Name""
                }";

                var jsonElement = JsonDocument.Parse(actorJson).RootElement;
                var tokenValidationParameters = new TokenValidationParameters
                {
                    ActorClaimName = "act"
                };

                string customAuthType = "CustomActorAuth";

                // Create ClaimsIdentity with custom auth type
                var identity = JsonWebTokenHandler.CreateActorClaimsIdentityFromJsonElement(
                    jsonElement,
                    tokenValidationParameters,
                    null);

                // Verify custom auth type was applied
                Assert.Equal(customAuthType, identity.AuthenticationType);

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
                    ActorClaimName = "act",
                    MaxActorChainLength = 5,
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
        public void WhenActClaimIsNotAnObject_ShouldBeAddedAsRegularClaim()
        {
            var context = new CompareContext($"{this}.WhenActClaimIsNotAnObject_ShouldBeAddedAsRegularClaim");
            bool switchValue = false;
            AppContext.TryGetSwitch(AppContextSwitches.EnableActClaimSupportSwitch, out switchValue);
            AppContext.SetSwitch(AppContextSwitches.EnableActClaimSupportSwitch, true);
            try
            {
                // Create JSON with "act" claim that is a string, not an object
                string actorJson = @"{
                    ""sub"": ""actor-subject-id"",
                    ""name"": ""Actor Name"",
                    ""act"": ""some-actor-reference-string""
                }";

                var jsonElement = JsonDocument.Parse(actorJson).RootElement;
                var tokenValidationParameters = new TokenValidationParameters
                {
                    ActorClaimName = "act"
                };

                // Create ClaimsIdentity from JsonElement
                var identity = JsonWebTokenHandler.CreateActorClaimsIdentityFromJsonElement(
                    jsonElement,
                    tokenValidationParameters);

                // Verify identity claims
                Assert.NotNull(identity);
                Assert.Equal("actor-subject-id", identity.Claims.First(c => c.Type == "sub").Value);
                Assert.Equal("Actor Name", identity.Claims.First(c => c.Type == "name").Value);

                // Verify "act" is a regular claim, not a nested actor
                Assert.Null(identity.Actor);
                Assert.Equal("some-actor-reference-string", identity.Claims.First(c => c.Type == "act").Value);

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
                    ActorClaimName = "act",
                    MaxActorChainLength = 5
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
                    ActorClaimName = "act",
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
            ClaimsIdentity CustomDelegate(JsonElement element)
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
                    ActorClaimName = "act",
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
                    ActorClaimName = "act",
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
                    ActorClaimName = "act",
                    MaxActorChainLength = 2
                };
                handler.MapInboundClaims = true;
                var result = await handler.ValidateTokenAsync(token, validationParameters);
                foreach (Claim claim in result.ClaimsIdentity.Claims)
                {
                    Console.WriteLine($"Claim Type: {claim.Type}, Value: {claim.Value}");
                }
                Assert.False(result.IsValid);
                Assert.NotNull(result.Exception);
                Assert.Contains("IDX14313", result.Exception.ToString());

                TestUtilities.AssertFailIfErrors(context);
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Exception: {ex}");
            }
            finally
            {
                AppContext.SetSwitch(AppContextSwitches.EnableActClaimSupportSwitch, false);
            }
        }

        [ResetAppContextSwitches]
        [Fact]
        public async Task ValidateTokenAsync_NestingBeyondMaxActorChain_CustomDelegate_ThrowsException()
        {
            var context = new CompareContext($"{this}.ValidateTokenAsync_NestingBeyondMaxActorChain_CustomDelegate_ThrowsException");
            AppContext.SetSwitch(AppContextSwitches.EnableActClaimSupportSwitch, true);

            ClaimsIdentity CustomDelegate(JsonElement element)
            {
                var id = new CaseSensitiveClaimsIdentity("CustomActorAuth");
                if (element.TryGetProperty("sub", out var sub))
                    id.AddClaim(new Claim("sub", sub.GetString()));
                if (element.TryGetProperty("act", out var nested) && nested.ValueKind == System.Text.Json.JsonValueKind.Object)
                    id.Actor = CustomDelegate(nested);
                return id;
            }

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
                    ActorClaimName = "act",
                    MaxActorChainLength = 2,
                    //ActClaimRetrieverDelegate = CustomDelegate
                };

                var result = await handler.ValidateTokenAsync(token, validationParameters);
                Assert.NotNull(result.ClaimsIdentity.Actor);
                TestUtilities.AssertFailIfErrors(context);
            }
            catch (Exception ex)
            {
                Assert.Contains("IDX14313", ex.ToString()); ;
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

            ClaimsIdentity CustomDelegate(JsonElement element)
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
                    ActorClaimName = "act",
                    MaxActorChainLength = 2,
                    ActClaimRetrieverDelegate = CustomDelegate
                };

                var result = await handler.ValidateTokenAsync(token, validationParameters);
                Assert.Null(result.ClaimsIdentity.Actor);
                TestUtilities.AssertFailIfErrors(context);
            }
            catch (Exception ex)
            {
                Assert.Contains("IDX14313", ex.ToString()); ;
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

            ClaimsIdentity CustomDelegate(JsonElement element)
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
                    ActorClaimName = "act"
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
