// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System;
using System.Collections.Generic;
using System.Security.Claims;
using Microsoft.IdentityModel.TestUtils;
using Microsoft.IdentityModel.Tokens;
using Microsoft.IdentityModel.JsonWebTokens;
using Xunit;
using System.Threading.Tasks;

namespace Microsoft.IdentityModel.Tests
{
    public class ActorClaimsTests
    {
        [Fact]
        public void ActorTokenInClaimsDictionaryShouldBeProperlySerialized()
        {
            var context = new CompareContext($"{this}.ActorTokenInClaimsDictionaryShouldBeProperlySerialized");
            bool switchValue = false;
            AppContext.TryGetSwitch(AppContextSwitches.SerializeDeserializeActorClaimSwitch, out switchValue);
            AppContext.SetSwitch(AppContextSwitches.SerializeDeserializeActorClaimSwitch, true);
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
                        { "act", actorIdentity }
                    }
                };
                var token = tokenHandler.CreateToken(tokenDescriptor);
                JsonWebToken decodedToken = tokenHandler.ReadJsonWebToken(token);

                // Verify actor claim exists in the token
                Assert.True(decodedToken.Payload.HasClaim(tokenDescriptor.ActorClaimName), "JWT token should contain 'actort' claim");
                // Get the actor token and verify it contains the expected claims
                var actorTokenString = decodedToken.Actor;
                Assert.NotNull(actorTokenString);

                JsonWebToken actorJwt = tokenHandler.ReadJsonWebToken(actorTokenString);
                Assert.Equal("actor-subject-id", actorJwt.Payload.GetValue<string>("sub"));
                Assert.Equal("Actor Name", actorJwt.Payload.GetValue<string>("name"));
                Assert.Equal("admin", actorJwt.Payload.GetValue<string>("role"));
                TestUtilities.AssertFailIfErrors(context);
            }
            catch (Exception ex)
            {
                context.Diffs.Add($"Exception: {ex}");
            }
            finally
            {
                AppContext.SetSwitch(AppContextSwitches.SerializeDeserializeActorClaimSwitch, false);
            }
        }

        [Fact]
        public void ActorTokenAsSubjectShouldBeProperlySerialized()
        {
            var context = new CompareContext($"{this}.ActorTokenAsSubjectShouldBeProperlySerialized");
            bool switchValue = false;
            AppContext.TryGetSwitch(AppContextSwitches.SerializeDeserializeActorClaimSwitch, out switchValue);
            AppContext.SetSwitch(AppContextSwitches.SerializeDeserializeActorClaimSwitch, true);
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
                Assert.True(decodedToken.Payload.HasClaim("act"), "JWT token should contain 'act' claim");

                // Get the actor token and verify it contains the expected claims
                var actorTokenString = decodedToken.Actor;
                Assert.NotNull(actorTokenString);

                JsonWebToken actorJwt = tokenHandler.ReadJsonWebToken(actorTokenString);
                Assert.Equal("actor-subject-id", actorJwt.Payload.GetValue<string>("sub"));
                Assert.Equal("Actor Name", actorJwt.Payload.GetValue<string>("name"));
                Assert.Equal("admin", actorJwt.Payload.GetValue<string>("role"));
                TestUtilities.AssertFailIfErrors(context);
            }
            catch (Exception ex)
            {
                context.Diffs.Add($"Exception: {ex}");
            }
            finally
            {
                AppContext.SetSwitch(AppContextSwitches.SerializeDeserializeActorClaimSwitch, false);
            }
        }

        [Fact]
        public void ActorTokenInBothClaimsAndSubjectShouldPreferClaimsValue()
        {
            var context = new CompareContext($"{this}.ActorTokenInBothClaimsAndSubjectShouldPreferClaimsValue");
            bool switchValue = false;
            AppContext.TryGetSwitch(AppContextSwitches.SerializeDeserializeActorClaimSwitch, out switchValue);
            AppContext.SetSwitch(AppContextSwitches.SerializeDeserializeActorClaimSwitch, true);
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
                        { "act", claimsActorIdentity }
                    }
                };
                var token = tokenHandler.CreateToken(tokenDescriptor);
                JsonWebToken decodedToken = tokenHandler.ReadJsonWebToken(token);

                // Verify actor claim exists
                Assert.True(decodedToken.Payload.HasClaim("act"), "JWT token should contain 'actort' claim");

                // Get the actor token and verify it contains the expected claims
                var actorTokenString = decodedToken.Actor;
                Assert.NotNull(actorTokenString);

                JsonWebToken actorJwt = tokenHandler.ReadJsonWebToken(actorTokenString);

                // Verify the Claims dictionary actor was used, not the Subject.Actor
                Assert.Equal("claims-actor-id", actorJwt.Payload.GetValue<string>("sub"));
                Assert.Equal("Claims Actor", actorJwt.Payload.GetValue<string>("name"));
                Assert.NotEqual("subject-actor-id", actorJwt.Payload.GetValue<string>("sub"));
                TestUtilities.AssertFailIfErrors(context);
            }
            catch (Exception ex)
            {
                context.Diffs.Add($"Exception: {ex}");
            }
            finally
            {
                AppContext.SetSwitch(AppContextSwitches.SerializeDeserializeActorClaimSwitch, false);
            }
        }

        [Fact]
        public void NestedActorTokenInClaimsDictionaryShouldBeProperlySerialized()
        {
            var context = new CompareContext($"{this}.NestedActorTokenInClaimsDictionaryShouldBeProperlySerialized");
            bool switchValue = false;
            AppContext.TryGetSwitch(AppContextSwitches.SerializeDeserializeActorClaimSwitch, out switchValue);
            AppContext.SetSwitch(AppContextSwitches.SerializeDeserializeActorClaimSwitch, true);
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

                // Read the main actor token
                var actorTokenString = decodedToken.Actor;
                Assert.NotNull(actorTokenString);
                JsonWebToken actorJwt = tokenHandler.ReadJsonWebToken(actorTokenString);

                // Verify main actor claims
                Assert.Equal("actor-subject-id", actorJwt.Payload.GetValue<string>("sub"));
                Assert.Equal("Actor Name", actorJwt.Payload.GetValue<string>("name"));

                // Verify nested actor exists
                Assert.True(actorJwt.Payload.HasClaim("act"), "Actor token should contain nested 'actort' claim");

                // Read the nested actor token
                var nestedActorTokenString = actorJwt.Actor;
                Assert.NotNull(nestedActorTokenString);
                JsonWebToken nestedActorJwt = tokenHandler.ReadJsonWebToken(nestedActorTokenString);

                // Verify nested actor claims
                Assert.Equal("nested-actor-id", nestedActorJwt.Payload.GetValue<string>("sub"));
                Assert.Equal("Nested Actor", nestedActorJwt.Payload.GetValue<string>("name"));
                TestUtilities.AssertFailIfErrors(context);
            }
            catch (Exception ex)
            {
                context.Diffs.Add($"Exception: {ex}");
            }
            finally
            {
                AppContext.SetSwitch(AppContextSwitches.SerializeDeserializeActorClaimSwitch, false);
            }
        }

        [Fact]
        public void NestedActorTokenAsSubjectShouldBeProperlySerialized()
        {
            var context = new CompareContext($"{this}.NestedActorTokenAsSubjectShouldBeProperlySerialized");
            bool switchValue = false;
            AppContext.TryGetSwitch(AppContextSwitches.SerializeDeserializeActorClaimSwitch, out switchValue);
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
                };
                AppContext.SetSwitch(AppContextSwitches.SerializeDeserializeActorClaimSwitch, true);
                var token = tokenHandler.CreateToken(tokenDescriptor);
                JsonWebToken decodedToken = tokenHandler.ReadJsonWebToken(token);

                // Verify actor claim exists
                Assert.True(decodedToken.Payload.HasClaim("act"), "JWT token should contain 'actort' claim");

                // Read the main actor token
                var actorTokenString = decodedToken.Actor;
                Assert.NotNull(actorTokenString);
                JsonWebToken actorJwt = tokenHandler.ReadJsonWebToken(actorTokenString);

                // Verify main actor claims
                Assert.Equal("actor-subject-id", actorJwt.Payload.GetValue<string>("sub"));
                Assert.Equal("Actor Name", actorJwt.Payload.GetValue<string>("name"));

                // Verify nested actor exists
                Assert.True(actorJwt.Payload.HasClaim("act"), "Actor token should contain nested 'actort' claim");

                // Read the nested actor token
                var nestedActorTokenString = actorJwt.Actor;
                Assert.NotNull(nestedActorTokenString);
                JsonWebToken nestedActorJwt = tokenHandler.ReadJsonWebToken(nestedActorTokenString);

                // Verify nested actor claims
                Assert.Equal("nested-actor-id", nestedActorJwt.Payload.GetValue<string>("sub"));
                Assert.Equal("Nested Actor", nestedActorJwt.Payload.GetValue<string>("name"));
                TestUtilities.AssertFailIfErrors(context);
            }
            catch (Exception ex)
            {
                context.Diffs.Add($"Exception: {ex}");
            }
            finally
            {
                AppContext.SetSwitch(AppContextSwitches.SerializeDeserializeActorClaimSwitch, false);
            }
        }
        [ResetAppContextSwitches]
        [Fact]
        public void MaxActorChainLength_RejectsNegativeValues()
        {
            bool switchValue = false;
            AppContext.TryGetSwitch(AppContextSwitches.SerializeDeserializeActorClaimSwitch, out switchValue);

            // Arrange
            SecurityTokenDescriptor tokenDescriptor = new SecurityTokenDescriptor
            {
                Subject = null,
                Issuer = "https://example.com",
                Audience = "https://api.example.com",
                SigningCredentials = Default.AsymmetricSigningCredentials
            };
            AppContext.SetSwitch(AppContextSwitches.SerializeDeserializeActorClaimSwitch, true);
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
                AppContext.SetSwitch(AppContextSwitches.SerializeDeserializeActorClaimSwitch, false);
            }
        }

        [Fact]
        public void NestedSubjectActorTokens_ExceedingMaxDepth_ThrowsException()
        {
            var context = new CompareContext($"{this}.NestedActorTokens_ExceedingMaxDepth_ThrowsException");
            bool switchValue = false;
            AppContext.TryGetSwitch(AppContextSwitches.SerializeDeserializeActorClaimSwitch, out switchValue);
            AppContext.SetSwitch(AppContextSwitches.SerializeDeserializeActorClaimSwitch, true);
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
                AppContext.SetSwitch(AppContextSwitches.SerializeDeserializeActorClaimSwitch, false);
            }

        }

        [Fact]
        public void NestedClaimsDictionaryActorTokens_ExceedingMaxDepth_ThrowsException()
        {
            var context = new CompareContext($"{this}.NestedClaimsDictionaryActorTokens_ExceedingMaxDepth_ThrowsException");
            bool switchValue = false;
            AppContext.TryGetSwitch(AppContextSwitches.SerializeDeserializeActorClaimSwitch, out switchValue);
            AppContext.SetSwitch(AppContextSwitches.SerializeDeserializeActorClaimSwitch, true);
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
                AppContext.SetSwitch(AppContextSwitches.SerializeDeserializeActorClaimSwitch, false);
            }
        }
        [ResetAppContextSwitches]
        [Fact]
        public void ActorTokens_MixedSourceRespectMaxActorChainLength()
        {
            AppContext.SetSwitch(AppContextSwitches.SerializeDeserializeActorClaimSwitch, true);
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

                // Assert
                Assert.True(jwtToken.Payload.HasClaim(actorname), "JWT token should contain 'act' claim");

                // Verify we get the actor from Claims dictionary (should be level2Actor)
                var actorToken = handler.ReadJsonWebToken(jwtToken.Actor);
                Assert.Equal("level2-actor", actorToken.Payload.GetValue<string>("sub"));
                Assert.Equal("Level 2 Actor", actorToken.Payload.GetValue<string>("name"));

                // There should be no nested actor because we're already at max depth
                Assert.False(actorToken.Payload.HasClaim("actort"), "There should be no nested actor claim due to MaxActorChainLength");
            }
            finally
            {
                AppContext.SetSwitch(AppContextSwitches.SerializeDeserializeActorClaimSwitch, false);
            }
        }
        [Fact]
        public void NestedClaimTokens_ExceedingMaxDepth_ThrowsException()
        {
            var context = new CompareContext($"{this}.NestedActorTokens_ExceedingMaxDepth_ThrowsException");
            bool switchValue = false;
            AppContext.TryGetSwitch(AppContextSwitches.SerializeDeserializeActorClaimSwitch, out switchValue);
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
                AppContext.SetSwitch(AppContextSwitches.SerializeDeserializeActorClaimSwitch, true);

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
                AppContext.SetSwitch(AppContextSwitches.SerializeDeserializeActorClaimSwitch, false);
            }
        }

        [Fact]
        public async Task ValidateActorToken_WithMaxChainLength_ValidatesSuccessfully()
        {
            var context = new CompareContext($"{this}.ValidateActorToken_WithMaxChainLength_ValidatesSuccessfully");
            bool switchValue = false;
            AppContext.TryGetSwitch(AppContextSwitches.SerializeDeserializeActorClaimSwitch, out switchValue);
            AppContext.SetSwitch(AppContextSwitches.SerializeDeserializeActorClaimSwitch, true);
            try
            {
                // Create a token with nested actors
                var handler = new JsonWebTokenHandler();
                string actorname = "actortoken";
                // Create level 3 actor (innermost)
                var level3Actor = new CaseSensitiveClaimsIdentity("Level3Auth");
                level3Actor.AddClaim(new Claim("sub", "level3-actor"));
                level3Actor.AddClaim(new Claim("name", "Level 3 Actor"));
                level3Actor.AddClaim(new Claim("exp", EpochTime.GetIntDate(DateTime.UtcNow.AddHours(1)).ToString()));


                // Create level 2 actor with level 3 as its actor
                var level2Actor = new CaseSensitiveClaimsIdentity("Level2Auth");
                level2Actor.AddClaim(new Claim("sub", "level2-actor"));
                level2Actor.AddClaim(new Claim("name", "Level 2 Actor"));
                level2Actor.Actor = level3Actor;
                level2Actor.AddClaim(new Claim("exp", EpochTime.GetIntDate(DateTime.UtcNow.AddHours(1)).ToString()));

                // Create level 1 actor with level 2 as its actor
                var level1Actor = new CaseSensitiveClaimsIdentity("Level1Auth");
                level1Actor.AddClaim(new Claim("sub", "level1-actor"));
                level1Actor.AddClaim(new Claim("name", "Level 1 Actor"));
                level1Actor.Actor = level2Actor;
                level1Actor.AddClaim(new Claim("exp", EpochTime.GetIntDate(DateTime.UtcNow.AddHours(1)).ToString()));

                // Create main identity with level 1 as its actor
                var mainIdentity = new CaseSensitiveClaimsIdentity("Bearer");
                mainIdentity.AddClaim(new Claim("sub", "main-subject-id"));
                mainIdentity.AddClaim(new Claim("name", "Main User"));
                mainIdentity.Actor = level1Actor;

                // Define audience
                string audience = "https://api.example.com";
                string issuer = "https://example.com";

                // Create token with actor chain
                var tokenDescriptor = new SecurityTokenDescriptor
                {
                    Subject = mainIdentity,
                    Issuer = issuer,
                    Audience = audience,
                    SigningCredentials = Default.AsymmetricSigningCredentials,
                    ActorClaimName = actorname,
                    MaxActorChainLength = 3
                };
                var token = handler.CreateToken(tokenDescriptor);

                // Configure validation parameters
                var validationParameters = Default.AsymmetricSignTokenValidationParameters;
                validationParameters.ValidIssuer = issuer;
                validationParameters.ValidAudience = audience;
                validationParameters.ValidateActor = true;
                validationParameters.MaxActorChainLength = 3;
                validationParameters.ActorClaimName = actorname;
                validationParameters.ActorValidationParameters = validationParameters.Clone();

                // Create actor validation parameters
                var actorValidationParameters = validationParameters.Clone();
                actorValidationParameters.RequireSignedTokens = false;
                actorValidationParameters.ValidateLifetime = false;
                actorValidationParameters.ValidateAudience = false;
                actorValidationParameters.ValidateIssuer = false;

                validationParameters.ActorValidationParameters = actorValidationParameters;
                // Validate token
                var result = await handler.ValidateTokenAsync(token, validationParameters);
                if (!result.IsValid)
                {
                    Console.WriteLine($"Validation failed: {result.Exception?.Message}");
                }
                Assert.True(result.IsValid, "Token should be valid");

                // Get the main JsonWebToken from the result
                var mainToken = result.SecurityToken as JsonWebToken;
                Assert.NotNull(mainToken);
                Assert.Equal("main-subject-id", mainToken.Subject);
                Console.WriteLine($"Main User Subject: {mainToken.Subject}");

                // Follow and verify actor chain using JsonWebToken.Actor and ReadJsonWebToken
                var currentToken = mainToken;
                var actorLevels = new[] { "level1-actor", "level2-actor", "level3-actor" };

                for (int i = 0; i < actorLevels.Length; i++)
                {
                    // Get actor JWT string and convert it to JsonWebToken
                    var actorTokenString = currentToken.Actor;
                    Assert.False(string.IsNullOrEmpty(actorTokenString), $"Actor token at level {i} should not be null or empty");
                    Console.WriteLine($"Here is the token for {i} iteration : {actorTokenString}");
                    // Parse the actor token string into a JsonWebToken
                    var actorToken = handler.ReadJsonWebToken(actorTokenString);
                    Assert.NotNull(actorToken);
                    actorToken.ActorClaimName = actorname;
                    // Verify actor token claims
                    Assert.Equal(actorLevels[i], actorToken.Subject);
                    Assert.NotNull(actorToken.GetPayloadValue<string>("name"));
                    Console.WriteLine($"Actor {i + 1}: Subject={actorToken.Subject}, Name={actorToken.GetPayloadValue<string>("name")}");

                    // Move to next actor in the chain
                    currentToken = actorToken;
                }
                // Verify no more actors beyond max depth
                Assert.True(string.IsNullOrEmpty(currentToken.Actor), "There should be no more actors beyond the specified depth");
                TestUtilities.AssertFailIfErrors(context);
            }
            finally
            {
                AppContext.SetSwitch(AppContextSwitches.SerializeDeserializeActorClaimSwitch, false);
            }
        }
    }
}
