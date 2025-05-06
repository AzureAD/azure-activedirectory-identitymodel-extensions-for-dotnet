// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System;
using System.Collections.Generic;
using System.Security.Claims;
using Microsoft.IdentityModel.TestUtils;
using Microsoft.IdentityModel.Tokens;
using Microsoft.IdentityModel.JsonWebTokens;
using Xunit;

namespace Microsoft.IdentityModel.Tests
{
    public class ActorClaimsTests
    {
        [Fact]
        public void ActorTokenInClaimsDictionaryShouldBeProperlySerialized()
        {
            var context = new CompareContext($"{this}.ActorTokenInClaimsDictionaryShouldBeProperlySerialized");

            try
            {
                AppContext.SetSwitch(AppContextSwitches.UseClaimsIdentityTypeSwitch, true);
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
                        { JwtRegisteredClaimNames.Actort, actorIdentity }
                    }
                };

                var token = tokenHandler.CreateToken(tokenDescriptor);
                JsonWebToken decodedToken = tokenHandler.ReadJsonWebToken(token);

                // Verify actor claim exists in the token
                Assert.True(decodedToken.Payload.HasClaim("actort"), "JWT token should contain 'actort' claim");
                // Get the actor token and verify it contains the expected claims
                var actorTokenString = decodedToken.Actor;
                Assert.NotNull(actorTokenString);

                JsonWebToken actorJwt = tokenHandler.ReadJsonWebToken(actorTokenString);
                Assert.Equal("actor-subject-id", actorJwt.Payload.GetValue<string>("sub"));
                Assert.Equal("Actor Name", actorJwt.Payload.GetValue<string>("name"));
                Assert.Equal("admin", actorJwt.Payload.GetValue<string>("role"));
            }
            catch (Exception ex)
            {
                context.Diffs.Add($"Exception: {ex}");
            }

            TestUtilities.AssertFailIfErrors(context);
        }

        [Fact]
        public void ActorTokenAsSubjectShouldBeProperlySerialized()
        {
            var context = new CompareContext($"{this}.ActorTokenAsSubjectShouldBeProperlySerialized");

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
                Assert.True(decodedToken.Payload.HasClaim("actort"), "JWT token should contain 'actort' claim");

                // Get the actor token and verify it contains the expected claims
                var actorTokenString = decodedToken.Actor;
                Assert.NotNull(actorTokenString);

                JsonWebToken actorJwt = tokenHandler.ReadJsonWebToken(actorTokenString);
                Assert.Equal("actor-subject-id", actorJwt.Payload.GetValue<string>("sub"));
                Assert.Equal("Actor Name", actorJwt.Payload.GetValue<string>("name"));
                Assert.Equal("admin", actorJwt.Payload.GetValue<string>("role"));
            }
            catch (Exception ex)
            {
                context.Diffs.Add($"Exception: {ex}");
            }

            TestUtilities.AssertFailIfErrors(context);
        }

        [Fact]
        public void ActorTokenInBothClaimsAndSubjectShouldPreferClaimsValue()
        {
            var context = new CompareContext($"{this}.ActorTokenInBothClaimsAndSubjectShouldPreferClaimsValue");

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
                        { JwtRegisteredClaimNames.Actort, claimsActorIdentity }
                    }
                };

                var token = tokenHandler.CreateToken(tokenDescriptor);
                JsonWebToken decodedToken = tokenHandler.ReadJsonWebToken(token);

                // Verify actor claim exists
                Assert.True(decodedToken.Payload.HasClaim("actort"), "JWT token should contain 'actort' claim");

                // Get the actor token and verify it contains the expected claims
                var actorTokenString = decodedToken.Actor;
                Assert.NotNull(actorTokenString);

                JsonWebToken actorJwt = tokenHandler.ReadJsonWebToken(actorTokenString);

                // Verify the Claims dictionary actor was used, not the Subject.Actor
                Assert.Equal("claims-actor-id", actorJwt.Payload.GetValue<string>("sub"));
                Assert.Equal("Claims Actor", actorJwt.Payload.GetValue<string>("name"));
                Assert.NotEqual("subject-actor-id", actorJwt.Payload.GetValue<string>("sub"));
            }
            catch (Exception ex)
            {
                context.Diffs.Add($"Exception: {ex}");
            }

            TestUtilities.AssertFailIfErrors(context);
        }

        [Fact]
        public void NestedActorTokenInClaimsDictionaryShouldBeProperlySerialized()
        {
            var context = new CompareContext($"{this}.NestedActorTokenInClaimsDictionaryShouldBeProperlySerialized");

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
                        { JwtRegisteredClaimNames.Actort, actorIdentity }
                    }
                };

                var token = tokenHandler.CreateToken(tokenDescriptor);
                JsonWebToken decodedToken = tokenHandler.ReadJsonWebToken(token);

                // Verify actor claim exists
                Assert.True(decodedToken.Payload.HasClaim("actort"), "JWT token should contain 'actort' claim");

                // Read the main actor token
                var actorTokenString = decodedToken.Actor;
                Assert.NotNull(actorTokenString);
                JsonWebToken actorJwt = tokenHandler.ReadJsonWebToken(actorTokenString);

                // Verify main actor claims
                Assert.Equal("actor-subject-id", actorJwt.Payload.GetValue<string>("sub"));
                Assert.Equal("Actor Name", actorJwt.Payload.GetValue<string>("name"));

                // Verify nested actor exists
                Assert.True(actorJwt.Payload.HasClaim("actort"), "Actor token should contain nested 'actort' claim");

                // Read the nested actor token
                var nestedActorTokenString = actorJwt.Actor;
                Assert.NotNull(nestedActorTokenString);
                JsonWebToken nestedActorJwt = tokenHandler.ReadJsonWebToken(nestedActorTokenString);

                // Verify nested actor claims
                Assert.Equal("nested-actor-id", nestedActorJwt.Payload.GetValue<string>("sub"));
                Assert.Equal("Nested Actor", nestedActorJwt.Payload.GetValue<string>("name"));
            }
            catch (Exception ex)
            {
                context.Diffs.Add($"Exception: {ex}");
            }

            TestUtilities.AssertFailIfErrors(context);
        }

        [Fact]
        public void NestedActorTokenAsSubjectShouldBeProperlySerialized()
        {
            var context = new CompareContext($"{this}.NestedActorTokenAsSubjectShouldBeProperlySerialized");

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
                    SigningCredentials = Default.AsymmetricSigningCredentials
                };

                var token = tokenHandler.CreateToken(tokenDescriptor);
                JsonWebToken decodedToken = tokenHandler.ReadJsonWebToken(token);

                // Verify actor claim exists
                Assert.True(decodedToken.Payload.HasClaim("actort"), "JWT token should contain 'actort' claim");

                // Read the main actor token
                var actorTokenString = decodedToken.Actor;
                Assert.NotNull(actorTokenString);
                JsonWebToken actorJwt = tokenHandler.ReadJsonWebToken(actorTokenString);

                // Verify main actor claims
                Assert.Equal("actor-subject-id", actorJwt.Payload.GetValue<string>("sub"));
                Assert.Equal("Actor Name", actorJwt.Payload.GetValue<string>("name"));

                // Verify nested actor exists
                Assert.True(actorJwt.Payload.HasClaim("actort"), "Actor token should contain nested 'actort' claim");

                // Read the nested actor token
                var nestedActorTokenString = actorJwt.Actor;
                Assert.NotNull(nestedActorTokenString);
                JsonWebToken nestedActorJwt = tokenHandler.ReadJsonWebToken(nestedActorTokenString);

                // Verify nested actor claims
                Assert.Equal("nested-actor-id", nestedActorJwt.Payload.GetValue<string>("sub"));
                Assert.Equal("Nested Actor", nestedActorJwt.Payload.GetValue<string>("name"));
            }
            catch (Exception ex)
            {
                context.Diffs.Add($"Exception: {ex}");
            }

            TestUtilities.AssertFailIfErrors(context);
        }
        [Fact]
        public void MaxActorChainLength_DefaultValue_Is5()
        {
            // Arrange
            var handler = new JsonWebTokenHandler();

            // Assert
            Assert.Equal(5, JsonWebTokenHandler.MaxActorChainLength);
        }

        [Fact]
        public void MaxActorChainLength_CanBeChanged()
        {
            // Arrange
            var handler = new JsonWebTokenHandler();

            // Act
            JsonWebTokenHandler.MaxActorChainLength = 10;

            // Assert
            Assert.Equal(10, JsonWebTokenHandler.MaxActorChainLength);
        }

        [Fact]
        public void NestedActorTokens_WithinMaxDepth_AreSerializedProperly()
        {
            // Arrange
            var handler = new JsonWebTokenHandler();
            JsonWebTokenHandler.MaxActorChainLength = 3; // Allow 3 levels of nesting

            // Create nested actor identities (3 levels)
            var level3Actor = new CaseSensitiveClaimsIdentity("Level3Auth");
            level3Actor.AddClaim(new Claim("sub", "level3-actor"));
            level3Actor.AddClaim(new Claim("name", "Level 3 Actor"));

            var level2Actor = new CaseSensitiveClaimsIdentity("Level2Auth");
            level2Actor.AddClaim(new Claim("sub", "level2-actor"));
            level2Actor.AddClaim(new Claim("name", "Level 2 Actor"));
            level2Actor.Actor = level3Actor;

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
                SigningCredentials = Default.AsymmetricSigningCredentials
            };

            // Act
            var token = handler.CreateToken(tokenDescriptor);
            var jwtToken = handler.ReadJsonWebToken(token);

            // Assert
            Assert.NotNull(jwtToken.Actor);

            // Check first level actor
            var level1Token = handler.ReadJsonWebToken(jwtToken.Actor);
            Assert.Equal("level1-actor", level1Token.Payload.GetValue<string>("sub"));
            Assert.Equal("Level 1 Actor", level1Token.Payload.GetValue<string>("name"));
            Assert.NotNull(level1Token.Actor);

            // Check second level actor
            var level2Token = handler.ReadJsonWebToken(level1Token.Actor);
            Assert.Equal("level2-actor", level2Token.Payload.GetValue<string>("sub"));
            Assert.Equal("Level 2 Actor", level2Token.Payload.GetValue<string>("name"));
            Assert.NotNull(level2Token.Actor);

            // Check third level actor
            var level3Token = handler.ReadJsonWebToken(level2Token.Actor);
            Assert.Equal("level3-actor", level3Token.Payload.GetValue<string>("sub"));
            Assert.Equal("Level 3 Actor", level3Token.Payload.GetValue<string>("name"));
            Assert.False(level3Token.Payload.HasClaim("actort"), "There should be no deeper actor at level 3");
        }

        [Fact]
        public void NestedActorTokens_ExceedingMaxDepth_ThrowsException()
        {
            var context = new CompareContext($"{this}.NestedActorTokens_ExceedingMaxDepth_ThrowsException");

            try
            {
                // Arrange
                var handler = new JsonWebTokenHandler();
                JsonWebTokenHandler.MaxActorChainLength = 2; // Allow only 2 levels of nesting

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
                    SigningCredentials = Default.AsymmetricSigningCredentials
                };

                // Act - This should throw a SecurityTokenException
                var token = handler.CreateToken(tokenDescriptor);
                context.Diffs.Add("Expected exception was not thrown.");
            }
            catch (SecurityTokenException ex)
            {
                // Assert - Verify the exception message contains the expected content
                if (ex.Message.Contains("IDX14313"))
                {
                    // Test passed - expected exception was thrown with the right message
                }
                else
                {
                    context.Diffs.Add($"Exception message does not contain expected content. Message: {ex.Message}");
                }
            }
            catch (Exception ex)
            {
                // Unexpected exception type
                context.Diffs.Add($"Unexpected exception type: {ex.GetType()}, Message: {ex.Message}");
            }

            TestUtilities.AssertFailIfErrors(context);
        }



        [Fact]
        public void NestedActorTokens_WithZeroMaxDepth_ThrowsException()
        {
            var context = new CompareContext($"{this}.NestedActorTokens_WithZeroMaxDepth_ThrowsException");

            try
            {
                // Arrange
                var handler = new JsonWebTokenHandler();
                JsonWebTokenHandler.MaxActorChainLength = 0; // Setting to 0 should now cause an exception

                // Create an actor identity
                var actorIdentity = new CaseSensitiveClaimsIdentity("ActorAuth");
                actorIdentity.AddClaim(new Claim("sub", "actor-subject-id"));
                actorIdentity.AddClaim(new Claim("name", "Actor Name"));

                // Create the main identity with Actor set
                var mainIdentity = new CaseSensitiveClaimsIdentity("Bearer");
                mainIdentity.AddClaim(new Claim("sub", "main-subject-id"));
                mainIdentity.AddClaim(new Claim("name", "Main User"));
                mainIdentity.Actor = actorIdentity;

                // Create token descriptor
                var tokenDescriptor = new SecurityTokenDescriptor
                {
                    Subject = mainIdentity,
                    Issuer = "https://example.com",
                    Audience = "https://api.example.com",
                    SigningCredentials = Default.AsymmetricSigningCredentials
                };

                // Act - This should throw a SecurityTokenException
                var token = handler.CreateToken(tokenDescriptor);
                context.Diffs.Add("Expected exception was not thrown.");
            }
            catch (SecurityTokenException ex)
            {
                Console.WriteLine("Here is the exception message: " + ex.Message);
                // Assert - Verify the exception message contains the expected content
                if (ex.Message.Contains("IDX14313"))
                {
                    // Test passed - expected exception was thrown with the right message
                }
                else
                {
                    context.Diffs.Add($"Exception message does not contain expected content. Message: {ex.Message}");
                }
            }
            catch (Exception ex)
            {
                // Unexpected exception type
                context.Diffs.Add($"Unexpected exception type: {ex.GetType()}, Message: {ex.Message}");
            }

            TestUtilities.AssertFailIfErrors(context);
        }

        [Fact]
        public void ActorTokenInClaimsDictionary_RespectsMaxActorChainLength()
        {
            // Arrange
            var handler = new JsonWebTokenHandler();
            JsonWebTokenHandler.MaxActorChainLength = 1; // Allow only 1 level of nesting

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
                    { JwtRegisteredClaimNames.Actort, actorIdentity }
                }
            };

            // Act
            var token = handler.CreateToken(tokenDescriptor);
            var jwtToken = handler.ReadJsonWebToken(token);

            // Assert
            Assert.True(jwtToken.Payload.HasClaim("actort"), "JWT token should contain 'actort' claim");

            // Read the actor token
            var actorToken = handler.ReadJsonWebToken(jwtToken.Actor);
            Assert.Equal("actor-subject-id", actorToken.Payload.GetValue<string>("sub"));
            Assert.Equal("Actor Name", actorToken.Payload.GetValue<string>("name"));

            // The nested actor should not be included because MaxActorChainLength is 1
            Assert.False(actorToken.Payload.HasClaim("actort"), "There should be no nested actor claim due to MaxActorChainLength");
        }

        [Fact]
        public void ActorTokens_MixedSourceRespectMaxActorChainLength()
        {
            // Arrange
            var handler = new JsonWebTokenHandler();
            JsonWebTokenHandler.MaxActorChainLength = 2; // Allow 2 levels of nesting

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
                { JwtRegisteredClaimNames.Actort, level2Actor }
            }
            };

            // Act
            var token = handler.CreateToken(tokenDescriptor);
            var jwtToken = handler.ReadJsonWebToken(token);

            // Assert
            Assert.True(jwtToken.Payload.HasClaim("actort"), "JWT token should contain 'actort' claim");

            // Verify we get the actor from Claims dictionary (should be level2Actor)
            var actorToken = handler.ReadJsonWebToken(jwtToken.Actor);
            Assert.Equal("level2-actor", actorToken.Payload.GetValue<string>("sub"));
            Assert.Equal("Level 2 Actor", actorToken.Payload.GetValue<string>("name"));

            // There should be no nested actor because we're already at max depth
            Assert.False(actorToken.Payload.HasClaim("actort"), "There should be no nested actor claim due to MaxActorChainLength");
        }

        [Fact]
        public void CreateToken_ExceedingMaxActorChainDepth_ThrowsException()
        {
            var context = new CompareContext($"{this}.CreateToken_ExceedingMaxActorChainDepth_ThrowsException");

            try
            {
                // Arrange
                var handler = new JsonWebTokenHandler();
                JsonWebTokenHandler.MaxActorChainLength = 2; // Set max depth to 2 for the test

                // Create nested actor identities (3 levels, exceeding max depth)
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

                // Create the main identity with Actor set
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
                    SigningCredentials = Default.AsymmetricSigningCredentials
                };

                // Act - This should throw a SecurityTokenException
                var token = handler.CreateToken(tokenDescriptor);
                context.Diffs.Add("Expected exception was not thrown.");
            }
            catch (SecurityTokenException ex)
            {
                // Assert - Verify the exception message contains the expected content
                if (ex.Message.Contains("Actor chain exceeded maximum depth of 2"))
                {
                    // Test passed - expected exception was thrown with the right message
                }
                else
                {
                    context.Diffs.Add($"Exception message does not contain expected content. Message: {ex.Message}");
                }
            }
            catch (Exception ex)
            {
                // Unexpected exception type
                context.Diffs.Add($"Unexpected exception type: {ex.GetType()}, Message: {ex.Message}");
            }

            TestUtilities.AssertFailIfErrors(context);
        }

        [Fact]
        public void CreateToken_WithClaimsActorChainExceedingMaxDepth_ThrowsException()
        {
            var context = new CompareContext($"{this}.CreateToken_WithClaimsActorChainExceedingMaxDepth_ThrowsException");

            try
            {
                // Arrange
                var handler = new JsonWebTokenHandler();
                JsonWebTokenHandler.MaxActorChainLength = 2; // Set max depth to 2 for the test

                // Create nested actor for level 3 (will exceed max depth)
                var level3Actor = new CaseSensitiveClaimsIdentity("Level3Auth");
                level3Actor.AddClaim(new Claim("sub", "level3-actor"));
                level3Actor.AddClaim(new Claim("name", "Level 3 Actor"));

                // Create nested actor for level 2
                var level2Actor = new CaseSensitiveClaimsIdentity("Level2Auth");
                level2Actor.AddClaim(new Claim("sub", "level2-actor"));
                level2Actor.AddClaim(new Claim("name", "Level 2 Actor"));
                level2Actor.Actor = level3Actor; // Will exceed max depth in Claims dictionary

                // Create actor for level 1 to be included in Claims dictionary
                var level1Actor = new CaseSensitiveClaimsIdentity("Level1Auth");
                level1Actor.AddClaim(new Claim("sub", "level1-actor"));
                level1Actor.AddClaim(new Claim("name", "Level 1 Actor"));
                level1Actor.Actor = level2Actor;

                // Create the main identity
                var mainIdentity = new CaseSensitiveClaimsIdentity("Bearer");
                mainIdentity.AddClaim(new Claim("sub", "main-subject-id"));
                mainIdentity.AddClaim(new Claim("name", "Main User"));

                // Create token with actor chain in Claims dictionary
                var tokenDescriptor = new SecurityTokenDescriptor
                {
                    Subject = mainIdentity,
                    Issuer = "https://example.com",
                    Audience = "https://api.example.com",
                    SigningCredentials = Default.AsymmetricSigningCredentials,
                    Claims = new Dictionary<string, object>
            {
                { JwtRegisteredClaimNames.Actort, level1Actor }
            }
                };

                // Act - This should throw a SecurityTokenException
                var token = handler.CreateToken(tokenDescriptor);
                context.Diffs.Add("Expected exception was not thrown.");
            }
            catch (SecurityTokenException ex)
            {
                // Assert - Verify the exception message contains the expected content
                if (ex.Message.Contains("Actor chain exceeded maximum depth of 2"))
                {
                    // Test passed - expected exception was thrown with the right message
                }
                else
                {
                    context.Diffs.Add($"Exception message does not contain expected content. Message: {ex.Message}");
                }
            }
            catch (Exception ex)
            {
                // Unexpected exception type
                context.Diffs.Add($"Unexpected exception type: {ex.GetType()}, Message: {ex.Message}");
            }

            TestUtilities.AssertFailIfErrors(context);
        }
    }
}

