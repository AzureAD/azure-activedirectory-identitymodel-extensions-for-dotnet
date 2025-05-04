using System;
using System.Collections.Generic;
using System.Security.Claims;
using Microsoft.IdentityModel.TestUtils;
using Microsoft.IdentityModel.Tokens;
using Microsoft.IdentityModel.JsonWebTokens;
using Xunit;

namespace Microsoft.IdentityModel.Tests
{
    public class ActorTokenSerializationTests
    {
        [Fact]
        public void ActorTokenInClaimsDictionaryShouldBeProperlySerialized()
        {
            var context = new CompareContext($"{this}.ActorTokenInClaimsDictionaryShouldBeProperlySerialized");

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
    }
}
