// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System;
using System.Security.Claims;
using Microsoft.IdentityModel.TestUtils;
using Microsoft.IdentityModel.Tokens;
using Xunit;
using Microsoft.IdentityModel.JsonWebTokens;
using Newtonsoft.Json;

#pragma warning disable CS3016 // Arrays as attribute arguments is not CLS-compliant

namespace Microsoft.IdentityModel.Tests
{
    public class ActorClaimsTests
    {
        [Fact]
        public void ActorTokenAsClaimShouldBeSerialized()
        {
            var context = new CompareContext($"{this}.ActorTokenAsClaimShouldBeSerialized");

            try
            {
                // Create the main identity
                var mainIdentity = new CaseSensitiveClaimsIdentity("Bearer");
                mainIdentity.AddClaim(new Claim("sub", "main-subject-id"));
                mainIdentity.AddClaim(new Claim("name", "Main User"));

                // Create an actor claim with a JSON string payload
                var actorJson = JsonConvert.SerializeObject(new
                {
                    sub = "actor-subject-id",
                    name = "Actor Name",
                    role = "admin"
                });

                mainIdentity.AddClaim(new Claim(ClaimTypes.Actor, actorJson));

                var principal = new ClaimsPrincipal(mainIdentity);

                // Create a token with JsonWebTokenHandler
                var tokenHandler = new JsonWebTokenHandler();
                SecurityTokenDescriptor tokenDescriptor = new SecurityTokenDescriptor
                {
                    Subject = principal.Identity as ClaimsIdentity,
                    Issuer = "https://example.com",
                    Audience = "https://api.example.com",
                    Expires = DateTime.UtcNow.AddHours(1),
                    SigningCredentials = Default.AsymmetricSigningCredentials
                };

                var token = tokenHandler.CreateToken(tokenDescriptor);

                // Verify token was created successfully
                JsonWebToken decodedToken = tokenHandler.ReadJsonWebToken(token);

                // Verify actor claim exists in the token
                Assert.True(decodedToken.Payload.HasClaim("actort"), "JWT token should contain 'actort' claim");

                // Verify actor token can be parsed
                var actorToken = decodedToken.Actor;
                Assert.NotNull(actorToken);

                // Try to deserialize the actor token string into a JSON object
                var actorTokenString = decodedToken.Actor;
                JsonWebToken actorJwt = tokenHandler.ReadJsonWebToken(actorTokenString);

                // Verify actor claims
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
        public void ActorTokenAsClaimsIdentityShouldBeSerialized()
        {
            var context = new CompareContext($"{this}.ActorTokenAsClaimsIdentityShouldBeSerialized");

            try
            {
                // Create actor claims identity
                var actorIdentity = new CaseSensitiveClaimsIdentity("ActorAuth");
                actorIdentity.AddClaim(new Claim("sub", "actor-subject-id"));
                actorIdentity.AddClaim(new Claim("name", "Actor Name"));
                actorIdentity.AddClaim(new Claim("role", "admin"));

                // Create nested actor
                var nestedActorIdentity = new CaseSensitiveClaimsIdentity("NestedActorAuth");
                nestedActorIdentity.AddClaim(new Claim("sub", "nested-actor-id"));
                nestedActorIdentity.AddClaim(new Claim("name", "Nested Actor"));

                // Set nested actor
                actorIdentity.Actor = nestedActorIdentity;

                // Create the main identity
                var mainIdentity = new CaseSensitiveClaimsIdentity("Bearer");
                mainIdentity.AddClaim(new Claim("sub", "main-subject-id"));
                mainIdentity.AddClaim(new Claim("name", "Main User"));

                // Set the actor
                mainIdentity.Actor = actorIdentity;

                var principal = new ClaimsPrincipal(mainIdentity);

                // Create a token with JsonWebTokenHandler
                var tokenHandler = new JsonWebTokenHandler();
                SecurityTokenDescriptor tokenDescriptor = new SecurityTokenDescriptor
                {
                    Subject = principal.Identity as ClaimsIdentity,
                    Issuer = "https://example.com",
                    Audience = "https://api.example.com",
                    Expires = DateTime.UtcNow.AddHours(1),
                    SigningCredentials = Default.AsymmetricSigningCredentials
                };

                var token = tokenHandler.CreateToken(tokenDescriptor);
                JsonWebToken decodedToken = tokenHandler.ReadJsonWebToken(token);

                // Verify actor claim exists
                Assert.True(decodedToken.Payload.HasClaim("actort"), "JWT token should contain 'actort' claim");

                // Validate actor token and its claims
                var result = tokenHandler.ValidateToken(token, new TokenValidationParameters
                {
                    ValidateActor = true,
                    ValidIssuer = "https://example.com",
                    ValidAudience = "https://api.example.com",
                    IssuerSigningKey = Default.AsymmetricSigningCredentials.Key
                });

                Assert.True(result.IsValid);

                // Verify actor identity structure
                Assert.NotNull(result.ClaimsIdentity.Actor);
                Assert.Equal("actor-subject-id", result.ClaimsIdentity.Actor.FindFirst("sub")?.Value);
                Assert.Equal("Actor Name", result.ClaimsIdentity.Actor.FindFirst("name")?.Value);
                Assert.Equal("admin", result.ClaimsIdentity.Actor.FindFirst("role")?.Value);

                // Verify nested actor
                Assert.NotNull(result.ClaimsIdentity.Actor.Actor);
                Assert.Equal("nested-actor-id", result.ClaimsIdentity.Actor.Actor.FindFirst("sub")?.Value);
                Assert.Equal("Nested Actor", result.ClaimsIdentity.Actor.Actor.FindFirst("name")?.Value);
            }
            catch (Exception ex)
            {
                context.Diffs.Add($"Exception: {ex}");
            }

            TestUtilities.AssertFailIfErrors(context);
        }

        [Fact]
        public void ActorTokenInBothClaimAndIdentityShouldPreferClaim()
        {
            var context = new CompareContext($"{this}.ActorTokenInBothClaimAndIdentityShouldPreferClaim");

            try
            {
                // Create actor claims identity that should NOT be used
                var actorIdentity = new CaseSensitiveClaimsIdentity("ActorAuth");
                actorIdentity.AddClaim(new Claim("sub", "identity-actor-id"));
                actorIdentity.AddClaim(new Claim("name", "Identity Actor"));

                // Create the main identity with Actor set
                var mainIdentity = new CaseSensitiveClaimsIdentity("Bearer");
                mainIdentity.AddClaim(new Claim("sub", "main-subject-id"));
                mainIdentity.AddClaim(new Claim("name", "Main User"));
                mainIdentity.Actor = actorIdentity;

                // Add an actor claim that should take precedence
                var actorJson = JsonConvert.SerializeObject(new
                {
                    sub = "claim-actor-id",
                    name = "Claim Actor"
                });

                mainIdentity.AddClaim(new Claim(ClaimTypes.Actor, actorJson));

                var principal = new ClaimsPrincipal(mainIdentity);

                // Create a token with JsonWebTokenHandler
                var tokenHandler = new JsonWebTokenHandler();
                SecurityTokenDescriptor tokenDescriptor = new SecurityTokenDescriptor
                {
                    Subject = principal.Identity as ClaimsIdentity,
                    Issuer = "https://example.com",
                    Audience = "https://api.example.com",
                    Expires = DateTime.UtcNow.AddHours(1),
                    SigningCredentials = Default.AsymmetricSigningCredentials
                };

                var token = tokenHandler.CreateToken(tokenDescriptor);

                // Verify token was created successfully
                JsonWebToken decodedToken = tokenHandler.ReadJsonWebToken(token);

                // Verify actor claim exists in the token
                Assert.True(decodedToken.Payload.HasClaim("actort"), "JWT token should contain 'actort' claim");

                // Verify the actor token contains the claim data, not the identity data
                var actorTokenString = decodedToken.Actor;
                JsonWebToken actorJwt = tokenHandler.ReadJsonWebToken(actorTokenString);

                Assert.Equal("claim-actor-id", actorJwt.Payload.GetValue<string>("sub"));
                Assert.Equal("Claim Actor", actorJwt.Payload.GetValue<string>("name"));
                Assert.NotEqual("identity-actor-id", actorJwt.Payload.GetValue<string>("sub"));
                Assert.NotEqual("Identity Actor", actorJwt.Payload.GetValue<string>("name"));
            }
            catch (Exception ex)
            {
                context.Diffs.Add($"Exception: {ex}");
            }

            TestUtilities.AssertFailIfErrors(context);
        }

        [Fact]
        public void InvalidActorTokenJsonShouldNotParse()
        {
            var context = new CompareContext($"{this}.InvalidActorTokenJsonShouldNotParse");

            try
            {
                // Create the main identity
                var mainIdentity = new CaseSensitiveClaimsIdentity("Bearer");
                mainIdentity.AddClaim(new Claim("sub", "main-subject-id"));

                // Create an actor claim with an invalid JSON string
                var invalidJson = "{ invalid json format }";
                mainIdentity.AddClaim(new Claim(ClaimTypes.Actor, invalidJson));

                var principal = new ClaimsPrincipal(mainIdentity);

                // Create a token with JsonWebTokenHandler
                var tokenHandler = new JsonWebTokenHandler();
                SecurityTokenDescriptor tokenDescriptor = new SecurityTokenDescriptor
                {
                    Subject = principal.Identity as ClaimsIdentity,
                    Issuer = "https://example.com",
                    Audience = "https://api.example.com",
                    Expires = DateTime.UtcNow.AddHours(1),
                    SigningCredentials = Default.AsymmetricSigningCredentials
                };

                var token = tokenHandler.CreateToken(tokenDescriptor);

                // Verify token was created successfully
                JsonWebToken decodedToken = tokenHandler.ReadJsonWebToken(token);

                // The actort claim should exist but with the raw value
                Assert.True(decodedToken.Payload.HasClaim("actort"), "JWT token should contain 'actort' claim");

                // Verify the actor token is not parseable as a JWT
                var actorTokenString = decodedToken.Actor;

                // This should not be parseable as a JWT
                var exception = Record.Exception(() => tokenHandler.ReadJsonWebToken(actorTokenString));
                Assert.NotNull(exception);

                // The actor claim should be the raw invalid JSON
                Assert.Equal(invalidJson, decodedToken.Payload.GetValue<string>("actort"));

                // When validating a token with an invalid actor, validation should still pass if not validating actor
                var result = tokenHandler.ValidateToken(token, new TokenValidationParameters
                {
                    ValidateActor = false,
                    ValidIssuer = "https://example.com",
                    ValidAudience = "https://api.example.com",
                    IssuerSigningKey = Default.AsymmetricSigningCredentials.Key
                });

                Assert.True(result.IsValid);
            }
            catch (Exception ex)
            {
                context.Diffs.Add($"Exception: {ex}");
            }

            TestUtilities.AssertFailIfErrors(context);
        }

        [Fact]
        public void ClaimPropertiesShouldBePreservedInActorToken()
        {
            var context = new CompareContext($"{this}.ClaimPropertiesShouldBePreservedInActorToken");

            try
            {
                // Create actor claims identity with properties
                // Add a claim with properties
                var actorIdentityInner = new CaseSensitiveClaimsIdentity("ActorAuth"); // Updated to CaseSensitiveClaimsIdentity
                actorIdentityInner.AddClaim(new Claim("destination", "accesstoken id_token"));
                actorIdentityInner.AddClaim(new Claim("custom_property", "custom_value"));

                // Create the main identity
                var mainIdentity = new CaseSensitiveClaimsIdentity("Bearer");
                mainIdentity.AddClaim(new Claim("sub", "main-subject-id"));
                mainIdentity.Actor = actorIdentityInner;

                var principal = new ClaimsPrincipal(mainIdentity);

                // Create a token with JsonWebTokenHandler
                var tokenHandler = new JsonWebTokenHandler();
                SecurityTokenDescriptor tokenDescriptor = new SecurityTokenDescriptor
                {
                    Subject = principal.Identity as ClaimsIdentity,
                    Issuer = "https://example.com",
                    Audience = "https://api.example.com",
                    Expires = DateTime.UtcNow.AddHours(1),
                    SigningCredentials = Default.AsymmetricSigningCredentials
                };

                var token = tokenHandler.CreateToken(tokenDescriptor);
                Console.WriteLine($"Here is the token {token}");
                // Validate and check if properties were preserved
                var result = tokenHandler.ValidateToken(token, new TokenValidationParameters
                {
                    ValidIssuer = "https://example.com",
                    ValidAudience = "https://api.example.com",
                    IssuerSigningKey = Default.AsymmetricSigningCredentials.Key
                });

                Assert.True(result.IsValid);
                Assert.NotNull(result.ClaimsIdentity.Actor);

                // Check if property was preserved in actor claim
                var roleClaim = result.ClaimsIdentity.Actor.FindFirst("role");
                Assert.NotNull(roleClaim);
                Assert.Equal("admin", roleClaim.Value);
                Assert.Equal("accesstoken id_token", roleClaim.Properties["destination"]);
                Assert.Equal("custom_value", roleClaim.Properties["custom_property"]);
            }
            catch (Exception ex)
            {
                context.Diffs.Add($"Exception: {ex}");
            }

            TestUtilities.AssertFailIfErrors(context);
        }
    }
}

#pragma warning restore CS3016 // Arrays as attribute arguments is not CLS-compliant
