// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System;
using System.Collections.Generic;
using System.Security.Claims;
//using System.IdentityModel.Tokens.Jwt;
using Microsoft.IdentityModel.TestUtils;
using Microsoft.IdentityModel.Tokens;
using Xunit;
using Microsoft.IdentityModel.JsonWebTokens;

#pragma warning disable CS3016 // Arrays as attribute arguments is not CLS-compliant

namespace Microsoft.IdentityModel.Tests
{
    public class ActorClaimsTests
    {
        [Fact]
        public void ActorClaimsShouldBeSerializedInTokens()
        {
            var context = new CompareContext($"{this}.ActorClaimsShouldBeSerializedInTokens");

            try
            {
                // Create actor claims identity
                var actorIdentity = new CaseSensitiveClaimsIdentity("ActorAuth"); // Updated to CaseSensitiveClaimsIdentity
                actorIdentity.AddClaim(new Claim("sub", "actor-subject-id"));
                actorIdentity.AddClaim(new Claim("name", "Actor Name"));

                var actorIdentityInner = new CaseSensitiveClaimsIdentity("ActorAuthInner"); // Updated to CaseSensitiveClaimsIdentity
                actorIdentityInner.AddClaim(new Claim("sub", "actor-subject-id_inner"));
                actorIdentityInner.AddClaim(new Claim("name", "Actor Name Inner"));
                // Add a claim with destinations
                var claim = new Claim("role", "admin");
                claim.Properties["destination"] = "accesstoken id_token";
                actorIdentity.AddClaim(claim);
                actorIdentity.Actor = actorIdentityInner;

                // Create the main identity
                var mainIdentity = new CaseSensitiveClaimsIdentity("Bearer"); // Updated to CaseSensitiveClaimsIdentity
                mainIdentity.AddClaim(new Claim("sub", "main-subject-id"));
                mainIdentity.AddClaim(new Claim("name", "Main User"));

                // Set the actor
                mainIdentity.Actor = actorIdentity;

                // Create a ClaimsPrincipal
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
                //Console.WriteLine($"Token Descriptor: {tokenDescriptor.Subject.Actor.Claims.IsNullOrEmpty()}");
                var token = tokenHandler.CreateToken(tokenDescriptor);

                // Encode the token
                var encodedToken = token;
                JsonWebToken decodedToken = tokenHandler.ReadJsonWebToken(encodedToken);
                Console.WriteLine($"jsonWeb Token: {token}");
                Console.WriteLine($"Decoded Token Subject Actor: {decodedToken.Actor}");
                // Verify actor claim exists in the token
                Assert.True(decodedToken.Payload.HasClaim("actort"), "JWT token should contain 'act' claim");
                //decodedToken.Payload.TryGetValue("actort", out object actorClaimStr);
                //Console.WriteLine($"Decoded Actor Token: {tokenHandler.ReadJwtToken(actorClaimStr as string)}");
                //// Parse actor token and verify its claims
                var actorClaim = decodedToken.Payload.GetValue<Dictionary<string, object>>("actort");
                Assert.NotNull(actorClaim);
                Assert.Equal("actor-subject-id", actorClaim["sub"]);
                Assert.Equal("Actor Name", actorClaim["name"]);

                //// Verify the destination property was maintained for the role claim
                //if (actorClaim.TryGetValue("role", out object roleValue))
                //{
                //    // Further verification could be done here for the destination properties
                //    Assert.Equal("admin", roleValue);
                //}
                //else
                //{
                //    context.Diffs.Add("Actor claim should contain 'role' claim with destination properties");
                //}
            }
            catch (Exception ex)
            {
                context.Diffs.Add($"Exception: {ex.ToString()}");
            }

            TestUtilities.AssertFailIfErrors(context);
        }

        [Fact]
        public void ActorClaimsWithDestinationsShouldBePreserved()
        {
            var context = new CompareContext($"{this}.ActorClaimsWithDestinationsShouldBePreserved");

            try
            {
                // Create actor claims identity
                var actorIdentity = new CaseSensitiveClaimsIdentity("ActorAuth"); // Updated to CaseSensitiveClaimsIdentity

                // Add claims with destinations
                var claim1 = new Claim("role", "admin");
                claim1.Properties["destination"] = "accesstoken";
                actorIdentity.AddClaim(claim1);

                var claim2 = new Claim("email", "actor@example.com");
                claim2.Properties["destination"] = "id_token";
                actorIdentity.AddClaim(claim2);

                // Create the main identity
                var mainIdentity = new CaseSensitiveClaimsIdentity("Bearer"); // Updated to CaseSensitiveClaimsIdentity
                mainIdentity.AddClaim(new Claim("sub", "main-subject-id"));

                // Set the actor
                mainIdentity.Actor = actorIdentity;

                // Create a ClaimsPrincipal
                var principal = new ClaimsPrincipal(mainIdentity);

                // Create a token with JsonWebTokenHandler to test its handling
                var handler = new JsonWebTokenHandler();
                var tokenDescriptor = new SecurityTokenDescriptor
                {
                    Subject = principal.Identity as ClaimsIdentity,
                    Issuer = "https://example.com",
                    Audience = "https://api.example.com",
                    Expires = DateTime.UtcNow.AddHours(1),
                    SigningCredentials = Default.AsymmetricSigningCredentials
                };

                var token = handler.CreateToken(tokenDescriptor);

                // Read back the token
                var validationParameters = new TokenValidationParameters
                {
                    ValidIssuer = "https://example.com",
                    ValidAudience = "https://api.example.com",
                    IssuerSigningKey = Default.AsymmetricSigningCredentials.Key
                };

                var result = handler.ValidateToken(token, validationParameters);
                Assert.True(result.IsValid);

                // Check if actor claim is preserved with correct identity
                var claimsIdentity = result.ClaimsIdentity;
                Assert.NotNull(claimsIdentity.Actor);

                // Check destination properties on actor claims
                bool foundRoleClaim = false;
                bool foundEmailClaim = false;

                foreach (var claim in claimsIdentity.Actor.Claims)
                {
                    if (claim.Type == "role")
                    {
                        foundRoleClaim = true;
                        Assert.Equal("accesstoken", claim.Properties["destination"]);
                    }
                    else if (claim.Type == "email")
                    {
                        foundEmailClaim = true;
                        Assert.Equal("id_token", claim.Properties["destination"]);
                    }
                }

                if (!foundRoleClaim || !foundEmailClaim)
                {
                    context.Diffs.Add("Actor identity should preserve claims with destination properties");
                }
            }
            catch (Exception ex)
            {
                context.Diffs.Add($"Exception: {ex.ToString()}");
            }

            TestUtilities.AssertFailIfErrors(context);
        }
    }
}

#pragma warning restore CS3016 // Arrays as attribute arguments is not CLS-compliant
