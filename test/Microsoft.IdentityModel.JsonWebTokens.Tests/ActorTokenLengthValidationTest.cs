// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.IdentityModel.TestUtils;
using Microsoft.IdentityModel.Tokens;
using Microsoft.IdentityModel.Tokens.Experimental;
using Xunit;

#nullable enable
namespace Microsoft.IdentityModel.JsonWebTokens.Tests
{
    /// <summary>
    /// Tests for actor token length validation to ensure CanReadToken is called before ReadToken
    /// for actor tokens in the experimental validation code.
    /// </summary>
    public class ActorTokenLengthValidationTest
    {
        [Fact]
        public async Task ValidateTokenAsync_ActorTokenTooLong_ShouldFail()
        {
            // Arrange
            TestUtilities.WriteHeader($"{this}.ValidateTokenAsync_ActorTokenTooLong_ShouldFail");
            var context = new CompareContext();

            var handler = new JsonWebTokenHandler();
            
            // Create a very long invalid actor token (exceeds MaximumTokenSizeInBytes)
            var longActorToken = new string('a', ValidationParameters.DefaultMaximumTokenSizeInBytes + 1);
            
            // Create a main JWT with the long actor token
            var tokenDescriptor = new SecurityTokenDescriptor
            {
                Subject = ClaimSets.DefaultClaimsIdentity,
                SigningCredentials = KeyingMaterial.JsonWebKeyRsa256SigningCredentials,
                Audience = Default.Audience,
                Issuer = Default.Issuer,
                Claims = new System.Collections.Generic.Dictionary<string, object>
                {
                    { JwtRegisteredClaimNames.Actort, longActorToken }
                }
            };

            var token = handler.CreateToken(tokenDescriptor);

            var validationParameters = ValidationUtils.CreateValidationParameters(
                audiences: new List<string> { Default.Audience },
                issuers: new List<string> { Default.Issuer },
                signingKeys: new List<SecurityKey> { KeyingMaterial.JsonWebKeyRsa256SigningCredentials.Key });
            validationParameters.ValidateActor = true;
            validationParameters.ActorValidationParameters = ValidationUtils.CreateValidationParameters(
                audiences: new List<string> { Default.Audience },
                issuers: new List<string> { Default.Issuer },
                signingKeys: new List<SecurityKey> { KeyingMaterial.JsonWebKeyRsa256SigningCredentials.Key });

            var callContext = new CallContext();

            // Act
            var result = await handler.ValidateTokenAsync(token, validationParameters, callContext, CancellationToken.None);

            // Assert
            Assert.False(result.Succeeded);
            Assert.NotNull(result.Error);
            // Check that the error is related to token being too large (which is the correct behavior)
            Assert.Equal(ValidationFailureType.SecurityTokenTooLarge, result.Error.FailureType);

            TestUtilities.AssertFailIfErrors(context);
        }

        [Fact]
        public async Task ValidateTokenAsync_ActorTokenMalformed_ShouldFail()
        {
            // Arrange
            TestUtilities.WriteHeader($"{this}.ValidateTokenAsync_ActorTokenMalformed_ShouldFail");
            var context = new CompareContext();

            var handler = new JsonWebTokenHandler();
            
            // Create a malformed actor token (not a valid JWT structure)
            var malformedActorToken = "not.a.valid.jwt.token";
            
            // Create a main JWT with the malformed actor token
            var tokenDescriptor = new SecurityTokenDescriptor
            {
                Subject = ClaimSets.DefaultClaimsIdentity,
                SigningCredentials = KeyingMaterial.JsonWebKeyRsa256SigningCredentials,
                Audience = Default.Audience,
                Issuer = Default.Issuer,
                Claims = new System.Collections.Generic.Dictionary<string, object>
                {
                    { JwtRegisteredClaimNames.Actort, malformedActorToken }
                }
            };

            var token = handler.CreateToken(tokenDescriptor);

            var validationParameters = ValidationUtils.CreateValidationParameters(
                audiences: new List<string> { Default.Audience },
                issuers: new List<string> { Default.Issuer },
                signingKeys: new List<SecurityKey> { KeyingMaterial.JsonWebKeyRsa256SigningCredentials.Key });
            validationParameters.ValidateActor = true;
            validationParameters.ActorValidationParameters = ValidationUtils.CreateValidationParameters(
                audiences: new List<string> { Default.Audience },
                issuers: new List<string> { Default.Issuer },
                signingKeys: new List<SecurityKey> { KeyingMaterial.JsonWebKeyRsa256SigningCredentials.Key });

            var callContext = new CallContext();

            // Act
            var result = await handler.ValidateTokenAsync(token, validationParameters, callContext, CancellationToken.None);

            // Assert
            Assert.False(result.Succeeded);
            Assert.NotNull(result.Error);
            // Check that the error is related to token reading failure
            Assert.Equal(ValidationFailureType.TokenReadingFailed, result.Error.FailureType);

            TestUtilities.AssertFailIfErrors(context);
        }

        [Fact]
        public async Task ValidateTokenAsync_ValidActorToken_ShouldSucceed()
        {
            // Arrange
            TestUtilities.WriteHeader($"{this}.ValidateTokenAsync_ValidActorToken_ShouldSucceed");
            var context = new CompareContext();

            var handler = new JsonWebTokenHandler();
            
            // Create a valid actor token
            var actorTokenDescriptor = new SecurityTokenDescriptor
            {
                Subject = ClaimSets.DefaultClaimsIdentity,
                SigningCredentials = KeyingMaterial.JsonWebKeyRsa256SigningCredentials,
                Audience = Default.Audience,
                Issuer = Default.Issuer
            };
            var validActorToken = handler.CreateToken(actorTokenDescriptor);
            
            // Create a main JWT with the valid actor token
            var tokenDescriptor = new SecurityTokenDescriptor
            {
                Subject = ClaimSets.DefaultClaimsIdentity,
                SigningCredentials = KeyingMaterial.JsonWebKeyRsa256SigningCredentials,
                Audience = Default.Audience,
                Issuer = Default.Issuer,
                Claims = new System.Collections.Generic.Dictionary<string, object>
                {
                    { JwtRegisteredClaimNames.Actort, validActorToken }
                }
            };

            var token = handler.CreateToken(tokenDescriptor);

            var validationParameters = ValidationUtils.CreateValidationParameters(
                audiences: new List<string> { Default.Audience },
                issuers: new List<string> { Default.Issuer },
                signingKeys: new List<SecurityKey> { KeyingMaterial.JsonWebKeyRsa256SigningCredentials.Key });
            validationParameters.ValidateActor = true;
            validationParameters.ActorValidationParameters = ValidationUtils.CreateValidationParameters(
                audiences: new List<string> { Default.Audience },
                issuers: new List<string> { Default.Issuer },
                signingKeys: new List<SecurityKey> { KeyingMaterial.JsonWebKeyRsa256SigningCredentials.Key });

            var callContext = new CallContext();

            // Act
            var result = await handler.ValidateTokenAsync(token, validationParameters, callContext, CancellationToken.None);

            // Assert - This should succeed after our fix
            Assert.True(result.Succeeded);

            TestUtilities.AssertFailIfErrors(context);
        }
    }
}
#nullable restore