// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using Microsoft.IdentityModel.TestExtensions;
using Microsoft.IdentityModel.Tokens;
using Xunit;
using Microsoft.IdentityModel.TestUtils;
using Microsoft.IdentityModel.Tokens.Experimental;

namespace Microsoft.IdentityModel.JsonWebTokens.Tests
{
    public class JsonWebTokenHandlerValidateTokenSyncTests
    {
        private TestTokenCreator testTokenCreator = new TestTokenCreator()
        {
            SigningCredentials = KeyingMaterial.JsonWebKeyRsa256SigningCredentials
        };
        private JsonWebTokenHandler jsonWebTokenHandler = new JsonWebTokenHandler();

        [Fact]
        public void TestNotYetValidToken()
        {
            string token = testTokenCreator.CreateNotYetValidToken();
            ValidationParameters validationParameters = ValidationUtils.CreateValidationParameters(
                audiences: ["http://Default.Audience.com"],
                issuers: ["http://Default.Issuer.com"],
                signingKeys: [KeyingMaterial.JsonWebKeyRsa256SigningCredentials.Key]);
            CallContext callContext = new CallContext();

            ValidationResult<ValidatedToken, ValidationError> validationResult = jsonWebTokenHandler.ValidateToken(token, validationParameters, callContext, default);

            Assert.False(validationResult.Succeeded);
            Assert.Null(validationResult.Result);
            Assert.NotNull(validationResult.Error);
            Assert.IsType<LifetimeValidationError>(validationResult.Error);
            Assert.Contains("IDX10222:", validationResult.Error.Message);
            // IDX10222: Lifetime validation failed. The token is not yet valid. ValidFrom (UTC): '1/6/2025 9:03:26 PM', Current time (UTC): '1/6/2025 5:03:26 PM'.
        }

        [Fact]
        public void TestTokenWithFutureIssuedAt()
        {
            string token = testTokenCreator.CreateTokenWithFutureIssuedAt();
            ValidationParameters validationParameters = ValidationUtils.CreateValidationParameters(
                audiences: ["http://Default.Audience.com"],
                issuers: ["http://Default.Issuer.com"],
                signingKeys: [KeyingMaterial.JsonWebKeyRsa256SigningCredentials.Key]
            );
            CallContext callContext = new CallContext();

            ValidationResult<ValidatedToken, ValidationError> validationResult = jsonWebTokenHandler.ValidateToken(token, validationParameters, callContext, default);

            Assert.True(validationResult.Succeeded);
            Assert.NotNull(validationResult.Result);
            Assert.Null(validationResult.Error);
            // TODO: Define potentially adding a setting to reject tokens issued in the future.
            // As it is not part of the specification, it should be optional.
        }

        [Fact]
        public void TestTokenWithMissingIssuedAt()
        {
            string token = testTokenCreator.CreateTokenWithMissingIssuedAt();
            ValidationParameters validationParameters = ValidationUtils.CreateValidationParameters(
                audiences: ["http://Default.Audience.com"],
                issuers: ["http://Default.Issuer.com"],
                signingKeys: [KeyingMaterial.JsonWebKeyRsa256SigningCredentials.Key]
            );
            CallContext callContext = new CallContext();

            ValidationResult<ValidatedToken, ValidationError> validationResult = jsonWebTokenHandler.ValidateToken(token, validationParameters, callContext, default);

            Assert.True(validationResult.Succeeded);
            Assert.NotNull(validationResult.Result);
            Assert.Null(validationResult.Error);
            // The iat claim is optional.
        }

        [Fact]
        public void TestTokenWithMissingNotBefore()
        {
            string token = testTokenCreator.CreateTokenWithMissingNotBefore();
            ValidationParameters validationParameters = ValidationUtils.CreateValidationParameters(
                audiences: ["http://Default.Audience.com"],
                issuers: ["http://Default.Issuer.com"],
                signingKeys: [KeyingMaterial.JsonWebKeyRsa256SigningCredentials.Key]
            );
            CallContext callContext = new CallContext();

            ValidationResult<ValidatedToken, ValidationError> validationResult = jsonWebTokenHandler.ValidateToken(token, validationParameters, callContext, default);

            Assert.True(validationResult.Succeeded);
            Assert.NotNull(validationResult.Result);
            Assert.Null(validationResult.Error);
            // The nbf claim is optional.
        }

        [Fact]
        public void TestTokenSucceeds()
        {
            string token = testTokenCreator.CreateDefaultValidToken();
            ValidationParameters validationParameters = ValidationUtils.CreateValidationParameters(
                audiences: ["http://Default.Audience.com"],
                issuers: ["http://Default.Issuer.com"],
                signingKeys: [KeyingMaterial.JsonWebKeyRsa256SigningCredentials.Key]
            );
            CallContext callContext = new CallContext();

            ValidationResult<ValidatedToken, ValidationError> validationResult = jsonWebTokenHandler.ValidateToken(token, validationParameters, callContext, default);

            Assert.True(validationResult.Succeeded);
            Assert.NotNull(validationResult.Result);
            Assert.Null(validationResult.Error);
        }

        [Fact]
        public void TestNotYetValidTokenTvp()
        {
            string token = testTokenCreator.CreateNotYetValidToken();
            TokenValidationParameters tokenValidationParameters = CreateTokenValidationParameters();

            TokenValidationResult validationResult = ValidateTokenSync(token, tokenValidationParameters);

            Assert.False(validationResult.IsValid);
            Assert.Null(validationResult.SecurityToken);
            Assert.NotNull(validationResult.Exception);
            Assert.IsType<SecurityTokenNotYetValidException>(validationResult.Exception);
            Assert.Contains("IDX10222:", validationResult.Exception.Message);
            // IDX10222: Lifetime validation failed. The token is not yet valid.
        }

        [Fact]
        public void TestTokenWithFutureIssuedAtTvp()
        {
            string token = testTokenCreator.CreateTokenWithFutureIssuedAt();
            TokenValidationParameters tokenValidationParameters = CreateTokenValidationParameters();

            TokenValidationResult validationResult = ValidateTokenSync(token, tokenValidationParameters);

            Assert.True(validationResult.IsValid);
            Assert.NotNull(validationResult.SecurityToken);
            Assert.Null(validationResult.Exception);
            // TODO: Define potentially adding a setting to reject tokens issued in the future.
            // As it is not part of the specification, it should be optional.
        }

        [Fact]
        public void TestTokenWithMissingIssuedAtTvp()
        {
            string token = testTokenCreator.CreateTokenWithMissingIssuedAt();
            TokenValidationParameters tokenValidationParameters = CreateTokenValidationParameters();

            TokenValidationResult validationResult = ValidateTokenSync(token, tokenValidationParameters);

            Assert.True(validationResult.IsValid);
            Assert.NotNull(validationResult.SecurityToken);
            Assert.Null(validationResult.Exception);
            // The iat claim is optional.
        }

        [Fact]
        public void TestTokenWithMissingNotBeforeTvp()
        {
            string token = testTokenCreator.CreateTokenWithMissingNotBefore();
            TokenValidationParameters tokenValidationParameters = CreateTokenValidationParameters();

            TokenValidationResult validationResult = ValidateTokenSync(token, tokenValidationParameters);

            Assert.True(validationResult.IsValid);
            Assert.NotNull(validationResult.SecurityToken);
            Assert.Null(validationResult.Exception);
            // The nbf claim is optional.
        }

        [Fact]
        public void TestTokenSucceedsTvp()
        {
            string token = testTokenCreator.CreateDefaultValidToken();
            TokenValidationParameters tokenValidationParameters = CreateTokenValidationParameters();

            TokenValidationResult validationResult = ValidateTokenSync(token, tokenValidationParameters);

            Assert.True(validationResult.IsValid);
            Assert.NotNull(validationResult.SecurityToken);
            Assert.Null(validationResult.Exception);
        }

        private static TokenValidationParameters CreateTokenValidationParameters() =>
            new TokenValidationParameters
            {
                ValidAudiences = ["http://Default.Audience.com"],
                ValidIssuers = ["http://Default.Issuer.com"],
                IssuerSigningKeys = [KeyingMaterial.JsonWebKeyRsa256SigningCredentials.Key],
            };

        private TokenValidationResult ValidateTokenSync(string token, TokenValidationParameters tokenValidationParameters)
        {
#pragma warning disable CS0618 // Legacy synchronous overload is intentionally exercised here.
            return jsonWebTokenHandler.ValidateToken(token, tokenValidationParameters);
#pragma warning restore CS0618
        }

    }
}
