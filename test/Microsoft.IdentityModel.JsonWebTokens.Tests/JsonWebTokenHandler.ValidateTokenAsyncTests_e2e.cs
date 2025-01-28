// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System.Threading.Tasks;
using Microsoft.IdentityModel.TestExtensions;
using Microsoft.IdentityModel.Tokens;
using Xunit;
using Microsoft.IdentityModel.TestUtils;

namespace Microsoft.IdentityModel.JsonWebTokens.Tests
{
    public class JsonWebTokenHandlerValidateTokenAsyncTestsE2e
    {
        private TestTokenCreator testTokenCreator = new TestTokenCreator()
        {
            SigningCredentials = KeyingMaterial.JsonWebKeyRsa256SigningCredentials
        };
        private JsonWebTokenHandler jsonWebTokenHandler = new JsonWebTokenHandler();

        [Fact]
        public async Task TestDefaultValidToken()
        {
            string token = testTokenCreator.CreateDefaultValidToken();
            ValidationParameters validationParameters = new ValidationParameters()
            {
                ValidAudiences = ["http://Default.Audience.com"],
                ValidIssuers = ["http://Default.Issuer.com"],
                IssuerSigningKeys = [KeyingMaterial.JsonWebKeyRsa256SigningCredentials.Key]
            };
            CallContext callContext = new CallContext();

            ValidationResult<ValidatedToken> validationResult = await jsonWebTokenHandler.ValidateTokenAsync(token, validationParameters, callContext, default);

            Assert.True(validationResult.IsValid);
            Assert.NotNull(validationResult.Result);
            Assert.Null(validationResult.Error);
        }

        [Fact]
        public async Task TestDefaultValidTokenValidAudiencesNotSpecified()
        {
            string token = testTokenCreator.CreateDefaultValidToken();
            ValidationParameters validationParameters = new ValidationParameters()
            {
                ValidIssuers = ["http://Default.Issuer.com"],
                IssuerSigningKeys = [KeyingMaterial.JsonWebKeyRsa256SigningCredentials.Key]
            };
            CallContext callContext = new CallContext();

            ValidationResult<ValidatedToken> validationResult = await jsonWebTokenHandler.ValidateTokenAsync(token, validationParameters, callContext, default);

            Assert.False(validationResult.IsValid);
            Assert.Null(validationResult.Result);
            Assert.NotNull(validationResult.Error);
            Assert.IsType<AudienceValidationError>(validationResult.Error);
            Assert.Contains("IDX10268", validationResult.Error.Message);
            // IDX10268: Unable to validate audience, validationParameters.ValidAudiences.Count == 0.
        }

        [Fact]
        public async Task TestDefaultValidTokenValidIssuersNotSpecified()
        {
            string token = testTokenCreator.CreateDefaultValidToken();
            ValidationParameters validationParameters = new ValidationParameters()
            {
                ValidAudiences = ["http://Default.Audience.com"],
                IssuerSigningKeys = [KeyingMaterial.JsonWebKeyRsa256SigningCredentials.Key]
            };
            CallContext callContext = new CallContext();

            ValidationResult<ValidatedToken> validationResult = await jsonWebTokenHandler.ValidateTokenAsync(token, validationParameters, callContext, default);

            Assert.False(validationResult.IsValid);
            Assert.Null(validationResult.Result);
            Assert.NotNull(validationResult.Error);
            Assert.IsType<IssuerValidationError>(validationResult.Error);
            Assert.Contains("IDX10211", validationResult.Error.Message);
            // IDX10211: Unable to validate issuer. The 'issuer' parameter is null or whitespace.
        }

        [Fact]
        public async Task TestDefaultValidTokenIssuerSigningKeyNotSpecified()
        {
            string token = testTokenCreator.CreateDefaultValidToken();
            ValidationParameters validationParameters = new ValidationParameters()
            {
                ValidAudiences = ["http://Default.Audience.com"],
                ValidIssuers = ["http://Default.Issuer.com"],
            };
            CallContext callContext = new CallContext();

            ValidationResult<ValidatedToken> validationResult = await jsonWebTokenHandler.ValidateTokenAsync(token, validationParameters, callContext, default);

            Assert.False(validationResult.IsValid);
            Assert.Null(validationResult.Result);
            Assert.NotNull(validationResult.Error);
            Assert.IsType<SignatureValidationError>(validationResult.Error);
            Assert.Contains("IDX10502", validationResult.Error.Message);
            // IDX10502: Signature validation failed. The token's kid is: 'JsonWebKeyRsa_2048', but did not match any keys in ValidationParameters or Configuration and TryAllIssuerSigningKeys is false. Number of keys in ValidationParameters: '0'. 
            // Number of keys in Configuration: '0'.
            // token: '[PII of type 'Microsoft.IdentityModel.Logging.SecurityArtifact' is hidden. For more details, see https://aka.ms/IdentityModel/PII.]'.
        }

        [Fact]
        public async Task TestTokenWithInvalidSignature()
        {
            string token = testTokenCreator.CreateTokenWithInvalidSignature();
            ValidationParameters validationParameters = new ValidationParameters()
            {
                ValidAudiences = ["http://Default.Audience.com"],
                ValidIssuers = ["http://Default.Issuer.com"],
                IssuerSigningKeys = [KeyingMaterial.JsonWebKeyRsa256SigningCredentials.Key]
            };
            CallContext callContext = new CallContext();

            ValidationResult<ValidatedToken> validationResult = await jsonWebTokenHandler.ValidateTokenAsync(token, validationParameters, callContext, default);

            Assert.False(validationResult.IsValid);
            Assert.Null(validationResult.Result);
            Assert.NotNull(validationResult.Error);
            Assert.IsType<SignatureValidationError>(validationResult.Error);
            Assert.Contains("IDX10520", validationResult.Error.Message);
            // IDX10520: Signature validation failed. The key provided could not validate the signature. Key tried: '{0}'.
        }

        [Fact]
        public async Task TestTokenWithNoSignature()
        {
            string token = testTokenCreator.CreateTokenWithNoSignature();
            ValidationParameters validationParameters = new ValidationParameters()
            {
                ValidAudiences = ["http://Default.Audience.com"],
                ValidIssuers = ["http://Default.Issuer.com"],
                IssuerSigningKeys = [KeyingMaterial.JsonWebKeyRsa256SigningCredentials.Key]
            };
            CallContext callContext = new CallContext();

            ValidationResult<ValidatedToken> validationResult = await jsonWebTokenHandler.ValidateTokenAsync(token, validationParameters, callContext, default);

            Assert.False(validationResult.IsValid);
            Assert.Null(validationResult.Result);
            Assert.NotNull(validationResult.Error);
            Assert.IsType<SignatureValidationError>(validationResult.Error);
            Assert.Contains("IDX10504", validationResult.Error.Message);
            // IDX10504: Unable to validate signature, token does not have a signature: '[PII of type 'Microsoft.IdentityModel.Logging.SecurityArtifact' is hidden. For more details, see https://aka.ms/IdentityModel/PII.]'.
        }

        [Fact]
        public async Task TestExpiredToken()
        {
            string token = testTokenCreator.CreateExpiredToken();
            ValidationParameters validationParameters = new ValidationParameters()
            {
                ValidAudiences = ["http://Default.Audience.com"],
                ValidIssuers = ["http://Default.Issuer.com"],
                IssuerSigningKeys = [KeyingMaterial.JsonWebKeyRsa256SigningCredentials.Key]
            };
            CallContext callContext = new CallContext();

            ValidationResult<ValidatedToken> validationResult = await jsonWebTokenHandler.ValidateTokenAsync(token, validationParameters, callContext, default);

            Assert.False(validationResult.IsValid);
            Assert.Null(validationResult.Result);
            Assert.NotNull(validationResult.Error);
            Assert.IsType<LifetimeValidationError>(validationResult.Error);
            Assert.Contains("IDX10223", validationResult.Error.Message);
            // IDX10223: Lifetime validation failed. The token is expired. ValidTo (UTC): '1/6/2025 1:03:26 PM', Current time (UTC): '1/6/2025 5:03:26 PM'.
        }

        [Fact]
        public async Task TestNotYetValidToken()
        {
            string token = testTokenCreator.CreateNotYetValidToken();
            ValidationParameters validationParameters = new ValidationParameters()
            {
                ValidAudiences = ["http://Default.Audience.com"],
                ValidIssuers = ["http://Default.Issuer.com"],
                IssuerSigningKeys = [KeyingMaterial.JsonWebKeyRsa256SigningCredentials.Key]
            };
            CallContext callContext = new CallContext();

            ValidationResult<ValidatedToken> validationResult = await jsonWebTokenHandler.ValidateTokenAsync(token, validationParameters, callContext, default);

            Assert.False(validationResult.IsValid);
            Assert.Null(validationResult.Result);
            Assert.NotNull(validationResult.Error);
            Assert.IsType<LifetimeValidationError>(validationResult.Error);
            Assert.Contains("IDX10222", validationResult.Error.Message);
            // IDX10222: Lifetime validation failed. The token is not yet valid. ValidFrom (UTC): '1/6/2025 9:03:26 PM', Current time (UTC): '1/6/2025 5:03:26 PM'.
        }

        [Fact]
        public async Task TestTokenWithFutureIssuedAt()
        {
            string token = testTokenCreator.CreateTokenWithFutureIssuedAt();
            ValidationParameters validationParameters = new ValidationParameters()
            {
                ValidAudiences = ["http://Default.Audience.com"],
                ValidIssuers = ["http://Default.Issuer.com"],
                IssuerSigningKeys = [KeyingMaterial.JsonWebKeyRsa256SigningCredentials.Key]
            };
            CallContext callContext = new CallContext();

            ValidationResult<ValidatedToken> validationResult = await jsonWebTokenHandler.ValidateTokenAsync(token, validationParameters, callContext, default);

            Assert.True(validationResult.IsValid);
            Assert.NotNull(validationResult.Result);
            Assert.Null(validationResult.Error);
            // TODO: Define potentially adding a setting to reject tokens issued in the future.
            // As it is not part of the specification, it should be optional.
        }

        [Fact]
        public async Task TestTokenWithBadAudience()
        {
            string token = testTokenCreator.CreateTokenWithBadAudience();
            ValidationParameters validationParameters = new ValidationParameters()
            {
                ValidAudiences = ["http://Default.Audience.com"],
                ValidIssuers = ["http://Default.Issuer.com"],
                IssuerSigningKeys = [KeyingMaterial.JsonWebKeyRsa256SigningCredentials.Key]
            };
            CallContext callContext = new CallContext();

            ValidationResult<ValidatedToken> validationResult = await jsonWebTokenHandler.ValidateTokenAsync(token, validationParameters, callContext, default);

            Assert.False(validationResult.IsValid);
            Assert.Null(validationResult.Result);
            Assert.NotNull(validationResult.Error);
            Assert.IsType<AudienceValidationError>(validationResult.Error);
            Assert.Contains("IDX10215", validationResult.Error.Message);
            // IDX10215: Audience validation failed. Audiences: '7e4dcb88-7e75-4ae6-9ad1-5c84c44c80c5'. Did not match: validationParameters.ValidAudiences: 'http://Default.Audience.com'.
        }

        [Fact]
        public async Task TestTokenWithBadIssuer()
        {
            string token = testTokenCreator.CreateTokenWithBadIssuer();
            ValidationParameters validationParameters = new ValidationParameters()
            {
                ValidAudiences = ["http://Default.Audience.com"],
                ValidIssuers = ["http://Default.Issuer.com"],
                IssuerSigningKeys = [KeyingMaterial.JsonWebKeyRsa256SigningCredentials.Key]
            };
            CallContext callContext = new CallContext();

            ValidationResult<ValidatedToken> validationResult = await jsonWebTokenHandler.ValidateTokenAsync(token, validationParameters, callContext, default);

            Assert.False(validationResult.IsValid);
            Assert.Null(validationResult.Result);
            Assert.NotNull(validationResult.Error);
            Assert.IsType<IssuerValidationError>(validationResult.Error);
            Assert.Contains("IDX10212", validationResult.Error.Message);
            // IDX10212: Issuer validation failed. Issuer: '7bed6a6e-3245-47b9-9e10-1120565cfe3c'. Did not match any: validationParameters.ValidIssuers: 'http://Default.Issuer.com' or validationParameters.ConfigurationManager.CurrentConfiguration.Issuer: 'Null'. For more details, see https://aka.ms/IdentityModel/issuer-validation. 
        }

        [Fact]
        public async Task TestTokenWithBadSignatureKey_TryAllIssuerSigningKeysFalse()
        {
            string token = testTokenCreator.CreateTokenWithBadSignatureKey();
            ValidationParameters validationParameters = new ValidationParameters()
            {
                ValidAudiences = ["http://Default.Audience.com"],
                ValidIssuers = ["http://Default.Issuer.com"],
                IssuerSigningKeys = [KeyingMaterial.JsonWebKeyRsa256SigningCredentials.Key]
            };
            CallContext callContext = new CallContext();

            ValidationResult<ValidatedToken> validationResult = await jsonWebTokenHandler.ValidateTokenAsync(token, validationParameters, callContext, default);

            Assert.False(validationResult.IsValid);
            Assert.Null(validationResult.Result);
            Assert.NotNull(validationResult.Error);
            Assert.IsType<SignatureValidationError>(validationResult.Error);
            Assert.Contains("IDX10519", validationResult.Error.Message);
            // IDX10519: Signature validation failed. The token's kid is missing and ValidationParameters.TryAllIssuerSigningKeys is set to false.
        }

        [Fact]
        public async Task TestTokenWithBadSignatureKey_TryAllIssuerSigningKeysTrue()
        {
            string token = testTokenCreator.CreateTokenWithBadSignatureKey();
            ValidationParameters validationParameters = new ValidationParameters()
            {
                ValidAudiences = ["http://Default.Audience.com"],
                ValidIssuers = ["http://Default.Issuer.com"],
                IssuerSigningKeys = [KeyingMaterial.JsonWebKeyRsa256SigningCredentials.Key]
            };
            validationParameters.TryAllIssuerSigningKeys = true;
            CallContext callContext = new CallContext();

            ValidationResult<ValidatedToken> validationResult = await jsonWebTokenHandler.ValidateTokenAsync(token, validationParameters, callContext, default);

            Assert.False(validationResult.IsValid);
            Assert.Null(validationResult.Result);
            Assert.NotNull(validationResult.Error);
            Assert.IsType<SignatureValidationError>(validationResult.Error);
            Assert.Contains("IDX10517", validationResult.Error.Message);
            // IDX10517: Signature validation failed. The token's kid is missing. Keys tried: '{0}'. Number of keys in TokenValidationParameters: '{1}'. \nNumber of keys in Configuration: '{2}'. \nExceptions caught:\n '{3}'.\ntoken: '{4}'. See https://aka.ms/IDX10503 for details.
        }

        [Fact]
        public async Task TestTokenWithMissingIssuer()
        {
            string token = testTokenCreator.CreateTokenWithMissingIssuer();
            ValidationParameters validationParameters = new ValidationParameters()
            {
                ValidAudiences = ["http://Default.Audience.com"],
                ValidIssuers = ["http://Default.Issuer.com"],
                IssuerSigningKeys = [KeyingMaterial.JsonWebKeyRsa256SigningCredentials.Key]
            };
            CallContext callContext = new CallContext();

            ValidationResult<ValidatedToken> validationResult = await jsonWebTokenHandler.ValidateTokenAsync(token, validationParameters, callContext, default);

            Assert.False(validationResult.IsValid);
            Assert.Null(validationResult.Result);
            Assert.NotNull(validationResult.Error);
            Assert.IsType<IssuerValidationError>(validationResult.Error);
            Assert.Contains("IDX10211", validationResult.Error.Message);
            // IDX10211: Unable to validate issuer. The 'issuer' parameter is null or whitespace.

            // This message needs to be updated to specifiy that it was not specified in the ValidationParameters?
        }

        [Fact]
        public async Task TestTokenWithMissingAudience()
        {
            string token = testTokenCreator.CreateTokenWithMissingAudience();
            ValidationParameters validationParameters = new ValidationParameters()
            {
                ValidAudiences = ["http://Default.Audience.com"],
                ValidIssuers = ["http://Default.Issuer.com"],
                IssuerSigningKeys = [KeyingMaterial.JsonWebKeyRsa256SigningCredentials.Key]
            };
            CallContext callContext = new CallContext();

            ValidationResult<ValidatedToken> validationResult = await jsonWebTokenHandler.ValidateTokenAsync(token, validationParameters, callContext, default);

            Assert.False(validationResult.IsValid);
            Assert.Null(validationResult.Result);
            Assert.NotNull(validationResult.Error);
            Assert.IsType<AudienceValidationError>(validationResult.Error);
            Assert.Contains("IDX10206", validationResult.Error.Message);
            // IDX10206: Unable to validate audience. The 'audiences' parameter is empty.
            // This message needs to be updated to specifiy that it was not specified in the ValidationParameters?
        }

        [Fact]
        public async Task TestTokenWithMissingIssuedAt()
        {
            string token = testTokenCreator.CreateTokenWithMissingIssuedAt();
            ValidationParameters validationParameters = new ValidationParameters()
            {
                ValidAudiences = ["http://Default.Audience.com"],
                ValidIssuers = ["http://Default.Issuer.com"],
                IssuerSigningKeys = [KeyingMaterial.JsonWebKeyRsa256SigningCredentials.Key]
            };
            CallContext callContext = new CallContext();

            ValidationResult<ValidatedToken> validationResult = await jsonWebTokenHandler.ValidateTokenAsync(token, validationParameters, callContext, default);

            Assert.True(validationResult.IsValid);
            Assert.NotNull(validationResult.Result);
            Assert.Null(validationResult.Error);
            // The iat claim is optional.
        }

        [Fact]
        public async Task TestTokenWithMissingNotBefore()
        {
            string token = testTokenCreator.CreateTokenWithMissingNotBefore();
            ValidationParameters validationParameters = new ValidationParameters()
            {
                ValidAudiences = ["http://Default.Audience.com"],
                ValidIssuers = ["http://Default.Issuer.com"],
                IssuerSigningKeys = [KeyingMaterial.JsonWebKeyRsa256SigningCredentials.Key]
            };
            CallContext callContext = new CallContext();

            ValidationResult<ValidatedToken> validationResult = await jsonWebTokenHandler.ValidateTokenAsync(token, validationParameters, callContext, default);

            Assert.True(validationResult.IsValid);
            Assert.NotNull(validationResult.Result);
            Assert.Null(validationResult.Error);
            // The nbf claim is optional.
        }

        [Fact]
        public async Task TestTokenWithMissingExpires()
        {
            string token = testTokenCreator.CreateTokenWithMissingExpires();
            ValidationParameters validationParameters = new ValidationParameters()
            {
                ValidAudiences = ["http://Default.Audience.com"],
                ValidIssuers = ["http://Default.Issuer.com"],
                IssuerSigningKeys = [KeyingMaterial.JsonWebKeyRsa256SigningCredentials.Key]
            };
            CallContext callContext = new CallContext();

            ValidationResult<ValidatedToken> validationResult = await jsonWebTokenHandler.ValidateTokenAsync(token, validationParameters, callContext, default);

            Assert.False(validationResult.IsValid);
            Assert.Null(validationResult.Result);
            Assert.NotNull(validationResult.Error);
            Assert.IsType<LifetimeValidationError>(validationResult.Error);
            Assert.Contains("IDX10225", validationResult.Error.Message);
            // IDX10225: Lifetime validation failed. The token is missing an Expiration Time. Tokentype: 'Microsoft.IdentityModel.JsonWebTokens.JsonWebToken'.
        }

        [Fact]
        public async Task TestTokenWithMissingKey()
        {
            string token = testTokenCreator.CreateTokenWithMissingKey();
            ValidationParameters validationParameters = new ValidationParameters()
            {
                ValidAudiences = ["http://Default.Audience.com"],
                ValidIssuers = ["http://Default.Issuer.com"],
                IssuerSigningKeys = [KeyingMaterial.JsonWebKeyRsa256SigningCredentials.Key]
            };
            CallContext callContext = new CallContext();

            ValidationResult<ValidatedToken> validationResult = await jsonWebTokenHandler.ValidateTokenAsync(token, validationParameters, callContext, default);

            Assert.False(validationResult.IsValid);
            Assert.Null(validationResult.Result);
            Assert.NotNull(validationResult.Error);
            Assert.IsType<SignatureValidationError>(validationResult.Error);
            Assert.Contains("IDX10504", validationResult.Error.Message);
            // IDX10504: Unable to validate signature, token does not have a signature: '[PII of type 'Microsoft.IdentityModel.Logging.SecurityArtifact' is hidden. For more details, see https://aka.ms/IdentityModel/PII.]'.
        }
    }
}
