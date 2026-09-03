// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using Microsoft.IdentityModel.TestUtils;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.IdentityModel.Tokens;
using Microsoft.IdentityModel.Tokens.Experimental;
using Xunit;

namespace Microsoft.IdentityModel.JsonWebTokens.Tests
{
    public class JsonWebTokenHandlerDecryptTokenDecryptionKeysTests
    {
        [Fact]
        public void GetContentEncryptionKeys_CombiningConfigurationKeys_DoesNotMutateValidationParameters()
        {
            // Arrange
            var handler = new JsonWebTokenHandler();
            var encryptingCredentials = new EncryptingCredentials(
                KeyingMaterial.RsaSecurityKey_2048,
                SecurityAlgorithms.RsaPKCS1,
                SecurityAlgorithms.Aes128CbcHmacSha256);
            string token = handler.CreateToken(new SecurityTokenDescriptor
            {
                SigningCredentials = KeyingMaterial.JsonWebKeyRsa256SigningCredentials,
                EncryptingCredentials = encryptingCredentials,
                Claims = Default.PayloadDictionary
            });

            var validationParameters = new ValidationParameters();
            validationParameters.DecryptionKeys.Add(
                new SymmetricSecurityKey(KeyingMaterial.DefaultSymmetricKeyBytes_256)
                {
                    KeyId = "UnmatchedKeyId"
                });

            var configuration = new OpenIdConnectConfiguration();
            configuration.TokenDecryptionKeys.Add(
                new SymmetricSecurityKey(KeyingMaterial.DefaultSymmetricKeyBytes_512)
                {
                    KeyId = "ConfigurationKeyId"
                });

            // Act
            handler.GetContentEncryptionKeys(
                new JsonWebToken(token),
                validationParameters,
                configuration,
                callContext: null);

            // Assert
            Assert.Single(validationParameters.DecryptionKeys);
            Assert.Equal("UnmatchedKeyId", validationParameters.DecryptionKeys[0].KeyId);
        }
    }
}
