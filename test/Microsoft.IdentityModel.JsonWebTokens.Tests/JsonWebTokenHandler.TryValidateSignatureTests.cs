// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System;
using System.Threading.Tasks;
using Microsoft.IdentityModel.TestUtils;
using Microsoft.IdentityModel.Tokens;
using Xunit;

namespace Microsoft.IdentityModel.JsonWebTokens.Tests
{
    public class JsonWebTokenHandlerTryValidateSignatureTests
    {
        [Fact]
        public void TryValidateSignature_ValidSignature_ReturnsTrue()
        {
            var handler = new JsonWebTokenHandler();
            var descriptor = new SecurityTokenDescriptor
            {
                SigningCredentials = new SigningCredentials(
                    KeyingMaterial.RsaSecurityKey_2048, SecurityAlgorithms.RsaSha256),
                Issuer = "https://test-issuer.example.com"
            };

            var tokenString = handler.CreateToken(descriptor);
            var jsonWebToken = new JsonWebToken(tokenString);

            var tvp = new TokenValidationParameters
            {
                ValidateIssuer = false,
                ValidateAudience = false,
                ValidateLifetime = false
            };

            bool result = handler.TryValidateSignature(
                jsonWebToken,
                KeyingMaterial.RsaSecurityKey_2048,
                tvp);

            Assert.True(result);
        }

        [Fact]
        public void TryValidateSignature_WrongKey_ReturnsFalse()
        {
            var handler = new JsonWebTokenHandler();
            var descriptor = new SecurityTokenDescriptor
            {
                SigningCredentials = new SigningCredentials(
                    KeyingMaterial.RsaSecurityKey_2048, SecurityAlgorithms.RsaSha256),
                Issuer = "https://test-issuer.example.com"
            };

            var tokenString = handler.CreateToken(descriptor);
            var jsonWebToken = new JsonWebToken(tokenString);

            var tvp = new TokenValidationParameters
            {
                ValidateIssuer = false,
                ValidateAudience = false,
                ValidateLifetime = false
            };

            // Use a different key — signature should not match
            bool result = handler.TryValidateSignature(
                jsonWebToken,
                KeyingMaterial.RsaSecurityKey_4096,
                tvp);

            Assert.False(result);
        }

        [Fact]
        public void TryValidateSignature_EcdsaKey_ReturnsTrue()
        {
            var handler = new JsonWebTokenHandler();
            var descriptor = new SecurityTokenDescriptor
            {
                SigningCredentials = new SigningCredentials(
                    KeyingMaterial.Ecdsa256Key, SecurityAlgorithms.EcdsaSha256),
                Issuer = "https://test-issuer.example.com"
            };

            var tokenString = handler.CreateToken(descriptor);
            var jsonWebToken = new JsonWebToken(tokenString);

            var tvp = new TokenValidationParameters
            {
                ValidateIssuer = false,
                ValidateAudience = false,
                ValidateLifetime = false
            };

            bool result = handler.TryValidateSignature(
                jsonWebToken,
                KeyingMaterial.Ecdsa256Key,
                tvp);

            Assert.True(result);
        }

        [Fact]
        public void TryValidateSignature_NullToken_ThrowsArgumentNullException()
        {
            var handler = new JsonWebTokenHandler();
            var tvp = new TokenValidationParameters();

            Assert.Throws<ArgumentNullException>(() =>
                handler.TryValidateSignature(null, KeyingMaterial.RsaSecurityKey_2048, tvp));
        }

        [Fact]
        public void TryValidateSignature_NullKey_ThrowsArgumentNullException()
        {
            var handler = new JsonWebTokenHandler();
            var tokenString = handler.CreateToken(new SecurityTokenDescriptor
            {
                SigningCredentials = new SigningCredentials(
                    KeyingMaterial.RsaSecurityKey_2048, SecurityAlgorithms.RsaSha256)
            });
            var jsonWebToken = new JsonWebToken(tokenString);
            var tvp = new TokenValidationParameters();

            Assert.Throws<ArgumentNullException>(() =>
                handler.TryValidateSignature(jsonWebToken, null, tvp));
        }

        [Fact]
        public void TryValidateSignature_NullValidationParameters_ThrowsArgumentNullException()
        {
            var handler = new JsonWebTokenHandler();
            var tokenString = handler.CreateToken(new SecurityTokenDescriptor
            {
                SigningCredentials = new SigningCredentials(
                    KeyingMaterial.RsaSecurityKey_2048, SecurityAlgorithms.RsaSha256)
            });
            var jsonWebToken = new JsonWebToken(tokenString);

            Assert.Throws<ArgumentNullException>(() =>
                handler.TryValidateSignature(jsonWebToken, KeyingMaterial.RsaSecurityKey_2048, null));
        }

        [Fact]
        public void TryValidateSignature_AlgorithmMismatch_ReturnsFalse()
        {
            var handler = new JsonWebTokenHandler();
            var descriptor = new SecurityTokenDescriptor
            {
                SigningCredentials = new SigningCredentials(
                    KeyingMaterial.RsaSecurityKey_2048, SecurityAlgorithms.RsaSha256),
                Issuer = "https://test-issuer.example.com"
            };

            var tokenString = handler.CreateToken(descriptor);
            var jsonWebToken = new JsonWebToken(tokenString);

            var tvp = new TokenValidationParameters
            {
                ValidateIssuer = false,
                ValidateAudience = false,
                ValidateLifetime = false
            };

            // ECDSA key can't verify RSA signature
            bool result = handler.TryValidateSignature(
                jsonWebToken,
                KeyingMaterial.Ecdsa256Key,
                tvp);

            Assert.False(result);
        }

        [Fact]
        public async Task TryValidateSignature_UsedWithinSignatureValidatorDelegate()
        {
            var handler = new JsonWebTokenHandler();
            var signingKey = KeyingMaterial.RsaSecurityKey_2048;

            var tokenString = handler.CreateToken(new SecurityTokenDescriptor
            {
                SigningCredentials = new SigningCredentials(signingKey, SecurityAlgorithms.RsaSha256),
                Issuer = "https://test-issuer.example.com",
                Audience = "https://test-audience.example.com"
            });

            // Set up a SignatureValidatorWithToken delegate that calls back
            // via TryValidateSignature, simulating a delegate that handles some algorithms
            // directly and falls back to the handler for others.
            var tvp = new TokenValidationParameters
            {
                ValidIssuer = "https://test-issuer.example.com",
                ValidAudience = "https://test-audience.example.com",
                IssuerSigningKey = signingKey,
                ValidateLifetime = false,
                SignatureValidatorWithToken = (token, validationParameters, configuration) =>
                {
                    var jwt = (JsonWebToken)token;
                    var key = validationParameters.IssuerSigningKey;

                    if (!handler.TryValidateSignature(jwt, key, validationParameters))
                        throw new SecurityTokenInvalidSignatureException("Signature validation failed.");

                    jwt.SigningKey = key;
                    return jwt;
                }
            };

            var result = await handler.ValidateTokenAsync(tokenString, tvp);
            Assert.True(result.IsValid, $"Validation failed: {result.Exception?.Message}");
        }
    }
}
