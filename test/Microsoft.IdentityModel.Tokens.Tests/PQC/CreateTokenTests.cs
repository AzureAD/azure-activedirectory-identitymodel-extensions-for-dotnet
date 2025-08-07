// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System.Collections.Generic;
using System.Security.Cryptography;
using System.Threading.Tasks;
using Microsoft.IdentityModel.JsonWebTokens;
using Xunit;

namespace Microsoft.IdentityModel.Tokens.PQC.Tests
{
    /// <summary>
    /// This class tests integration with SymCrypt
    /// </summary>
    public class CreateTokenTests
    {
        /// <summary>
        /// Signs and Validates a JsonWebToken with MLDSA.
        /// </summary>
        [Fact]
        public async Task SignAndValidateJsonWebToken()
        {
            ECDsa ecdsa = null;
            Mldsa mldsa = null;
            RSA rsa = null;
            try
            {
                ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
                mldsa = Mldsa.Create(SecurityAlgorithms.Mldsa44);
                rsa = RSA.Create(2048);

                MldsaSecurityKey mldsaKey = new MldsaSecurityKey(mldsa);

                SecurityTokenDescriptor securityTokenDescriptor = new SecurityTokenDescriptor
                {
                    Issuer = "https://localhost:5001",
                    Audience = "https://localhost:5001",
                    SigningCredentials = new SigningCredentials(mldsaKey, SecurityAlgorithms.Mldsa44),
                    Claims = new Dictionary<string, object>
                {
                    { "sub", "1234567890" },
                    { "name", "John Doe" },
                    { "admin", true }
                },
                };

                JsonWebTokenHandler jsonWebTokenHandler = new JsonWebTokenHandler();
                string token = jsonWebTokenHandler.CreateToken(securityTokenDescriptor);
                JsonWebToken jsonWebToken = new JsonWebToken(token);


                TokenValidationParameters tokenValidationParameters = new TokenValidationParameters
                {
                    ValidIssuer = "https://localhost:5001",
                    ValidAudience = "https://localhost:5001"
                };

                tokenValidationParameters.ConfigurationManager = PQCTestUtilities.GetStaticConfiguration(
                    ecdsa,
                    rsa,
                    mldsa,
                    tokenValidationParameters.ValidIssuer,
                    "https://localhost:5001/.well-known/openid-configuration/jwks",
                    "https://localhost:5001/.well-known/openid-configuration");

                // Validate the token
                TokenValidationResult validationResult = await jsonWebTokenHandler.ValidateTokenAsync(token, tokenValidationParameters);
            }
            finally
            {
                ecdsa?.Dispose();
                rsa?.Dispose();
                mldsa?.Dispose();
            }
        }
    }
}
