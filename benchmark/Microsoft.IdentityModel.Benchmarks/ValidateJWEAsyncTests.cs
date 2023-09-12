// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using BenchmarkDotNet.Attributes;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.TestUtils;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Threading.Tasks;

namespace Microsoft.IdentityModel.Benchmarks
{
    [Config(typeof(AntiVirusFriendlyConfig))]
    [HideColumns("Type", "Job", "WarmupCount", "LaunchCount")]
    [MemoryDiagnoser]
    public class ValidateJWEAsyncTests
    {
        JsonWebTokenHandler jsonWebTokenHandler;
        JwtSecurityTokenHandler jwtSecurityTokenHandler;
        SecurityTokenDescriptor tokenDescriptor;
        string jweFromJsonHandler;
        string jweFromJwtHandler;
        TokenValidationParameters validationParameters;

        [GlobalSetup]
        public void Setup()
        {
            jsonWebTokenHandler = new JsonWebTokenHandler();
            jwtSecurityTokenHandler = new JwtSecurityTokenHandler();
            tokenDescriptor = new SecurityTokenDescriptor
            {
                SigningCredentials = KeyingMaterial.JsonWebKeyRsa256SigningCredentials,
                EncryptingCredentials = KeyingMaterial.DefaultSymmetricEncryptingCreds_Aes256_Sha512_512,
                Subject = new ClaimsIdentity(Default.PayloadClaims),
                TokenType = "TokenType"
            };
            jweFromJsonHandler = jsonWebTokenHandler.CreateToken(tokenDescriptor);
            jweFromJwtHandler = jwtSecurityTokenHandler.CreateEncodedJwt(tokenDescriptor);
            validationParameters = new TokenValidationParameters
            {
                IssuerSigningKey = KeyingMaterial.JsonWebKeyRsa256SigningCredentials.Key,
                TokenDecryptionKey = KeyingMaterial.DefaultSymmetricSecurityKey_512,
                ValidAudience = Default.Audience,
                ValidIssuer = Default.Issuer
            };
        }

        [Benchmark]
        public async Task<TokenValidationResult> JsonWebTokenHandler_ValidateJWEAsync() => await jsonWebTokenHandler.ValidateTokenAsync(jweFromJsonHandler, validationParameters);

        [Benchmark]
        public ClaimsPrincipal JwtSecurityTokenHandler_ValidateJWEAsync() => jwtSecurityTokenHandler.ValidateToken(jweFromJwtHandler, validationParameters, out _);
    }
}
