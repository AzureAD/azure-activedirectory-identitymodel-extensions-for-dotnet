// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System;
using System.Threading.Tasks;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;

namespace Microsoft.IdentityModel.Benchmarks
{
    public class ProfilerRuns
    {
        ReadOnlyMemory<char> _encodedJWSAsMemory;
        private JsonWebTokenHandler _jsonWebTokenHandler;
        private SecurityTokenDescriptor _tokenDescriptorExtendedClaims;
        private string _jwsExtendedClaims;
        private TokenValidationParameters _tokenValidationParameters;

        public ProfilerRuns()
        {
            var jsonWebTokenHandler = new JsonWebTokenHandler();
            var jwsTokenDescriptor = new SecurityTokenDescriptor
            {
                SigningCredentials = BenchmarkUtils.SigningCredentialsRsaSha256,
                TokenType = JwtHeaderParameterNames.Jwk,
                Claims = BenchmarkUtils.Claims
            };

            var encodedJWS = jsonWebTokenHandler.CreateToken(jwsTokenDescriptor);
            _encodedJWSAsMemory = encodedJWS.AsMemory();

            _tokenDescriptorExtendedClaims = new SecurityTokenDescriptor
            {
                Claims = BenchmarkUtils.ClaimsExtendedExample,
                SigningCredentials = BenchmarkUtils.SigningCredentialsRsaSha256,
            };

            _jsonWebTokenHandler = new JsonWebTokenHandler();
            _jwsExtendedClaims = _jsonWebTokenHandler.CreateToken(_tokenDescriptorExtendedClaims);

            _tokenValidationParameters = new TokenValidationParameters()
            { 
                ValidAudience = BenchmarkUtils.Audience,
                ValidateLifetime = true,
                ValidIssuer = BenchmarkUtils.Issuer,
                IssuerSigningKey = BenchmarkUtils.SigningCredentialsRsaSha256.Key,
            };
        }

        public void ReadJws()
        {
            JsonWebToken jwt;

            for (int i = 0; i < 1000; i++)
            {
                jwt = new JsonWebToken(_encodedJWSAsMemory);
            }
        }

        public async Task ValidateJws()
        {
            TokenValidationResult tokenValidationResult;

            for (int i = 0; i < 1000; i++)
            {
                tokenValidationResult = await _jsonWebTokenHandler.ValidateTokenAsync(_jwsExtendedClaims, _tokenValidationParameters).ConfigureAwait(false);
            }
        }
    }
}
