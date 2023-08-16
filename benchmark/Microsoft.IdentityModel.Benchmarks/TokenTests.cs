// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System.Security.Claims;
using BenchmarkDotNet.Attributes;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using Microsoft.IdentityModel.TestUtils;

namespace Microsoft.IdentityModel.Benchmarks
{
    public class JsonWebTokenTests
    {

        JsonWebTokenHandler tokenHandler;
        SecurityTokenDescriptor tokenDescriptor;
        string token;
        TokenValidationParameters validationParameters;

        [GlobalSetup(Targets = new[] { nameof(ValidateToken) })]
        public void ValidateTokenSetup()
        {
            tokenHandler = new JsonWebTokenHandler();
            tokenDescriptor = new SecurityTokenDescriptor
            {
                Subject = new ClaimsIdentity(Default.PayloadClaims),
                SigningCredentials = KeyingMaterial.JsonWebKeyRsa256SigningCredentials,
            };
            token = tokenHandler.CreateToken(tokenDescriptor);
            validationParameters = new TokenValidationParameters()
            {
                ValidAudience = "http://Default.Audience.com",
                ValidateLifetime = false,
                ValidIssuer = "http://Default.Issuer.com",
                IssuerSigningKey = KeyingMaterial.JsonWebKeyRsa256SigningCredentials.Key,
            };
        }

        [Benchmark]
        public TokenValidationResult ValidateToken() => tokenHandler.ValidateToken(token, validationParameters);
    }
}
