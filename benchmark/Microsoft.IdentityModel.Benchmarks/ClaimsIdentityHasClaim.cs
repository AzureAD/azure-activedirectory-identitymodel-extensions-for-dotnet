// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System.Threading.Tasks;
using BenchmarkDotNet.Attributes;
using BenchmarkDotNet.Configs;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens.Saml2;
using Microsoft.IdentityModel.Tokens;
using System.Security.Claims;
using System.Collections.Generic;

namespace Microsoft.IdentityModel.Benchmarks
{
    // dotnet run -c release -f net8.0 --filter Microsoft.IdentityModel.Benchmarks.ClaimsIdentityHasClaim*

    [GroupBenchmarksBy(BenchmarkLogicalGroupRule.ByCategory)]
    public class ClaimsIdentityHasClaim
    {
        private CallContext _callContext;
        private JsonWebTokenHandler _jsonWebTokenHandler;
        private Saml2SecurityTokenHandler _saml2SecurityTokenHandler;
        private JsonWebTokenHandler _jsonWebTokenHandlerTokenSpecificClaimsIdentity;
        private Saml2SecurityTokenHandler _saml2SecurityTokenHandlerTokenSpecificClaimsIdentity;
        private SecurityTokenDescriptor _jwtTokenDescriptor;
        private SecurityTokenDescriptor _saml2TokenDescriptor;
        private string _jws;
        private string _saml2;
        private TokenValidationParameters _tokenValidationParameters;

        [GlobalSetup]
        public void Setup()
        {
            _jwtTokenDescriptor = new SecurityTokenDescriptor
            {
                Claims = BenchmarkUtils.Claims,
                Issuer = BenchmarkUtils.Issuer,
                SigningCredentials = BenchmarkUtils.SigningCredentialsRsaSha256,
            };

            _saml2TokenDescriptor = new SecurityTokenDescriptor
            {
                Audience = BenchmarkUtils.Audience,
                Claims = BenchmarkUtils.Claims,
                Issuer = BenchmarkUtils.Issuer,
                Subject = new CaseSensitiveClaimsIdentity(new List<Claim> { new Claim(ClaimTypes.NameIdentifier, "bob") }, "Federation"),
                SigningCredentials = BenchmarkUtils.SigningCredentialsRsaSha256,
            };

            _jsonWebTokenHandler = new JsonWebTokenHandler();
            _saml2SecurityTokenHandler = new Saml2SecurityTokenHandler();
            _jsonWebTokenHandlerTokenSpecificClaimsIdentity = new JsonWebTokenHandler();
            _jsonWebTokenHandlerTokenSpecificClaimsIdentity.UseTokenSpecificClaimsIdentity = true;
            _saml2SecurityTokenHandlerTokenSpecificClaimsIdentity = new Saml2SecurityTokenHandler();
            _saml2SecurityTokenHandlerTokenSpecificClaimsIdentity.UseTokenSpecificClaimsIdentity = true;

            _jws = _jsonWebTokenHandler.CreateToken(_jwtTokenDescriptor);
            SecurityToken saml2SecurityToken = _saml2SecurityTokenHandler.CreateToken(_saml2TokenDescriptor);
            _saml2 = _saml2SecurityTokenHandler.WriteToken(saml2SecurityToken);

            _tokenValidationParameters = new TokenValidationParameters()
            {
                ValidAudience = BenchmarkUtils.Audience,
                ValidateLifetime = true,
                ValidIssuer = BenchmarkUtils.Issuer,
                IssuerSigningKey = BenchmarkUtils.SigningCredentialsRsaSha256.Key,
            };

            _callContext = new CallContext();
        }

        [Benchmark]
        public async Task<bool> JsonWebToken_HasClaim()
        {
            TokenValidationResult tokenValidationResult = await _jsonWebTokenHandler.ValidateTokenAsync(_jws, _tokenValidationParameters).ConfigureAwait(false);
            return tokenValidationResult.ClaimsIdentity.HasClaim("given_name", "Bob");
        }

        [Benchmark]
        public async Task<bool> JsonWebToken_Has4Claims()
        {
            TokenValidationResult tokenValidationResult = await _jsonWebTokenHandler.ValidateTokenAsync(_jws, _tokenValidationParameters).ConfigureAwait(false);
            for (int i = 0; i < 4; i++)
                tokenValidationResult.ClaimsIdentity.HasClaim("given_name", "Bob");

            return tokenValidationResult.ClaimsIdentity.HasClaim("given_name", "Bob");
        }

        [Benchmark]
        public async Task<bool> Saml2Token_HasClaim()
        {
            TokenValidationResult tokenValidationResult = await _saml2SecurityTokenHandler.ValidateTokenAsync(_saml2, _tokenValidationParameters).ConfigureAwait(false);
            return tokenValidationResult.ClaimsIdentity.HasClaim("given_name", "Bob");
        }

        [Benchmark]
        public async Task<bool> JsonWebToken_HasClaim_TokenSpecific()
        {
            TokenValidationResult tokenValidationResult = await _jsonWebTokenHandlerTokenSpecificClaimsIdentity.ValidateTokenAsync(_jws, _tokenValidationParameters).ConfigureAwait(false);
            return tokenValidationResult.ClaimsIdentity.HasClaim("given_name", "Bob");
        }

        [Benchmark]
        public async Task<bool> JsonWebToken_Has4Claims_TokenSpecific()
        {
            TokenValidationResult tokenValidationResult = await _jsonWebTokenHandlerTokenSpecificClaimsIdentity.ValidateTokenAsync(_jws, _tokenValidationParameters).ConfigureAwait(false);
            for (int i = 0; i < 4; i++)
                tokenValidationResult.ClaimsIdentity.HasClaim("given_name", "Bob");

            return tokenValidationResult.ClaimsIdentity.HasClaim("given_name", "Bob");
        }

        [Benchmark]
        public async Task<bool> Saml2Token_HasClaim_TokenSpecific()
        {
            TokenValidationResult tokenValidationResult = await _saml2SecurityTokenHandlerTokenSpecificClaimsIdentity.ValidateTokenAsync(_saml2, _tokenValidationParameters).ConfigureAwait(false);
            return tokenValidationResult.ClaimsIdentity.HasClaim("given_name", "Bob");
        }
    }
}
