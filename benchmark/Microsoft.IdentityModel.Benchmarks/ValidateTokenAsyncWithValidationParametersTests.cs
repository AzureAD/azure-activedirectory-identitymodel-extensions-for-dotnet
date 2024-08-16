﻿// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;
using BenchmarkDotNet.Attributes;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using System;

namespace Microsoft.IdentityModel.Benchmarks
{
    // dotnet run -c release -f net8.0 --filter Microsoft.IdentityModel.Benchmarks.ValidateTokenAsyncWithVPTests*

    public class ValidateTokenAsyncWithVPTests
    {
        private CallContext _callContext;
        private JsonWebTokenHandler _jsonWebTokenHandler;
        private SecurityTokenDescriptor _tokenDescriptor;
        private SecurityTokenDescriptor _tokenDescriptorExtendedClaims;
        private string _jws;
        private string _jwsExtendedClaims;
        private TokenValidationParameters _tokenValidationParameters;
        private ValidationParameters _validationParameters;
        private TokenValidationParameters _invalidTokenValidationParameters;
        private ValidationParameters _invalidValidationParameters;

        [GlobalSetup]
        public void Setup()
        {
            _tokenDescriptor = new SecurityTokenDescriptor
            {
                Claims = BenchmarkUtils.Claims,
                SigningCredentials = BenchmarkUtils.SigningCredentialsRsaSha256,
            };

            _tokenDescriptorExtendedClaims = new SecurityTokenDescriptor
            {
                Claims = BenchmarkUtils.ClaimsExtendedExample,
                SigningCredentials = BenchmarkUtils.SigningCredentialsRsaSha256,
            };

            _jsonWebTokenHandler = new JsonWebTokenHandler();
            _jws = _jsonWebTokenHandler.CreateToken(_tokenDescriptor);
            _jwsExtendedClaims = _jsonWebTokenHandler.CreateToken(_tokenDescriptorExtendedClaims);

            _validationParameters = new ValidationParameters();
            _validationParameters.ValidAudiences.Add(BenchmarkUtils.Audience);
            _validationParameters.ValidIssuers.Add(BenchmarkUtils.Issuer);
            _validationParameters.IssuerSigningKeys.Add(BenchmarkUtils.SigningCredentialsRsaSha256.Key);

            _invalidValidationParameters = new ValidationParameters();
            _invalidValidationParameters.ValidAudiences.Add(BenchmarkUtils.Audience);
            _invalidValidationParameters.ValidIssuers.Add(BenchmarkUtils.Issuer);

            _callContext = new CallContext();

            _tokenValidationParameters = new TokenValidationParameters()
            {
                ValidAudience = BenchmarkUtils.Audience,
                ValidateLifetime = true,
                ValidIssuer = BenchmarkUtils.Issuer,
                IssuerSigningKey = BenchmarkUtils.SigningCredentialsRsaSha256.Key,
                ValidateIssuerSigningKey = true,
                ValidateTokenReplay = true,
                RequireSignedTokens = true,
                ValidateSignatureLast = true
            };

            _invalidTokenValidationParameters = new TokenValidationParameters()
            {
                ValidAudience = BenchmarkUtils.Audience,
                ValidateLifetime = true,
                ValidIssuer = BenchmarkUtils.Issuer,
                ValidateIssuerSigningKey = true,
                ValidateTokenReplay = true,
                ValidateSignatureLast = true
            };
        }

        [Benchmark]
        public async Task<TokenValidationResult> JsonWebTokenHandler_01_ValidateTokenAsyncWithTVP() => await _jsonWebTokenHandler.ValidateTokenAsync(_jwsExtendedClaims, _tokenValidationParameters).ConfigureAwait(false);

        [Benchmark]
        public async Task<TokenValidationResult> JsonWebTokenHandler_02_ValidateTokenAsyncWithTVPUsingClone() => await _jsonWebTokenHandler.ValidateTokenAsync(_jwsExtendedClaims, _tokenValidationParameters.Clone()).ConfigureAwait(false);

        [Benchmark]
        public async Task<TokenValidationResult> JsonWebTokenHandler_03_ValidateTokenAsyncWithVP() => await _jsonWebTokenHandler.ValidateTokenAsync(_jwsExtendedClaims, _validationParameters, _callContext, null).ConfigureAwait(false);

        [Benchmark]
        public async Task<TokenValidationResult> JsonWebTokenHandler_04_ValidateTokenAsyncWithTVP_SucceedOnThirdAttempt()
        {
            TokenValidationResult result = await _jsonWebTokenHandler.ValidateTokenAsync(_jwsExtendedClaims, _invalidTokenValidationParameters).ConfigureAwait(false);
            result = await _jsonWebTokenHandler.ValidateTokenAsync(_jwsExtendedClaims, _invalidTokenValidationParameters).ConfigureAwait(false);
            result = await _jsonWebTokenHandler.ValidateTokenAsync(_jwsExtendedClaims, _tokenValidationParameters).ConfigureAwait(false);

            return result;
        }

        [Benchmark]
        public async Task<TokenValidationResult> JsonWebTokenHandler_05_ValidateTokenAsyncWithTVPUsingClone_SucceedOnThirdAttempt()
        {
            TokenValidationResult result = await _jsonWebTokenHandler.ValidateTokenAsync(_jwsExtendedClaims, _invalidTokenValidationParameters.Clone()).ConfigureAwait(false);
            result = await _jsonWebTokenHandler.ValidateTokenAsync(_jwsExtendedClaims, _invalidTokenValidationParameters.Clone()).ConfigureAwait(false);
            result = await _jsonWebTokenHandler.ValidateTokenAsync(_jwsExtendedClaims, _tokenValidationParameters.Clone()).ConfigureAwait(false);

            return result;
        }

        [Benchmark]
        public async Task<TokenValidationResult> JsonWebTokenHandler_06_ValidateTokenAsyncWithVP_SucceedOnThirdAttempt()
        {
            var result = await _jsonWebTokenHandler.ValidateTokenAsync(_jwsExtendedClaims, _invalidValidationParameters, _callContext, null).ConfigureAwait(false);
            result = await _jsonWebTokenHandler.ValidateTokenAsync(_jwsExtendedClaims, _invalidValidationParameters, _callContext, null).ConfigureAwait(false);
            return await _jsonWebTokenHandler.ValidateTokenAsync(_jwsExtendedClaims, _validationParameters, _callContext, null).ConfigureAwait(false);
        }

        [Benchmark]
        public async Task<TokenValidationResult> JsonWebTokenHandler_07_ValidateTokenAsyncWithTVP_SucceedOnFifthAttempt()
        {
            TokenValidationResult result = await _jsonWebTokenHandler.ValidateTokenAsync(_jwsExtendedClaims, _invalidTokenValidationParameters).ConfigureAwait(false);
            result = await _jsonWebTokenHandler.ValidateTokenAsync(_jwsExtendedClaims, _invalidTokenValidationParameters).ConfigureAwait(false);
            result = await _jsonWebTokenHandler.ValidateTokenAsync(_jwsExtendedClaims, _invalidTokenValidationParameters).ConfigureAwait(false);
            result = await _jsonWebTokenHandler.ValidateTokenAsync(_jwsExtendedClaims, _invalidTokenValidationParameters).ConfigureAwait(false);
            result = await _jsonWebTokenHandler.ValidateTokenAsync(_jwsExtendedClaims, _tokenValidationParameters).ConfigureAwait(false);

            return result;
        }

        [Benchmark]
        public async Task<TokenValidationResult> JsonWebTokenHandler_08_ValidateTokenAsyncWithTVPUsingClone_SucceedOnFifthAttempt()
        {
            TokenValidationResult result = await _jsonWebTokenHandler.ValidateTokenAsync(_jwsExtendedClaims, _invalidTokenValidationParameters.Clone()).ConfigureAwait(false);
            result = await _jsonWebTokenHandler.ValidateTokenAsync(_jwsExtendedClaims, _invalidTokenValidationParameters.Clone()).ConfigureAwait(false);
            result = await _jsonWebTokenHandler.ValidateTokenAsync(_jwsExtendedClaims, _invalidTokenValidationParameters.Clone()).ConfigureAwait(false);
            result = await _jsonWebTokenHandler.ValidateTokenAsync(_jwsExtendedClaims, _invalidTokenValidationParameters.Clone()).ConfigureAwait(false);
            result = await _jsonWebTokenHandler.ValidateTokenAsync(_jwsExtendedClaims, _tokenValidationParameters.Clone()).ConfigureAwait(false);

            return result;
        }

        [Benchmark]
        public async Task<TokenValidationResult> JsonWebTokenHandler_09_ValidateTokenAsyncWithVP_SucceedOnFifthAttempt()
        {
            var result = await _jsonWebTokenHandler.ValidateTokenAsync(_jwsExtendedClaims, _invalidValidationParameters, _callContext, null).ConfigureAwait(false);
            result = await _jsonWebTokenHandler.ValidateTokenAsync(_jwsExtendedClaims, _invalidValidationParameters, _callContext, null).ConfigureAwait(false);
            result = await _jsonWebTokenHandler.ValidateTokenAsync(_jwsExtendedClaims, _invalidValidationParameters, _callContext, null).ConfigureAwait(false);
            result = await _jsonWebTokenHandler.ValidateTokenAsync(_jwsExtendedClaims, _invalidValidationParameters, _callContext, null).ConfigureAwait(false);
            return await _jsonWebTokenHandler.ValidateTokenAsync(_jwsExtendedClaims, _validationParameters, _callContext, null).ConfigureAwait(false);
        }

        [Benchmark]
        public async Task<List<Claim>> JsonWebTokenHandler_10_ValidateTokenAsyncWithTVP_CreateClaims()
        {
            var result = await _jsonWebTokenHandler.ValidateTokenAsync(_jwsExtendedClaims, _tokenValidationParameters.Clone()).ConfigureAwait(false);
            var claimsIdentity = result.ClaimsIdentity;
            var claims = claimsIdentity.Claims;
            return claims.ToList();
        }

        [Benchmark]
        public async Task<List<Claim>> JsonWebTokenHandler_11_ValidateTokenAsyncWithVP_CreateClaims()
        {
            var result = await _jsonWebTokenHandler.ValidateTokenAsync(_jwsExtendedClaims, _validationParameters, _callContext, null).ConfigureAwait(false);
            var claimsIdentity = result.ClaimsIdentity;
            var claims = claimsIdentity.Claims;
            return claims.ToList();
        }
    }
}
