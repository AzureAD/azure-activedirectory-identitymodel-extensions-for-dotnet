// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using System.Threading;
using BenchmarkDotNet.Attributes;
using BenchmarkDotNet.Configs;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using Microsoft.IdentityModel.Tokens.Experimental;

#pragma warning disable CS0618 // Type or member is obsolete

namespace Microsoft.IdentityModel.Benchmarks
{
    // dotnet run -c release -f net8.0 --filter Microsoft.IdentityModel.Benchmarks.ValidateTokenSyncTests*

    [GroupBenchmarksBy(BenchmarkLogicalGroupRule.ByCategory)]
    public class ValidateTokenSyncTests
    {
        private CallContext _callContext;
        private JsonWebTokenHandler _jsonWebTokenHandler;
        private JwtSecurityTokenHandler _jwtSecurityTokenHandler;
        private SecurityTokenDescriptor _tokenDescriptor;
        private SecurityTokenDescriptor _tokenDescriptorExtendedClaims;
        private string _jws;
        private string _jwsExtendedClaims;
        private TokenValidationParameters _tokenValidationParameters;
        private TokenValidationParameters _invalidTokenValidationParameters;
        private ValidationParameters _validationParameters;
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

            _jwtSecurityTokenHandler = new JwtSecurityTokenHandler();
            _jwtSecurityTokenHandler.SetDefaultTimesOnTokenCreation = false;

            _tokenValidationParameters = new TokenValidationParameters()
            {
                ValidAudience = BenchmarkUtils.Audience,
                ValidateLifetime = true,
                ValidIssuer = BenchmarkUtils.Issuer,
                IssuerSigningKey = BenchmarkUtils.SigningCredentialsRsaSha256.Key,
            };

            _validationParameters = new ValidationParameters();
            _validationParameters.ValidAudiences.Add(BenchmarkUtils.Audience);
            _validationParameters.ValidIssuers.Add(BenchmarkUtils.Issuer);
            _validationParameters.SigningKeys.Add(BenchmarkUtils.SigningCredentialsRsaSha256.Key);

            _invalidTokenValidationParameters = new TokenValidationParameters()
            {
                ValidAudience = BenchmarkUtils.Audience,
                ValidateLifetime = true,
                ValidIssuer = BenchmarkUtils.Issuer,
                ValidateIssuerSigningKey = true,
                ValidateTokenReplay = true,
                ValidateSignatureLast = true
            };

            _invalidValidationParameters = new ValidationParameters();
            _invalidValidationParameters.ValidAudiences.Add(BenchmarkUtils.Audience);
            _invalidValidationParameters.ValidIssuers.Add(BenchmarkUtils.Issuer);

            _callContext = new CallContext();
        }

        [BenchmarkCategory("ValidateTokenSync_Success"), Benchmark]
        public bool JsonWebTokenHandler_ValidateTokenWithVP()
        {
            // Because ValidationResult is an internal type, we cannot return it in the benchmark.
            // We return a boolean instead until the type is made public.
            ValidationResult<ValidatedToken, ValidationError> validationResult = _jsonWebTokenHandler.ValidateToken(_jwsExtendedClaims, _validationParameters, _callContext, CancellationToken.None);
            return validationResult.Succeeded;
        }

        [BenchmarkCategory("ValidateTokenSync_Success"), Benchmark]
        public bool JsonWebTokenHandler_ValidateTokenWithTVP()
        {
            TokenValidationResult validationResult = _jsonWebTokenHandler.ValidateToken(_jwsExtendedClaims, _tokenValidationParameters);
            return validationResult.IsValid;
        }

        [BenchmarkCategory("ValidateTokenSync_FailTwiceBeforeSuccess"), Benchmark]
        public bool JsonWebTokenHandler_ValidateTokenWithVP_SucceedOnThirdAttempt()
        {
            ValidationResult<ValidatedToken, ValidationError> validationResult = _jsonWebTokenHandler.ValidateToken(_jwsExtendedClaims, _invalidValidationParameters, _callContext, CancellationToken.None);
            validationResult = _jsonWebTokenHandler.ValidateToken(_jwsExtendedClaims, _invalidValidationParameters, _callContext, CancellationToken.None);
            validationResult = _jsonWebTokenHandler.ValidateToken(_jwsExtendedClaims, _validationParameters, _callContext, CancellationToken.None);

            return validationResult.Succeeded;
        }

        [BenchmarkCategory("ValidateTokenSync_FailTwiceBeforeSuccess"), Benchmark]
        public bool JsonWebTokenHandler_ValidateTokenWithTVP_SucceedOnThirdAttempt()
        {
            TokenValidationResult validationResult = _jsonWebTokenHandler.ValidateToken(_jwsExtendedClaims, _invalidTokenValidationParameters);
            validationResult = _jsonWebTokenHandler.ValidateToken(_jwsExtendedClaims, _invalidTokenValidationParameters);
            validationResult = _jsonWebTokenHandler.ValidateToken(_jwsExtendedClaims, _tokenValidationParameters);

            return validationResult.IsValid;
        }

        [BenchmarkCategory("ValidateTokenSync_FailFourTimesBeforeSuccess"), Benchmark]
        public bool JsonWebTokenHandler_ValidateTokenWithVP_SucceedOnFifthAttempt()
        {
            ValidationResult<ValidatedToken, ValidationError> validationResult = _jsonWebTokenHandler.ValidateToken(_jwsExtendedClaims, _invalidValidationParameters, _callContext, CancellationToken.None);
            validationResult = _jsonWebTokenHandler.ValidateToken(_jwsExtendedClaims, _invalidValidationParameters, _callContext, CancellationToken.None);
            validationResult = _jsonWebTokenHandler.ValidateToken(_jwsExtendedClaims, _invalidValidationParameters, _callContext, CancellationToken.None);
            validationResult = _jsonWebTokenHandler.ValidateToken(_jwsExtendedClaims, _invalidValidationParameters, _callContext, CancellationToken.None);
            validationResult = _jsonWebTokenHandler.ValidateToken(_jwsExtendedClaims, _validationParameters, _callContext, CancellationToken.None);

            return validationResult.Succeeded;
        }

        [BenchmarkCategory("ValidateTokenSync_FailFourTimesBeforeSuccess"), Benchmark]
        public bool JsonWebTokenHandler_ValidateTokenWithTVP_SucceedOnFifthAttempt()
        {
            TokenValidationResult validationResult = _jsonWebTokenHandler.ValidateToken(_jwsExtendedClaims, _invalidTokenValidationParameters);
            validationResult = _jsonWebTokenHandler.ValidateToken(_jwsExtendedClaims, _invalidTokenValidationParameters);
            validationResult = _jsonWebTokenHandler.ValidateToken(_jwsExtendedClaims, _invalidTokenValidationParameters);
            validationResult = _jsonWebTokenHandler.ValidateToken(_jwsExtendedClaims, _invalidTokenValidationParameters);
            validationResult = _jsonWebTokenHandler.ValidateToken(_jwsExtendedClaims, _tokenValidationParameters);

            return validationResult.IsValid;
        }


        [BenchmarkCategory("ValidateTokenSyncClaimAccess"), Benchmark]
        public List<Claim> JsonWebTokenHandler_ValidateTokenWithVP_CreateClaims()
        {
            ValidationResult<ValidatedToken, ValidationError> validationResult = _jsonWebTokenHandler.ValidateToken(_jwsExtendedClaims, _validationParameters, _callContext, CancellationToken.None);
            var claimsIdentity = validationResult.Result.ClaimsIdentity;
            var claims = claimsIdentity.Claims;
            return claims.ToList();
        }

        [BenchmarkCategory("ValidateTokenSyncClaimAccess"), Benchmark]
        public List<Claim> JsonWebTokenHandler_ValidateTokenWithTVP_CreateClaims()
        {
            TokenValidationResult validationResult = _jsonWebTokenHandler.ValidateToken(_jwsExtendedClaims, _tokenValidationParameters);
            var claimsIdentity = validationResult.ClaimsIdentity;
            var claims = claimsIdentity.Claims;
            return claims.ToList();
        }
    }
}
#pragma warning restore CS0618 // Type or member is obsolete
