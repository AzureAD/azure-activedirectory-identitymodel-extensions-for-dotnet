// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using BenchmarkDotNet.Attributes;
using BenchmarkDotNet.Configs;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Telemetry;
using Microsoft.IdentityModel.Tokens;

#pragma warning disable CS0618 // The legacy synchronous entry points are the benchmark targets.

namespace Microsoft.IdentityModel.Benchmarks
{
    // dotnet run -c release -f net8.0 --filter Microsoft.IdentityModel.Benchmarks.ValidateTokenSyncTests*

    [GroupBenchmarksBy(BenchmarkLogicalGroupRule.ByCategory)]
    public class ValidateTokenSyncTests
    {
        private JsonWebTokenHandler _jsonWebTokenHandler;
        private JwtSecurityTokenHandler _jwtSecurityTokenHandler;
        private string _jwsExtendedClaims;
        private TokenValidationParameters _tokenValidationParameters;
        private TokenValidationParameters _invalidTokenValidationParameters;

        [GlobalSetup]
        public void Setup()
        {
            var tokenDescriptorExtendedClaims = new SecurityTokenDescriptor
            {
                Claims = BenchmarkUtils.ClaimsExtendedExample,
                SigningCredentials = BenchmarkUtils.SigningCredentialsRsaSha256,
            };

            _jsonWebTokenHandler = new JsonWebTokenHandler();
            _jwsExtendedClaims = _jsonWebTokenHandler.CreateToken(tokenDescriptorExtendedClaims);

            _jwtSecurityTokenHandler = new JwtSecurityTokenHandler();
            _jwtSecurityTokenHandler.SetDefaultTimesOnTokenCreation = false;

            _tokenValidationParameters = new TokenValidationParameters
            {
                ValidAudience = BenchmarkUtils.Audience,
                ValidateLifetime = true,
                ValidIssuer = BenchmarkUtils.Issuer,
                IssuerSigningKey = BenchmarkUtils.SigningCredentialsRsaSha256.Key,
            };

            _invalidTokenValidationParameters = new TokenValidationParameters
            {
                ValidAudience = BenchmarkUtils.Audience,
                ValidateLifetime = true,
                ValidIssuer = BenchmarkUtils.Issuer,
                ValidateIssuerSigningKey = true,
                ValidateTokenReplay = true,
                ValidateSignatureLast = true,
            };
        }

        [BenchmarkCategory("ValidateTokenSync_Success"), Benchmark]
        public ClaimsPrincipal JwtSecurityTokenHandler_ValidateToken()
        {
            return _jwtSecurityTokenHandler.ValidateToken(
                _jwsExtendedClaims,
                _tokenValidationParameters,
                out _);
        }

        [BenchmarkCategory("ValidateTokenSync_Success"), Benchmark(Baseline = true)]
        public TokenValidationResult JsonWebTokenHandler_ValidateTokenWithTVP()
        {
            return _jsonWebTokenHandler.ValidateToken(_jwsExtendedClaims, _tokenValidationParameters);
        }

        [BenchmarkCategory("ValidateTokenSync_Success"), Benchmark]
        public TokenValidationResult JsonWebTokenHandler_ValidateTokenWithTVPUsingModifiedClone()
        {
            var tokenValidationParameters = _tokenValidationParameters.Clone();
            tokenValidationParameters.ValidIssuer = "different-issuer";
            tokenValidationParameters.ValidAudience = "different-audience";
            tokenValidationParameters.ValidateLifetime = false;
            return _jsonWebTokenHandler.ValidateToken(_jwsExtendedClaims, tokenValidationParameters);
        }

        [BenchmarkCategory("ValidateTokenSync_FailTwiceBeforeSuccess"), Benchmark(Baseline = true)]
        public TokenValidationResult JsonWebTokenHandler_ValidateTokenWithTVP_SucceedOnThirdAttempt()
        {
            TokenValidationResult result = _jsonWebTokenHandler.ValidateToken(_jwsExtendedClaims, _invalidTokenValidationParameters);
            result = _jsonWebTokenHandler.ValidateToken(_jwsExtendedClaims, _invalidTokenValidationParameters);
            result = _jsonWebTokenHandler.ValidateToken(_jwsExtendedClaims, _tokenValidationParameters);

            return result;
        }

        [BenchmarkCategory("ValidateTokenSync_FailTwiceBeforeSuccess"), Benchmark]
        public TokenValidationResult JsonWebTokenHandler_ValidateTokenWithTVPUsingClone_SucceedOnThirdAttempt()
        {
            TokenValidationResult result = _jsonWebTokenHandler.ValidateToken(_jwsExtendedClaims, _invalidTokenValidationParameters.Clone());
            result = _jsonWebTokenHandler.ValidateToken(_jwsExtendedClaims, _invalidTokenValidationParameters.Clone());
            result = _jsonWebTokenHandler.ValidateToken(_jwsExtendedClaims, _tokenValidationParameters.Clone());

            return result;
        }

        [BenchmarkCategory("ValidateTokenSync_FailFourTimesBeforeSuccess"), Benchmark(Baseline = true)]
        public TokenValidationResult JsonWebTokenHandler_ValidateTokenWithTVP_SucceedOnFifthAttempt()
        {
            TokenValidationResult result = _jsonWebTokenHandler.ValidateToken(_jwsExtendedClaims, _invalidTokenValidationParameters);
            result = _jsonWebTokenHandler.ValidateToken(_jwsExtendedClaims, _invalidTokenValidationParameters);
            result = _jsonWebTokenHandler.ValidateToken(_jwsExtendedClaims, _invalidTokenValidationParameters);
            result = _jsonWebTokenHandler.ValidateToken(_jwsExtendedClaims, _invalidTokenValidationParameters);
            result = _jsonWebTokenHandler.ValidateToken(_jwsExtendedClaims, _tokenValidationParameters);

            return result;
        }

        [BenchmarkCategory("ValidateTokenSync_FailFourTimesBeforeSuccess"), Benchmark]
        public TokenValidationResult JsonWebTokenHandler_ValidateTokenWithTVPUsingClone_SucceedOnFifthAttempt()
        {
            TokenValidationResult result = _jsonWebTokenHandler.ValidateToken(_jwsExtendedClaims, _invalidTokenValidationParameters.Clone());
            result = _jsonWebTokenHandler.ValidateToken(_jwsExtendedClaims, _invalidTokenValidationParameters.Clone());
            result = _jsonWebTokenHandler.ValidateToken(_jwsExtendedClaims, _invalidTokenValidationParameters.Clone());
            result = _jsonWebTokenHandler.ValidateToken(_jwsExtendedClaims, _invalidTokenValidationParameters.Clone());
            result = _jsonWebTokenHandler.ValidateToken(_jwsExtendedClaims, _tokenValidationParameters.Clone());

            return result;
        }

        [BenchmarkCategory("ValidateTokenSyncClaimAccess"), Benchmark]
        public List<Claim> JsonWebTokenHandler_ValidateTokenWithTVP_CreateClaims()
        {
            TokenValidationResult result = _jsonWebTokenHandler.ValidateToken(_jwsExtendedClaims, _tokenValidationParameters);
            return result.ClaimsIdentity.Claims.ToList();
        }
    }

    [GroupBenchmarksBy(BenchmarkLogicalGroupRule.ByCategory)]
    public class ValidateTokenSyncTests_TelemetryImpact
    {
        private const int IterationCount = 10000;
        private JsonWebTokenHandler _jsonWebTokenHandler;
        private string _jwsClaims;
        private TokenValidationParameters _tokenValidationParameters;

        [GlobalSetup]
        public void GlobalSetup()
        {
            var tokenDescriptorClaims = new SecurityTokenDescriptor
            {
                Claims = BenchmarkUtils.Claims,
                SigningCredentials = BenchmarkUtils.SigningCredentialsRsaSha256,
            };

            _jsonWebTokenHandler = new JsonWebTokenHandler();
            _jwsClaims = _jsonWebTokenHandler.CreateToken(tokenDescriptorClaims);

            _tokenValidationParameters = new TokenValidationParameters
            {
                ValidAudience = BenchmarkUtils.Audience,
                ValidateLifetime = true,
                ValidIssuer = BenchmarkUtils.Issuer,
                IssuerSigningKey = BenchmarkUtils.SigningCredentialsRsaSha256.Key,
            };
        }

        [IterationSetup(Target = nameof(JsonWebTokenHandler_ValidateToken_TelemetryDisabled))]
        public void Setup_TelemetryDisabled()
        {
            CryptoTelemetry.EnableSignatureValidationTelemetry(false, null);
        }

        [BenchmarkCategory("ValidateTokenSync_TelemetryImpact"), Benchmark(Baseline = true, OperationsPerInvoke = IterationCount)]
        public TokenValidationResult JsonWebTokenHandler_ValidateToken_TelemetryDisabled()
        {
            return _jsonWebTokenHandler.ValidateToken(_jwsClaims, _tokenValidationParameters);
        }

        [IterationSetup(Target = nameof(JsonWebTokenHandler_ValidateToken_TelemetryEnabledNoTracking))]
        public void Setup_TelemetryEnabledNoTracking()
        {
            CryptoTelemetry.EnableSignatureValidationTelemetry(true, null);
        }

        [BenchmarkCategory("ValidateTokenSync_TelemetryImpact"), Benchmark(OperationsPerInvoke = IterationCount)]
        public TokenValidationResult JsonWebTokenHandler_ValidateToken_TelemetryEnabledNoTracking()
        {
            return _jsonWebTokenHandler.ValidateToken(_jwsClaims, _tokenValidationParameters);
        }

        [IterationSetup(Target = nameof(JsonWebTokenHandler_ValidateToken_TelemetryEnabledWithTracking))]
        public void Setup_TelemetryEnabledWithTracking()
        {
            CryptoTelemetry.EnableSignatureValidationTelemetry(true, new[] { "contoso.com" });
        }

        [BenchmarkCategory("ValidateTokenSync_TelemetryImpact"), Benchmark(OperationsPerInvoke = IterationCount)]
        public TokenValidationResult JsonWebTokenHandler_ValidateToken_TelemetryEnabledWithTracking()
        {
            return _jsonWebTokenHandler.ValidateToken(_jwsClaims, _tokenValidationParameters);
        }
    }
}

#pragma warning restore CS0618
