// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#if NET8_0_OR_GREATER
using System;
using System.Text;
#endif

using System.Security.Claims;
using System.Threading.Tasks;
using BenchmarkDotNet.Attributes;
using BenchmarkDotNet.Configs;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using System.Collections.Generic;

namespace Microsoft.IdentityModel.Benchmarks
{
    // dotnet run -c release -f net8.0 --filter Microsoft.IdentityModel.Benchmarks.ValuePosition*

    [GroupBenchmarksBy(BenchmarkLogicalGroupRule.ByCategory)]
    public class ValuePosition
    {
        private CallContext _callContext;
        private JsonWebTokenHandler _jsonWebTokenHandlerReadBytes;
        private JsonWebTokenHandler _jsonWebTokenHandler;
        private SecurityTokenDescriptor _tokenDescriptor;
        private string _jws;
        private TokenValidationParameters _tokenValidationParametersValidateStrings;
        private TokenValidationParameters _tokenValidationParametersValidateBytes;

#if NET8_0_OR_GREATER
        private static ReadOnlyMemory<byte> _appidBytes = Encoding.UTF8.GetBytes(BenchmarkUtils.Appid);
        private static ReadOnlyMemory<byte> _azpacrBytes = Encoding.UTF8.GetBytes(BenchmarkUtils.Azpacr);
        private static ReadOnlyMemory<byte> _idtypBytes = Encoding.UTF8.GetBytes(BenchmarkUtils.Idtyp);
        private static ReadOnlyMemory<byte> _tidBytes = Encoding.UTF8.GetBytes(BenchmarkUtils.Tid);
        private static ReadOnlyMemory<byte> _verBytes = Encoding.UTF8.GetBytes(BenchmarkUtils.Ver);
#endif
        private static ValueTask<string> IssuerValidatorCompareString(string issuer, SecurityToken token, TokenValidationParameters validationParameters)
        {
            JsonWebToken jsonWebToken = (JsonWebToken)token;
            var isValid = string.Equals(jsonWebToken.Issuer, validationParameters.ValidIssuer);

#if never
            if (jsonWebToken.TryGetPayloadValue(JwtRegisteredClaimNames.Idtyp, out string idtyp))
            {
                isValid &= string.Equals(idtyp, BenchmarkUtils.Idtyp);
            }

            if (jsonWebToken.TryGetPayloadValue(JwtRegisteredClaimNames.Appid, out string appid))
            {
                isValid &= string.Equals(appid, BenchmarkUtils.Appid);
            }

            if (jsonWebToken.TryGetPayloadValue(JwtRegisteredClaimNames.Tid, out string tid))
            {
                isValid &= string.Equals(tid, BenchmarkUtils.Tid);
            }

            if (jsonWebToken.TryGetPayloadValue(JwtRegisteredClaimNames.Ver, out string ver))
            {
                isValid &= string.Equals(ver, BenchmarkUtils.Ver);
            }

            if (jsonWebToken.TryGetPayloadValue(JwtRegisteredClaimNames.Azpacr, out string azpacr))
            {
                isValid &= string.Equals(azpacr, BenchmarkUtils.Azpacr);
            }
#endif

            return new ValueTask<string>(issuer);
        }

        private static ValueTask<string> IssuerValidatorCompareBytes(string issuer, SecurityToken token, TokenValidationParameters validationParameters)
        {
#if NET8_0_OR_GREATER
            JsonWebToken jsonWebToken = (JsonWebToken)token;
            var isValid = jsonWebToken.IssuerBytes.SequenceEqual(validationParameters.ValidIssuerBytes.Span);
#if never
            jsonWebToken.IdTypBytes.SequenceEqual(_idtypBytes.Span);
            jsonWebToken.AppidBytes.SequenceEqual(_appidBytes.Span);
            jsonWebToken.VerBytes.SequenceEqual(_verBytes.Span);
            jsonWebToken.TidBytes.SequenceEqual(_tidBytes.Span);
            jsonWebToken.AzpacrBytes.SequenceEqual(_azpacrBytes.Span);
#endif
#endif
            return new ValueTask<string>(issuer);
        }

        [GlobalSetup]
        public void Setup()
        {
            _tokenDescriptor = new SecurityTokenDescriptor
            {
                Claims = BenchmarkUtils.ClaimsExtendedExample,
                SigningCredentials = BenchmarkUtils.SigningCredentialsRsaSha256,
            };

            _jsonWebTokenHandler = new JsonWebTokenHandler();
            _jsonWebTokenHandlerReadBytes = new JsonWebTokenHandler { ReadBytesForPayload = true };

            _jws = _jsonWebTokenHandler.CreateToken(_tokenDescriptor);

            _tokenValidationParametersValidateStrings = new TokenValidationParameters()
            {
                ValidAudience = BenchmarkUtils.Audience,
                ValidateLifetime = true,
                ValidIssuer = BenchmarkUtils.Issuer,
                IssuerSigningKey = BenchmarkUtils.SigningCredentialsRsaSha256.Key,
                IssuerValidatorAsync = IssuerValidatorCompareString,
                RoleClaimType = "role",
                NameClaimType = "name"
            };

            _tokenValidationParametersValidateBytes = new TokenValidationParameters()
            {
                ValidAudience = BenchmarkUtils.Audience,
                ValidateLifetime = true,
                ValidIssuer = BenchmarkUtils.Issuer,
                IssuerSigningKey = BenchmarkUtils.SigningCredentialsRsaSha256.Key,
                IssuerValidatorAsync = IssuerValidatorCompareBytes
            };

            _callContext = new CallContext();
        }

        [Benchmark]
        public async Task<TokenValidationResult> ValidateStrings()
        {

            return await _jsonWebTokenHandler.ValidateTokenAsync(_jws, _tokenValidationParametersValidateStrings).ConfigureAwait(false);
        }

        [Benchmark]
        public async Task<TokenValidationResult> ValidateBytes()
        {
            return await _jsonWebTokenHandlerReadBytes.ValidateTokenAsync(_jws, _tokenValidationParametersValidateBytes).ConfigureAwait(false);
        }
    }
}
