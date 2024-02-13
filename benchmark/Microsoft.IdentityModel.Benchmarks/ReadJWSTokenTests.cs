// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System;
using BenchmarkDotNet.Attributes;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;

namespace Microsoft.IdentityModel.Benchmarks
{
    // dotnet run -c release -f net8.0 --filter Microsoft.IdentityModel.Benchmarks.ReadJWSTokenTests*

    [Config(typeof(BenchmarkConfig))]
    [HideColumns("Type", "Job", "WarmupCount", "LaunchCount")]
    [MemoryDiagnoser]
    [RankColumn]
    public class ReadJWSTokenTests
    {
        string _encodedJWS;

        [GlobalSetup]
        public void Setup()
        {
            var jsonWebTokenHandler = new JsonWebTokenHandler();
            var jwsTokenDescriptor = new SecurityTokenDescriptor
            {
                SigningCredentials = BenchmarkUtils.SigningCredentialsRsaSha256,
                TokenType = JwtHeaderParameterNames.Jwk,
                Claims = BenchmarkUtils.Claims
            };

            _encodedJWS = jsonWebTokenHandler.CreateToken(jwsTokenDescriptor);
        }

        [Benchmark]
        public JsonWebToken ReadJWS_FromString()
        {
            return new JsonWebToken(_encodedJWS);
        }

        [Benchmark]
        public JsonWebToken ReadJWS_FromMemory()
        {
            return new JsonWebToken(_encodedJWS.AsMemory());
        }
    }
}
