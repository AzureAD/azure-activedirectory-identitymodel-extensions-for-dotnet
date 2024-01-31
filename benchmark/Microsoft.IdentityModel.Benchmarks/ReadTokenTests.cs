// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System;
using BenchmarkDotNet.Attributes;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;

namespace Microsoft.IdentityModel.Benchmarks
{
    // dotnet run -c release -f net8.0 --filter Microsoft.IdentityModel.Benchmarks.ReadTokenTests*

    [Config(typeof(BenchmarkConfig))]
    [HideColumns("Type", "Job", "WarmupCount", "LaunchCount")]
    [MemoryDiagnoser]
    public class ReadTokenTests
    {
        string _encodedToken;

        [GlobalSetup]
        public void Setup()
        {
            var tokenDescriptor = new SecurityTokenDescriptor
            {
                Claims = BenchmarkUtils.Claims,
                SigningCredentials = BenchmarkUtils.SigningCredentialsRsaSha256,
                TokenType = JwtHeaderParameterNames.Jwk
            };

            _encodedToken = new JsonWebTokenHandler().CreateToken(tokenDescriptor);
        }

            [Benchmark]
        public JsonWebToken ReadJWTFromEncodedString()
        {
            return new JsonWebToken(_encodedToken);
        }

        [Benchmark]
        public JsonWebToken ReadJWTFromEncodedSpan()
        {
            return new JsonWebToken(_encodedToken.AsSpan());
        }
    }
}
