// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System;
using BenchmarkDotNet.Attributes;
using Microsoft.IdentityModel.JsonWebTokens;

namespace Microsoft.IdentityModel.Benchmarks
{
    // dotnet run -c release -f net8.0 --filter Microsoft.IdentityModel.Benchmarks.ReadTokenTests*

    [Config(typeof(BenchmarkConfig))]
    [HideColumns("Type", "Job", "WarmupCount", "LaunchCount")]
    [MemoryDiagnoser]
    public class ReadTokenTests
    {
        [Benchmark]
        public JsonWebToken ReadJWTFromEncodedString()
        {
            return new JsonWebToken(EncodedJWTs.Asymmetric_LocalSts);
        }

        [Benchmark]
        public JsonWebToken ReadJWTFromEncodedSpan()
        {
            return new JsonWebToken(EncodedJWTs.Asymmetric_LocalStsSpan);
        }
    }
}
