// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System.Collections.Generic;
using BenchmarkDotNet.Attributes;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;

namespace Microsoft.IdentityModel.Benchmarks
{
    // Isolates the cost of building a header-replaced JsonWebToken two ways:
    //   * Reparse:            parse a reassembled "header.payload.signature" string (header AND payload parsed).
    //   * ReuseParsedPayload: new JsonWebToken(source, encodedHeader) reuses the source's parsed payload (header only parsed).
    // Three payload sizes show the win scaling with payload. Approximate encoded token sizes:
    //   Minimal ~0.7 KB (standard claims), Small ~1.9 KB (+50 claims), Typical ~4 KB (+125 claims, ~ a real Graph user token).
    // The reassembled strings are built once in setup so the benchmark body measures construction, not the concat.
    //
    // dotnet run -c release -f net8.0 --filter Microsoft.IdentityModel.Benchmarks.JsonWebTokenHeaderReplacementBenchmarks*

    [MemoryDiagnoser]
    public class JsonWebTokenHeaderReplacementBenchmarks
    {
        private const int SmallExtraClaims = 50;
        private const int TypicalExtraClaims = 125;

        private JsonWebToken _minimalSource;
        private string _minimalHeader;
        private string _minimalReassembled;

        private JsonWebToken _smallSource;
        private string _smallHeader;
        private string _smallReassembled;

        private JsonWebToken _typicalSource;
        private string _typicalHeader;
        private string _typicalReassembled;

        [GlobalSetup]
        public void Setup()
        {
            var handler = new JsonWebTokenHandler();

            (_minimalSource, _minimalHeader, _minimalReassembled) = BuildCase(handler, 0);
            (_smallSource, _smallHeader, _smallReassembled) = BuildCase(handler, SmallExtraClaims);
            (_typicalSource, _typicalHeader, _typicalReassembled) = BuildCase(handler, TypicalExtraClaims);
        }

        private static (JsonWebToken source, string header, string reassembled) BuildCase(JsonWebTokenHandler handler, int extraClaims)
        {
            var claims = new Dictionary<string, object>(BenchmarkUtils.Claims);
            for (int i = 0; i < extraClaims; i++)
                claims[$"claim{i}"] = $"value{i}";

            string encoded = handler.CreateToken(new SecurityTokenDescriptor
            {
                SigningCredentials = BenchmarkUtils.SigningCredentialsRsaSha256,
                Claims = claims
            });

            var source = new JsonWebToken(encoded);
            string header = source.EncodedHeader;
            string reassembled = header + "." + source.EncodedPayload + "." + source.EncodedSignature;
            return (source, header, reassembled);
        }

        [Benchmark(Baseline = true)]
        public JsonWebToken Reparse_Minimal()
        {
            return new JsonWebToken(_minimalReassembled);
        }

        [Benchmark]
        public JsonWebToken ReuseParsedPayload_Minimal()
        {
            return new JsonWebToken(_minimalSource, _minimalHeader);
        }

        [Benchmark]
        public JsonWebToken Reparse_Small()
        {
            return new JsonWebToken(_smallReassembled);
        }

        [Benchmark]
        public JsonWebToken ReuseParsedPayload_Small()
        {
            return new JsonWebToken(_smallSource, _smallHeader);
        }

        [Benchmark]
        public JsonWebToken Reparse_Typical()
        {
            return new JsonWebToken(_typicalReassembled);
        }

        [Benchmark]
        public JsonWebToken ReuseParsedPayload_Typical()
        {
            return new JsonWebToken(_typicalSource, _typicalHeader);
        }
    }
}
