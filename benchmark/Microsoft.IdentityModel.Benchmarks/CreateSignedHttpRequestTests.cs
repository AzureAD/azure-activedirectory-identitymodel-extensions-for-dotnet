// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System.Collections.Generic;
using BenchmarkDotNet.Attributes;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Protocols;
using Microsoft.IdentityModel.Protocols.SignedHttpRequest;
using Microsoft.IdentityModel.Tokens;

namespace Microsoft.IdentityModel.Benchmarks
{
    [HideColumns("Type", "Job", "WarmupCount", "LaunchCount")]
    [MemoryDiagnoser]
    public class CreateSignedHttpRequestTests
    {
        private SignedHttpRequestHandler _signedHttpRequestHandler;
        private SignedHttpRequestDescriptor _signedHttpRequestDescriptor;

        [GlobalSetup]
        public void Setup()
        {
            _signedHttpRequestHandler = new SignedHttpRequestHandler();
            _signedHttpRequestDescriptor = new SignedHttpRequestDescriptor(
                    BenchmarkUtils.CreateAccessTokenWithCnf(),
                    BenchmarkUtils.HttpRequestData,
                    BenchmarkUtils.SigningCredentialsRsaSha256,
                    new SignedHttpRequestCreationParameters()
                    {
                        CreateM = true,
                        CreateP = false,
                        CreateU = true
                    });
        }

        [Benchmark]
        public string SHRHandler_CreateSignedHttpRequest() => _signedHttpRequestHandler.CreateSignedHttpRequest(_signedHttpRequestDescriptor);
    }
}
