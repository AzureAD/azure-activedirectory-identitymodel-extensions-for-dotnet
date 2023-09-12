// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using BenchmarkDotNet.Attributes;
using Microsoft.IdentityModel.Protocols.SignedHttpRequest;
using Microsoft.IdentityModel.Protocols.SignedHttpRequest.Tests;
using Microsoft.IdentityModel.Protocols;

namespace Microsoft.IdentityModel.Benchmarks
{
    [HideColumns("Type", "Job", "WarmupCount", "LaunchCount")]
    [MemoryDiagnoser]
    public class CreateSignedHttpRequestTests
    {
        SignedHttpRequestHandler signedHttpRequestHandler;
        SignedHttpRequestDescriptor signedHttpRequestDescriptor;

        [GlobalSetup]
        public void Setup()
        {
            signedHttpRequestHandler = new SignedHttpRequestHandler();
            signedHttpRequestDescriptor = new SignedHttpRequestDescriptor(
                    SignedHttpRequestTestUtils.DefaultEncodedAccessToken,
                    new HttpRequestData(),
                    SignedHttpRequestTestUtils.DefaultSigningCredentials,
                    new SignedHttpRequestCreationParameters()
                    {
                        CreateM = false,
                        CreateP = false,
                        CreateU = false
                    });
        }

        [Benchmark]
        public string SHRHandler_CreateSignedHttpRequest() => signedHttpRequestHandler.CreateSignedHttpRequest(signedHttpRequestDescriptor);

    }
}
