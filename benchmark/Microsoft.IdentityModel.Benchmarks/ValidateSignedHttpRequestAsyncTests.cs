// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using BenchmarkDotNet.Attributes;
using Microsoft.IdentityModel.Protocols.SignedHttpRequest.Tests;
using Microsoft.IdentityModel.Protocols.SignedHttpRequest;
using Microsoft.IdentityModel.Protocols;
using System.Threading;
using System.Threading.Tasks;

namespace Microsoft.IdentityModel.Benchmarks
{
    [HideColumns("Type", "Job", "WarmupCount", "LaunchCount")]
    [MemoryDiagnoser]
    public class ValidateSignedHttpRequestAsyncTests
    {
        SignedHttpRequestHandler signedHttpRequestHandler;
        SignedHttpRequestDescriptor signedHttpRequestDescriptor;
        SignedHttpRequestValidationContext validationContext;
        string signedHttpRequest;

        [GlobalSetup]
        public void Setup()
        {
            var requestData = new HttpRequestData();
            signedHttpRequestHandler = new SignedHttpRequestHandler();
            signedHttpRequestDescriptor = new SignedHttpRequestDescriptor(
                    SignedHttpRequestTestUtils.DefaultEncodedAccessToken,
                    requestData,
                    SignedHttpRequestTestUtils.DefaultSigningCredentials,
                    new SignedHttpRequestCreationParameters()
                    {
                        CreateM = false,
                        CreateP = false,
                        CreateU = false
                    });
            signedHttpRequest = signedHttpRequestHandler.CreateSignedHttpRequest(signedHttpRequestDescriptor);
            validationContext = new SignedHttpRequestValidationContext(
                signedHttpRequest,
                requestData,
                SignedHttpRequestTestUtils.DefaultTokenValidationParameters);
        }

        [Benchmark]
        public async Task<SignedHttpRequestValidationResult> SHRHandler_ValidateSignedHttpRequestAsync() => await signedHttpRequestHandler.ValidateSignedHttpRequestAsync(validationContext, CancellationToken.None);
    }
}
