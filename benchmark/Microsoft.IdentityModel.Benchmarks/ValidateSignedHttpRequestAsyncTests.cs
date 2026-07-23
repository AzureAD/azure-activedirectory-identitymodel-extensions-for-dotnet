// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System;
using System.Threading;
using System.Threading.Tasks;
using BenchmarkDotNet.Attributes;
using Microsoft.IdentityModel.Protocols;
using Microsoft.IdentityModel.Protocols.SignedHttpRequest;
using Microsoft.IdentityModel.Tokens;

namespace Microsoft.IdentityModel.Benchmarks
{
    // dotnet run -c release -f net8.0 --filter Microsoft.IdentityModel.Benchmarks.ValidateSignedHttpRequestAsyncTests*

    public class ValidateSignedHttpRequestAsyncTests
    {
        private SignedHttpRequestHandler _signedHttpRequestHandler;
        private SignedHttpRequestValidationContext _validationContext;

        [Params("path/to/resource", "path%2fto%2fresource")]
        public string Path { get; set; }

        [GlobalSetup]
        public void Setup()
        {
            _signedHttpRequestHandler = new SignedHttpRequestHandler();
            var httpRequestData = new HttpRequestData
            {
                Method = "GET",
                Uri = new Uri($"https://www.relyingparty.com/{Path}")
            };
            _validationContext = new SignedHttpRequestValidationContext(
                    _signedHttpRequestHandler.CreateSignedHttpRequest(
                        new SignedHttpRequestDescriptor(
                            BenchmarkUtils.CreateAccessTokenWithCnf(),
                            httpRequestData,
                            BenchmarkUtils.SigningCredentialsRsaSha256,
                            new SignedHttpRequestCreationParameters()
                            {
                                CreateM = true,
                                CreateP = true,
                                CreateU = true
                            })),
                    httpRequestData,
                    new TokenValidationParameters
                    {
                        IssuerSigningKey = BenchmarkUtils.SigningCredentialsRsaSha256.Key,
                        ValidIssuer = BenchmarkUtils.Issuer,
                        ValidAudience = BenchmarkUtils.Audience,
                        TokenDecryptionKey = BenchmarkUtils.EncryptingCredentialsAes256Sha512.Key
                    },
                    new SignedHttpRequestValidationParameters
                    {
                        ValidateP = true
                    });
        }

        [Benchmark]
        public async Task<SignedHttpRequestValidationResult> SHRHandler_ValidateSignedHttpRequestAsync() => await _signedHttpRequestHandler.ValidateSignedHttpRequestAsync(_validationContext, CancellationToken.None);
    }
}
