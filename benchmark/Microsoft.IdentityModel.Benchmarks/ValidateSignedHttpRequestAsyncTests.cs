// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System;
using System.Threading;
using System.Threading.Tasks;
using BenchmarkDotNet.Attributes;
using Microsoft.IdentityModel.Protocols.SignedHttpRequest;
using Microsoft.IdentityModel.Tokens;
using Microsoft.IdentityModel.Tokens.Experimental;
using Experimental = Microsoft.IdentityModel.Protocols.SignedHttpRequest.Experimental;

namespace Microsoft.IdentityModel.Benchmarks
{
    // dotnet run -c release -f net8.0 --filter Microsoft.IdentityModel.Benchmarks.ValidateSignedHttpRequestAsyncTests*

    public class ValidateSignedHttpRequestAsyncTests
    {
        private SignedHttpRequestHandler _signedHttpRequestHandler;
        private SignedHttpRequestValidationContext _validationContext;
        private Experimental.SignedHttpRequestValidationContext _experimentalValidationContext;

        [GlobalSetup(Target = nameof(SHRHandler_ValidateSignedHttpRequestAsync))]
        public void Setup()
        {
            _signedHttpRequestHandler = new SignedHttpRequestHandler();
            _validationContext = new SignedHttpRequestValidationContext(
                    _signedHttpRequestHandler.CreateSignedHttpRequest(
                        new SignedHttpRequestDescriptor(
                            BenchmarkUtils.CreateAccessTokenWithCnf(),
                            BenchmarkUtils.HttpRequestData,
                            BenchmarkUtils.SigningCredentialsRsaSha256,
                            new SignedHttpRequestCreationParameters()
                            {
                                CreateM = true,
                                CreateP = false,
                                CreateU = true
                            })),
                    BenchmarkUtils.HttpRequestData,
                    new TokenValidationParameters
                    {
                        IssuerSigningKey = BenchmarkUtils.SigningCredentialsRsaSha256.Key,
                        ValidIssuer = BenchmarkUtils.Issuer,
                        ValidAudience = BenchmarkUtils.Audience,
                        TokenDecryptionKey = BenchmarkUtils.EncryptingCredentialsAes256Sha512.Key
                    },
                    new SignedHttpRequestValidationParameters
                    {
                        ValidateP = false
                    });
        }

        [GlobalSetup(Target = nameof(SHRHandler_ValidateSignedHttpRequestAsyncWithVP))]
        public async Task SetupExperimentalAsync()
        {
            Setup();

            var validationParameters = new ValidationParameters();
            validationParameters.SigningKeys.Add(BenchmarkUtils.SigningCredentialsRsaSha256.Key);
            validationParameters.ValidIssuers.Add(BenchmarkUtils.Issuer);
            validationParameters.ValidAudiences.Add(BenchmarkUtils.Audience);
            validationParameters.DecryptionKeys.Add(BenchmarkUtils.EncryptingCredentialsAes256Sha512.Key);

            _experimentalValidationContext = new Experimental.SignedHttpRequestValidationContext(
                _validationContext.SignedHttpRequest,
                _validationContext.HttpRequestData,
                validationParameters,
                new Experimental.SignedHttpRequestValidationParameters
                {
                    ValidateP = false
                });

            var result = await _signedHttpRequestHandler.ValidateSignedHttpRequestAsync(_experimentalValidationContext, CancellationToken.None).ConfigureAwait(false);
            if (!result.Succeeded)
                throw new InvalidOperationException("Experimental signed HTTP request benchmark setup validation failed.", result.Error.GetException());
        }

        [Benchmark(Baseline = true)]
        public async Task<SignedHttpRequestValidationResult> SHRHandler_ValidateSignedHttpRequestAsync() => await _signedHttpRequestHandler.ValidateSignedHttpRequestAsync(_validationContext, CancellationToken.None);

        [Benchmark]
        public async Task<bool> SHRHandler_ValidateSignedHttpRequestAsyncWithVP()
        {
            var result = await _signedHttpRequestHandler.ValidateSignedHttpRequestAsync(_experimentalValidationContext, CancellationToken.None).ConfigureAwait(false);
            return result.Succeeded;
        }
    }
}
