// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

//#define DEBUG_TESTS

#if DEBUG_TESTS
using Microsoft.IdentityModel.Protocols.SignedHttpRequest;
using Microsoft.IdentityModel.Tokens;
#endif
using BenchmarkDotNet.Running;

namespace Microsoft.IdentityModel.Benchmarks
{
    public static class Program
    {
        public static void Main(string[] args)
        {
#if DEBUG_TESTS
            DebugThroughTests();
#endif
            BenchmarkSwitcher.FromAssembly(typeof(Program).Assembly).Run(args);
        }

#if DEBUG_TESTS
        private static void DebugThroughTests()
        {
            CreateJWETests createJWETests = new CreateJWETests();
            createJWETests.Setup();
            string jwe = createJWETests.JsonWebTokenHandler_CreateJWE();

            CreateSignedHttpRequestTests createSignedHttpRequestTests = new CreateSignedHttpRequestTests();
            createSignedHttpRequestTests.Setup();
            string shr = createSignedHttpRequestTests.SHRHandler_CreateSignedHttpRequest();

            CreateTokenTests createTokenTests = new CreateTokenTests();
            createTokenTests.Setup();
            string jws = createTokenTests.JsonWebTokenHandler_CreateToken();

            ValidateTokenAsyncTests validateTokenAsyncTests = new ValidateTokenAsyncTests();
            validateTokenAsyncTests.Setup();
            TokenValidationResult tokenValidationResult = validateTokenAsyncTests.JsonWebTokenHandler_ValidateTokenAsync().Result;

            ValidateSignedHttpRequestAsyncTests validateSignedHttpRequestAsyncTests = new ValidateSignedHttpRequestAsyncTests();
            validateSignedHttpRequestAsyncTests.Setup();
            SignedHttpRequestValidationResult signedHttpRequestValidationResult = validateSignedHttpRequestAsyncTests.SHRHandler_ValidateSignedHttpRequestAsync().Result;
        }
#endif
    }
}
