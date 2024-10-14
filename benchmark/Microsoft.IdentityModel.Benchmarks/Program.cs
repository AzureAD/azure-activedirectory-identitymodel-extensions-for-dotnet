﻿// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using Microsoft.IdentityModel.Protocols.SignedHttpRequest;
using Microsoft.IdentityModel.Tokens;
using BenchmarkDotNet.Running;
using BenchmarkDotNet.Configs;

namespace Microsoft.IdentityModel.Benchmarks
{
    public static class Program
    {
        public static void Main(string[] args)
        {
            //DebugThroughTests();

#if DEBUG
            var benchmarkConfig = ManualConfig.Union(DefaultConfig.Instance, new DebugInProcessConfig()); // Allows debugging into benchmarks
#else
            var benchmarkConfig = ManualConfig.Union(DefaultConfig.Instance, new BenchmarkConfig());
#endif

            BenchmarkSwitcher.FromAssembly(typeof(Program).Assembly).Run(args, benchmarkConfig);
        }
        private static void DebugThroughTests()
        {
            ClaimsIdentityTests claimsIdentityTests = new ClaimsIdentityTests();
            claimsIdentityTests.SetupAsync().GetAwaiter().GetResult();
            var claim = claimsIdentityTests.ClaimsIdentity_FindFirst();
            var claimsList = claimsIdentityTests.ClaimsIdentity_FindAll();
            var hasClaim = claimsIdentityTests.ClaimsIdentity_HasClaim();
            claim = claimsIdentityTests.NewClaimsIdentity_FindFirst();
            claimsList = claimsIdentityTests.NewClaimsIdentity_FindAll();
            hasClaim = claimsIdentityTests.NewClaimsIdentity_HasClaim();

            ReadJWETokenTests readTokenTests = new ReadJWETokenTests();
            readTokenTests.Setup();
            readTokenTests.ReadJWE_FromMemory();

            AsymmetricAdapterSignatures asymmetricAdapter = new AsymmetricAdapterSignatures();
            asymmetricAdapter.Setup();
            asymmetricAdapter.SignDotnetCreatingBufferRSA();
            asymmetricAdapter.SignSpanWithArrayPoolRSA();
            asymmetricAdapter.SignSpanWithFixedBufferRSA();

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
            TokenValidationResult tokenValidationResult = validateTokenAsyncTests.JsonWebTokenHandler_ValidateTokenAsyncWithTVP().Result;
            bool validationResult = validateTokenAsyncTests.JsonWebTokenHandler_ValidateTokenAsyncWithVP().Result;
            var claims = validateTokenAsyncTests.JsonWebTokenHandler_ValidateTokenAsyncWithTVP_CreateClaims();

            ValidateSignedHttpRequestAsyncTests validateSignedHttpRequestAsyncTests = new ValidateSignedHttpRequestAsyncTests();
            validateSignedHttpRequestAsyncTests.Setup();
            SignedHttpRequestValidationResult signedHttpRequestValidationResult = validateSignedHttpRequestAsyncTests.SHRHandler_ValidateSignedHttpRequestAsync().Result;
        }
    }
}
