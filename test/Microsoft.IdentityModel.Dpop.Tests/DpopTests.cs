// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Threading.Tasks;
using Microsoft.IdentityModel.Tokens;
using Xunit;

namespace Microsoft.IdentityModel.Dpop.Tests
{
    public class DPoPTests
    {
        private static RSA CreateTestRsa()
        {
#if NET462
            return new RSACryptoServiceProvider(2048);
#else
            return RSA.Create(2048);
#endif
        }

        [Fact]
        public async Task CreateAndValidateProof_Success()
        {
            // Arrange
            var rsaKey = new RsaSecurityKey(CreateTestRsa());
            var signingCredentials = new SigningCredentials(rsaKey, SecurityAlgorithms.RsaSha256);

            var dpopProof = new DPoPProofCreator(new DPoPProofCreatorOptions { SigningCredentials = signingCredentials });
            var httpMethod = "POST";
            var uri = new Uri("https://example.com/token");

            // Act
            var proof = dpopProof.CreateProof(httpMethod, uri);
            var validator = new DPoPProofValidator();
            var result = await validator.ValidateAsync(proof, httpMethod, uri, null,
                new DPoPValidationOptions { AllowedSigningAlgorithms = new HashSet<string> { "RS256" } });

            // Assert
            Assert.NotNull(proof);
            Assert.True(result.IsValid);
            Assert.Null(result.Error);
        }

        [Fact]
        public async Task ValidateProof_InvalidHttpMethod_Fails()
        {
            // Arrange
            var rsaKey = new RsaSecurityKey(CreateTestRsa());
            var signingCredentials = new SigningCredentials(rsaKey, SecurityAlgorithms.RsaSha256);

            var dpopProof = new DPoPProofCreator(new DPoPProofCreatorOptions { SigningCredentials = signingCredentials });
            var uri = new Uri("https://example.com/token");

            // Act
            var proof = dpopProof.CreateProof("POST", uri);
            var validator = new DPoPProofValidator();
            var result = await validator.ValidateAsync(proof, "GET", uri, null,
                new DPoPValidationOptions { AllowedSigningAlgorithms = new HashSet<string> { "RS256" } });

            // Assert
            Assert.False(result.IsValid);
            Assert.Contains("htm", result.Error);
        }

        [Fact]
        public async Task ValidateProof_InvalidUri_Fails()
        {
            // Arrange
            var rsaKey = new RsaSecurityKey(CreateTestRsa());
            var signingCredentials = new SigningCredentials(rsaKey, SecurityAlgorithms.RsaSha256);

            var dpopProof = new DPoPProofCreator(new DPoPProofCreatorOptions { SigningCredentials = signingCredentials });
            var uri = new Uri("https://example.com/token");

            // Act
            var proof = dpopProof.CreateProof("POST", uri);
            var validator = new DPoPProofValidator();
            var result = await validator.ValidateAsync(proof, "POST", new Uri("https://example.com/resource"), null,
                new DPoPValidationOptions { AllowedSigningAlgorithms = new HashSet<string> { "RS256" } });

            // Assert
            Assert.False(result.IsValid);
            Assert.Contains("htu", result.Error);
        }

        [Fact]
        public async Task ValidateProof_WithNonce_Success()
        {
            // Arrange
            var rsaKey = new RsaSecurityKey(CreateTestRsa());
            var signingCredentials = new SigningCredentials(rsaKey, SecurityAlgorithms.RsaSha256);

            var dpopProof = new DPoPProofCreator(new DPoPProofCreatorOptions
            {
                SigningCredentials = signingCredentials,
                IncludeNonce = true,
                Nonce = "test-nonce-123"
            });
            var uri = new Uri("https://example.com/token");

            // Act
            var proof = dpopProof.CreateProof("POST", uri);
            var validator = new DPoPProofValidator();
            var result = await validator.ValidateAsync(proof, "POST", uri, null,
                new DPoPValidationOptions
                {
                    AllowedSigningAlgorithms = new HashSet<string> { "RS256" },
                    ExpectedNonce = "test-nonce-123",
                });

            // Assert
            Assert.True(result.IsValid);
        }

        [Fact]
        public void CreateProofAndSetHeaders_Success()
        {
            // Arrange
            var rsaKey = new RsaSecurityKey(CreateTestRsa());
            var signingCredentials = new SigningCredentials(rsaKey, SecurityAlgorithms.RsaSha256);

            var options = new DPoPProofCreatorOptions
            {
                SigningCredentials = signingCredentials
            };

            var dpopProof = new DPoPProofCreator(options);
            var request = new HttpRequestMessage(HttpMethod.Post, "https://example.com/token");

            // Act — use CreateProof directly, set headers manually
            string proof = dpopProof.CreateProof(request.Method.Method, request.RequestUri, "access_token");
            request.Headers.Add(DPoPConstants.DPoPHeaderName, proof);

            // Assert
            Assert.True(request.Headers.Contains(DPoPConstants.DPoPHeaderName));
            var dpopHeader = request.Headers.GetValues(DPoPConstants.DPoPHeaderName).FirstOrDefault();
            Assert.NotNull(dpopHeader);
        }

        [Fact]
        public void CreateProofWithBoundAccessToken_Success()
        {
            // Arrange
            var rsaKey = new RsaSecurityKey(CreateTestRsa());
            var signingCredentials = new SigningCredentials(rsaKey, SecurityAlgorithms.RsaSha256);

            var options = new DPoPProofCreatorOptions
            {
                SigningCredentials = signingCredentials
            };

            var dpopProof = new DPoPProofCreator(options);
            var request = new HttpRequestMessage(HttpMethod.Post, "https://example.com/resource");
            var accessToken = "test-access-token-123";

            // Act — use CreateProof directly, set headers manually
            string proof = dpopProof.CreateProof(request.Method.Method, request.RequestUri, accessToken);
            request.Headers.Add(DPoPConstants.DPoPHeaderName, proof);
            request.Headers.Authorization = new AuthenticationHeaderValue(DPoPConstants.DPoPTokenType, accessToken);

            // Assert
            Assert.True(request.Headers.Contains(DPoPConstants.DPoPHeaderName));
            Assert.NotNull(request.Headers.Authorization);
            Assert.Equal(DPoPConstants.DPoPTokenType, request.Headers.Authorization.Scheme);
            Assert.Equal(accessToken, request.Headers.Authorization.Parameter);
        }
    }
}
