// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Security.Cryptography;
using System.Text.Json;
using System.Threading.Tasks;
using Microsoft.IdentityModel.Dpop;
using Microsoft.IdentityModel.Tokens;
using Xunit;

namespace Microsoft.IdentityModel.Protocols.OAuth2.Tests
{
    public class DPoPTests
    {
        const string KeyCloakRealmAndClient = "http://localhost:8080/realms/dpop/";

        /// <summary>
        /// This test is an integration test that requires a running Keycloak server.
        /// </summary>
        [Fact(Skip = "integration test")]
        public async Task KeyCloak_IntegrationTest_RequestDpopBoundAT()
        {
            var rsa = RSA.Create(2048);
            var key = new RsaSecurityKey(rsa);
            var signingCredentials = new SigningCredentials(key, "RS256");
            var httpClient = new HttpClient();

            var options = new DPoPProofOptions
            {
                SigningCredentials = signingCredentials,
                ValidationParameters = new()
            };

            var dpopProof = new DPoPProof(options);
            // provide the code from the authorization code flow.
            string dpopToken = await GetDPoPToken(httpClient, dpopProof, code: "");

            var boundRequest = new HttpRequestMessage(HttpMethod.Post, "http://localhost:8080/someapi");
            boundRequest.AddDPoPProof(dpopProof, dpopToken);

            // Make a request to a resource server...
            var response = await httpClient.SendAsync(boundRequest);
        }

        private static async Task<string> GetDPoPToken(HttpClient httpClient, DPoPProof dpopProof, string code)
        {
            var request = new HttpRequestMessage(HttpMethod.Post, KeyCloakRealmAndClient + "protocol/openid-connect/token");
            request.AddDPoPProof(dpopProof);
            request.Content = new FormUrlEncodedContent(new[]
            {
                new KeyValuePair<string, string>("grant_type", "authorization_code"),
                new KeyValuePair<string, string>("code", code),
                new KeyValuePair<string, string>("redirect_uri", "http://localhost/callback"),
                new KeyValuePair<string, string>("client_id", "demo"),
                // Set the client secret if required
                new KeyValuePair<string, string>("client_secret", "")
            });

            request.Headers.TryGetValues("dpop", out var dpopValues);

            var response = await httpClient.SendAsync(request);
            var body = await response.Content.ReadAsStringAsync();

            var content = JsonDocument.Parse(body);
            var dpopToken = content.RootElement.GetProperty("access_token").GetString();
            return dpopToken;
        }

        [Fact]
        public async Task CreateAndValidateProof_Success()
        {
            // Arrange
            var rsaKey = new RsaSecurityKey(RSA.Create(2048));
            var signingCredentials = new SigningCredentials(rsaKey, SecurityAlgorithms.RsaSha256);

            var options = new DPoPProofOptions
            {
                SigningCredentials = signingCredentials,
            };

            var dpopProof = new DPoPProof(options);
            var httpMethod = "POST";
            var uri = new Uri("https://example.com/token");

            // Act
            var proof = dpopProof.CreateProof(httpMethod, uri);
            var result = await dpopProof.ValidateProofAsync(proof, httpMethod, uri);

            // Assert
            Assert.NotNull(proof);
            Assert.True(result.IsValid);
            Assert.Null(result.Error);
        }

        [Fact]
        public async Task ValidateProof_InvalidHttpMethod_Fails()
        {
            // Arrange
            var rsaKey = new RsaSecurityKey(RSA.Create(2048));
            var signingCredentials = new SigningCredentials(rsaKey, SecurityAlgorithms.RsaSha256);

            var options = new DPoPProofOptions
            {
                SigningCredentials = signingCredentials
            };

            var dpopProof = new DPoPProof(options);
            var httpMethod = "POST";
            var uri = new Uri("https://example.com/token");

            // Act
            var proof = dpopProof.CreateProof(httpMethod, uri);
            var result = await dpopProof.ValidateProofAsync(proof, "GET", uri);  // Different HTTP method

            // Assert
            Assert.False(result.IsValid);
            Assert.Contains("htm claim", result.Error);
        }

        [Fact]
        public async Task ValidateProof_InvalidUri_Fails()
        {
            // Arrange
            var rsaKey = new RsaSecurityKey(RSA.Create(2048));
            var signingCredentials = new SigningCredentials(rsaKey, SecurityAlgorithms.RsaSha256);

            var options = new DPoPProofOptions
            {
                SigningCredentials = signingCredentials
            };

            var dpopProof = new DPoPProof(options);
            var httpMethod = "POST";
            var uri = new Uri("https://example.com/token");

            // Act
            var proof = dpopProof.CreateProof(httpMethod, uri);
            var result = await dpopProof.ValidateProofAsync(proof, httpMethod, new Uri("https://example.com/resource"));  // Different URI

            // Assert
            Assert.False(result.IsValid);
            Assert.Contains("htu claim", result.Error);
        }

        [Fact]
        public async Task ValidateProof_WithNonce_Success()
        {
            // Arrange
            var rsaKey = new RsaSecurityKey(RSA.Create(2048));
            var signingCredentials = new SigningCredentials(rsaKey, SecurityAlgorithms.RsaSha256);

            var options = new DPoPProofOptions
            {
                SigningCredentials = signingCredentials,
                IncludeNonce = true,
                Nonce = "test-nonce-123"
            };

            var dpopProof = new DPoPProof(options);
            var httpMethod = "POST";
            var uri = new Uri("https://example.com/token");

            // Act
            var proof = dpopProof.CreateProof(httpMethod, uri);
            var result = await dpopProof.ValidateProofAsync(proof, httpMethod, uri, "test-nonce-123");

            // Assert
            Assert.True(result.IsValid);
        }

        [Fact]
        public void AddDPoPToHttpRequest_Success()
        {
            // Arrange
            var rsaKey = new RsaSecurityKey(RSA.Create(2048));
            var signingCredentials = new SigningCredentials(rsaKey, SecurityAlgorithms.RsaSha256);

            var options = new DPoPProofOptions
            {
                SigningCredentials = signingCredentials
            };

            var dpopProof = new DPoPProof(options);
            var request = new HttpRequestMessage(HttpMethod.Post, "https://example.com/token");

            // Act
            request.AddDPoPProof(dpopProof, "access_token");

            // Assert
            Assert.True(request.Headers.Contains(DPoPConstants.DPoPHeaderName));
            var dpopHeader = request.Headers.GetValues(DPoPConstants.DPoPHeaderName).FirstOrDefault();
            Assert.NotNull(dpopHeader);
        }

        [Fact]
        public void AddDPoPBoundAccessToken_Success()
        {
            // Arrange
            var rsaKey = new RsaSecurityKey(RSA.Create(2048));
            var signingCredentials = new SigningCredentials(rsaKey, SecurityAlgorithms.RsaSha256);

            var options = new DPoPProofOptions
            {
                SigningCredentials = signingCredentials
            };

            var dpopProof = new DPoPProof(options);
            var request = new HttpRequestMessage(HttpMethod.Post, "https://example.com/resource");
            var accessToken = "test-access-token-123";

            // Act
            request.AddDPoPBoundAccessToken(accessToken, dpopProof);

            // Assert
            Assert.True(request.Headers.Contains(DPoPConstants.DPoPHeaderName));
            Assert.NotNull(request.Headers.Authorization);
            Assert.Equal(DPoPConstants.DPoPTokenType, request.Headers.Authorization.Scheme);
            Assert.Equal(accessToken, request.Headers.Authorization.Parameter);
        }
    }
}
