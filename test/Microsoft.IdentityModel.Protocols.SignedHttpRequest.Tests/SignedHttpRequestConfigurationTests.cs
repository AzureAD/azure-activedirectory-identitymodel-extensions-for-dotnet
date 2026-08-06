// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.IdentityModel.Tokens;
using Newtonsoft.Json.Linq;
using Xunit;

namespace Microsoft.IdentityModel.Protocols.SignedHttpRequest.Tests
{
    public class SignedHttpRequestConfigurationTests
    {
        [Fact]
        public void UseCaseSensitivePClaimComparison_DefaultsToCaseInsensitiveComparison()
        {
            // Arrange and Act
            var validationParameters = new SignedHttpRequestValidationParameters();

            // Assert
            Assert.False(SignedHttpRequestValidationParameters.DefaultUseCaseSensitivePClaimComparison);
            Assert.False(validationParameters.UseCaseSensitivePClaimComparison);
        }

        [Theory]
        [InlineData(true, false)]
        [InlineData(false, true)]
        public async Task ValidateSignedHttpRequestAsync_UsesExplicitPathComparisonConfiguration(
            bool useCaseSensitiveComparison,
            bool expectedValid)
        {
            // Arrange
            var validationParameters = CreatePathValidationParameters(useCaseSensitiveComparison);
            var validationContext = CreateValidationContext(validationParameters);
            var handler = new SignedHttpRequestHandler();

            // Act
            var result = await handler.ValidateSignedHttpRequestAsync(validationContext, CancellationToken.None);

            // Assert
            Assert.Equal(expectedValid, result.IsValid);
            if (expectedValid)
                Assert.Null(result.Exception);
            else
                Assert.IsType<SignedHttpRequestInvalidPClaimException>(result.Exception);
        }

        [Fact]
        public async Task ValidateSignedHttpRequestAsync_DefaultContextUsesDefaultPathComparison()
        {
            // Arrange
            var signedHttpRequest = CreateSignedHttpRequestWithPath("/Path1");
            var httpRequestData = CreateHttpRequestData();
            var validationContext = new SignedHttpRequestValidationContext(
                signedHttpRequest,
                httpRequestData,
                SignedHttpRequestTestUtils.DefaultTokenValidationParameters);
            var handler = new SignedHttpRequestHandler();

            // Act
            var result = await handler.ValidateSignedHttpRequestAsync(validationContext, CancellationToken.None);

            // Assert
            Assert.False(validationContext.SignedHttpRequestValidationParameters.UseCaseSensitivePClaimComparison);
            Assert.True(result.IsValid);
            Assert.Null(result.Exception);
        }

        private static SignedHttpRequestValidationParameters CreatePathValidationParameters(bool useCaseSensitiveComparison)
        {
            return new SignedHttpRequestValidationParameters
            {
                UseCaseSensitivePClaimComparison = useCaseSensitiveComparison,
                ValidateB = false,
                ValidateH = false,
                ValidateM = false,
                ValidateP = true,
                ValidateQ = false,
                ValidateTs = false,
                ValidateU = false
            };
        }

        private static SignedHttpRequestValidationContext CreateValidationContext(
            SignedHttpRequestValidationParameters validationParameters)
        {
            return new SignedHttpRequestValidationContext(
                CreateSignedHttpRequestWithPath("/Path1"),
                CreateHttpRequestData(),
                SignedHttpRequestTestUtils.DefaultTokenValidationParameters,
                validationParameters);
        }

        private static HttpRequestData CreateHttpRequestData()
        {
            return new HttpRequestData
            {
                Method = "GET",
                Uri = new Uri("https://www.contoso.com/path1")
            };
        }

        private static string CreateSignedHttpRequestWithPath(string path)
        {
            return SignedHttpRequestTestUtils.ReplaceOrAddPropertyAndCreateDefaultSignedHttpRequest(
                new JProperty(SignedHttpRequestClaimTypes.P, path)).EncodedToken;
        }
    }
}
