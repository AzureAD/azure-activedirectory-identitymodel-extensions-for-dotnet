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
    [Collection("SignedHttpRequest Configuration")]
    public class SignedHttpRequestConfigurationTests
    {
        [Fact]
        public void UseCaseSensitivePClaimComparison_SeedsFromAppContext()
        {
            try
            {
                // Arrange
                AppContext.SetSwitch(SignedHttpRequestValidationParameters.UseCaseSensitivePClaimComparisonSwitch, false);

                // Act
                var validationParameters = new SignedHttpRequestValidationParameters();

                // Assert
                Assert.False(validationParameters.UseCaseSensitivePClaimComparison);
            }
            finally
            {
                RestoreUseCaseSensitivePClaimComparisonSwitch();
            }
        }

        [Fact]
        public void UseCaseSensitivePClaimComparison_ExplicitPropertyOverridesSeed()
        {
            try
            {
                // Arrange
                AppContext.SetSwitch(SignedHttpRequestValidationParameters.UseCaseSensitivePClaimComparisonSwitch, false);

                // Act
                var validationParameters = new SignedHttpRequestValidationParameters
                {
                    UseCaseSensitivePClaimComparison = true
                };

                // Assert
                Assert.True(validationParameters.UseCaseSensitivePClaimComparison);
            }
            finally
            {
                RestoreUseCaseSensitivePClaimComparisonSwitch();
            }
        }

        [Fact]
        public void UseCaseSensitivePClaimComparison_CapturesAppContextValueAtConstruction()
        {
            try
            {
                // Arrange
                AppContext.SetSwitch(SignedHttpRequestValidationParameters.UseCaseSensitivePClaimComparisonSwitch, false);
                var validationParameters = new SignedHttpRequestValidationParameters();

                // Act
                AppContext.SetSwitch(
                    SignedHttpRequestValidationParameters.UseCaseSensitivePClaimComparisonSwitch,
                    !SignedHttpRequestValidationParameters.DefaultUseCaseSensitivePClaimComparison);

                // Assert
                Assert.False(validationParameters.UseCaseSensitivePClaimComparison);
            }
            finally
            {
                RestoreUseCaseSensitivePClaimComparisonSwitch();
            }
        }

        [Fact]
        public void UseCaseSensitivePClaimComparison_DefaultsToTrueOn9x()
        {
            Assert.True(SignedHttpRequestValidationParameters.DefaultUseCaseSensitivePClaimComparison);
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
        public async Task ValidateSignedHttpRequestAsync_DefaultContextUses9xPathComparison()
        {
            // Arrange
            RestoreUseCaseSensitivePClaimComparisonSwitch();
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
            Assert.True(validationContext.SignedHttpRequestValidationParameters.UseCaseSensitivePClaimComparison);
            Assert.False(result.IsValid);
            Assert.IsType<SignedHttpRequestInvalidPClaimException>(result.Exception);
        }

        [Fact]
        public async Task ValidateSignedHttpRequestAsync_DefaultContextUsesAppContextSeed()
        {
            try
            {
                // Arrange
                AppContext.SetSwitch(SignedHttpRequestValidationParameters.UseCaseSensitivePClaimComparisonSwitch, false);
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
            finally
            {
                RestoreUseCaseSensitivePClaimComparisonSwitch();
            }
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

        private static void RestoreUseCaseSensitivePClaimComparisonSwitch()
        {
            AppContext.SetSwitch(
                SignedHttpRequestValidationParameters.UseCaseSensitivePClaimComparisonSwitch,
                SignedHttpRequestValidationParameters.DefaultUseCaseSensitivePClaimComparison);
        }
    }
}
