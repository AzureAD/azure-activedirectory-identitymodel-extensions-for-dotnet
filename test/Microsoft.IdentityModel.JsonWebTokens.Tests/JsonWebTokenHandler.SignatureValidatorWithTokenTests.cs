// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System;
using System.Threading.Tasks;
using Microsoft.IdentityModel.Protocols;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.IdentityModel.TestUtils;
using Microsoft.IdentityModel.Tokens;
using Xunit;

namespace Microsoft.IdentityModel.JsonWebTokens.Tests
{
    public class JsonWebTokenHandlerSignatureValidatorWithTokenTests
    {
        private static JsonWebTokenHandler CreateHandler() => new JsonWebTokenHandler();

        private static string CreateSignedToken(SecurityKey signingKey, string algorithm)
        {
            var handler = CreateHandler();
            return handler.CreateToken(new SecurityTokenDescriptor
            {
                SigningCredentials = new SigningCredentials(signingKey, algorithm),
                Issuer = "https://test-issuer.example.com",
                Audience = "https://test-audience.example.com"
            });
        }

        private static TokenValidationParameters CreateBaseValidationParameters(SecurityKey signingKey)
        {
            return new TokenValidationParameters
            {
                ValidIssuer = "https://test-issuer.example.com",
                ValidAudience = "https://test-audience.example.com",
                IssuerSigningKey = signingKey,
                ValidateLifetime = false
            };
        }

        [Fact]
        public async Task DelegateHandlesSignature_ValidationSucceeds()
        {
            // Arrange
            var signingKey = KeyingMaterial.RsaSecurityKey_2048;
            var tokenString = CreateSignedToken(signingKey, SecurityAlgorithms.RsaSha256);

            var tvp = CreateBaseValidationParameters(signingKey);
            tvp.SignatureValidatorWithToken = (token, validationParameters, configuration) =>
            {
                var jwt = (JsonWebToken)token;
                jwt.SigningKey = validationParameters.IssuerSigningKey;
                return SignatureValidationDelegateResult.Success(jwt);
            };

            // Act
            var result = await CreateHandler().ValidateTokenAsync(tokenString, tvp);

            // Assert
            Assert.True(result.IsValid, $"Validation failed: {result.Exception?.Message}");
        }

        [Fact]
        public async Task DelegateDeclines_HandlerValidatesNormally()
        {
            // Arrange
            var signingKey = KeyingMaterial.RsaSecurityKey_2048;
            var tokenString = CreateSignedToken(signingKey, SecurityAlgorithms.RsaSha256);

            bool delegateWasCalled = false;
            var tvp = CreateBaseValidationParameters(signingKey);
            tvp.SignatureValidatorWithToken = (token, validationParameters, configuration) =>
            {
                delegateWasCalled = true;
                return SignatureValidationDelegateResult.NotHandled;
            };

            // Act
            var result = await CreateHandler().ValidateTokenAsync(tokenString, tvp);

            // Assert
            Assert.True(delegateWasCalled, "Delegate should have been called.");
            Assert.True(result.IsValid, $"Validation failed: {result.Exception?.Message}");
        }

        [Fact]
        public async Task DelegateThrows_ExceptionPropagatesAsInvalidResult()
        {
            // Arrange
            var signingKey = KeyingMaterial.RsaSecurityKey_2048;
            var tokenString = CreateSignedToken(signingKey, SecurityAlgorithms.RsaSha256);

            var tvp = CreateBaseValidationParameters(signingKey);
            tvp.SignatureValidatorWithToken = (token, validationParameters, configuration) =>
            {
                throw new SecurityTokenInvalidSignatureException("Signature is invalid.");
            };

            // Act
            var result = await CreateHandler().ValidateTokenAsync(tokenString, tvp);

            // Assert
            Assert.False(result.IsValid);
            Assert.IsType<SecurityTokenInvalidSignatureException>(result.Exception);
        }

        [Fact]
        public async Task DelegateDeclines_WrongKey_ValidationFails()
        {
            // Arrange — sign with one key, validate with another
            var signingKey = KeyingMaterial.RsaSecurityKey_2048;
            var wrongKey = KeyingMaterial.RsaSecurityKey_4096;
            var tokenString = CreateSignedToken(signingKey, SecurityAlgorithms.RsaSha256);

            var tvp = CreateBaseValidationParameters(wrongKey);
            tvp.SignatureValidatorWithToken = (token, validationParameters, configuration) =>
            {
                // Decline — let the handler try (and fail) with the wrong key
                return SignatureValidationDelegateResult.NotHandled;
            };

            // Act
            var result = await CreateHandler().ValidateTokenAsync(tokenString, tvp);

            // Assert
            Assert.False(result.IsValid);
        }

        [Fact]
        public async Task OldDelegatesTakePriority_NewDelegateNotCalled()
        {
            // Arrange
            var signingKey = KeyingMaterial.RsaSecurityKey_2048;
            var tokenString = CreateSignedToken(signingKey, SecurityAlgorithms.RsaSha256);

            bool newDelegateCalled = false;
            var tvp = CreateBaseValidationParameters(signingKey);
            tvp.SignatureValidatorUsingConfiguration = (token, validationParameters, configuration) =>
            {
                var jwt = new JsonWebToken(token);
                jwt.SigningKey = validationParameters.IssuerSigningKey;
                return jwt;
            };
            tvp.SignatureValidatorWithToken = (token, validationParameters, configuration) =>
            {
                newDelegateCalled = true;
                return SignatureValidationDelegateResult.Success((JsonWebToken)token);
            };

            // Act
            var result = await CreateHandler().ValidateTokenAsync(tokenString, tvp);

            // Assert
            Assert.True(result.IsValid, $"Validation failed: {result.Exception?.Message}");
            Assert.False(newDelegateCalled, "New delegate should not be called when old delegate is set.");
        }

        [Fact]
        public async Task DelegateReceivesResolvedBaseConfiguration()
        {
            // Arrange
            var signingKey = KeyingMaterial.RsaSecurityKey_2048;
            var tokenString = CreateSignedToken(signingKey, SecurityAlgorithms.RsaSha256);

            BaseConfiguration capturedConfiguration = null;

            var expectedConfiguration = new OpenIdConnectConfiguration
            {
                Issuer = "https://test-issuer.example.com"
            };
            expectedConfiguration.SigningKeys.Add(signingKey);

            var tvp = CreateBaseValidationParameters(signingKey);
            tvp.ConfigurationManager = new StaticConfigurationManager<BaseConfiguration>(expectedConfiguration);
            tvp.SignatureValidatorWithToken = (token, validationParameters, configuration) =>
            {
                capturedConfiguration = configuration;
                var jwt = (JsonWebToken)token;
                jwt.SigningKey = validationParameters.IssuerSigningKey;
                return SignatureValidationDelegateResult.Success(jwt);
            };

            // Act
            var result = await CreateHandler().ValidateTokenAsync(tokenString, tvp);

            // Assert
            Assert.True(result.IsValid, $"Validation failed: {result.Exception?.Message}");
            Assert.NotNull(capturedConfiguration);
            Assert.Same(expectedConfiguration, capturedConfiguration);
        }

        [Fact]
        public async Task DelegateDeclines_ConfigurationPassedToHandlerSignatureValidation()
        {
            // Arrange — use ConfigurationManager as the only source of signing keys
            var signingKey = KeyingMaterial.RsaSecurityKey_2048;
            var tokenString = CreateSignedToken(signingKey, SecurityAlgorithms.RsaSha256);

            var expectedConfiguration = new OpenIdConnectConfiguration
            {
                Issuer = "https://test-issuer.example.com"
            };
            expectedConfiguration.SigningKeys.Add(signingKey);

            var tvp = new TokenValidationParameters
            {
                ValidIssuer = "https://test-issuer.example.com",
                ValidAudience = "https://test-audience.example.com",
                ValidateLifetime = false,
                ConfigurationManager = new StaticConfigurationManager<BaseConfiguration>(expectedConfiguration),
                SignatureValidatorWithToken = (token, validationParameters, configuration) =>
                {
                    // Decline — the handler should use configuration to resolve signing key
                    return SignatureValidationDelegateResult.NotHandled;
                }
            };

            // Act
            var result = await CreateHandler().ValidateTokenAsync(tokenString, tvp);

            // Assert
            Assert.True(result.IsValid, $"Validation failed: {result.Exception?.Message}");
        }

        [Fact]
        public async Task DelegateHandled_IssuerSigningKeyValidation_ReceivesConfiguration()
        {
            // Arrange
            var signingKey = KeyingMaterial.RsaSecurityKey_2048;
            var tokenString = CreateSignedToken(signingKey, SecurityAlgorithms.RsaSha256);

            BaseConfiguration capturedKeyValidationConfig = null;

            var expectedConfiguration = new OpenIdConnectConfiguration
            {
                Issuer = "https://test-issuer.example.com"
            };
            expectedConfiguration.SigningKeys.Add(signingKey);

            var tvp = CreateBaseValidationParameters(signingKey);
            tvp.ValidateIssuerSigningKey = true;
            tvp.ConfigurationManager = new StaticConfigurationManager<BaseConfiguration>(expectedConfiguration);
            tvp.SignatureValidatorWithToken = (token, validationParameters, configuration) =>
            {
                var jwt = (JsonWebToken)token;
                jwt.SigningKey = validationParameters.IssuerSigningKey;
                return SignatureValidationDelegateResult.Success(jwt);
            };
            tvp.IssuerSigningKeyValidatorUsingConfiguration = (securityKey, securityToken, tvpInner, configuration) =>
            {
                capturedKeyValidationConfig = configuration;
                return true;
            };

            // Act
            var result = await CreateHandler().ValidateTokenAsync(tokenString, tvp);

            // Assert
            Assert.True(result.IsValid, $"Validation failed: {result.Exception?.Message}");
            Assert.NotNull(capturedKeyValidationConfig);
            Assert.Same(expectedConfiguration, capturedKeyValidationConfig);
        }

        [Fact]
        public async Task DelegateHandled_TelemetryRecordsSuccess()
        {
            // Arrange
            var signingKey = KeyingMaterial.RsaSecurityKey_2048;
            var tokenString = CreateSignedToken(signingKey, SecurityAlgorithms.RsaSha256);

            var mockTelemetry = new SignatureValidationMockTelemetryClient();
            var handler = new JsonWebTokenHandler
            {
                TelemetryClient = mockTelemetry
            };

            var tvp = CreateBaseValidationParameters(signingKey);
            tvp.SignatureValidatorWithToken = (token, validationParameters, configuration) =>
            {
                var jwt = (JsonWebToken)token;
                jwt.SigningKey = validationParameters.IssuerSigningKey;
                return SignatureValidationDelegateResult.Success(jwt);
            };

            // Act
            Telemetry.CryptoTelemetry.EnableSignatureValidationTelemetry(true, null);
            try
            {
                var result = await handler.ValidateTokenAsync(tokenString, tvp);

                // Assert
                Assert.True(result.IsValid, $"Validation failed: {result.Exception?.Message}");
                Assert.Equal(1, mockTelemetry.SignatureValidationCallCount);
                Assert.Equal(Telemetry.TelemetryConstants.SignatureValidationErrors.None, mockTelemetry.LastErrorType);
            }
            finally
            {
                Telemetry.CryptoTelemetry.EnableSignatureValidationTelemetry(false, null);
            }
        }

        [Fact]
        public async Task DelegateThrows_TelemetryRecordsFailure()
        {
            // Arrange
            var signingKey = KeyingMaterial.RsaSecurityKey_2048;
            var tokenString = CreateSignedToken(signingKey, SecurityAlgorithms.RsaSha256);

            var mockTelemetry = new SignatureValidationMockTelemetryClient();
            var handler = new JsonWebTokenHandler
            {
                TelemetryClient = mockTelemetry
            };

            var tvp = CreateBaseValidationParameters(signingKey);
            tvp.SignatureValidatorWithToken = (token, validationParameters, configuration) =>
            {
                throw new SecurityTokenInvalidSignatureException("Bad signature.");
            };

            // Act
            Telemetry.CryptoTelemetry.EnableSignatureValidationTelemetry(true, null);
            try
            {
                var result = await handler.ValidateTokenAsync(tokenString, tvp);

                // Assert
                Assert.False(result.IsValid);
                Assert.Equal(1, mockTelemetry.SignatureValidationCallCount);
                Assert.Equal(Telemetry.TelemetryConstants.SignatureValidationErrors.SignatureVerificationFailed, mockTelemetry.LastErrorType);
            }
            finally
            {
                Telemetry.CryptoTelemetry.EnableSignatureValidationTelemetry(false, null);
            }
        }

        [Fact]
        public void SignatureValidationDelegateResult_NotHandled_HasCorrectDefaults()
        {
            // Act
            var result = SignatureValidationDelegateResult.NotHandled;

            // Assert
            Assert.False(result.Handled);
            Assert.Null(result.Token);
        }

        [Fact]
        public void SignatureValidationDelegateResult_Success_SetsProperties()
        {
            // Arrange
            var handler = CreateHandler();
            var tokenString = CreateSignedToken(KeyingMaterial.RsaSecurityKey_2048, SecurityAlgorithms.RsaSha256);
            var token = new JsonWebToken(tokenString);

            // Act
            var result = SignatureValidationDelegateResult.Success(token);

            // Assert
            Assert.True(result.Handled);
            Assert.Same(token, result.Token);
        }

        [Fact]
        public void SignatureValidationDelegateResult_Success_NullToken_ThrowsArgumentNullException()
        {
            // Act & Assert
            Assert.Throws<ArgumentNullException>(() => SignatureValidationDelegateResult.Success(null));
        }

        [Fact]
        public async Task CopyConstructor_CopiesSignatureValidatorWithToken()
        {
            // Arrange
            var signingKey = KeyingMaterial.RsaSecurityKey_2048;
            var tokenString = CreateSignedToken(signingKey, SecurityAlgorithms.RsaSha256);

            bool delegateCalled = false;
            var originalTvp = CreateBaseValidationParameters(signingKey);
            originalTvp.SignatureValidatorWithToken = (token, validationParameters, configuration) =>
            {
                delegateCalled = true;
                var jwt = (JsonWebToken)token;
                jwt.SigningKey = validationParameters.IssuerSigningKey;
                return SignatureValidationDelegateResult.Success(jwt);
            };

            // Act — clone via copy constructor
            var clonedTvp = originalTvp.Clone();
            var result = await CreateHandler().ValidateTokenAsync(tokenString, clonedTvp);

            // Assert
            Assert.True(delegateCalled, "Delegate from cloned TVP should have been called.");
            Assert.True(result.IsValid, $"Validation failed: {result.Exception?.Message}");
        }

        /// <summary>
        /// A minimal mock that captures signature validation telemetry calls.
        /// Inherits from <see cref="Telemetry.TelemetryClient"/> and overrides nothing
        /// except signature validation counter to capture the call.
        /// </summary>
        private class SignatureValidationMockTelemetryClient : Telemetry.ITelemetryClient
        {
            public int SignatureValidationCallCount { get; private set; }
            public string LastErrorType { get; private set; }
            public string LastAlgorithm { get; private set; }

            void Telemetry.ITelemetryClient.IncrementSignatureValidationCounter(string errorType, string issuer, string algorithm, SecurityKey key)
            {
                SignatureValidationCallCount++;
                LastErrorType = errorType;
                LastAlgorithm = algorithm;
            }

            void Telemetry.ITelemetryClient.IncrementConfigurationRefreshRequestCounter(string metadataAddress, string operationStatus, string configurationSource) { }
            void Telemetry.ITelemetryClient.IncrementConfigurationRefreshRequestCounter(string metadataAddress, string operationStatus, string configurationSource, Exception exception) { }
            void Telemetry.ITelemetryClient.IncrementConfigurationRefreshRequestCounter(string metadataAddress, string operationStatus, Exception exception) { }
            void Telemetry.ITelemetryClient.IncrementConfigurationRefreshRequestCounter(string metadataAddress, string operationStatus) { }
            void Telemetry.ITelemetryClient.LogConfigurationRetrievalDuration(string metadataAddress, string configurationSource, TimeSpan operationDuration) { }
            void Telemetry.ITelemetryClient.LogConfigurationRetrievalDuration(string metadataAddress, string configurationSource, TimeSpan operationDuration, Exception exception) { }
            void Telemetry.ITelemetryClient.LogConfigurationRetrievalDuration(string metadataAddress, TimeSpan operationDuration) { }
            void Telemetry.ITelemetryClient.LogConfigurationRetrievalDuration(string metadataAddress, TimeSpan operationDuration, Exception exception) { }
            void Telemetry.ITelemetryClient.LogBackgroundConfigurationRefreshFailure(string metadataAddress, string configurationSource, Exception exception) { }
            void Telemetry.ITelemetryClient.LogBackgroundConfigurationRefreshFailure(string metadataAddress, Exception exception) { }
        }
    }
}
