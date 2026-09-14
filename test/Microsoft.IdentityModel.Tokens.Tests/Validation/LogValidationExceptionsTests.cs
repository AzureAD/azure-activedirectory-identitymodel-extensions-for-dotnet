// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using Microsoft.IdentityModel.Abstractions;
using Microsoft.IdentityModel.Logging;
using Microsoft.IdentityModel.TestUtils;
using Xunit;

namespace Microsoft.IdentityModel.Tokens.Tests
{
    /// <summary>
    /// Tests for verifying that the LogValidationExceptions flag correctly controls
    /// whether validation exceptions are logged or not.
    /// </summary>
    public class LogValidationExceptionsTests : IDisposable
    {
        private readonly IIdentityLogger _originalLogger;

        public LogValidationExceptionsTests()
        {
            // Save original logger to restore after each test
            _originalLogger = LogHelper.Logger;
        }

        public void Dispose()
        {
            // Restore original logger after each test
            LogHelper.Logger = _originalLogger;
        }

        #region ValidateAlgorithm Tests

        [Fact]
        public void ValidateAlgorithm_CustomValidator_LogValidationExceptionsTrue_ExceptionIsLogged()
        {
            // Arrange
            var logger = new TestLogger();
            LogHelper.Logger = logger;

            var validationParameters = new TokenValidationParameters
            {
                LogValidationExceptions = true,
                AlgorithmValidator = (algorithm, securityKey, token, tvp) => false // Always fail
            };

            // Act & Assert
            var exception = Assert.Throws<SecurityTokenInvalidAlgorithmException>(() =>
                Validators.ValidateAlgorithm("RS256", null, null, validationParameters));

            // Verify exception was logged
            Assert.True(logger.ContainsLog("IDX10697"), "IDX10697 should be logged when LogValidationExceptions is true");
        }

        [Fact]
        public void ValidateAlgorithm_CustomValidator_LogValidationExceptionsFalse_ExceptionIsNotLogged()
        {
            // Arrange
            var logger = new TestLogger();
            LogHelper.Logger = logger;

            var validationParameters = new TokenValidationParameters
            {
                LogValidationExceptions = false,
                AlgorithmValidator = (algorithm, securityKey, token, tvp) => false // Always fail
            };

            // Act & Assert
            var exception = Assert.Throws<SecurityTokenInvalidAlgorithmException>(() =>
                Validators.ValidateAlgorithm("RS256", null, null, validationParameters));

            // Verify exception was NOT logged
            Assert.False(logger.ContainsLog("IDX10697"), "IDX10697 should NOT be logged when LogValidationExceptions is false");
        }

        [Fact]
        public void ValidateAlgorithm_InvalidAlgorithm_LogValidationExceptionsTrue_ExceptionIsLogged()
        {
            // Arrange
            var logger = new TestLogger();
            LogHelper.Logger = logger;

            var validationParameters = new TokenValidationParameters
            {
                LogValidationExceptions = true,
                ValidAlgorithms = new List<string> { "HS256" }
            };

            // Act & Assert
            var exception = Assert.Throws<SecurityTokenInvalidAlgorithmException>(() =>
                Validators.ValidateAlgorithm("RS256", null, null, validationParameters));

            // Verify exception was logged
            Assert.True(logger.ContainsLog("IDX10696"), "IDX10696 should be logged when LogValidationExceptions is true");
        }

        [Fact]
        public void ValidateAlgorithm_InvalidAlgorithm_LogValidationExceptionsFalse_ExceptionIsNotLogged()
        {
            // Arrange
            var logger = new TestLogger();
            LogHelper.Logger = logger;

            var validationParameters = new TokenValidationParameters
            {
                LogValidationExceptions = false,
                ValidAlgorithms = new List<string> { "HS256" }
            };

            // Act & Assert
            var exception = Assert.Throws<SecurityTokenInvalidAlgorithmException>(() =>
                Validators.ValidateAlgorithm("RS256", null, null, validationParameters));

            // Verify exception was NOT logged
            Assert.False(logger.ContainsLog("IDX10696"), "IDX10696 should NOT be logged when LogValidationExceptions is false");
        }

        #endregion

        #region ValidateAudience Tests

        [Fact]
        public void ValidateAudience_CustomValidator_LogValidationExceptionsTrue_ExceptionIsLogged()
        {
            // Arrange
            var logger = new TestLogger();
            LogHelper.Logger = logger;

            var validationParameters = new TokenValidationParameters
            {
                LogValidationExceptions = true,
                AudienceValidator = (audiences, token, tvp) => false // Always fail
            };

            // Act & Assert
            var exception = Assert.Throws<SecurityTokenInvalidAudienceException>(() =>
                Validators.ValidateAudience(new List<string> { "audience" }, null, validationParameters));

            // Verify exception was logged
            Assert.True(logger.ContainsLog("IDX10231"), "IDX10231 should be logged when LogValidationExceptions is true");
        }

        [Fact]
        public void ValidateAudience_CustomValidator_LogValidationExceptionsFalse_ExceptionIsNotLogged()
        {
            // Arrange
            var logger = new TestLogger();
            LogHelper.Logger = logger;

            var validationParameters = new TokenValidationParameters
            {
                LogValidationExceptions = false,
                AudienceValidator = (audiences, token, tvp) => false // Always fail
            };

            // Act & Assert
            var exception = Assert.Throws<SecurityTokenInvalidAudienceException>(() =>
                Validators.ValidateAudience(new List<string> { "audience" }, null, validationParameters));

            // Verify exception was NOT logged
            Assert.False(logger.ContainsLog("IDX10231"), "IDX10231 should NOT be logged when LogValidationExceptions is false");
        }

        [Fact]
        public void ValidateAudience_NullAudiences_LogValidationExceptionsTrue_ExceptionIsLogged()
        {
            // Arrange
            var logger = new TestLogger();
            LogHelper.Logger = logger;

            var validationParameters = new TokenValidationParameters
            {
                LogValidationExceptions = true,
                ValidateAudience = true
            };

            // Act & Assert
            var exception = Assert.Throws<SecurityTokenInvalidAudienceException>(() =>
                Validators.ValidateAudience(null, null, validationParameters));

            // Verify exception was logged
            Assert.True(logger.ContainsLog("IDX10207"), "IDX10207 should be logged when LogValidationExceptions is true");
        }

        [Fact]
        public void ValidateAudience_NullAudiences_LogValidationExceptionsFalse_ExceptionIsNotLogged()
        {
            // Arrange
            var logger = new TestLogger();
            LogHelper.Logger = logger;

            var validationParameters = new TokenValidationParameters
            {
                LogValidationExceptions = false,
                ValidateAudience = true
            };

            // Act & Assert
            var exception = Assert.Throws<SecurityTokenInvalidAudienceException>(() =>
                Validators.ValidateAudience(null, null, validationParameters));

            // Verify exception was NOT logged
            Assert.False(logger.ContainsLog("IDX10207"), "IDX10207 should NOT be logged when LogValidationExceptions is false");
        }

        [Fact]
        public void ValidateAudience_NoValidAudienceConfigured_LogValidationExceptionsTrue_ExceptionIsLogged()
        {
            // Arrange
            var logger = new TestLogger();
            LogHelper.Logger = logger;

            var validationParameters = new TokenValidationParameters
            {
                LogValidationExceptions = true,
                ValidateAudience = true,
                ValidAudience = null,
                ValidAudiences = null
            };

            // Act & Assert
            var exception = Assert.Throws<SecurityTokenInvalidAudienceException>(() =>
                Validators.ValidateAudience(new List<string> { "audience" }, null, validationParameters));

            // Verify exception was logged (IDX10208)
            Assert.True(logger.ContainsLog("IDX10208"), "IDX10208 should be logged when LogValidationExceptions is true");
        }

        [Fact]
        public void ValidateAudience_NoValidAudienceConfigured_LogValidationExceptionsFalse_ExceptionIsNotLogged()
        {
            // Arrange
            var logger = new TestLogger();
            LogHelper.Logger = logger;

            var validationParameters = new TokenValidationParameters
            {
                LogValidationExceptions = false,
                ValidateAudience = true,
                ValidAudience = null,
                ValidAudiences = null
            };

            // Act & Assert
            var exception = Assert.Throws<SecurityTokenInvalidAudienceException>(() =>
                Validators.ValidateAudience(new List<string> { "audience" }, null, validationParameters));

            // Verify exception was NOT logged (IDX10208)
            Assert.False(logger.ContainsLog("IDX10208"), "IDX10208 should NOT be logged when LogValidationExceptions is false");
        }

        [Fact]
        public void ValidateAudience_EmptyAudiencesList_LogValidationExceptionsTrue_ExceptionIsLogged()
        {
            // Arrange
            var logger = new TestLogger();
            LogHelper.Logger = logger;

            var validationParameters = new TokenValidationParameters
            {
                LogValidationExceptions = true,
                ValidateAudience = true,
                ValidAudience = "valid-audience"
            };

            // Act & Assert
            var exception = Assert.Throws<SecurityTokenInvalidAudienceException>(() =>
                Validators.ValidateAudience(new List<string>(), null, validationParameters));

            // Verify exception was logged (IDX10206)
            Assert.True(logger.ContainsLog("IDX10206"), "IDX10206 should be logged when LogValidationExceptions is true");
        }

        [Fact]
        public void ValidateAudience_EmptyAudiencesList_LogValidationExceptionsFalse_ExceptionIsNotLogged()
        {
            // Arrange
            var logger = new TestLogger();
            LogHelper.Logger = logger;

            var validationParameters = new TokenValidationParameters
            {
                LogValidationExceptions = false,
                ValidateAudience = true,
                ValidAudience = "valid-audience"
            };

            // Act & Assert
            var exception = Assert.Throws<SecurityTokenInvalidAudienceException>(() =>
                Validators.ValidateAudience(new List<string>(), null, validationParameters));

            // Verify exception was NOT logged (IDX10206)
            Assert.False(logger.ContainsLog("IDX10206"), "IDX10206 should NOT be logged when LogValidationExceptions is false");
        }

        #endregion

        #region ValidateLifetime Tests

        [Fact]
        public void ValidateLifetime_CustomValidator_LogValidationExceptionsTrue_ExceptionIsLogged()
        {
            // Arrange
            var logger = new TestLogger();
            LogHelper.Logger = logger;

            var validationParameters = new TokenValidationParameters
            {
                LogValidationExceptions = true,
                LifetimeValidator = (notBefore, expires, token, tvp) => false // Always fail
            };

            // Act & Assert
            var exception = Assert.Throws<SecurityTokenInvalidLifetimeException>(() =>
                Validators.ValidateLifetime(DateTime.UtcNow, DateTime.UtcNow.AddHours(1), null, validationParameters));

            // Verify exception was logged - This is the IDX10230 mentioned in the issue
            Assert.True(logger.ContainsLog("IDX10230"), "IDX10230 should be logged when LogValidationExceptions is true");
        }

        [Fact]
        public void ValidateLifetime_CustomValidator_LogValidationExceptionsFalse_ExceptionIsNotLogged()
        {
            // Arrange
            var logger = new TestLogger();
            LogHelper.Logger = logger;

            var validationParameters = new TokenValidationParameters
            {
                LogValidationExceptions = false,
                LifetimeValidator = (notBefore, expires, token, tvp) => false // Always fail
            };

            // Act & Assert
            var exception = Assert.Throws<SecurityTokenInvalidLifetimeException>(() =>
                Validators.ValidateLifetime(DateTime.UtcNow, DateTime.UtcNow.AddHours(1), null, validationParameters));

            // Verify exception was NOT logged - This verifies the fix for the issue
            Assert.False(logger.ContainsLog("IDX10230"), "IDX10230 should NOT be logged when LogValidationExceptions is false");
        }

        [Fact]
        public void ValidatorUtilities_ValidateLifetime_NoExpiration_LogValidationExceptionsTrue_ExceptionIsLogged()
        {
            // Arrange
            var logger = new TestLogger();
            LogHelper.Logger = logger;

            var validationParameters = new TokenValidationParameters
            {
                LogValidationExceptions = true,
                RequireExpirationTime = true,
                ValidateLifetime = true
            };

            // Act & Assert
            var exception = Assert.Throws<SecurityTokenNoExpirationException>(() =>
                ValidatorUtilities.ValidateLifetime(DateTime.UtcNow, null, null, validationParameters));

            // Verify exception was logged
            Assert.True(logger.ContainsLog("IDX10225"), "IDX10225 should be logged when LogValidationExceptions is true");
        }

        [Fact]
        public void ValidatorUtilities_ValidateLifetime_NoExpiration_LogValidationExceptionsFalse_ExceptionIsNotLogged()
        {
            // Arrange
            var logger = new TestLogger();
            LogHelper.Logger = logger;

            var validationParameters = new TokenValidationParameters
            {
                LogValidationExceptions = false,
                RequireExpirationTime = true,
                ValidateLifetime = true
            };

            // Act & Assert
            var exception = Assert.Throws<SecurityTokenNoExpirationException>(() =>
                ValidatorUtilities.ValidateLifetime(DateTime.UtcNow, null, null, validationParameters));

            // Verify exception was NOT logged
            Assert.False(logger.ContainsLog("IDX10225"), "IDX10225 should NOT be logged when LogValidationExceptions is false");
        }

        [Fact]
        public void ValidatorUtilities_ValidateLifetime_TokenExpired_LogValidationExceptionsTrue_ExceptionIsLogged()
        {
            // Arrange
            var logger = new TestLogger();
            LogHelper.Logger = logger;

            var validationParameters = new TokenValidationParameters
            {
                LogValidationExceptions = true,
                ValidateLifetime = true
            };

            // Act & Assert
            var exception = Assert.Throws<SecurityTokenExpiredException>(() =>
                ValidatorUtilities.ValidateLifetime(null, DateTime.UtcNow.AddHours(-1), null, validationParameters));

            // Verify exception was logged
            Assert.True(logger.ContainsLog("IDX10223"), "IDX10223 should be logged when LogValidationExceptions is true");
        }

        [Fact]
        public void ValidatorUtilities_ValidateLifetime_TokenExpired_LogValidationExceptionsFalse_ExceptionIsNotLogged()
        {
            // Arrange
            var logger = new TestLogger();
            LogHelper.Logger = logger;

            var validationParameters = new TokenValidationParameters
            {
                LogValidationExceptions = false,
                ValidateLifetime = true
            };

            // Act & Assert
            var exception = Assert.Throws<SecurityTokenExpiredException>(() =>
                ValidatorUtilities.ValidateLifetime(null, DateTime.UtcNow.AddHours(-1), null, validationParameters));

            // Verify exception was NOT logged
            Assert.False(logger.ContainsLog("IDX10223"), "IDX10223 should NOT be logged when LogValidationExceptions is false");
        }

        [Fact]
        public void ValidatorUtilities_ValidateLifetime_InvalidLifetimeNotBeforeAfterExpires_LogValidationExceptionsTrue_ExceptionIsLogged()
        {
            // Arrange
            var logger = new TestLogger();
            LogHelper.Logger = logger;

            var validationParameters = new TokenValidationParameters
            {
                LogValidationExceptions = true,
                ValidateLifetime = true
            };

            var notBefore = DateTime.UtcNow.AddHours(1);
            var expires = DateTime.UtcNow; // expires before notBefore

            // Act & Assert
            var exception = Assert.Throws<SecurityTokenInvalidLifetimeException>(() =>
                ValidatorUtilities.ValidateLifetime(notBefore, expires, null, validationParameters));

            // Verify exception was logged (IDX10224)
            Assert.True(logger.ContainsLog("IDX10224"), "IDX10224 should be logged when LogValidationExceptions is true");
        }

        [Fact]
        public void ValidatorUtilities_ValidateLifetime_InvalidLifetimeNotBeforeAfterExpires_LogValidationExceptionsFalse_ExceptionIsNotLogged()
        {
            // Arrange
            var logger = new TestLogger();
            LogHelper.Logger = logger;

            var validationParameters = new TokenValidationParameters
            {
                LogValidationExceptions = false,
                ValidateLifetime = true
            };

            var notBefore = DateTime.UtcNow.AddHours(1);
            var expires = DateTime.UtcNow; // expires before notBefore

            // Act & Assert
            var exception = Assert.Throws<SecurityTokenInvalidLifetimeException>(() =>
                ValidatorUtilities.ValidateLifetime(notBefore, expires, null, validationParameters));

            // Verify exception was NOT logged (IDX10224)
            Assert.False(logger.ContainsLog("IDX10224"), "IDX10224 should NOT be logged when LogValidationExceptions is false");
        }

        [Fact]
        public void ValidatorUtilities_ValidateLifetime_TokenNotYetValid_LogValidationExceptionsTrue_ExceptionIsLogged()
        {
            // Arrange
            var logger = new TestLogger();
            LogHelper.Logger = logger;

            var validationParameters = new TokenValidationParameters
            {
                LogValidationExceptions = true,
                ValidateLifetime = true,
                ClockSkew = TimeSpan.Zero
            };

            // Act & Assert
            var exception = Assert.Throws<SecurityTokenNotYetValidException>(() =>
                ValidatorUtilities.ValidateLifetime(DateTime.UtcNow.AddHours(1), DateTime.UtcNow.AddHours(2), null, validationParameters));

            // Verify exception was logged (IDX10222)
            Assert.True(logger.ContainsLog("IDX10222"), "IDX10222 should be logged when LogValidationExceptions is true");
        }

        [Fact]
        public void ValidatorUtilities_ValidateLifetime_TokenNotYetValid_LogValidationExceptionsFalse_ExceptionIsNotLogged()
        {
            // Arrange
            var logger = new TestLogger();
            LogHelper.Logger = logger;

            var validationParameters = new TokenValidationParameters
            {
                LogValidationExceptions = false,
                ValidateLifetime = true,
                ClockSkew = TimeSpan.Zero
            };

            // Act & Assert
            var exception = Assert.Throws<SecurityTokenNotYetValidException>(() =>
                ValidatorUtilities.ValidateLifetime(DateTime.UtcNow.AddHours(1), DateTime.UtcNow.AddHours(2), null, validationParameters));

            // Verify exception was NOT logged (IDX10222)
            Assert.False(logger.ContainsLog("IDX10222"), "IDX10222 should NOT be logged when LogValidationExceptions is false");
        }

        #endregion

        #region ValidateIssuer Tests

        [Fact]
        public void ValidateIssuer_EmptyIssuer_LogValidationExceptionsTrue_ExceptionIsLogged()
        {
            // Arrange
            var logger = new TestLogger();
            LogHelper.Logger = logger;

            var validationParameters = new TokenValidationParameters
            {
                LogValidationExceptions = true,
                ValidateIssuer = true
            };

            // Act & Assert
            var exception = Assert.Throws<SecurityTokenInvalidIssuerException>(() =>
                Validators.ValidateIssuer("", null, validationParameters));

            // Verify exception was logged
            Assert.True(logger.ContainsLog("IDX10211"), "IDX10211 should be logged when LogValidationExceptions is true");
        }

        [Fact]
        public void ValidateIssuer_EmptyIssuer_LogValidationExceptionsFalse_ExceptionIsNotLogged()
        {
            // Arrange
            var logger = new TestLogger();
            LogHelper.Logger = logger;

            var validationParameters = new TokenValidationParameters
            {
                LogValidationExceptions = false,
                ValidateIssuer = true
            };

            // Act & Assert
            var exception = Assert.Throws<SecurityTokenInvalidIssuerException>(() =>
                Validators.ValidateIssuer("", null, validationParameters));

            // Verify exception was NOT logged
            Assert.False(logger.ContainsLog("IDX10211"), "IDX10211 should NOT be logged when LogValidationExceptions is false");
        }

        [Fact]
        public void ValidateIssuer_NoValidIssuerConfigured_LogValidationExceptionsTrue_ExceptionIsLogged()
        {
            // Arrange
            var logger = new TestLogger();
            LogHelper.Logger = logger;

            var validationParameters = new TokenValidationParameters
            {
                LogValidationExceptions = true,
                ValidateIssuer = true,
                ValidIssuer = null,
                ValidIssuers = null
            };

            // Act & Assert
            var exception = Assert.Throws<SecurityTokenInvalidIssuerException>(() =>
                Validators.ValidateIssuer("issuer", null, validationParameters));

            // Verify exception was logged (IDX10204)
            Assert.True(logger.ContainsLog("IDX10204"), "IDX10204 should be logged when LogValidationExceptions is true");
        }

        [Fact]
        public void ValidateIssuer_NoValidIssuerConfigured_LogValidationExceptionsFalse_ExceptionIsNotLogged()
        {
            // Arrange
            var logger = new TestLogger();
            LogHelper.Logger = logger;

            var validationParameters = new TokenValidationParameters
            {
                LogValidationExceptions = false,
                ValidateIssuer = true,
                ValidIssuer = null,
                ValidIssuers = null
            };

            // Act & Assert
            var exception = Assert.Throws<SecurityTokenInvalidIssuerException>(() =>
                Validators.ValidateIssuer("issuer", null, validationParameters));

            // Verify exception was NOT logged (IDX10204)
            Assert.False(logger.ContainsLog("IDX10204"), "IDX10204 should NOT be logged when LogValidationExceptions is false");
        }

        #endregion

        #region ValidateIssuerSecurityKey Tests

        [Fact]
        public void ValidateIssuerSecurityKey_CustomValidator_LogValidationExceptionsTrue_ExceptionIsLogged()
        {
            // Arrange
            var logger = new TestLogger();
            LogHelper.Logger = logger;

            var validationParameters = new TokenValidationParameters
            {
                LogValidationExceptions = true,
                IssuerSigningKeyValidator = (securityKey, token, tvp) => false // Always fail
            };

            // Act & Assert
            var exception = Assert.Throws<SecurityTokenInvalidSigningKeyException>(() =>
                Validators.ValidateIssuerSecurityKey(KeyingMaterial.SymmetricSecurityKey2_256, new JwtSecurityToken(), validationParameters));

            // Verify exception was logged
            Assert.True(logger.ContainsLog("IDX10232"), "IDX10232 should be logged when LogValidationExceptions is true");
        }

        [Fact]
        public void ValidateIssuerSecurityKey_CustomValidator_LogValidationExceptionsFalse_ExceptionIsNotLogged()
        {
            // Arrange
            var logger = new TestLogger();
            LogHelper.Logger = logger;

            var validationParameters = new TokenValidationParameters
            {
                LogValidationExceptions = false,
                IssuerSigningKeyValidator = (securityKey, token, tvp) => false // Always fail
            };

            // Act & Assert
            var exception = Assert.Throws<SecurityTokenInvalidSigningKeyException>(() =>
                Validators.ValidateIssuerSecurityKey(KeyingMaterial.SymmetricSecurityKey2_256, new JwtSecurityToken(), validationParameters));

            // Verify exception was NOT logged
            Assert.False(logger.ContainsLog("IDX10232"), "IDX10232 should NOT be logged when LogValidationExceptions is false");
        }

        [Fact]
        public void ValidateIssuerSigningKeyLifeTime_ExpiredCertificate_LogValidationExceptionsTrue_ExceptionIsLogged()
        {
            // Arrange
            var logger = new TestLogger();
            LogHelper.Logger = logger;

            var validationParameters = new TokenValidationParameters
            {
                LogValidationExceptions = true,
                ValidateIssuerSigningKey = true
            };

            // Act & Assert
            var exception = Assert.Throws<SecurityTokenInvalidSigningKeyException>(() =>
                Validators.ValidateIssuerSecurityKey(KeyingMaterial.ExpiredX509SecurityKey_Public, new JwtSecurityToken(), validationParameters));

            // Verify exception was logged
            Assert.True(logger.ContainsLog("IDX10249"), "IDX10249 should be logged when LogValidationExceptions is true");
        }

        [Fact]
        public void ValidateIssuerSigningKeyLifeTime_ExpiredCertificate_LogValidationExceptionsFalse_ExceptionIsNotLogged()
        {
            // Arrange
            var logger = new TestLogger();
            LogHelper.Logger = logger;

            var validationParameters = new TokenValidationParameters
            {
                LogValidationExceptions = false,
                ValidateIssuerSigningKey = true
            };

            // Act & Assert
            var exception = Assert.Throws<SecurityTokenInvalidSigningKeyException>(() =>
                Validators.ValidateIssuerSecurityKey(KeyingMaterial.ExpiredX509SecurityKey_Public, new JwtSecurityToken(), validationParameters));

            // Verify exception was NOT logged
            Assert.False(logger.ContainsLog("IDX10249"), "IDX10249 should NOT be logged when LogValidationExceptions is false");
        }

        [Fact]
        public void ValidateIssuerSecurityKey_CustomValidatorUsingConfiguration_LogValidationExceptionsTrue_ExceptionIsLogged()
        {
            // Arrange
            var logger = new TestLogger();
            LogHelper.Logger = logger;

            var validationParameters = new TokenValidationParameters
            {
                LogValidationExceptions = true,
                IssuerSigningKeyValidatorUsingConfiguration = (securityKey, token, tvp, config) => false // Always fail
            };

            // Act & Assert
            var exception = Assert.Throws<SecurityTokenInvalidSigningKeyException>(() =>
                Validators.ValidateIssuerSecurityKey(KeyingMaterial.SymmetricSecurityKey2_256, new JwtSecurityToken(), validationParameters));

            // Verify exception was logged (IDX10232 - second path)
            Assert.True(logger.ContainsLog("IDX10232"), "IDX10232 should be logged when LogValidationExceptions is true (IssuerSigningKeyValidatorUsingConfiguration)");
        }

        [Fact]
        public void ValidateIssuerSecurityKey_CustomValidatorUsingConfiguration_LogValidationExceptionsFalse_ExceptionIsNotLogged()
        {
            // Arrange
            var logger = new TestLogger();
            LogHelper.Logger = logger;

            var validationParameters = new TokenValidationParameters
            {
                LogValidationExceptions = false,
                IssuerSigningKeyValidatorUsingConfiguration = (securityKey, token, tvp, config) => false // Always fail
            };

            // Act & Assert
            var exception = Assert.Throws<SecurityTokenInvalidSigningKeyException>(() =>
                Validators.ValidateIssuerSecurityKey(KeyingMaterial.SymmetricSecurityKey2_256, new JwtSecurityToken(), validationParameters));

            // Verify exception was NOT logged (IDX10232 - second path)
            Assert.False(logger.ContainsLog("IDX10232"), "IDX10232 should NOT be logged when LogValidationExceptions is false (IssuerSigningKeyValidatorUsingConfiguration)");
        }

        [Fact]
        public void ValidateIssuerSigningKeyLifeTime_NotYetValidCertificate_LogValidationExceptionsTrue_ExceptionIsLogged()
        {
            // Arrange
            var logger = new TestLogger();
            LogHelper.Logger = logger;

            var validationParameters = new TokenValidationParameters
            {
                LogValidationExceptions = true,
                ValidateIssuerSigningKey = true
            };

            // Act & Assert
            var exception = Assert.Throws<SecurityTokenInvalidSigningKeyException>(() =>
                Validators.ValidateIssuerSecurityKey(KeyingMaterial.NotYetValidX509SecurityKey_Public, new JwtSecurityToken(), validationParameters));

            // Verify exception was logged (IDX10248)
            Assert.True(logger.ContainsLog("IDX10248"), "IDX10248 should be logged when LogValidationExceptions is true");
        }

        [Fact]
        public void ValidateIssuerSigningKeyLifeTime_NotYetValidCertificate_LogValidationExceptionsFalse_ExceptionIsNotLogged()
        {
            // Arrange
            var logger = new TestLogger();
            LogHelper.Logger = logger;

            var validationParameters = new TokenValidationParameters
            {
                LogValidationExceptions = false,
                ValidateIssuerSigningKey = true
            };

            // Act & Assert
            var exception = Assert.Throws<SecurityTokenInvalidSigningKeyException>(() =>
                Validators.ValidateIssuerSecurityKey(KeyingMaterial.NotYetValidX509SecurityKey_Public, new JwtSecurityToken(), validationParameters));

            // Verify exception was NOT logged (IDX10248)
            Assert.False(logger.ContainsLog("IDX10248"), "IDX10248 should NOT be logged when LogValidationExceptions is false");
        }

        #endregion

        #region ValidateTokenReplay Tests

        [Fact]
        public void ValidateTokenReplay_CustomValidator_LogValidationExceptionsTrue_ExceptionIsLogged()
        {
            // Arrange
            var logger = new TestLogger();
            LogHelper.Logger = logger;

            var validationParameters = new TokenValidationParameters
            {
                LogValidationExceptions = true,
                TokenReplayValidator = (expirationTime, securityToken, tvp) => false // Always fail
            };

            // Act & Assert
            var exception = Assert.Throws<SecurityTokenReplayDetectedException>(() =>
                Validators.ValidateTokenReplay(DateTime.UtcNow.AddHours(1), "token", validationParameters));

            // Verify exception was logged
            Assert.True(logger.ContainsLog("IDX10228"), "IDX10228 should be logged when LogValidationExceptions is true");
        }

        [Fact]
        public void ValidateTokenReplay_CustomValidator_LogValidationExceptionsFalse_ExceptionIsNotLogged()
        {
            // Arrange
            var logger = new TestLogger();
            LogHelper.Logger = logger;

            var validationParameters = new TokenValidationParameters
            {
                LogValidationExceptions = false,
                TokenReplayValidator = (expirationTime, securityToken, tvp) => false // Always fail
            };

            // Act & Assert
            var exception = Assert.Throws<SecurityTokenReplayDetectedException>(() =>
                Validators.ValidateTokenReplay(DateTime.UtcNow.AddHours(1), "token", validationParameters));

            // Verify exception was NOT logged
            Assert.False(logger.ContainsLog("IDX10228"), "IDX10228 should NOT be logged when LogValidationExceptions is false");
        }

        [Fact]
        public void ValidateTokenReplay_TokenFoundInCache_LogValidationExceptionsTrue_ExceptionIsLogged()
        {
            // Arrange
            var logger = new TestLogger();
            LogHelper.Logger = logger;

            var validationParameters = new TokenValidationParameters
            {
                LogValidationExceptions = true,
                ValidateTokenReplay = true,
                TokenReplayCache = new TestTokenReplayCache { FindRetVal = true, AddRetVal = true }
            };

            // Act & Assert
            var exception = Assert.Throws<SecurityTokenReplayDetectedException>(() =>
                Validators.ValidateTokenReplay(DateTime.UtcNow.AddHours(1), "token", validationParameters));

            // Verify exception was logged (IDX10228 - second path)
            Assert.True(logger.ContainsLog("IDX10228"), "IDX10228 should be logged when LogValidationExceptions is true (TokenReplayCache.TryFind)");
        }

        [Fact]
        public void ValidateTokenReplay_TokenFoundInCache_LogValidationExceptionsFalse_ExceptionIsNotLogged()
        {
            // Arrange
            var logger = new TestLogger();
            LogHelper.Logger = logger;

            var validationParameters = new TokenValidationParameters
            {
                LogValidationExceptions = false,
                ValidateTokenReplay = true,
                TokenReplayCache = new TestTokenReplayCache { FindRetVal = true, AddRetVal = true }
            };

            // Act & Assert
            var exception = Assert.Throws<SecurityTokenReplayDetectedException>(() =>
                Validators.ValidateTokenReplay(DateTime.UtcNow.AddHours(1), "token", validationParameters));

            // Verify exception was NOT logged (IDX10228 - second path)
            Assert.False(logger.ContainsLog("IDX10228"), "IDX10228 should NOT be logged when LogValidationExceptions is false (TokenReplayCache.TryFind)");
        }

        [Fact]
        public void ValidateTokenReplay_AddToReplayCacheFailed_LogValidationExceptionsTrue_ExceptionIsLogged()
        {
            // Arrange
            var logger = new TestLogger();
            LogHelper.Logger = logger;

            var validationParameters = new TokenValidationParameters
            {
                LogValidationExceptions = true,
                ValidateTokenReplay = true,
                TokenReplayCache = new TestTokenReplayCache { FindRetVal = false, AddRetVal = false }
            };

            // Act & Assert
            var exception = Assert.Throws<SecurityTokenReplayAddFailedException>(() =>
                Validators.ValidateTokenReplay(DateTime.UtcNow.AddHours(1), "token", validationParameters));

            // Verify exception was logged (IDX10229)
            Assert.True(logger.ContainsLog("IDX10229"), "IDX10229 should be logged when LogValidationExceptions is true");
        }

        [Fact]
        public void ValidateTokenReplay_AddToReplayCacheFailed_LogValidationExceptionsFalse_ExceptionIsNotLogged()
        {
            // Arrange
            var logger = new TestLogger();
            LogHelper.Logger = logger;

            var validationParameters = new TokenValidationParameters
            {
                LogValidationExceptions = false,
                ValidateTokenReplay = true,
                TokenReplayCache = new TestTokenReplayCache { FindRetVal = false, AddRetVal = false }
            };

            // Act & Assert
            var exception = Assert.Throws<SecurityTokenReplayAddFailedException>(() =>
                Validators.ValidateTokenReplay(DateTime.UtcNow.AddHours(1), "token", validationParameters));

            // Verify exception was NOT logged (IDX10229)
            Assert.False(logger.ContainsLog("IDX10229"), "IDX10229 should NOT be logged when LogValidationExceptions is false");
        }

        #endregion

        #region ValidateTokenType Tests

        [Fact]
        public void ValidateTokenType_NullTokenType_LogValidationExceptionsTrue_ExceptionIsLogged()
        {
            // Arrange
            var logger = new TestLogger();
            LogHelper.Logger = logger;

            var validationParameters = new TokenValidationParameters
            {
                LogValidationExceptions = true,
                ValidTypes = new List<string> { "JWT" }
            };

            // Act & Assert
            var exception = Assert.Throws<SecurityTokenInvalidTypeException>(() =>
                Validators.ValidateTokenType(null, new JwtSecurityToken(), validationParameters));

            // Verify exception was logged
            Assert.True(logger.ContainsLog("IDX10256"), "IDX10256 should be logged when LogValidationExceptions is true");
        }

        [Fact]
        public void ValidateTokenType_NullTokenType_LogValidationExceptionsFalse_ExceptionIsNotLogged()
        {
            // Arrange
            var logger = new TestLogger();
            LogHelper.Logger = logger;

            var validationParameters = new TokenValidationParameters
            {
                LogValidationExceptions = false,
                ValidTypes = new List<string> { "JWT" }
            };

            // Act & Assert
            var exception = Assert.Throws<SecurityTokenInvalidTypeException>(() =>
                Validators.ValidateTokenType(null, new JwtSecurityToken(), validationParameters));

            // Verify exception was NOT logged
            Assert.False(logger.ContainsLog("IDX10256"), "IDX10256 should NOT be logged when LogValidationExceptions is false");
        }

        [Fact]
        public void ValidateTokenType_InvalidTokenType_LogValidationExceptionsTrue_ExceptionIsLogged()
        {
            // Arrange
            var logger = new TestLogger();
            LogHelper.Logger = logger;

            var validationParameters = new TokenValidationParameters
            {
                LogValidationExceptions = true,
                ValidTypes = new List<string> { "JWT" }
            };

            // Act & Assert
            var exception = Assert.Throws<SecurityTokenInvalidTypeException>(() =>
                Validators.ValidateTokenType("SAML", new JwtSecurityToken(), validationParameters));

            // Verify exception was logged
            Assert.True(logger.ContainsLog("IDX10257"), "IDX10257 should be logged when LogValidationExceptions is true");
        }

        [Fact]
        public void ValidateTokenType_InvalidTokenType_LogValidationExceptionsFalse_ExceptionIsNotLogged()
        {
            // Arrange
            var logger = new TestLogger();
            LogHelper.Logger = logger;

            var validationParameters = new TokenValidationParameters
            {
                LogValidationExceptions = false,
                ValidTypes = new List<string> { "JWT" }
            };

            // Act & Assert
            var exception = Assert.Throws<SecurityTokenInvalidTypeException>(() =>
                Validators.ValidateTokenType("SAML", new JwtSecurityToken(), validationParameters));

            // Verify exception was NOT logged
            Assert.False(logger.ContainsLog("IDX10257"), "IDX10257 should NOT be logged when LogValidationExceptions is false");
        }

        #endregion

        // Helper class for testing token replay cache behavior
        private class TestTokenReplayCache : ITokenReplayCache
        {
            public bool AddRetVal { get; set; }
            public bool FindRetVal { get; set; }

            public bool TryAdd(string securityToken, DateTime expiresOn)
            {
                return AddRetVal;
            }

            public bool TryFind(string securityToken)
            {
                return FindRetVal;
            }
        }

        // Helper class for testing logging behavior
        private class TestLogger : IIdentityLogger
        {
            readonly List<Tuple<string, EventLogLevel>> _logs = new List<Tuple<string, EventLogLevel>>();

            public bool IsEnabled(EventLogLevel logLevel)
            {
                return true;
            }

            public void Log(LogEntry entry)
            {
                _logs.Add(new Tuple<string, EventLogLevel>(entry.Message, entry.EventLogLevel));
            }

            public bool ContainsLog(string substring)
            {
                if (string.IsNullOrEmpty(substring))
                    return true;

                foreach (var log in _logs)
                {
                    if (log.Item1.Contains(substring))
                        return true;
                }

                return false;
            }

            public bool ContainsLogOfSpecificLevel(string substring, EventLogLevel logLevel)
            {
                if (string.IsNullOrEmpty(substring))
                    throw new ArgumentException("Provided value is null or empty.", nameof(substring));

                foreach (var log in _logs)
                {
                    if (log.Item1.Contains(substring) && log.Item2 == logLevel)
                        return true;
                }

                return false;
            }
        }
    }
}
