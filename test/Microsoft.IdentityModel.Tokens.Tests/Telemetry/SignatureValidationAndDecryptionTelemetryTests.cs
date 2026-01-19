// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
#if !NET462 && !NET472 && !NETSTANDARD2_0
using System.Security.Cryptography;
#endif
using System.Threading.Tasks;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Logging;
using Microsoft.IdentityModel.Telemetry;
using Microsoft.IdentityModel.TestUtils;
using Microsoft.IdentityModel.TestUtils.Telemetry;
using Microsoft.IdentityModel.Tokens.Experimental;
using Xunit;

namespace Microsoft.IdentityModel.Tokens.Telemetry.Tests;

/// <summary>
/// Tests for JWT signature validation and decryption telemetry.
/// These tests must run sequentially to avoid telemetry cross-contamination from parallel test execution.
/// </summary>
[Collection("Telemetry Tests")]
public class SignatureValidationAndDecryptionTelemetryTests
{
    [Fact]
    public async Task ValidateToken_SignatureValidationSuccess_RecordsTelemetry()
    {
        // Arrange
        using var listener = new TestMeterListener();
        var handler = new JsonWebTokenHandler();
        var tokenDescriptor = new SecurityTokenDescriptor
        {
            Subject = new CaseSensitiveClaimsIdentity(Default.PayloadClaims),
            SigningCredentials = KeyingMaterial.JsonWebKeyRsa256SigningCredentials,
        };

        var token = handler.CreateToken(tokenDescriptor);
        var validationParameters = new TokenValidationParameters
        {
            IssuerSigningKey = KeyingMaterial.JsonWebKeyRsa256SigningCredentials.Key,
            ValidAudience = Default.Audience,
            ValidIssuer = Default.Issuer,
            ValidateLifetime = false,
        };

        // Act
        var result = await handler.ValidateTokenAsync(token, validationParameters);

        // Assert
        Assert.True(result.IsValid);
        TelemetryAssertionHelpers.AssertTelemetryRecorded(listener, TelemetryDataRecorder.SignatureValidationCounterName,
            new Dictionary<string, object>
            {
                { TelemetryConstants.IdentityModelVersionTag, IdentityModelTelemetryUtil.ClientVer },
                { TelemetryConstants.StatusTag, TelemetryConstants.SuccessValue },
                { TelemetryConstants.AlgorithmTag, SecurityAlgorithms.RsaSha256 },
                { TelemetryConstants.KeyAlgorithmTag, "RSA-2048" }
            });
    }

    [Fact]
    public async Task ValidateToken_SignatureValidationFailure_RecordsTelemetry()
    {
        // Arrange
        using var listener = new TestMeterListener();
        var handler = new JsonWebTokenHandler();
        var tokenDescriptor = new SecurityTokenDescriptor
        {
            Subject = new CaseSensitiveClaimsIdentity(Default.PayloadClaims),
            SigningCredentials = KeyingMaterial.JsonWebKeyRsa256SigningCredentials,
            IncludeKeyIdInHeader = false
        };

        var token = handler.CreateToken(tokenDescriptor);
        var validationParameters = new TokenValidationParameters
        {
            IssuerSigningKey = Default.SymmetricSigningKey256,
            ValidAudience = Default.Audience,
            ValidIssuer = Default.Issuer,
            ValidateLifetime = false,
        };

        // Act
        var result = await handler.ValidateTokenAsync(token, validationParameters);

        // Assert
        Assert.False(result.IsValid);
        TelemetryAssertionHelpers.AssertTelemetryRecorded(listener, TelemetryDataRecorder.SignatureValidationCounterName,
            new Dictionary<string, object>
            {
                { TelemetryConstants.IdentityModelVersionTag, IdentityModelTelemetryUtil.ClientVer },
                { TelemetryConstants.StatusTag, TelemetryConstants.FailureValue },
                { TelemetryConstants.AlgorithmTag, SecurityAlgorithms.RsaSha256 },
                { TelemetryConstants.KeyAlgorithmTag, "SYM-256" }
            });
    }

    [Fact]
    public async Task ValidateToken_TokenDecryptionSuccess_RecordsTelemetry()
    {
        // Arrange
        using var listener = new TestMeterListener();
        var handler = new JsonWebTokenHandler();
        var tokenDescriptor = new SecurityTokenDescriptor
        {
            Subject = new CaseSensitiveClaimsIdentity(Default.PayloadClaims),
            SigningCredentials = Default.SymmetricSigningCredentials,
            EncryptingCredentials = Default.SymmetricEncryptingCredentials,
        };

        var token = handler.CreateToken(tokenDescriptor);
        var validationParameters = new TokenValidationParameters
        {
            IssuerSigningKey = Default.SymmetricSigningCredentials.Key,
            TokenDecryptionKey = Default.SymmetricEncryptingCredentials.Key,
            ValidAudience = Default.Audience,
            ValidIssuer = Default.Issuer,
            ValidateLifetime = false,
        };

        // Act
        var result = await handler.ValidateTokenAsync(token, validationParameters);

        // Assert
        Assert.True(result.IsValid);
        TelemetryAssertionHelpers.AssertTelemetryRecorded(listener, TelemetryDataRecorder.TokenDecryptionCounterName,
            new Dictionary<string, object>
            {
                { TelemetryConstants.IdentityModelVersionTag, IdentityModelTelemetryUtil.ClientVer },
                { TelemetryConstants.StatusTag, TelemetryConstants.SuccessValue },
                { TelemetryConstants.AlgorithmTag, Default.SymmetricEncryptingCredentials.Alg },
                { TelemetryConstants.EncryptionSchemeTag, Default.SymmetricEncryptingCredentials.Enc },
                { TelemetryConstants.KeyAlgorithmTag, "SYM-256" }
            });
    }

    [Fact]
    public async Task ValidateToken_TokenDecryptionFailure_RecordsTelemetry()
    {
        // Arrange
        using var listener = new TestMeterListener();
        var handler = new JsonWebTokenHandler();
        var tokenDescriptor = new SecurityTokenDescriptor
        {
            Subject = new CaseSensitiveClaimsIdentity(Default.PayloadClaims),
            SigningCredentials = Default.SymmetricSigningCredentials,
            EncryptingCredentials = Default.SymmetricEncryptingCredentials,
        };

        var token = handler.CreateToken(tokenDescriptor);
        var validationParameters = new TokenValidationParameters
        {
            IssuerSigningKey = Default.SymmetricSigningCredentials.Key,
            TokenDecryptionKey = KeyingMaterial.DefaultSymmetricSecurityKey_512,
            ValidAudience = Default.Audience,
            ValidIssuer = Default.Issuer,
            ValidateLifetime = false,
        };

        // Act
        var result = await handler.ValidateTokenAsync(token, validationParameters);

        // Assert
        Assert.False(result.IsValid);
        TelemetryAssertionHelpers.AssertTelemetryRecorded(listener, TelemetryDataRecorder.TokenDecryptionCounterName,
            new Dictionary<string, object>
            {
                { TelemetryConstants.IdentityModelVersionTag, IdentityModelTelemetryUtil.ClientVer },
                { TelemetryConstants.StatusTag, TelemetryConstants.FailureValue },
                { TelemetryConstants.AlgorithmTag, Default.SymmetricEncryptingCredentials.Alg },
                { TelemetryConstants.EncryptionSchemeTag, Default.SymmetricEncryptingCredentials.Enc },
                { TelemetryConstants.KeyAlgorithmTag, "SYM-512" }
            });
    }

    [Fact]
    public async Task ValidateToken_ExperimentalAPI_SignatureValidationSuccess_RecordsTelemetry()
    {
        // Arrange
        using var listener = new TestMeterListener();
        var handler = new JsonWebTokenHandler();
        var tokenDescriptor = new SecurityTokenDescriptor
        {
            Subject = new CaseSensitiveClaimsIdentity(Default.PayloadClaims),
            SigningCredentials = KeyingMaterial.JsonWebKeyRsa256SigningCredentials,
        };

        var token = handler.CreateToken(tokenDescriptor);
        var validationParameters = new ValidationParameters();
        validationParameters.SigningKeys.Add(KeyingMaterial.JsonWebKeyRsa256SigningCredentials.Key);

        // Skip validations that require additional setup
        validationParameters.AudienceValidator = SkipValidationDelegates.SkipAudienceValidation;
        validationParameters.SignatureKeyValidator = SkipValidationDelegates.SkipIssuerSigningKeyValidation;
        validationParameters.IssuerValidatorAsync = SkipValidationDelegates.SkipIssuerValidation;
        validationParameters.LifetimeValidator = SkipValidationDelegates.SkipLifetimeValidation;
        validationParameters.TokenReplayValidator = SkipValidationDelegates.SkipTokenReplayValidation;
        validationParameters.TokenTypeValidator = SkipValidationDelegates.SkipTokenTypeValidation;

        // Act
        var result = await ((IResultBasedValidation)handler).ValidateTokenAsync(token, validationParameters, new CallContext());

        // Assert
        Assert.True(result.Succeeded);
        TelemetryAssertionHelpers.AssertTelemetryRecorded(listener, TelemetryDataRecorder.SignatureValidationCounterName,
            new Dictionary<string, object>
            {
                { TelemetryConstants.IdentityModelVersionTag, IdentityModelTelemetryUtil.ClientVer },
                { TelemetryConstants.StatusTag, TelemetryConstants.SuccessValue },
                { TelemetryConstants.AlgorithmTag, SecurityAlgorithms.RsaSha256 },
                { TelemetryConstants.KeyAlgorithmTag, "RSA-2048" }
            });
    }

    [Fact]
    public async Task ValidateToken_ExperimentalAPI_TokenDecryptionSuccess_RecordsTelemetry()
    {
        // Arrange
        using var listener = new TestMeterListener();
        var handler = new JsonWebTokenHandler();
        var tokenDescriptor = new SecurityTokenDescriptor
        {
            Subject = new CaseSensitiveClaimsIdentity(Default.PayloadClaims),
            SigningCredentials = Default.SymmetricSigningCredentials,
            EncryptingCredentials = Default.SymmetricEncryptingCredentials,
        };

        var token = handler.CreateToken(tokenDescriptor);
        var validationParameters = new ValidationParameters();
        validationParameters.SigningKeys.Add(Default.SymmetricSigningCredentials.Key);
        validationParameters.DecryptionKeys.Add(Default.SymmetricEncryptingCredentials.Key);

        // Skip validations that require additional setup
        validationParameters.AudienceValidator = SkipValidationDelegates.SkipAudienceValidation;
        validationParameters.SignatureKeyValidator = SkipValidationDelegates.SkipIssuerSigningKeyValidation;
        validationParameters.IssuerValidatorAsync = SkipValidationDelegates.SkipIssuerValidation;
        validationParameters.LifetimeValidator = SkipValidationDelegates.SkipLifetimeValidation;
        validationParameters.TokenReplayValidator = SkipValidationDelegates.SkipTokenReplayValidation;
        validationParameters.TokenTypeValidator = SkipValidationDelegates.SkipTokenTypeValidation;

        // Act
        var result = await ((IResultBasedValidation)handler).ValidateTokenAsync(token, validationParameters, new CallContext());

        // Assert
        Assert.True(result.Succeeded);
        TelemetryAssertionHelpers.AssertTelemetryRecorded(listener, TelemetryDataRecorder.TokenDecryptionCounterName,
            new Dictionary<string, object>
            {
                { TelemetryConstants.IdentityModelVersionTag, IdentityModelTelemetryUtil.ClientVer },
                { TelemetryConstants.StatusTag, TelemetryConstants.SuccessValue },
                { TelemetryConstants.AlgorithmTag, Default.SymmetricEncryptingCredentials.Alg },
                { TelemetryConstants.EncryptionSchemeTag, Default.SymmetricEncryptingCredentials.Enc },
                { TelemetryConstants.KeyAlgorithmTag, "SYM-256" }
            });
    }

    [Fact]
    public async Task ValidateToken_ExperimentalAPI_SignatureValidationFailure_RecordsTelemetry()
    {
        // Arrange
        using var listener = new TestMeterListener();
        var handler = new JsonWebTokenHandler();
        var tokenDescriptor = new SecurityTokenDescriptor
        {
            Subject = new CaseSensitiveClaimsIdentity(Default.PayloadClaims),
            SigningCredentials = KeyingMaterial.JsonWebKeyRsa256SigningCredentials,
        };

        var token = handler.CreateToken(tokenDescriptor);
        var validationParameters = new ValidationParameters();
        validationParameters.SigningKeys.Add(Default.SymmetricSigningKey256);

        // Skip validations that require additional setup
        validationParameters.AudienceValidator = SkipValidationDelegates.SkipAudienceValidation;
        validationParameters.SignatureKeyValidator = SkipValidationDelegates.SkipIssuerSigningKeyValidation;
        validationParameters.IssuerValidatorAsync = SkipValidationDelegates.SkipIssuerValidation;
        validationParameters.LifetimeValidator = SkipValidationDelegates.SkipLifetimeValidation;
        validationParameters.TokenReplayValidator = SkipValidationDelegates.SkipTokenReplayValidation;
        validationParameters.TokenTypeValidator = SkipValidationDelegates.SkipTokenTypeValidation;

        // Act
        var result = await ((IResultBasedValidation)handler).ValidateTokenAsync(token, validationParameters, new CallContext());

        // Assert
        Assert.False(result.Succeeded);
        TelemetryAssertionHelpers.AssertTelemetryRecorded(listener, TelemetryDataRecorder.SignatureValidationCounterName,
            new Dictionary<string, object>
            {
                { TelemetryConstants.IdentityModelVersionTag, IdentityModelTelemetryUtil.ClientVer },
                { TelemetryConstants.StatusTag, TelemetryConstants.FailureValue },
                { TelemetryConstants.AlgorithmTag, SecurityAlgorithms.RsaSha256 },
                { TelemetryConstants.KeyAlgorithmTag, "NO-KEY" } // keys don't match, so key algorithm is reported as NO-KEY to avoid mixing with unknown key types
            });
    }

    [Fact]
    public async Task ValidateToken_ExperimentalAPI_TokenDecryptionFailure_RecordsTelemetry()
    {
        // Arrange
        using var listener = new TestMeterListener();
        var handler = new JsonWebTokenHandler();
        var tokenDescriptor = new SecurityTokenDescriptor
        {
            Subject = new CaseSensitiveClaimsIdentity(Default.PayloadClaims),
            SigningCredentials = Default.SymmetricSigningCredentials,
            EncryptingCredentials = Default.SymmetricEncryptingCredentials,
        };

        var token = handler.CreateToken(tokenDescriptor);
        var validationParameters = new ValidationParameters();
        validationParameters.SigningKeys.Add(Default.SymmetricSigningCredentials.Key);
        validationParameters.DecryptionKeys.Add(KeyingMaterial.DefaultSymmetricSecurityKey_512);

        // Skip validations that require additional setup
        validationParameters.AudienceValidator = SkipValidationDelegates.SkipAudienceValidation;
        validationParameters.SignatureKeyValidator = SkipValidationDelegates.SkipIssuerSigningKeyValidation;
        validationParameters.IssuerValidatorAsync = SkipValidationDelegates.SkipIssuerValidation;
        validationParameters.LifetimeValidator = SkipValidationDelegates.SkipLifetimeValidation;
        validationParameters.TokenReplayValidator = SkipValidationDelegates.SkipTokenReplayValidation;
        validationParameters.TokenTypeValidator = SkipValidationDelegates.SkipTokenTypeValidation;

        // Act
        var result = await ((IResultBasedValidation)handler).ValidateTokenAsync(token, validationParameters, new CallContext());

        // Assert
        Assert.False(result.Succeeded);
        TelemetryAssertionHelpers.AssertTelemetryRecorded(listener, TelemetryDataRecorder.TokenDecryptionCounterName,
            new Dictionary<string, object>
            {
                { TelemetryConstants.IdentityModelVersionTag, IdentityModelTelemetryUtil.ClientVer },
                { TelemetryConstants.StatusTag, TelemetryConstants.FailureValue },
                { TelemetryConstants.AlgorithmTag, Default.SymmetricEncryptingCredentials.Alg },
                { TelemetryConstants.EncryptionSchemeTag, Default.SymmetricEncryptingCredentials.Enc },
                { TelemetryConstants.KeyAlgorithmTag, "SYM-512" }
            });
    }

    [Fact]
    public void ValidateToken_LegacyJwtSecurityTokenHandler_SignatureValidationSuccess_RecordsTelemetry()
    {
        // Arrange
        using var listener = new TestMeterListener();
        var handler = new JwtSecurityTokenHandler();
        var tokenDescriptor = new SecurityTokenDescriptor
        {
            Subject = new CaseSensitiveClaimsIdentity(Default.PayloadClaims),
            SigningCredentials = KeyingMaterial.JsonWebKeyRsa256SigningCredentials,
        };

        var jsonHandler = new JsonWebTokenHandler();
        var token = jsonHandler.CreateToken(tokenDescriptor);
        var validationParameters = new TokenValidationParameters
        {
            IssuerSigningKey = KeyingMaterial.JsonWebKeyRsa256SigningCredentials.Key,
            ValidAudience = Default.Audience,
            ValidIssuer = Default.Issuer,
            ValidateLifetime = false,
        };

        // Act
        handler.ValidateToken(token, validationParameters, out _);

        // Assert
        TelemetryAssertionHelpers.AssertTelemetryRecorded(listener, TelemetryDataRecorder.SignatureValidationCounterName,
            new Dictionary<string, object>
            {
                { TelemetryConstants.IdentityModelVersionTag, IdentityModelTelemetryUtil.ClientVer },
                { TelemetryConstants.StatusTag, TelemetryConstants.SuccessValue },
                { TelemetryConstants.AlgorithmTag, SecurityAlgorithms.RsaSha256 },
                { TelemetryConstants.KeyAlgorithmTag, "RSA-2048" }
            });
    }

    [Fact]
    public void ValidateToken_LegacyJwtSecurityTokenHandler_SignatureValidationFailure_RecordsTelemetry()
    {
        // Arrange
        using var listener = new TestMeterListener();
        var handler = new JwtSecurityTokenHandler();
        var tokenDescriptor = new SecurityTokenDescriptor
        {
            Subject = new CaseSensitiveClaimsIdentity(Default.PayloadClaims),
            SigningCredentials = KeyingMaterial.JsonWebKeyRsa256SigningCredentials,
        };

        var jsonHandler = new JsonWebTokenHandler();
        var token = jsonHandler.CreateToken(tokenDescriptor);
        var validationParameters = new TokenValidationParameters
        {
            IssuerSigningKey = Default.SymmetricSigningKey256,
            ValidAudience = Default.Audience,
            ValidIssuer = Default.Issuer,
            ValidateLifetime = false,
        };

        // Act
        try
        {
            handler.ValidateToken(token, validationParameters, out _);
        }
        catch
        {
            // Expected to throw
        }

        // Assert
        TelemetryAssertionHelpers.AssertTelemetryRecorded(listener, TelemetryDataRecorder.SignatureValidationCounterName,
            new Dictionary<string, object>
            {
                { TelemetryConstants.IdentityModelVersionTag, IdentityModelTelemetryUtil.ClientVer },
                { TelemetryConstants.StatusTag, TelemetryConstants.FailureValue },
                { TelemetryConstants.AlgorithmTag, SecurityAlgorithms.RsaSha256 },
                { TelemetryConstants.KeyAlgorithmTag, "SYM-256" }
            });
    }

    [Fact]
    public void ValidateToken_LegacyJwtSecurityTokenHandler_TokenDecryptionSuccess_RecordsTelemetry()
    {
        // Arrange
        using var listener = new TestMeterListener();
        var handler = new JwtSecurityTokenHandler();
        var tokenDescriptor = new SecurityTokenDescriptor
        {
            Subject = new CaseSensitiveClaimsIdentity(Default.PayloadClaims),
            SigningCredentials = Default.SymmetricSigningCredentials,
            EncryptingCredentials = Default.SymmetricEncryptingCredentials,
        };

        var jsonHandler = new JsonWebTokenHandler();
        var token = jsonHandler.CreateToken(tokenDescriptor);
        var validationParameters = new TokenValidationParameters
        {
            IssuerSigningKey = Default.SymmetricSigningCredentials.Key,
            TokenDecryptionKey = Default.SymmetricEncryptingCredentials.Key,
            ValidAudience = Default.Audience,
            ValidIssuer = Default.Issuer,
            ValidateLifetime = false,
        };

        // Act
        handler.ValidateToken(token, validationParameters, out _);

        // Assert
        TelemetryAssertionHelpers.AssertTelemetryRecorded(listener, TelemetryDataRecorder.TokenDecryptionCounterName,
            new Dictionary<string, object>
            {
                { TelemetryConstants.IdentityModelVersionTag, IdentityModelTelemetryUtil.ClientVer },
                { TelemetryConstants.StatusTag, TelemetryConstants.SuccessValue },
                { TelemetryConstants.AlgorithmTag, Default.SymmetricEncryptingCredentials.Alg },
                { TelemetryConstants.EncryptionSchemeTag, Default.SymmetricEncryptingCredentials.Enc },
                { TelemetryConstants.KeyAlgorithmTag, "SYM-256" }
            });
    }

    [Fact]
    public void ValidateToken_LegacyJwtSecurityTokenHandler_TokenDecryptionFailure_RecordsTelemetry()
    {
        // Arrange
        using var listener = new TestMeterListener();
        var handler = new JwtSecurityTokenHandler();
        var tokenDescriptor = new SecurityTokenDescriptor
        {
            Subject = new CaseSensitiveClaimsIdentity(Default.PayloadClaims),
            SigningCredentials = Default.SymmetricSigningCredentials,
            EncryptingCredentials = Default.SymmetricEncryptingCredentials,
        };

        var jsonHandler = new JsonWebTokenHandler();
        var token = jsonHandler.CreateToken(tokenDescriptor);
        var validationParameters = new TokenValidationParameters
        {
            IssuerSigningKey = Default.SymmetricSigningCredentials.Key,
            TokenDecryptionKey = KeyingMaterial.DefaultSymmetricSecurityKey_512,
            ValidAudience = Default.Audience,
            ValidIssuer = Default.Issuer,
            ValidateLifetime = false,
        };

        // Act
        try
        {
            handler.ValidateToken(token, validationParameters, out _);
        }
        catch
        {
            // Expected to throw
        }

        // Assert
        TelemetryAssertionHelpers.AssertTelemetryRecorded(listener, TelemetryDataRecorder.TokenDecryptionCounterName,
            new Dictionary<string, object>
            {
                { TelemetryConstants.IdentityModelVersionTag, IdentityModelTelemetryUtil.ClientVer },
                { TelemetryConstants.StatusTag, TelemetryConstants.FailureValue },
                { TelemetryConstants.AlgorithmTag, Default.SymmetricEncryptingCredentials.Alg },
                { TelemetryConstants.EncryptionSchemeTag, Default.SymmetricEncryptingCredentials.Enc },
                { TelemetryConstants.KeyAlgorithmTag, "SYM-512" }
            });
    }

    [Fact]
    public async Task ValidateToken_SymmetricSignature_RecordsTelemetry()
    {
        // Arrange
        using var listener = new TestMeterListener();
        var handler = new JsonWebTokenHandler();
        var tokenDescriptor = new SecurityTokenDescriptor
        {
            Subject = new CaseSensitiveClaimsIdentity(Default.PayloadClaims),
            SigningCredentials = Default.SymmetricSigningCredentials,
        };

        var token = handler.CreateToken(tokenDescriptor);
        var validationParameters = new TokenValidationParameters
        {
            IssuerSigningKey = Default.SymmetricSigningCredentials.Key,
            ValidAudience = Default.Audience,
            ValidIssuer = Default.Issuer,
            ValidateLifetime = false,
        };

        // Act
        var result = await handler.ValidateTokenAsync(token, validationParameters);

        // Assert
        Assert.True(result.IsValid);
        TelemetryAssertionHelpers.AssertTelemetryRecorded(listener, TelemetryDataRecorder.SignatureValidationCounterName,
            new Dictionary<string, object>
            {
                { TelemetryConstants.IdentityModelVersionTag, IdentityModelTelemetryUtil.ClientVer },
                { TelemetryConstants.StatusTag, TelemetryConstants.SuccessValue },
                { TelemetryConstants.AlgorithmTag, Default.SymmetricSigningCredentials.Algorithm },
                { TelemetryConstants.KeyAlgorithmTag, "SYM-256" }
            });
    }

    [Fact]
    public async Task ValidateToken_RsaKeyWrapEncryption_2048_RecordsTelemetry()
    {
        // Arrange
        using var listener = new TestMeterListener();
        var handler = new JsonWebTokenHandler();
        var encryptingCredentials = new EncryptingCredentials(
            KeyingMaterial.RsaSecurityKey_2048,
            SecurityAlgorithms.RsaPKCS1,
            SecurityAlgorithms.Aes128CbcHmacSha256);

        var tokenDescriptor = new SecurityTokenDescriptor
        {
            Subject = new CaseSensitiveClaimsIdentity(Default.PayloadClaims),
            SigningCredentials = Default.SymmetricSigningCredentials,
            EncryptingCredentials = encryptingCredentials,
        };

        var token = handler.CreateToken(tokenDescriptor);
        var validationParameters = new TokenValidationParameters
        {
            IssuerSigningKey = Default.SymmetricSigningCredentials.Key,
            TokenDecryptionKey = KeyingMaterial.RsaSecurityKey_2048,
            ValidAudience = Default.Audience,
            ValidIssuer = Default.Issuer,
            ValidateLifetime = false,
        };

        // Act
        var result = await handler.ValidateTokenAsync(token, validationParameters);

        // Assert
        Assert.True(result.IsValid);
        // For key wrap scenarios, telemetry records the wrapping key size (RSA key) to monitor STS key upgrades (2048 ? 3072 ? 4096).
        TelemetryAssertionHelpers.AssertTelemetryRecorded(listener, TelemetryDataRecorder.TokenDecryptionCounterName,
            new Dictionary<string, object>
            {
                { TelemetryConstants.IdentityModelVersionTag, IdentityModelTelemetryUtil.ClientVer },
                { TelemetryConstants.StatusTag, TelemetryConstants.SuccessValue },
                { TelemetryConstants.AlgorithmTag, encryptingCredentials.Alg },
                { TelemetryConstants.EncryptionSchemeTag, encryptingCredentials.Enc },
                { TelemetryConstants.KeyAlgorithmTag, "RSA-2048" }
            });
    }

    [Fact]
    public async Task ValidateToken_RsaKeyWrapEncryption_3072_RecordsTelemetry()
    {
        // Arrange
        using var listener = new TestMeterListener();
        var handler = new JsonWebTokenHandler();

        // Create RSA 3072-bit key for encryption
        using var rsa = KeyingMaterial.CreateRsa(3072);
        var rsaKey = new RsaSecurityKey(rsa) { KeyId = "Rsa3072Key" };

        var encryptingCredentials = new EncryptingCredentials(
            rsaKey,
            SecurityAlgorithms.RsaPKCS1,
            SecurityAlgorithms.Aes256CbcHmacSha512);

        var tokenDescriptor = new SecurityTokenDescriptor
        {
            Subject = new CaseSensitiveClaimsIdentity(Default.PayloadClaims),
            SigningCredentials = Default.SymmetricSigningCredentials,
            EncryptingCredentials = encryptingCredentials,
        };

        var token = handler.CreateToken(tokenDescriptor);
        var validationParameters = new TokenValidationParameters
        {
            IssuerSigningKey = Default.SymmetricSigningCredentials.Key,
            TokenDecryptionKey = rsaKey,
            ValidAudience = Default.Audience,
            ValidIssuer = Default.Issuer,
            ValidateLifetime = false,
        };

        // Act
        var result = await handler.ValidateTokenAsync(token, validationParameters);

        // Assert
        Assert.True(result.IsValid);
        // Telemetry should track the 3072-bit RSA wrapping key size to monitor STS upgrades
        TelemetryAssertionHelpers.AssertTelemetryRecorded(listener, TelemetryDataRecorder.TokenDecryptionCounterName,
            new Dictionary<string, object>
            {
                { TelemetryConstants.IdentityModelVersionTag, IdentityModelTelemetryUtil.ClientVer },
                { TelemetryConstants.StatusTag, TelemetryConstants.SuccessValue },
                { TelemetryConstants.AlgorithmTag, SecurityAlgorithms.RsaPKCS1 },
                { TelemetryConstants.EncryptionSchemeTag, SecurityAlgorithms.Aes256CbcHmacSha512 },
                { TelemetryConstants.KeyAlgorithmTag, "RSA-3072" }
            });
    }

    [Fact]
    public async Task ValidateToken_RsaKeyWrapEncryption_4096_RecordsTelemetry()
    {
        // Arrange
        using var listener = new TestMeterListener();
        var handler = new JsonWebTokenHandler();

        // Create RSA 4096-bit key for encryption
        using var rsa = KeyingMaterial.CreateRsa(4096);
        var rsaKey = new RsaSecurityKey(rsa) { KeyId = "Rsa4096Key" };

        var encryptingCredentials = new EncryptingCredentials(
            rsaKey,
            SecurityAlgorithms.RsaPKCS1,
            SecurityAlgorithms.Aes256CbcHmacSha512);

        var tokenDescriptor = new SecurityTokenDescriptor
        {
            Subject = new CaseSensitiveClaimsIdentity(Default.PayloadClaims),
            SigningCredentials = Default.SymmetricSigningCredentials,
            EncryptingCredentials = encryptingCredentials,
        };

        var token = handler.CreateToken(tokenDescriptor);
        var validationParameters = new TokenValidationParameters
        {
            IssuerSigningKey = Default.SymmetricSigningCredentials.Key,
            TokenDecryptionKey = rsaKey,
            ValidAudience = Default.Audience,
            ValidIssuer = Default.Issuer,
            ValidateLifetime = false,
        };

        // Act
        var result = await handler.ValidateTokenAsync(token, validationParameters);

        // Assert
        Assert.True(result.IsValid);
        // Telemetry should track the 4096-bit RSA wrapping key size to monitor STS upgrades
        TelemetryAssertionHelpers.AssertTelemetryRecorded(listener, TelemetryDataRecorder.TokenDecryptionCounterName,
            new Dictionary<string, object>
            {
                { TelemetryConstants.IdentityModelVersionTag, IdentityModelTelemetryUtil.ClientVer },
                { TelemetryConstants.StatusTag, TelemetryConstants.SuccessValue },
                { TelemetryConstants.AlgorithmTag, SecurityAlgorithms.RsaPKCS1 },
                { TelemetryConstants.EncryptionSchemeTag, SecurityAlgorithms.Aes256CbcHmacSha512 },
                { TelemetryConstants.KeyAlgorithmTag, "RSA-4096" }
            });
    }

    [Fact]
    public async Task ValidateToken_RsaOaepKeyWrapEncryption_RecordsTelemetry()
    {
        // Arrange
        using var listener = new TestMeterListener();
        var handler = new JsonWebTokenHandler();
        var encryptingCredentials = new EncryptingCredentials(
            KeyingMaterial.RsaSecurityKey_2048,
            SecurityAlgorithms.RsaOAEP,
            SecurityAlgorithms.Aes256CbcHmacSha512);

        var tokenDescriptor = new SecurityTokenDescriptor
        {
            Subject = new CaseSensitiveClaimsIdentity(Default.PayloadClaims),
            SigningCredentials = Default.SymmetricSigningCredentials,
            EncryptingCredentials = encryptingCredentials,
        };

        var token = handler.CreateToken(tokenDescriptor);
        var validationParameters = new TokenValidationParameters
        {
            IssuerSigningKey = Default.SymmetricSigningCredentials.Key,
            TokenDecryptionKey = KeyingMaterial.RsaSecurityKey_2048,
            ValidAudience = Default.Audience,
            ValidIssuer = Default.Issuer,
            ValidateLifetime = false,
        };

        // Act
        var result = await handler.ValidateTokenAsync(token, validationParameters);

        // Assert
        Assert.True(result.IsValid);
        // RSA-OAEP is the recommended algorithm; telemetry should track wrapping key size
        TelemetryAssertionHelpers.AssertTelemetryRecorded(listener, TelemetryDataRecorder.TokenDecryptionCounterName,
            new Dictionary<string, object>
            {
                { TelemetryConstants.IdentityModelVersionTag, IdentityModelTelemetryUtil.ClientVer },
                { TelemetryConstants.StatusTag, TelemetryConstants.SuccessValue },
                { TelemetryConstants.AlgorithmTag, SecurityAlgorithms.RsaOAEP },
                { TelemetryConstants.EncryptionSchemeTag, SecurityAlgorithms.Aes256CbcHmacSha512 },
                { TelemetryConstants.KeyAlgorithmTag, "RSA-2048" }
            });
    }

    [Fact]
    public async Task ValidateToken_DirectKeyUseEncryption_RecordsTelemetry()
    {
        // Arrange
        using var listener = new TestMeterListener();
        var handler = new JsonWebTokenHandler();

        // Direct key use means no key wrapping - the encryption key is used directly
        var encryptionKey = Default.SymmetricEncryptingCredentials.Key;
        var encryptingCredentials = new EncryptingCredentials(
            encryptionKey,
            JsonWebTokens.JwtConstants.DirectKeyUseAlg,
            SecurityAlgorithms.Aes128CbcHmacSha256);

        var tokenDescriptor = new SecurityTokenDescriptor
        {
            Subject = new CaseSensitiveClaimsIdentity(Default.PayloadClaims),
            SigningCredentials = Default.SymmetricSigningCredentials,
            EncryptingCredentials = encryptingCredentials,
        };

        var token = handler.CreateToken(tokenDescriptor);
        var validationParameters = new TokenValidationParameters
        {
            IssuerSigningKey = Default.SymmetricSigningCredentials.Key,
            TokenDecryptionKey = encryptionKey,
            ValidAudience = Default.Audience,
            ValidIssuer = Default.Issuer,
            ValidateLifetime = false,
        };

        // Act
        var result = await handler.ValidateTokenAsync(token, validationParameters);

        // Assert
        Assert.True(result.IsValid);
        // For direct key use, key size equals the content encryption key size
        TelemetryAssertionHelpers.AssertTelemetryRecorded(listener, TelemetryDataRecorder.TokenDecryptionCounterName,
            new Dictionary<string, object>
            {
                { TelemetryConstants.IdentityModelVersionTag, IdentityModelTelemetryUtil.ClientVer },
                { TelemetryConstants.StatusTag, TelemetryConstants.SuccessValue },
                { TelemetryConstants.AlgorithmTag, JsonWebTokens.JwtConstants.DirectKeyUseAlg },
                { TelemetryConstants.EncryptionSchemeTag, SecurityAlgorithms.Aes128CbcHmacSha256 },
                { TelemetryConstants.KeyAlgorithmTag, "SYM-256" }
            });
    }

    [Fact]
    public async Task ValidateToken_AesKeyWrapEncryption_RecordsTelemetry()
    {
        // Arrange
        using var listener = new TestMeterListener();
        var handler = new JsonWebTokenHandler();

        // Use AES key wrapping (symmetric key wrap)
        var kekKey = Default.SymmetricEncryptingCredentials.Key;
        var encryptingCredentials = new EncryptingCredentials(
            kekKey,
            SecurityAlgorithms.Aes256KW,
            SecurityAlgorithms.Aes256CbcHmacSha512);

        var tokenDescriptor = new SecurityTokenDescriptor
        {
            Subject = new CaseSensitiveClaimsIdentity(Default.PayloadClaims),
            SigningCredentials = Default.SymmetricSigningCredentials,
            EncryptingCredentials = encryptingCredentials,
        };

        var token = handler.CreateToken(tokenDescriptor);
        var validationParameters = new TokenValidationParameters
        {
            IssuerSigningKey = Default.SymmetricSigningCredentials.Key,
            TokenDecryptionKey = kekKey,
            ValidAudience = Default.Audience,
            ValidIssuer = Default.Issuer,
            ValidateLifetime = false,
        };

        // Act
        var result = await handler.ValidateTokenAsync(token, validationParameters);

        // Assert
        Assert.True(result.IsValid);
        // For AES key wrap, telemetry tracks the KEK (Key Encryption Key) size
        TelemetryAssertionHelpers.AssertTelemetryRecorded(listener, TelemetryDataRecorder.TokenDecryptionCounterName,
            new Dictionary<string, object>
            {
                { TelemetryConstants.IdentityModelVersionTag, IdentityModelTelemetryUtil.ClientVer },
                { TelemetryConstants.StatusTag, TelemetryConstants.SuccessValue },
                { TelemetryConstants.AlgorithmTag, SecurityAlgorithms.Aes256KW },
                { TelemetryConstants.EncryptionSchemeTag, SecurityAlgorithms.Aes256CbcHmacSha512 },
                { TelemetryConstants.KeyAlgorithmTag, "SYM-256" }
            });
    }

#if !NET462 && !NET472 && !NETSTANDARD2_0
    [Fact]
    public async Task ValidateToken_ES256Signature_RecordsTelemetry()
    {
        // Arrange
        using var listener = new TestMeterListener();
        var handler = new JsonWebTokenHandler();

        using var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var ecdsaKey = new ECDsaSecurityKey(ecdsa) { KeyId = "ES256Key" };
        var signingCredentials = new SigningCredentials(ecdsaKey, SecurityAlgorithms.EcdsaSha256);

        var tokenDescriptor = new SecurityTokenDescriptor
        {
            Subject = new CaseSensitiveClaimsIdentity(Default.PayloadClaims),
            SigningCredentials = signingCredentials,
        };

        var token = handler.CreateToken(tokenDescriptor);
        var validationParameters = new TokenValidationParameters
        {
            IssuerSigningKey = ecdsaKey,
            ValidAudience = Default.Audience,
            ValidIssuer = Default.Issuer,
            ValidateLifetime = false,
        };

        // Act
        var result = await handler.ValidateTokenAsync(token, validationParameters);

        // Assert
        Assert.True(result.IsValid);
        TelemetryAssertionHelpers.AssertTelemetryRecorded(listener, TelemetryDataRecorder.SignatureValidationCounterName,
            new Dictionary<string, object>
            {
                { TelemetryConstants.IdentityModelVersionTag, IdentityModelTelemetryUtil.ClientVer },
                { TelemetryConstants.StatusTag, TelemetryConstants.SuccessValue },
                { TelemetryConstants.AlgorithmTag, SecurityAlgorithms.EcdsaSha256 },
                { TelemetryConstants.KeyAlgorithmTag, "ECDSA-P256" }
            });
    }

    [Fact]
    public async Task ValidateToken_ES384Signature_RecordsTelemetry()
    {
        // Arrange
        using var listener = new TestMeterListener();
        var handler = new JsonWebTokenHandler();

        using var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP384);
        var ecdsaKey = new ECDsaSecurityKey(ecdsa) { KeyId = "ES384Key" };
        var signingCredentials = new SigningCredentials(ecdsaKey, SecurityAlgorithms.EcdsaSha384);

        var tokenDescriptor = new SecurityTokenDescriptor
        {
            Subject = new CaseSensitiveClaimsIdentity(Default.PayloadClaims),
            SigningCredentials = signingCredentials,
        };

        var token = handler.CreateToken(tokenDescriptor);
        var validationParameters = new TokenValidationParameters
        {
            IssuerSigningKey = ecdsaKey,
            ValidAudience = Default.Audience,
            ValidIssuer = Default.Issuer,
            ValidateLifetime = false,
        };

        // Act
        var result = await handler.ValidateTokenAsync(token, validationParameters);

        // Assert
        Assert.True(result.IsValid);
        TelemetryAssertionHelpers.AssertTelemetryRecorded(listener, TelemetryDataRecorder.SignatureValidationCounterName,
            new Dictionary<string, object>
            {
                { TelemetryConstants.IdentityModelVersionTag, IdentityModelTelemetryUtil.ClientVer },
                { TelemetryConstants.StatusTag, TelemetryConstants.SuccessValue },
                { TelemetryConstants.AlgorithmTag, SecurityAlgorithms.EcdsaSha384 },
                { TelemetryConstants.KeyAlgorithmTag, "ECDSA-P384" }
            });
    }

    [Fact]
    public async Task ValidateToken_ES512Signature_RecordsTelemetry()
    {
        // Arrange
        using var listener = new TestMeterListener();
        var handler = new JsonWebTokenHandler();

        using var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP521);
        var ecdsaKey = new ECDsaSecurityKey(ecdsa) { KeyId = "ES512Key" };
        var signingCredentials = new SigningCredentials(ecdsaKey, SecurityAlgorithms.EcdsaSha512);

        var tokenDescriptor = new SecurityTokenDescriptor
        {
            Subject = new CaseSensitiveClaimsIdentity(Default.PayloadClaims),
            SigningCredentials = signingCredentials,
        };

        var token = handler.CreateToken(tokenDescriptor);
        var validationParameters = new TokenValidationParameters
        {
            IssuerSigningKey = ecdsaKey,
            ValidAudience = Default.Audience,
            ValidIssuer = Default.Issuer,
            ValidateLifetime = false,
        };

        // Act
        var result = await handler.ValidateTokenAsync(token, validationParameters);

        // Assert
        Assert.True(result.IsValid);
        TelemetryAssertionHelpers.AssertTelemetryRecorded(listener, TelemetryDataRecorder.SignatureValidationCounterName,
            new Dictionary<string, object>
            {
                { TelemetryConstants.IdentityModelVersionTag, IdentityModelTelemetryUtil.ClientVer },
                { TelemetryConstants.StatusTag, TelemetryConstants.SuccessValue },
                { TelemetryConstants.AlgorithmTag, SecurityAlgorithms.EcdsaSha512 },
                { TelemetryConstants.KeyAlgorithmTag, "ECDSA-P521" }
            });
    }
#endif
}
