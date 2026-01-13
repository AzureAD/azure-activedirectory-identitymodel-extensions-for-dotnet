// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System.Collections.Generic;
using System.Diagnostics.Metrics;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Cryptography;
using System.Threading.Tasks;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Telemetry;
using Microsoft.IdentityModel.TestUtils;
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
        var listener = new TestMeterListener();
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
        AssertTelemetryRecorded(listener, TelemetryDataRecorder.SignatureValidationCounterName,
            new Dictionary<string, object>
            {
                { "status", "success" },
                { "alg", SecurityAlgorithms.RsaSha256 },
                { "key_size", KeyingMaterial.JsonWebKeyRsa256SigningCredentials.Key.KeySize }
            });
    }

    [Fact]
    public async Task ValidateToken_SignatureValidationFailure_RecordsTelemetry()
    {
        // Arrange
        var listener = new TestMeterListener();
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
        AssertTelemetryRecorded(listener, TelemetryDataRecorder.SignatureValidationCounterName,
            new Dictionary<string, object>
            {
                { "status", "failure" },
                { "alg", SecurityAlgorithms.RsaSha256 },
                { "key_size", Default.SymmetricSigningKey256.KeySize }
            });
    }

    [Fact]
    public async Task ValidateToken_TokenDecryptionSuccess_RecordsTelemetry()
    {
        // Arrange
        var listener = new TestMeterListener();
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
        AssertTelemetryRecorded(listener, TelemetryDataRecorder.TokenDecryptionCounterName,
            new Dictionary<string, object>
            {
                { "status", "success" },
                { "alg", Default.SymmetricEncryptingCredentials.Alg },
                { "enc", Default.SymmetricEncryptingCredentials.Enc },
                { "key_size", Default.SymmetricEncryptingCredentials.Key.KeySize }
            });
    }

    [Fact]
    public async Task ValidateToken_TokenDecryptionFailure_RecordsTelemetry()
    {
        // Arrange
        var listener = new TestMeterListener();
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
        AssertTelemetryRecorded(listener, TelemetryDataRecorder.TokenDecryptionCounterName,
            new Dictionary<string, object>
            {
                { "status", "failure" },
                { "alg", Default.SymmetricEncryptingCredentials.Alg },
                { "enc", Default.SymmetricEncryptingCredentials.Enc },
                { "key_size", KeyingMaterial.DefaultSymmetricSecurityKey_512.KeySize }
            });
    }

    [Fact]
    public async Task ValidateToken_ExperimentalAPI_SignatureValidationSuccess_RecordsTelemetry()
    {
        // Arrange
        var listener = new TestMeterListener();
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
        AssertTelemetryRecorded(listener, TelemetryDataRecorder.SignatureValidationCounterName,
            new Dictionary<string, object>
            {
                { "status", "success" },
                { "alg", SecurityAlgorithms.RsaSha256 },
                { "key_size", KeyingMaterial.JsonWebKeyRsa256SigningCredentials.Key.KeySize }
            });
    }

    [Fact]
    public async Task ValidateToken_ExperimentalAPI_TokenDecryptionSuccess_RecordsTelemetry()
    {
        // Arrange
        var listener = new TestMeterListener();
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
        AssertTelemetryRecorded(listener, TelemetryDataRecorder.TokenDecryptionCounterName,
            new Dictionary<string, object>
            {
                { "status", "success" },
                { "alg", Default.SymmetricEncryptingCredentials.Alg },
                { "enc", Default.SymmetricEncryptingCredentials.Enc },
                { "key_size", Default.SymmetricEncryptingCredentials.Key.KeySize }
            });
    }

    [Fact]
    public async Task ValidateToken_ExperimentalAPI_SignatureValidationFailure_RecordsTelemetry()
    {
        // Arrange
        var listener = new TestMeterListener();
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
        AssertTelemetryRecorded(listener, TelemetryDataRecorder.SignatureValidationCounterName,
            new Dictionary<string, object>
            {
                { "status", "failure" },
                { "alg", SecurityAlgorithms.RsaSha256 },
                { "key_size", 0 } // keys don't match, so key size is reported as 0
            });
    }

    [Fact]
    public async Task ValidateToken_ExperimentalAPI_TokenDecryptionFailure_RecordsTelemetry()
    {
        // Arrange
        var listener = new TestMeterListener();
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
        AssertTelemetryRecorded(listener, TelemetryDataRecorder.TokenDecryptionCounterName,
            new Dictionary<string, object>
            {
                { "status", "failure" },
                { "alg", Default.SymmetricEncryptingCredentials.Alg },
                { "enc", Default.SymmetricEncryptingCredentials.Enc },
                { "key_size", KeyingMaterial.DefaultSymmetricSecurityKey_512.KeySize }
            });
    }

    [Fact]
    public void ValidateToken_LegacyJwtSecurityTokenHandler_SignatureValidationSuccess_RecordsTelemetry()
    {
        // Arrange
        var listener = new TestMeterListener();
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
        AssertTelemetryRecorded(listener, TelemetryDataRecorder.SignatureValidationCounterName,
            new Dictionary<string, object>
            {
                { "status", "success" },
                { "alg", SecurityAlgorithms.RsaSha256 },
                { "key_size", KeyingMaterial.JsonWebKeyRsa256SigningCredentials.Key.KeySize }
            });
    }

    [Fact]
    public void ValidateToken_LegacyJwtSecurityTokenHandler_SignatureValidationFailure_RecordsTelemetry()
    {
        // Arrange
        var listener = new TestMeterListener();
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
        AssertTelemetryRecorded(listener, TelemetryDataRecorder.SignatureValidationCounterName,
            new Dictionary<string, object>
            {
                { "status", "failure" },
                { "alg", SecurityAlgorithms.RsaSha256 },
                { "key_size", Default.SymmetricSigningKey256.KeySize }
            });
    }

    [Fact]
    public void ValidateToken_LegacyJwtSecurityTokenHandler_TokenDecryptionSuccess_RecordsTelemetry()
    {
        // Arrange
        var listener = new TestMeterListener();
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
        AssertTelemetryRecorded(listener, TelemetryDataRecorder.TokenDecryptionCounterName,
            new Dictionary<string, object>
            {
                { "status", "success" },
                { "alg", Default.SymmetricEncryptingCredentials.Alg },
                { "enc", Default.SymmetricEncryptingCredentials.Enc },
                { "key_size", Default.SymmetricEncryptingCredentials.Key.KeySize }
            });
    }

    [Fact]
    public void ValidateToken_LegacyJwtSecurityTokenHandler_TokenDecryptionFailure_RecordsTelemetry()
    {
        // Arrange
        var listener = new TestMeterListener();
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
        AssertTelemetryRecorded(listener, TelemetryDataRecorder.TokenDecryptionCounterName,
            new Dictionary<string, object>
            {
                { "status", "failure" },
                { "alg", Default.SymmetricEncryptingCredentials.Alg },
                { "enc", Default.SymmetricEncryptingCredentials.Enc },
                { "key_size", KeyingMaterial.DefaultSymmetricSecurityKey_512.KeySize }
            });
    }

    [Fact]
    public async Task ValidateToken_SymmetricSignature_RecordsTelemetry()
    {
        // Arrange
        var listener = new TestMeterListener();
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
        AssertTelemetryRecorded(listener, TelemetryDataRecorder.SignatureValidationCounterName,
            new Dictionary<string, object>
            {
                { "status", "success" },
                { "alg", Default.SymmetricSigningCredentials.Algorithm },
                { "key_size", Default.SymmetricSigningCredentials.Key.KeySize }
            });
    }

    [Fact]
    public async Task ValidateToken_RsaKeyWrapEncryption_2048_RecordsTelemetry()
    {
        // Arrange
        var listener = new TestMeterListener();
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
        // For key wrap scenarios, telemetry records the wrapping key size (RSA key) to monitor STS key upgrades (2048 → 3072 → 4096).
        AssertTelemetryRecorded(listener, TelemetryDataRecorder.TokenDecryptionCounterName,
            new Dictionary<string, object>
            {
                { "status", "success" },
                { "alg", encryptingCredentials.Alg },
                { "enc", encryptingCredentials.Enc },
                { "key_size", 2048 }
            });
    }

    /// <summary>
    /// Creates an RSA instance with the specified key size.
    /// On .NET Framework, uses RSACng for better support of larger key sizes (3072, 4096).
    /// On other platforms, uses the default RSA.Create().
    /// </summary>
    private static RSA CreateRsa(int keySize)
    {
#if NET462 || NET472
        // Use RSACng on .NET Framework for better support of 3072/4096 bit keys
        var rsa = new System.Security.Cryptography.RSACng();
        rsa.KeySize = keySize;
        return rsa;
#else
        var rsa = RSA.Create();
        rsa.KeySize = keySize;
        return rsa;
#endif
    }

    [Fact]
    public async Task ValidateToken_RsaKeyWrapEncryption_3072_RecordsTelemetry()
    {
        // Arrange
        var listener = new TestMeterListener();
        var handler = new JsonWebTokenHandler();

        // Create RSA 3072-bit key for encryption
        using var rsa = CreateRsa(3072);
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
        AssertTelemetryRecorded(listener, TelemetryDataRecorder.TokenDecryptionCounterName,
            new Dictionary<string, object>
            {
                { "status", "success" },
                { "alg", SecurityAlgorithms.RsaPKCS1 },
                { "enc", SecurityAlgorithms.Aes256CbcHmacSha512 },
                { "key_size", 3072 }
            });
    }

    [Fact]
    public async Task ValidateToken_RsaKeyWrapEncryption_4096_RecordsTelemetry()
    {
        // Arrange
        var listener = new TestMeterListener();
        var handler = new JsonWebTokenHandler();

        // Create RSA 4096-bit key for encryption
        using var rsa = CreateRsa(4096);
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
        AssertTelemetryRecorded(listener, TelemetryDataRecorder.TokenDecryptionCounterName,
            new Dictionary<string, object>
            {
                { "status", "success" },
                { "alg", SecurityAlgorithms.RsaPKCS1 },
                { "enc", SecurityAlgorithms.Aes256CbcHmacSha512 },
                { "key_size", 4096 }
            });
    }

    [Fact]
    public async Task ValidateToken_RsaOaepKeyWrapEncryption_RecordsTelemetry()
    {
        // Arrange
        var listener = new TestMeterListener();
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
        AssertTelemetryRecorded(listener, TelemetryDataRecorder.TokenDecryptionCounterName,
            new Dictionary<string, object>
            {
                { "status", "success" },
                { "alg", SecurityAlgorithms.RsaOAEP },
                { "enc", SecurityAlgorithms.Aes256CbcHmacSha512 },
                { "key_size", 2048 }
            });
    }

    [Fact]
    public async Task ValidateToken_DirectKeyUseEncryption_RecordsTelemetry()
    {
        // Arrange
        var listener = new TestMeterListener();
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
        AssertTelemetryRecorded(listener, TelemetryDataRecorder.TokenDecryptionCounterName,
            new Dictionary<string, object>
            {
                { "status", "success" },
                { "alg", JsonWebTokens.JwtConstants.DirectKeyUseAlg },
                { "enc", SecurityAlgorithms.Aes128CbcHmacSha256 },
                { "key_size", encryptionKey.KeySize }
            });
    }

    [Fact]
    public async Task ValidateToken_AesKeyWrapEncryption_RecordsTelemetry()
    {
        // Arrange
        var listener = new TestMeterListener();
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
        AssertTelemetryRecorded(listener, TelemetryDataRecorder.TokenDecryptionCounterName,
            new Dictionary<string, object>
            {
                { "status", "success" },
                { "alg", SecurityAlgorithms.Aes256KW },
                { "enc", SecurityAlgorithms.Aes256CbcHmacSha512 },
                { "key_size", kekKey.KeySize }
            });
    }

#if !NET462 && !NET472 && !NETSTANDARD2_0
    [Fact]
    public async Task ValidateToken_ES256Signature_RecordsTelemetry()
    {
        // Arrange
        var listener = new TestMeterListener();
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
        AssertTelemetryRecorded(listener, TelemetryDataRecorder.SignatureValidationCounterName,
            new Dictionary<string, object>
            {
                { "status", "success" },
                { "alg", SecurityAlgorithms.EcdsaSha256 },
                { "key_size", ecdsaKey.KeySize }
            });
    }

    [Fact]
    public async Task ValidateToken_ES384Signature_RecordsTelemetry()
    {
        // Arrange
        var listener = new TestMeterListener();
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
        AssertTelemetryRecorded(listener, TelemetryDataRecorder.SignatureValidationCounterName,
            new Dictionary<string, object>
            {
                { "status", "success" },
                { "alg", SecurityAlgorithms.EcdsaSha384 },
                { "key_size", ecdsaKey.KeySize }
            });
    }

    [Fact]
    public async Task ValidateToken_ES512Signature_RecordsTelemetry()
    {
        // Arrange
        var listener = new TestMeterListener();
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
        AssertTelemetryRecorded(listener, TelemetryDataRecorder.SignatureValidationCounterName,
            new Dictionary<string, object>
            {
                { "status", "success" },
                { "alg", SecurityAlgorithms.EcdsaSha512 },
                { "key_size", ecdsaKey.KeySize }
            });
    }
#endif

    private static void AssertTelemetryRecorded(TestMeterListener listener, string counterName, Dictionary<string, object> expectedTags)
    {
        var measurements = listener.GetMeasurements(counterName);
        Assert.NotEmpty(measurements);

        var lastMeasurement = measurements.Last();
        foreach (var expectedTag in expectedTags)
        {
            var actualTag = lastMeasurement.Tags.FirstOrDefault(t => t.Key == expectedTag.Key);
            Assert.NotNull(actualTag.Value);
            Assert.Equal(expectedTag.Value.ToString(), actualTag.Value.ToString());
        }
    }

    /// <summary>
    /// Test meter listener to capture telemetry measurements
    /// </summary>
    private class TestMeterListener
    {
        private readonly MeterListener _listener;
        private readonly List<Measurement> _measurements = new List<Measurement>();

        public TestMeterListener()
        {
            _listener = new MeterListener();
            _listener.InstrumentPublished = (instrument, listener) =>
            {
                if (instrument.Meter.Name == "MicrosoftIdentityModel_Meter")
                {
                    listener.EnableMeasurementEvents(instrument);
                }
            };

            _listener.SetMeasurementEventCallback<long>((instrument, measurement, tags, state) =>
            {
                lock (_measurements)
                {
                    _measurements.Add(new Measurement
                    {
                        InstrumentName = instrument.Name,
                        Value = measurement,
                        Tags = tags.ToArray()
                    });
                }
            });

            _listener.Start();
        }

        public List<Measurement> GetMeasurements(string instrumentName)
        {
            lock (_measurements)
            {
                return _measurements.Where(m => m.InstrumentName == instrumentName).ToList();
            }
        }

        public class Measurement
        {
            public string InstrumentName { get; set; }
            public long Value { get; set; }
            public KeyValuePair<string, object>[] Tags { get; set; }
        }
    }
}
