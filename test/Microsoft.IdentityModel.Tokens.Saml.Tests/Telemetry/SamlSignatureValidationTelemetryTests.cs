// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System;
using System.Collections.Generic;
using System.Diagnostics.Metrics;
using System.Linq;
using System.Security.Cryptography;
using Microsoft.IdentityModel.Logging;
using Microsoft.IdentityModel.Telemetry;
using Microsoft.IdentityModel.TestUtils;
using Xunit;

namespace Microsoft.IdentityModel.Tokens.Saml.Tests.Telemetry;

/// <summary>
/// Tests for SAML signature validation telemetry.
/// These tests must run sequentially to avoid telemetry cross-contamination from parallel test execution.
/// </summary>
[Collection("Telemetry Tests")]
public class SamlSignatureValidationTelemetryTests
{
    [Fact]
    public void ValidateToken_SamlSignatureValidationSuccess_RecordsTelemetry()
    {
        // Arrange
        using var listener = new TestMeterListener();
        ITestingTokenHandler handler = new SamlSecurityTestingTokenHandler();
        var tokenDescriptor = new SecurityTokenDescriptor
        {
            Subject = Default.ClaimsIdentityLongNames,
            SigningCredentials = Default.AsymmetricSigningCredentials,
            Audience = Default.Audience,
            Expires = DateTime.UtcNow + TimeSpan.FromDays(1),
            Issuer = Default.Issuer
        };

        var tokenString = handler.CreateStringToken(tokenDescriptor);

        var validationParameters = new TokenValidationParameters
        {
            IssuerSigningKey = Default.AsymmetricSigningCredentials.Key,
            ValidateAudience = false,
            ValidateIssuer = false,
            ValidateLifetime = false,
        };

        // Act
        handler.ValidateTokenAsync(tokenString, validationParameters);

        // Assert
        AssertTelemetryRecorded(listener, TelemetryDataRecorder.SignatureValidationCounterName,
            new Dictionary<string, object>
            {
                { TelemetryConstants.IdentityModelVersionTag, IdentityModelTelemetryUtil.ClientVer },
                { TelemetryConstants.StatusTag, TelemetryConstants.SuccessValue },
                { TelemetryConstants.AlgorithmTag, Default.AsymmetricSigningCredentials.Algorithm },
                { TelemetryConstants.KeySizeTag, Default.AsymmetricSigningCredentials.Key.KeySize }
            });
    }

    [Fact]
    public void ValidateToken_SamlSignatureValidationFailure_RecordsTelemetry()
    {
        // Arrange
        using var listener = new TestMeterListener();
        ITestingTokenHandler handler = new SamlSecurityTestingTokenHandler();
        var tokenDescriptor = new SecurityTokenDescriptor
        {
            Subject = Default.ClaimsIdentityLongNames,
            SigningCredentials = KeyingMaterial.DefaultX509SigningCreds_2048_RsaSha2_Sha2,
            Audience = Default.Audience,
            Expires = DateTime.UtcNow + TimeSpan.FromDays(1),
            Issuer = Default.Issuer
        };

        var tokenString = handler.CreateStringToken(tokenDescriptor);

        // Use a different key for validation (should fail)
        var validationParameters = new TokenValidationParameters
        {
            IssuerSigningKey = KeyingMaterial.RsaSecurityKey2,
            ValidateAudience = false,
            ValidateIssuer = false,
            ValidateLifetime = false,
        };

        // Act
        try
        {
            handler.ValidateTokenAsync(tokenString, validationParameters);
        }
        catch
        {
            // Expected to throw
        }

        // Assert
        AssertTelemetryRecorded(listener, TelemetryDataRecorder.SignatureValidationCounterName,
            new Dictionary<string, object>
            {
                { TelemetryConstants.IdentityModelVersionTag, IdentityModelTelemetryUtil.ClientVer },
                { TelemetryConstants.StatusTag, TelemetryConstants.FailureValue },
                { TelemetryConstants.AlgorithmTag, KeyingMaterial.DefaultX509SigningCreds_2048_RsaSha2_Sha2.Algorithm },
                { TelemetryConstants.KeySizeTag, KeyingMaterial.RsaSecurityKey2.KeySize }
            });
    }

    [Fact]
    public void ValidateToken_Saml2SignatureValidationSuccess_RecordsTelemetry()
    {
        // Arrange
        using var listener = new TestMeterListener();
        ITestingTokenHandler handler = new Saml2SecurityTestingTokenHandler();
        var tokenDescriptor = new SecurityTokenDescriptor
        {
            Subject = Default.ClaimsIdentityLongNames,
            SigningCredentials = Default.AsymmetricSigningCredentials,
            Audience = Default.Audience,
            Expires = DateTime.UtcNow + TimeSpan.FromDays(1),
            Issuer = Default.Issuer
        };

        var tokenString = handler.CreateStringToken(tokenDescriptor);

        var validationParameters = new TokenValidationParameters
        {
            IssuerSigningKey = Default.AsymmetricSigningCredentials.Key,
            ValidateAudience = false,
            ValidateIssuer = false,
            ValidateLifetime = false,
        };

        // Act
        handler.ValidateTokenAsync(tokenString, validationParameters);

        // Assert
        AssertTelemetryRecorded(listener, TelemetryDataRecorder.SignatureValidationCounterName,
            new Dictionary<string, object>
            {
                { TelemetryConstants.IdentityModelVersionTag, IdentityModelTelemetryUtil.ClientVer },
                { TelemetryConstants.StatusTag, TelemetryConstants.SuccessValue },
                { TelemetryConstants.AlgorithmTag, Default.AsymmetricSigningCredentials.Algorithm },
                { TelemetryConstants.KeySizeTag, Default.AsymmetricSigningCredentials.Key.KeySize }
            });
    }

    [Fact]
    public void ValidateToken_Saml2SignatureValidationFailure_RecordsTelemetry()
    {
        // Arrange
        using var listener = new TestMeterListener();
        ITestingTokenHandler handler = new Saml2SecurityTestingTokenHandler();
        var tokenDescriptor = new SecurityTokenDescriptor
        {
            Subject = Default.ClaimsIdentityLongNames,
            SigningCredentials = KeyingMaterial.DefaultX509SigningCreds_2048_RsaSha2_Sha2,
            Audience = Default.Audience,
            Expires = DateTime.UtcNow + TimeSpan.FromDays(1),
            Issuer = Default.Issuer
        };

        var tokenString = handler.CreateStringToken(tokenDescriptor);

        // Use a different key for validation (should fail)
        var validationParameters = new TokenValidationParameters
        {
            IssuerSigningKey = KeyingMaterial.RsaSecurityKey2,
            ValidateAudience = false,
            ValidateIssuer = false,
            ValidateLifetime = false,
        };

        // Act
        try
        {
            handler.ValidateTokenAsync(tokenString, validationParameters);
        }
        catch
        {
            // Expected to throw
        }

        // Assert
        AssertTelemetryRecorded(listener, TelemetryDataRecorder.SignatureValidationCounterName,
            new Dictionary<string, object>
            {
                { TelemetryConstants.IdentityModelVersionTag, IdentityModelTelemetryUtil.ClientVer },
                { TelemetryConstants.StatusTag, TelemetryConstants.FailureValue },
                { TelemetryConstants.AlgorithmTag, KeyingMaterial.DefaultX509SigningCreds_2048_RsaSha2_Sha2.Algorithm },
                { TelemetryConstants.KeySizeTag, KeyingMaterial.RsaSecurityKey2.KeySize }
            });
    }

    [Fact]
    public void ValidateToken_SamlSymmetricSignature_RecordsTelemetry()
    {
        // Arrange
        using var listener = new TestMeterListener();
        ITestingTokenHandler handler = new SamlSecurityTestingTokenHandler();
        var tokenDescriptor = new SecurityTokenDescriptor
        {
            Subject = Default.ClaimsIdentityLongNames,
            SigningCredentials = Default.SymmetricSigningCredentials,
            Audience = Default.Audience,
            Expires = DateTime.UtcNow + TimeSpan.FromDays(1),
            Issuer = Default.Issuer
        };

        var tokenString = handler.CreateStringToken(tokenDescriptor);

        var validationParameters = new TokenValidationParameters
        {
            IssuerSigningKey = Default.SymmetricSigningCredentials.Key,
            ValidateAudience = false,
            ValidateIssuer = false,
            ValidateLifetime = false,
        };

        // Act
        handler.ValidateTokenAsync(tokenString, validationParameters);

        // Assert
        AssertTelemetryRecorded(listener, TelemetryDataRecorder.SignatureValidationCounterName,
            new Dictionary<string, object>
            {
                { TelemetryConstants.IdentityModelVersionTag, IdentityModelTelemetryUtil.ClientVer },
                { TelemetryConstants.StatusTag, TelemetryConstants.SuccessValue },
                { TelemetryConstants.AlgorithmTag, Default.SymmetricSigningCredentials.Algorithm },
                { TelemetryConstants.KeySizeTag, Default.SymmetricSigningCredentials.Key.KeySize }
            });
    }

    [Fact]
    public void ValidateToken_Saml2SymmetricSignature_RecordsTelemetry()
    {
        // Arrange
        using var listener = new TestMeterListener();
        ITestingTokenHandler handler = new Saml2SecurityTestingTokenHandler();
        var tokenDescriptor = new SecurityTokenDescriptor
        {
            Subject = Default.ClaimsIdentityLongNames,
            SigningCredentials = Default.SymmetricSigningCredentials,
            Audience = Default.Audience,
            Expires = DateTime.UtcNow + TimeSpan.FromDays(1),
            Issuer = Default.Issuer
        };

        var tokenString = handler.CreateStringToken(tokenDescriptor);

        var validationParameters = new TokenValidationParameters
        {
            IssuerSigningKey = Default.SymmetricSigningCredentials.Key,
            ValidateAudience = false,
            ValidateIssuer = false,
            ValidateLifetime = false,
        };

        // Act
        handler.ValidateTokenAsync(tokenString, validationParameters);

        // Assert
        AssertTelemetryRecorded(listener, TelemetryDataRecorder.SignatureValidationCounterName,
            new Dictionary<string, object>
            {
                { TelemetryConstants.IdentityModelVersionTag, IdentityModelTelemetryUtil.ClientVer },
                { TelemetryConstants.StatusTag, TelemetryConstants.SuccessValue },
                { TelemetryConstants.AlgorithmTag, Default.SymmetricSigningCredentials.Algorithm },
                { TelemetryConstants.KeySizeTag, Default.SymmetricSigningCredentials.Key.KeySize }
            });
    }

    [Fact]
    public void ValidateToken_SamlRsa2048Signature_RecordsTelemetry()
    {
        // Arrange
        using var listener = new TestMeterListener();
        ITestingTokenHandler handler = new SamlSecurityTestingTokenHandler();
        var tokenDescriptor = new SecurityTokenDescriptor
        {
            Subject = Default.ClaimsIdentityLongNames,
            SigningCredentials = KeyingMaterial.DefaultX509SigningCreds_2048_RsaSha2_Sha2,
            Audience = Default.Audience,
            Expires = DateTime.UtcNow + TimeSpan.FromDays(1),
            Issuer = Default.Issuer
        };

        var tokenString = handler.CreateStringToken(tokenDescriptor);

        var validationParameters = new TokenValidationParameters
        {
            IssuerSigningKey = KeyingMaterial.DefaultX509SigningCreds_2048_RsaSha2_Sha2.Key,
            ValidateAudience = false,
            ValidateIssuer = false,
            ValidateLifetime = false,
        };

        // Act
        handler.ValidateTokenAsync(tokenString, validationParameters);

        // Assert
        AssertTelemetryRecorded(listener, TelemetryDataRecorder.SignatureValidationCounterName,
            new Dictionary<string, object>
            {
                { TelemetryConstants.IdentityModelVersionTag, IdentityModelTelemetryUtil.ClientVer },
                { TelemetryConstants.StatusTag, TelemetryConstants.SuccessValue },
                { TelemetryConstants.AlgorithmTag, KeyingMaterial.DefaultX509SigningCreds_2048_RsaSha2_Sha2.Algorithm },
                { TelemetryConstants.KeySizeTag, 2048 }
            });
    }

    [Fact]
    public void ValidateToken_Saml2Rsa2048Signature_RecordsTelemetry()
    {
        // Arrange
        using var listener = new TestMeterListener();
        ITestingTokenHandler handler = new Saml2SecurityTestingTokenHandler();
        var tokenDescriptor = new SecurityTokenDescriptor
        {
            Subject = Default.ClaimsIdentityLongNames,
            SigningCredentials = KeyingMaterial.DefaultX509SigningCreds_2048_RsaSha2_Sha2,
            Audience = Default.Audience,
            Expires = DateTime.UtcNow + TimeSpan.FromDays(1),
            Issuer = Default.Issuer
        };

        var tokenString = handler.CreateStringToken(tokenDescriptor);

        var validationParameters = new TokenValidationParameters
        {
            IssuerSigningKey = KeyingMaterial.DefaultX509SigningCreds_2048_RsaSha2_Sha2.Key,
            ValidateAudience = false,
            ValidateIssuer = false,
            ValidateLifetime = false,
        };

        // Act
        handler.ValidateTokenAsync(tokenString, validationParameters);

        // Assert
        AssertTelemetryRecorded(listener, TelemetryDataRecorder.SignatureValidationCounterName,
            new Dictionary<string, object>
            {
                { TelemetryConstants.IdentityModelVersionTag, IdentityModelTelemetryUtil.ClientVer },
                { TelemetryConstants.StatusTag, TelemetryConstants.SuccessValue },
                { TelemetryConstants.AlgorithmTag, KeyingMaterial.DefaultX509SigningCreds_2048_RsaSha2_Sha2.Algorithm },
                { TelemetryConstants.KeySizeTag, 2048 }
            });
    }

    private void AssertTelemetryRecorded(TestMeterListener listener, string counterName, Dictionary<string, object> expectedTags)
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
    private class TestMeterListener : System.IDisposable
    {
        private readonly MeterListener _listener;
        private readonly List<Measurement> _measurements = new List<Measurement>();
        private readonly long _startTimestamp;

        public TestMeterListener()
        {
            _startTimestamp = System.Diagnostics.Stopwatch.GetTimestamp();
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
                        Tags = tags.ToArray(),
                        Timestamp = System.Diagnostics.Stopwatch.GetTimestamp()
                    });
                }
            });

            _listener.Start();
        }

        public List<Measurement> GetMeasurements(string instrumentName)
        {
            lock (_measurements)
            {
                // Only return measurements that were recorded after this listener started
                return _measurements
                    .Where(m => m.InstrumentName == instrumentName && m.Timestamp >= _startTimestamp)
                    .ToList();
            }
        }

        public void Dispose()
        {
            _listener?.Dispose();
        }

        public class Measurement
        {
            public string InstrumentName { get; set; }
            public long Value { get; set; }
            public KeyValuePair<string, object>[] Tags { get; set; }
            public long Timestamp { get; set; }
        }
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

}
