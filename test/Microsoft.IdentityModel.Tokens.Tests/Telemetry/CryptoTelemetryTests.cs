// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System;
using Microsoft.IdentityModel.Telemetry;
using Microsoft.IdentityModel.TestUtils;
using Xunit;
#if !NET462 && !NET472 && !NETSTANDARD2_0
using System.Security.Cryptography;
#endif

namespace Microsoft.IdentityModel.Tokens.Tests.Telemetry;

/// <summary>
/// Tests for CryptoTelemetry utility methods.
/// </summary>
public class CryptoTelemetryTests
{
    [Theory]
    [InlineData("RSA-2048")]
    [InlineData("RSA-4096")]
    public void GetKeyAlgorithmId_RsaSecurityKey_ReturnsCorrectId(string expectedId)
    {
        // Arrange
        var rsaKey = expectedId == "RSA-2048"
            ? KeyingMaterial.RsaSecurityKey_2048
            : KeyingMaterial.RsaSecurityKey_4096;

        // Act
        var result = CryptoTelemetry.GetKeyAlgorithmId(rsaKey);

        // Assert
        Assert.Equal(expectedId, result);
    }

    [Theory]
    [InlineData(128, "SYM-128")]
    [InlineData(192, "SYM-192")]
    [InlineData(256, "SYM-256")]
    [InlineData(384, "SYM-384")]
    [InlineData(512, "SYM-512")]
    [InlineData(1024, "SYM-UNKNOWN")]
    public void GetKeyAlgorithmId_SymmetricSecurityKey_ReturnsCorrectId(int keySize, string expectedId)
    {
        // Arrange
        var key = new SymmetricSecurityKey(new byte[keySize / 8]);

        // Act
        var result = CryptoTelemetry.GetKeyAlgorithmId(key);

        // Assert
        Assert.Equal(expectedId, result);
    }

#if !NET462 && !NET472 && !NETSTANDARD2_0
    [Theory]
    [InlineData(256, "ECDSA-P256")]
    [InlineData(384, "ECDSA-P384")]
    [InlineData(521, "ECDSA-P521")]
    public void GetKeyAlgorithmId_ECDsaSecurityKey_ReturnsCorrectId(int keySize, string expectedId)
    {
        // Arrange
        ECDsaSecurityKey key = keySize switch
        {
            256 => new ECDsaSecurityKey(ECDsa.Create(ECCurve.NamedCurves.nistP256)),
            384 => new ECDsaSecurityKey(ECDsa.Create(ECCurve.NamedCurves.nistP384)),
            521 => new ECDsaSecurityKey(ECDsa.Create(ECCurve.NamedCurves.nistP521)),
            _ => throw new ArgumentException("Invalid key size")
        };

        // Act
        var result = CryptoTelemetry.GetKeyAlgorithmId(key);

        // Assert
        Assert.Equal(expectedId, result);
    }
#endif

    [Theory]
    [MemberData(nameof(GetKeyAlgorithmId_SecurityKey_TestData))]
    public void GetKeyAlgorithmId_SecurityKey_ReturnsCorrectId(SecurityKey key, string expectedId)
    {
        // Act
        var result = CryptoTelemetry.GetKeyAlgorithmId(key);

        // Assert
        Assert.Equal(expectedId, result);
    }

    public static TheoryData<SecurityKey, string> GetKeyAlgorithmId_SecurityKey_TestData
    {
        get
        {
            var data = new TheoryData<SecurityKey, string>
            {
                // Null key
                { null, "NO-KEY" },

                // X509SecurityKey
                { KeyingMaterial.DefaultX509Key_2048, "RSA-2048" },

                // RsaSecurityKey
                { KeyingMaterial.RsaSecurityKey_4096, "RSA-4096" },

                // JsonWebKey - RSA
                { KeyingMaterial.JsonWebKeyRsa_2048, "RSA-2048" },

                // JsonWebKey - Symmetric
                { KeyingMaterial.JsonWebKeySymmetric256, "SYM-256" },

                // JsonWebKey with ConvertedSecurityKey
                {
                    new JsonWebKey
                    {
                        Kty = JsonWebAlgorithmsKeyTypes.RSA,
                        N = Base64UrlEncoder.Encode(KeyingMaterial.RsaParameters_2048.Modulus),
                        E = Base64UrlEncoder.Encode(KeyingMaterial.RsaParameters_2048.Exponent),
                        ConvertedSecurityKey = KeyingMaterial.RsaSecurityKey_2048
                    },
                    "RSA-2048"
                }
            };

#if !NET462 && !NET472 && !NETSTANDARD2_0
            // JsonWebKey - ECDSA (only on supported platforms)
            using (var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256))
            {
                var ecdsaKey = new ECDsaSecurityKey(ecdsa);
                var jwk = JsonWebKeyConverter.ConvertFromECDsaSecurityKey(ecdsaKey);
                data.Add(jwk, "ECDSA-P256");
            }
#endif

            return data;
        }
    }

    [Theory]
    [MemberData(nameof(GetTrackedIssuerOrOther_BasicScenarios_TestData))]
    public void GetTrackedIssuerOrOther_BasicScenarios_ReturnsExpectedResult(string[] trackedIssuers, string issuer, string expectedResult)
    {
        // Arrange
        CryptoTelemetry.EnableSignatureValidationTelemetry(true, trackedIssuers);

        // Act
        var result = CryptoTelemetry.GetTrackedIssuerOrOther(issuer);

        // Assert
        Assert.Equal(expectedResult, result);
    }

    public static TheoryData<string[], string, string> GetTrackedIssuerOrOther_BasicScenarios_TestData
    {
        get
        {
            return new TheoryData<string[], string, string>
            {
                // Tracked issuer - returns host
                { new[] { "login.microsoftonline.com", "accounts.google.com" }, "https://login.microsoftonline.com/tenant/v2.0", "login.microsoftonline.com" },

                // Untracked issuer - returns "other"
                { new[] { "login.microsoftonline.com" }, "https://example.com/path", "other" },

                // Null issuer - returns "other"
                { new[] { "login.microsoftonline.com" }, null, "other" },

                // Empty issuer - returns "other"
                { new[] { "login.microsoftonline.com" }, string.Empty, "other" },

                // No tracked issuers - returns "other"
                { Array.Empty<string>(), "https://login.microsoftonline.com/tenant/v2.0", "other" },
            };
        }
    }

    [Fact]
    public void GetKeyAlgorithmId_JsonWebKey_WithConvertedSecurityKey_ReturnsConvertedKeyId()
    {
        // Arrange
        var jwk = new JsonWebKey
        {
            Kty = JsonWebAlgorithmsKeyTypes.RSA,
            N = Base64UrlEncoder.Encode(KeyingMaterial.RsaParameters_2048.Modulus),
            E = Base64UrlEncoder.Encode(KeyingMaterial.RsaParameters_2048.Exponent)
        };
        jwk.ConvertedSecurityKey = KeyingMaterial.RsaSecurityKey_2048;

        // Act
        var result = CryptoTelemetry.GetKeyAlgorithmId(jwk);

        // Assert
        Assert.Equal("RSA-2048", result);
    }

    [Theory]
    [MemberData(nameof(JsonWebKeyTestData))]
    public void GetKeyAlgorithmId_JsonWebKey_ReturnsCorrectId(JsonWebKey jwk, string expectedId)
    {
        // Act
        var result = CryptoTelemetry.GetKeyAlgorithmId(jwk);

        // Assert
        Assert.Equal(expectedId, result);
    }

    public static TheoryData<JsonWebKey, string> JsonWebKeyTestData
    {
        get
        {
            var data = new TheoryData<JsonWebKey, string>();

            // RSA keys
            data.Add(KeyingMaterial.JsonWebKeyRsa_2048, "RSA-2048");

            // Symmetric keys
            data.Add(KeyingMaterial.JsonWebKeySymmetric128, "SYM-128");
            data.Add(KeyingMaterial.JsonWebKeySymmetric256, "SYM-256");

            return data;
        }
    }

    [Fact]
    public void GetKeyAlgorithmId_JsonWebKey_UnknownKty_ReturnsUnknown()
    {
        // Arrange
        var jwk = new JsonWebKey
        {
            Kty = "UnknownKeyType"
        };

        // Act
        var result = CryptoTelemetry.GetKeyAlgorithmId(jwk);

        // Assert
        Assert.Equal("UNKNOWN", result);
    }

    [Fact]
    public void GetKeyAlgorithmId_CustomSecurityKey_ReturnsUnknown()
    {
        // Arrange
        var customKey = new CustomSecurityKey();

        // Act
        var result = CryptoTelemetry.GetKeyAlgorithmId(customKey);

        // Assert
        Assert.Equal("UNKNOWN", result);
    }

    [Theory]
    [InlineData("https://login.microsoftonline.com/tenant/v2.0", "login.microsoftonline.com")]
    [InlineData("https://example.com:8080", "example.com")]
    public void GetTrackedIssuerOrOther_MultipleTrackedIssuers_ReturnsCorrectResult(string issuer, string expectedTrackedHost)
    {
        // Arrange
        CryptoTelemetry.EnableSignatureValidationTelemetry(true, new[]
        {
            "login.microsoftonline.com",
            "accounts.google.com",
            "example.com"
        });

        // Act
        var result = CryptoTelemetry.GetTrackedIssuerOrOther(issuer);

        // Assert - Returns the tracked host from allowlist (case preserved from allowlist)
        Assert.Equal(expectedTrackedHost, result);
    }

    [Theory]
    [InlineData("https://notexample.com/path", "example.com")] // Substring match (false positive)
    [InlineData("https://different.com/example.com/path", "example.com")] // Match in path (false positive)
    [InlineData("https://example.com:8080/path", "example.com")] // With port
    public void GetTrackedIssuerOrOther_IndexOfBehavior_ReturnsFalsePositives(string issuer, string expectedResult)
    {
        // Arrange - Current implementation uses IndexOf which can have false positives
        CryptoTelemetry.EnableSignatureValidationTelemetry(true, new[] { "example.com" });

        // Act
        var result = CryptoTelemetry.GetTrackedIssuerOrOther(issuer);

        // Assert - Current implementation returns match even for false positives
        // This demonstrates potential issues with the IndexOf approach
        Assert.Equal(expectedResult, result);
    }

    [Theory]
    [InlineData("https://notexample.com/path", "other")]
    [InlineData("https://different.com/example.com/path", "other")]
    [InlineData("https://example.com:8080/path", "https://example.com")]
    public void GetTrackedIssuerOrOther_IndexOfBehavior_AvoidsFalsePositivesByUsingScheme(string issuer, string expectedResult)
    {
        // Arrange - Specifying tracked issuers with scheme to avoid false positives
        CryptoTelemetry.EnableSignatureValidationTelemetry(true, new[] { "https://example.com" });

        // Act
        var result = CryptoTelemetry.GetTrackedIssuerOrOther(issuer);

        Assert.Equal(expectedResult, result);
    }

    [Theory]
    [MemberData(nameof(EnableSignatureValidationTelemetry_Filtering_TestData))]
    public void EnableSignatureValidationTelemetry_Filtering_ValidatesCorrectly(string[] inputTrackedIssuers, string testIssuer, string expectedResult)
    {
        // Arrange & Act
        CryptoTelemetry.EnableSignatureValidationTelemetry(true, inputTrackedIssuers);

        // Assert - Verify filtering behavior
        var result = CryptoTelemetry.GetTrackedIssuerOrOther(testIssuer);
        Assert.Equal(expectedResult, result);
    }

    public static TheoryData<string[], string, string> EnableSignatureValidationTelemetry_Filtering_TestData
    {
        get
        {
            return new TheoryData<string[], string, string>
            {
                // Duplicates are removed (case-insensitive)
                {
                    new[] { "login.microsoftonline.com", "LOGIN.MICROSOFTONLINE.COM", "accounts.google.com", "accounts.google.com" },
                    "https://login.microsoftonline.com/tenant",
                    "login.microsoftonline.com"
                },

                // Null/empty/whitespace values are filtered out (first host)
                {
                    new[] { "login.microsoftonline.com", null!, "", "   ", "accounts.google.com" },
                    "https://login.microsoftonline.com/tenant",
                    "login.microsoftonline.com"
                },

                // Null/empty/whitespace values are filtered out (second host)
                {
                    new[] { "login.microsoftonline.com", null!, "", "   ", "accounts.google.com" },
                    "https://accounts.google.com/auth",
                    "accounts.google.com"
                }
            };
        }
    }

    /// <summary>
    /// Custom security key for testing unknown key type scenario
    /// </summary>
    private class CustomSecurityKey : SecurityKey
    {
        public override int KeySize => 256;
    }
}
