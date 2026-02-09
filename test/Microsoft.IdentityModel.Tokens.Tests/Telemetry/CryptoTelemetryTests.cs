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

    [Fact]
    public void GetKeyAlgorithmId_X509SecurityKey_Rsa2048_ReturnsCorrectId()
    {
        // Arrange
        var x509Key = KeyingMaterial.DefaultX509Key_2048;

        // Act
        var result = CryptoTelemetry.GetKeyAlgorithmId(x509Key);

        // Assert
        Assert.Equal("RSA-2048", result);
    }

    [Fact]
    public void GetKeyAlgorithmId_RsaSecurityKey_4096_ReturnsCorrectId()
    {
        // Arrange
        var rsaKey = KeyingMaterial.RsaSecurityKey_4096;

        // Act
        var result = CryptoTelemetry.GetKeyAlgorithmId(rsaKey);

        // Assert
        Assert.Equal("RSA-4096", result);
    }

    [Fact]
    public void GetKeyAlgorithmId_JsonWebKey_Rsa_ReturnsCorrectId()
    {
        // Arrange
        var jwk = KeyingMaterial.JsonWebKeyRsa_2048;

        // Act
        var result = CryptoTelemetry.GetKeyAlgorithmId(jwk);

        // Assert
        Assert.Equal("RSA-2048", result);
    }

    [Fact]
    public void GetKeyAlgorithmId_JsonWebKey_Symmetric_ReturnsCorrectId()
    {
        // Arrange
        var jwk = KeyingMaterial.JsonWebKeySymmetric256;

        // Act
        var result = CryptoTelemetry.GetKeyAlgorithmId(jwk);

        // Assert
        Assert.Equal("SYM-256", result);
    }

#if !NET462 && !NET472 && !NETSTANDARD2_0
    [Fact]
    public void GetKeyAlgorithmId_JsonWebKey_ECDSA_ReturnsCorrectId()
    {
        // Arrange
        using var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var ecdsaKey = new ECDsaSecurityKey(ecdsa);
        var jwk = JsonWebKeyConverter.ConvertFromECDsaSecurityKey(ecdsaKey);

        // Act
        var result = CryptoTelemetry.GetKeyAlgorithmId(jwk);

        // Assert
        Assert.Equal("ECDSA-P256", result);
    }
#endif

    [Fact]
    public void GetKeyAlgorithmId_NullKey_ReturnsNoKey()
    {
        // Act
        var result = CryptoTelemetry.GetKeyAlgorithmId(null);

        // Assert
        Assert.Equal("NO-KEY", result);
    }

    [Theory]
    [MemberData(nameof(ExtractHostFromIssuerTestData))]
    public void ExtractHostFromIssuer_VariousFormats_ReturnsCorrectHost(string issuer, string expectedHost)
    {
        // Arrange
        CryptoTelemetry.EnableSignatureValidationTelemetry(false, null);

        // Act
        var result = CryptoTelemetry.ExtractHostFromIssuer(issuer);

        // Assert
        Assert.Equal(expectedHost, result);
    }

    public static TheoryData<string, string> ExtractHostFromIssuerTestData => new()
    {
        // Standard HTTPS URLs
        { "https://login.microsoftonline.com/tenant/v2.0", "login.microsoftonline.com" },
        { "https://accounts.google.com", "accounts.google.com" },
        { "https://example.com:8080/path", "example.com" },
        { "https://example.com:443", "example.com" },
        
        // HTTP URLs
        { "http://localhost:5000/api", "localhost" },
        { "http://example.com", "example.com" },
        
        // Without scheme
        { "example.com/path", "example.com" },
        { "example.com:8080", "example.com" },
        
        // With query parameters
        { "https://example.com/path?query=value", "example.com" },
        { "https://example.com:8080?query=value", "example.com" },
        
        // Edge cases
        { "", "" },
        { "https://", "" },
        { "://example.com", "example.com" },
        
        // Complex paths
        { "https://login.microsoftonline.com/common/v2.0/.well-known/openid-configuration", "login.microsoftonline.com" },
        { "https://accounts.google.com/.well-known/openid-configuration", "accounts.google.com" },
        
        // With port and path
        { "https://localhost:5001/auth/token", "localhost" },
        { "http://example.com:8080/api/v1/token", "example.com" },
    };

    [Fact]
    public void GetTrackedIssuerOrOther_TrackedIssuer_ReturnsHost()
    {
        // Arrange
        CryptoTelemetry.EnableSignatureValidationTelemetry(true, new[] { "login.microsoftonline.com", "accounts.google.com" });
        string issuer = "https://login.microsoftonline.com/tenant/v2.0";

        // Act
        var result = CryptoTelemetry.GetTrackedIssuerOrOther(issuer);

        // Assert
        Assert.Equal("login.microsoftonline.com", result);
    }

    [Fact]
    public void GetTrackedIssuerOrOther_UntrackedIssuer_ReturnsOther()
    {
        // Arrange
        CryptoTelemetry.EnableSignatureValidationTelemetry(true, new[] { "login.microsoftonline.com" });
        string issuer = "https://example.com/path";

        // Act
        var result = CryptoTelemetry.GetTrackedIssuerOrOther(issuer);

        // Assert
        Assert.Equal("other", result);
    }

    [Fact]
    public void GetTrackedIssuerOrOther_NullIssuer_ReturnsOther()
    {
        // Arrange
        CryptoTelemetry.EnableSignatureValidationTelemetry(true, new[] { "login.microsoftonline.com" });

        // Act
        var result = CryptoTelemetry.GetTrackedIssuerOrOther(null);

        // Assert
        Assert.Equal("other", result);
    }

    [Fact]
    public void GetTrackedIssuerOrOther_EmptyIssuer_ReturnsOther()
    {
        // Arrange
        CryptoTelemetry.EnableSignatureValidationTelemetry(true, new[] { "login.microsoftonline.com" });

        // Act
        var result = CryptoTelemetry.GetTrackedIssuerOrOther(string.Empty);

        // Assert
        Assert.Equal("other", result);
    }

    [Fact]
    public void GetTrackedIssuerOrOther_NoTrackedIssuers_ReturnsOther()
    {
        // Arrange
        CryptoTelemetry.EnableSignatureValidationTelemetry(true, Array.Empty<string>());
        string issuer = "https://login.microsoftonline.com/tenant/v2.0";

        // Act
        var result = CryptoTelemetry.GetTrackedIssuerOrOther(issuer);

        // Assert
        Assert.Equal("other", result);
    }

    [Fact]
    public void GetTrackedIssuerOrOther_CaseInsensitive_ReturnsHost()
    {
        // Arrange
        CryptoTelemetry.EnableSignatureValidationTelemetry(true, new[] { "login.microsoftonline.com" });
        string issuer = "https://LOGIN.MICROSOFTONLINE.COM/tenant/v2.0";

        // Act
        var result = CryptoTelemetry.GetTrackedIssuerOrOther(issuer);

        // Assert
        Assert.Equal("LOGIN.MICROSOFTONLINE.COM", result);
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
    [InlineData("https://ACCOUNTS.GOOGLE.COM/path", "ACCOUNTS.GOOGLE.COM")]
    [InlineData("https://example.com:8080", "example.com")]
    public void GetTrackedIssuerOrOther_MultipleTrackedIssuers_ReturnsCorrectResult(string issuer, string trackedHost)
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

        // Assert
        Assert.Equal(trackedHost, result);
    }

    [Fact]
    public void RecordSignatureValidationTelemetry_Property_CanBeSetAndGet()
    {
        // Act
        CryptoTelemetry.RecordSignatureValidationTelemetry = true;
        var enabled = CryptoTelemetry.RecordSignatureValidationTelemetry;

        // Assert
        Assert.True(enabled);

        // Cleanup
        CryptoTelemetry.RecordSignatureValidationTelemetry = false;
    }

    [Theory]
    [InlineData("https://login.microsoftonline.com:443/tenant", "login.microsoftonline.com")]
    [InlineData("https://example.com:8080/path/to/resource", "example.com")]
    [InlineData("https://api.example.com:9000?query=param", "api.example.com")]
    [InlineData("http://localhost:5000", "localhost")]
    public void ExtractHostFromIssuer_WithPortNumber_StripsPort(string issuer, string expectedHost)
    {
        // Arrange
        CryptoTelemetry.EnableSignatureValidationTelemetry(false, null);

        // Act
        var result = CryptoTelemetry.ExtractHostFromIssuer(issuer);

        // Assert
        Assert.Equal(expectedHost, result);
    }

    /// <summary>
    /// Custom security key for testing unknown key type scenario
    /// </summary>
    private class CustomSecurityKey : SecurityKey
    {
        public override int KeySize => 256;
    }
}
