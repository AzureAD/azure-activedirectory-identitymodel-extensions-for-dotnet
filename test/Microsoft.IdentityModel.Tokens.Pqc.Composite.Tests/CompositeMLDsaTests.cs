// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#nullable enable

using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using Microsoft.IdentityModel.Tokens.Pqc.Composite;
using Xunit;

#pragma warning disable CS3016 // Arrays as attribute arguments is not CLS-compliant

namespace Microsoft.IdentityModel.Tokens.Pqc.Composite.Tests;

public class CompositeMLDsaTests
{
    #region SecurityKey Tests

    [Fact]
    public void SecurityKey_NullCompositeMLDsa_ThrowsArgumentNullException()
    {
        Assert.Throws<ArgumentNullException>(() => new CompositeMLDsaSecurityKey(null!));
    }

    [Theory]
    [InlineData("ML-DSA-44-ES256")]
    [InlineData("ML-DSA-65-ES256")]
    [InlineData("ML-DSA-87-ES384")]
    public void SecurityKey_Constructor_ValidKey(string algorithm)
    {
        // Arrange
        var dotNetAlg = CompositeMLDsaAlgorithms.GetCompositeMLDsaAlgorithm(algorithm);
        using var composite = CompositeMLDsa.GenerateKey(dotNetAlg);

        // Act
        var key = new CompositeMLDsaSecurityKey(composite);

        // Assert
        Assert.NotNull(key.CompositeMLDsa);
        Assert.True(key.KeySize > 0, "KeySize should be positive");
    }

    [Theory]
    [InlineData("ML-DSA-44-ES256")]
    [InlineData("ML-DSA-65-ES256")]
    [InlineData("ML-DSA-87-ES384")]
    public void SecurityKey_PrivateKeyStatus_WithPrivateKey_ReturnsExists(string algorithm)
    {
        // Arrange
        var dotNetAlg = CompositeMLDsaAlgorithms.GetCompositeMLDsaAlgorithm(algorithm);
        using var composite = CompositeMLDsa.GenerateKey(dotNetAlg);
        var key = new CompositeMLDsaSecurityKey(composite);

        // Act & Assert
        Assert.Equal(PrivateKeyStatus.Exists, key.PrivateKeyStatus);
    }

    [Theory]
    [InlineData("ML-DSA-44-ES256")]
    public void SecurityKey_PrivateKeyStatus_PublicOnly_ReturnsDoesNotExist(string algorithm)
    {
        // Arrange
        var dotNetAlg = CompositeMLDsaAlgorithms.GetCompositeMLDsaAlgorithm(algorithm);
        using var composite = CompositeMLDsa.GenerateKey(dotNetAlg);
        byte[] spki = composite.ExportSubjectPublicKeyInfo();
        using var publicOnly = CompositeMLDsa.ImportSubjectPublicKeyInfo(spki);
        var key = new CompositeMLDsaSecurityKey(publicOnly);

        // Act & Assert
        Assert.Equal(PrivateKeyStatus.DoesNotExist, key.PrivateKeyStatus);
    }

    [Theory]
    [InlineData("ML-DSA-44-ES256")]
    [InlineData("ML-DSA-65-ES256")]
    [InlineData("ML-DSA-87-ES384")]
    public void SecurityKey_JwkThumbprint_Is32Bytes(string algorithm)
    {
        // Arrange
        var dotNetAlg = CompositeMLDsaAlgorithms.GetCompositeMLDsaAlgorithm(algorithm);
        using var composite = CompositeMLDsa.GenerateKey(dotNetAlg);
        var key = new CompositeMLDsaSecurityKey(composite);

        // Act
        Assert.True(key.CanComputeJwkThumbprint());
        byte[] thumbprint = key.ComputeJwkThumbprint();

        // Assert
        Assert.NotNull(thumbprint);
        Assert.Equal(32, thumbprint.Length); // SHA-256 = 32 bytes
    }

    [Theory]
    [InlineData("ML-DSA-44-ES256")]
    public void SecurityKey_JwkThumbprint_IsDeterministic(string algorithm)
    {
        // Arrange
        var dotNetAlg = CompositeMLDsaAlgorithms.GetCompositeMLDsaAlgorithm(algorithm);
        using var composite = CompositeMLDsa.GenerateKey(dotNetAlg);
        var key = new CompositeMLDsaSecurityKey(composite);

        // Act
        byte[] thumbprint1 = key.ComputeJwkThumbprint();
        byte[] thumbprint2 = key.ComputeJwkThumbprint();

        // Assert
        Assert.Equal(thumbprint1, thumbprint2);
    }

    #endregion

    #region SignatureProvider Tests

    [Theory]
    [InlineData("ML-DSA-44-ES256")]
    [InlineData("ML-DSA-65-ES256")]
    [InlineData("ML-DSA-87-ES384")]
    public void SignatureProvider_SignVerify_RoundTrip(string algorithm)
    {
        // Arrange
        var dotNetAlg = CompositeMLDsaAlgorithms.GetCompositeMLDsaAlgorithm(algorithm);
        using var composite = CompositeMLDsa.GenerateKey(dotNetAlg);
        var key = new CompositeMLDsaSecurityKey(composite);
        using var provider = new CompositeMLDsaSignatureProvider(key, algorithm, true);
        byte[] data = Encoding.UTF8.GetBytes("Hello, Composite ML-DSA!");

        // Act
        byte[] signature = provider.Sign(data);
        bool isValid = provider.Verify(data, signature);

        // Assert
        Assert.NotNull(signature);
        Assert.True(signature.Length > 0);
        Assert.True(isValid);
    }

    [Theory]
    [InlineData("ML-DSA-44-ES256")]
    public void SignatureProvider_TamperedSignature_FailsVerification(string algorithm)
    {
        // Arrange
        var dotNetAlg = CompositeMLDsaAlgorithms.GetCompositeMLDsaAlgorithm(algorithm);
        using var composite = CompositeMLDsa.GenerateKey(dotNetAlg);
        var key = new CompositeMLDsaSecurityKey(composite);
        using var provider = new CompositeMLDsaSignatureProvider(key, algorithm, true);
        byte[] data = Encoding.UTF8.GetBytes("Hello, Composite ML-DSA!");

        // Act
        byte[] signature = provider.Sign(data);
        signature[0] ^= 0xFF; // Tamper with signature
        bool isValid = provider.Verify(data, signature);

        // Assert
        Assert.False(isValid);
    }

    [Theory]
    [InlineData("ML-DSA-44-ES256")]
    public void SignatureProvider_DifferentData_FailsVerification(string algorithm)
    {
        // Arrange
        var dotNetAlg = CompositeMLDsaAlgorithms.GetCompositeMLDsaAlgorithm(algorithm);
        using var composite = CompositeMLDsa.GenerateKey(dotNetAlg);
        var key = new CompositeMLDsaSecurityKey(composite);
        using var provider = new CompositeMLDsaSignatureProvider(key, algorithm, true);
        byte[] data = Encoding.UTF8.GetBytes("Original message");
        byte[] differentData = Encoding.UTF8.GetBytes("Different message");

        // Act
        byte[] signature = provider.Sign(data);
        bool isValid = provider.Verify(differentData, signature);

        // Assert
        Assert.False(isValid);
    }

    [Fact]
    public void SignatureProvider_NullInput_ThrowsArgumentNullException()
    {
        // Arrange
        using var composite = CompositeMLDsa.GenerateKey(CompositeMLDsaAlgorithm.MLDsa44WithECDsaP256);
        var key = new CompositeMLDsaSecurityKey(composite);
        using var provider = new CompositeMLDsaSignatureProvider(key, CompositeMLDsaAlgorithms.MlDsa44Es256, true);

        // Act & Assert
        Assert.Throws<ArgumentNullException>(() => provider.Sign(null!));
        Assert.Throws<ArgumentNullException>(() => provider.Verify(null!, new byte[1]));
        Assert.Throws<ArgumentNullException>(() => provider.Verify(new byte[1], null!));
    }

    #endregion

    #region CryptoProvider Tests

    [Fact]
    public void CryptoProvider_IsSupportedAlgorithm_CompositeAlgorithmWithKey_ReturnsTrue()
    {
        // Arrange
        var provider = new CompositeMLDsaCryptoProvider();
        using var composite = CompositeMLDsa.GenerateKey(CompositeMLDsaAlgorithm.MLDsa44WithECDsaP256);
        var key = new CompositeMLDsaSecurityKey(composite);

        // Act & Assert
        Assert.True(provider.IsSupportedAlgorithm(CompositeMLDsaAlgorithms.MlDsa44Es256, key));
    }

    [Fact]
    public void CryptoProvider_IsSupportedAlgorithm_NonCompositeAlgorithm_ReturnsFalse()
    {
        // Arrange
        var provider = new CompositeMLDsaCryptoProvider();

        // Act & Assert
        Assert.False(provider.IsSupportedAlgorithm("RS256"));
        Assert.False(provider.IsSupportedAlgorithm("ES256"));
    }

    [Fact]
    public void CryptoProvider_IsSupportedAlgorithm_WrongKeyType_ReturnsFalse()
    {
        // Arrange
        var provider = new CompositeMLDsaCryptoProvider();
        using var rsa = RSA.Create();
        var rsaKey = new RsaSecurityKey(rsa);

        // Act & Assert
        Assert.False(provider.IsSupportedAlgorithm(CompositeMLDsaAlgorithms.MlDsa44Es256, rsaKey));
    }

    [Theory]
    [InlineData("ML-DSA-44-ES256")]
    [InlineData("ML-DSA-65-ES256")]
    [InlineData("ML-DSA-87-ES384")]
    public void CryptoProvider_Create_ReturnsSignatureProvider(string algorithm)
    {
        // Arrange
        var cryptoProvider = new CompositeMLDsaCryptoProvider();
        var dotNetAlg = CompositeMLDsaAlgorithms.GetCompositeMLDsaAlgorithm(algorithm);
        using var composite = CompositeMLDsa.GenerateKey(dotNetAlg);
        var key = new CompositeMLDsaSecurityKey(composite);

        // Act
        var result = cryptoProvider.Create(algorithm, key, true);

        // Assert
        Assert.IsType<CompositeMLDsaSignatureProvider>(result);
        cryptoProvider.Release(result);
    }

    #endregion

    #region JWK Serialization Tests

    [Theory]
    [InlineData("ML-DSA-44-ES256")]
    [InlineData("ML-DSA-65-ES256")]
    [InlineData("ML-DSA-87-ES384")]
    public void JwkSerializer_RoundTrip_PrivateKey(string algorithm)
    {
        // Arrange
        var dotNetAlg = CompositeMLDsaAlgorithms.GetCompositeMLDsaAlgorithm(algorithm);
        using var composite = CompositeMLDsa.GenerateKey(dotNetAlg);
        var originalKey = new CompositeMLDsaSecurityKey(composite);

        // Act
        JsonWebKey jwk = CompositeMLDsaJwkSerializer.ToJsonWebKey(originalKey);
        var restoredKey = CompositeMLDsaJwkSerializer.FromJsonWebKey(jwk);

        // Assert
        Assert.Equal(JsonWebAlgorithmsKeyTypes.Akp, jwk.Kty);
        Assert.Equal(algorithm, jwk.Alg);
        Assert.NotNull(jwk.Pub);
        Assert.NotNull(jwk.Priv);
        Assert.Equal(PrivateKeyStatus.Exists, restoredKey.PrivateKeyStatus);

        // Verify sign/verify round-trip with restored key
        byte[] data = Encoding.UTF8.GetBytes("JWK round-trip test");
        using var originalProvider = new CompositeMLDsaSignatureProvider(originalKey, algorithm, true);
        using var restoredProvider = new CompositeMLDsaSignatureProvider(restoredKey, algorithm, false);
        byte[] sig = originalProvider.Sign(data);
        Assert.True(restoredProvider.Verify(data, sig));
    }

    [Theory]
    [InlineData("ML-DSA-44-ES256")]
    public void JwkSerializer_RoundTrip_PublicKeyOnly(string algorithm)
    {
        // Arrange
        var dotNetAlg = CompositeMLDsaAlgorithms.GetCompositeMLDsaAlgorithm(algorithm);
        using var composite = CompositeMLDsa.GenerateKey(dotNetAlg);
        byte[] spki = composite.ExportSubjectPublicKeyInfo();
        using var publicOnly = CompositeMLDsa.ImportSubjectPublicKeyInfo(spki);
        var publicKey = new CompositeMLDsaSecurityKey(publicOnly);

        // Act
        JsonWebKey jwk = CompositeMLDsaJwkSerializer.ToJsonWebKey(publicKey);
        var restoredKey = CompositeMLDsaJwkSerializer.FromJsonWebKey(jwk);

        // Assert
        Assert.Equal(JsonWebAlgorithmsKeyTypes.Akp, jwk.Kty);
        Assert.NotNull(jwk.Pub);
        Assert.True(string.IsNullOrEmpty(jwk.Priv));
        Assert.Equal(PrivateKeyStatus.DoesNotExist, restoredKey.PrivateKeyStatus);
    }

    [Fact]
    public void JwkSerializer_FromJsonWebKey_WrongKty_ThrowsArgumentException()
    {
        // Arrange
        var jwk = new JsonWebKey { Kty = "RSA" };

        // Act & Assert
        Assert.Throws<ArgumentException>(() => CompositeMLDsaJwkSerializer.FromJsonWebKey(jwk));
    }

    [Fact]
    public void JwkSerializer_FromJsonWebKey_NoKeyMaterial_ThrowsArgumentException()
    {
        // Arrange
        var jwk = new JsonWebKey { Kty = JsonWebAlgorithmsKeyTypes.Akp };

        // Act & Assert
        Assert.Throws<ArgumentException>(() => CompositeMLDsaJwkSerializer.FromJsonWebKey(jwk));
    }

    [Fact]
    public void JwkSerializer_ToJsonWebKey_Null_ThrowsArgumentNullException()
    {
        Assert.Throws<ArgumentNullException>(() => CompositeMLDsaJwkSerializer.ToJsonWebKey(null!));
    }

    [Fact]
    public void JwkSerializer_FromJsonWebKey_Null_ThrowsArgumentNullException()
    {
        Assert.Throws<ArgumentNullException>(() => CompositeMLDsaJwkSerializer.FromJsonWebKey(null!));
    }

    [Theory]
    [InlineData("ML-DSA-44-ES256")]
    public void JwkSerializer_PreservesKeyId(string algorithm)
    {
        // Arrange
        var dotNetAlg = CompositeMLDsaAlgorithms.GetCompositeMLDsaAlgorithm(algorithm);
        using var composite = CompositeMLDsa.GenerateKey(dotNetAlg);
        var key = new CompositeMLDsaSecurityKey(composite) { KeyId = "test-key-id" };

        // Act
        JsonWebKey jwk = CompositeMLDsaJwkSerializer.ToJsonWebKey(key);
        var restoredKey = CompositeMLDsaJwkSerializer.FromJsonWebKey(jwk);

        // Assert
        Assert.Equal("test-key-id", jwk.Kid);
        Assert.Equal("test-key-id", restoredKey.KeyId);
    }

    #endregion

    #region Algorithm Constants Tests

    [Fact]
    public void Algorithms_IsCompositeAlgorithm_CorrectValues()
    {
        // Assert - Composite algorithms return true
        Assert.True(CompositeMLDsaAlgorithms.IsCompositeAlgorithm("ML-DSA-44-ES256"));
        Assert.True(CompositeMLDsaAlgorithms.IsCompositeAlgorithm("ML-DSA-65-ES256"));
        Assert.True(CompositeMLDsaAlgorithms.IsCompositeAlgorithm("ML-DSA-87-ES384"));
        Assert.True(CompositeMLDsaAlgorithms.IsCompositeAlgorithm("ML-DSA-44-Ed25519"));
        Assert.True(CompositeMLDsaAlgorithms.IsCompositeAlgorithm("ML-DSA-65-Ed25519"));
        Assert.True(CompositeMLDsaAlgorithms.IsCompositeAlgorithm("ML-DSA-87-Ed448"));

        // Assert - Non-composite algorithms return false
        Assert.False(CompositeMLDsaAlgorithms.IsCompositeAlgorithm("RS256"));
        Assert.False(CompositeMLDsaAlgorithms.IsCompositeAlgorithm("ES256"));
        Assert.False(CompositeMLDsaAlgorithms.IsCompositeAlgorithm("ML-DSA-44"));
    }

    [Theory]
    [InlineData("ML-DSA-44-ES256")]
    [InlineData("ML-DSA-65-ES256")]
    [InlineData("ML-DSA-87-ES384")]
    [InlineData("ML-DSA-44-Ed25519")]
    [InlineData("ML-DSA-65-Ed25519")]
    [InlineData("ML-DSA-87-Ed448")]
    public void Algorithms_GetCompositeMLDsaAlgorithm_RoundTrip(string joseAlgorithm)
    {
        // Act
        var dotNetAlg = CompositeMLDsaAlgorithms.GetCompositeMLDsaAlgorithm(joseAlgorithm);
        string result = CompositeMLDsaAlgorithms.GetJoseAlgorithm(dotNetAlg);

        // Assert
        Assert.Equal(joseAlgorithm, result);
    }

    [Fact]
    public void Algorithms_GetCompositeMLDsaAlgorithm_Unknown_ThrowsArgumentException()
    {
        Assert.Throws<ArgumentException>(() => CompositeMLDsaAlgorithms.GetCompositeMLDsaAlgorithm("UNKNOWN"));
    }

    #endregion

    #region End-to-End JWT Tests

    [Theory]
    [InlineData("ML-DSA-44-ES256")]
    [InlineData("ML-DSA-65-ES256")]
    [InlineData("ML-DSA-87-ES384")]
    public async Task JwtCreateAndValidate_EndToEnd(string algorithm)
    {
        // Arrange
        var dotNetAlg = CompositeMLDsaAlgorithms.GetCompositeMLDsaAlgorithm(algorithm);
        using var composite = CompositeMLDsa.GenerateKey(dotNetAlg);
        var key = new CompositeMLDsaSecurityKey(composite);

        var cryptoProvider = new CompositeMLDsaCryptoProvider();
        var factory = new CryptoProviderFactory
        {
            CustomCryptoProvider = cryptoProvider,
            CacheSignatureProviders = false,
        };
        key.CryptoProviderFactory = factory;

        // Build JWT manually because JsonWebTokenHandler.CreateToken on NET6+
        // pre-allocates the signature buffer via SupportedAlgorithms.GetMaxByteCount(),
        // which returns 0 for external composite algorithms.
        string header = $@"{{""alg"":""{algorithm}"",""typ"":""JWT""}}";
        string encodedHeader = Base64UrlEncoder.Encode(Encoding.UTF8.GetBytes(header));

        long now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        string payload = $@"{{""iss"":""test-issuer"",""aud"":""test-audience"",""sub"":""test-user"",""iat"":{now},""exp"":{now + 3600}}}";
        string encodedPayload = Base64UrlEncoder.Encode(Encoding.UTF8.GetBytes(payload));

        byte[] dataToSign = Encoding.ASCII.GetBytes($"{encodedHeader}.{encodedPayload}");
        using var signingProvider = new CompositeMLDsaSignatureProvider(key, algorithm, true);
        byte[] signature = signingProvider.Sign(dataToSign);
        string encodedSignature = Base64UrlEncoder.Encode(signature);

        string token = $"{encodedHeader}.{encodedPayload}.{encodedSignature}";

        // Sanity check: manual verification should succeed
        using var verifyProvider = new CompositeMLDsaSignatureProvider(key, algorithm, false);
        Assert.True(verifyProvider.Verify(dataToSign, signature), "Manual verification failed");

        // Act — validate through the standard handler path
        var handler = new JsonWebTokenHandler();
        var validationParameters = new TokenValidationParameters
        {
            ValidIssuer = "test-issuer",
            ValidAudience = "test-audience",
            IssuerSigningKey = key,
            CryptoProviderFactory = factory,
            TryAllIssuerSigningKeys = true,
        };

        var result = await handler.ValidateTokenAsync(token, validationParameters);

        // Assert
        Assert.True(result.IsValid, $"Token validation failed: {result.Exception?.Message}");
    }

    [Theory]
    [InlineData("ML-DSA-44-ES256")]
    public async Task JwtValidate_WrongKey_Fails(string algorithm)
    {
        // Arrange
        var dotNetAlg = CompositeMLDsaAlgorithms.GetCompositeMLDsaAlgorithm(algorithm);
        using var signingComposite = CompositeMLDsa.GenerateKey(dotNetAlg);
        using var differentComposite = CompositeMLDsa.GenerateKey(dotNetAlg);
        var signingKey = new CompositeMLDsaSecurityKey(signingComposite);
        var wrongKey = new CompositeMLDsaSecurityKey(differentComposite);

        var cryptoProvider = new CompositeMLDsaCryptoProvider();
        var factory = new CryptoProviderFactory
        {
            CustomCryptoProvider = cryptoProvider,
            CacheSignatureProviders = false,
        };

        // Sign with signingKey
        string header = $@"{{""alg"":""{algorithm}"",""typ"":""JWT""}}";
        string encodedHeader = Base64UrlEncoder.Encode(Encoding.UTF8.GetBytes(header));
        long now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        string payload = $@"{{""iss"":""test-issuer"",""aud"":""test-audience"",""exp"":{now + 3600}}}";
        string encodedPayload = Base64UrlEncoder.Encode(Encoding.UTF8.GetBytes(payload));

        byte[] dataToSign = Encoding.ASCII.GetBytes($"{encodedHeader}.{encodedPayload}");
        using var signingProvider = new CompositeMLDsaSignatureProvider(signingKey, algorithm, true);
        byte[] signature = signingProvider.Sign(dataToSign);
        string token = $"{encodedHeader}.{encodedPayload}.{Base64UrlEncoder.Encode(signature)}";

        // Validate with wrongKey
        var handler = new JsonWebTokenHandler();
        var validationParameters = new TokenValidationParameters
        {
            ValidIssuer = "test-issuer",
            ValidAudience = "test-audience",
            IssuerSigningKey = wrongKey,
            CryptoProviderFactory = factory,
        };

        var result = await handler.ValidateTokenAsync(token, validationParameters);

        // Assert
        Assert.False(result.IsValid);
    }

    #endregion
}
