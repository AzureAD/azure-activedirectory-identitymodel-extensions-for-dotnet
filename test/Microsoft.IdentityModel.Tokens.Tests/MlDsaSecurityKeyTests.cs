// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.TestUtils;
using Microsoft.IdentityModel.Tokens.Json;
using Xunit;

#pragma warning disable CS3016 // Arrays as attribute arguments is not CLS-compliant

namespace Microsoft.IdentityModel.Tokens.Tests
{
    public class MlDsaSecurityKeyTests
    {
        [Fact]
        public void Constructor_NullMlDsa_ThrowsArgumentNullException()
        {
            var ee = ExpectedException.ArgumentNullException("mlDsa");
            try
            {
                var key = new MlDsaSecurityKey(null);
                ee.ProcessNoException();
            }
            catch (Exception ex)
            {
                ee.ProcessException(ex);
            }
        }

        [Fact]
        public void Constructor_ValidMlDsa()
        {
            using var mlDsa = MLDsa.GenerateKey(MLDsaAlgorithm.MLDsa44);
            var key = new MlDsaSecurityKey(mlDsa);

            Assert.NotNull(key.MLDsa);
            Assert.True(key.KeySize > 0, "KeySize should be positive");
        }

        [Theory]
        [InlineData("ML-DSA-44")]
        [InlineData("ML-DSA-65")]
        [InlineData("ML-DSA-87")]
        public void KeySize_MatchesExpectedBits(string algorithm)
        {
            var mlDsaAlg = MlDsaAdapter.GetMLDsaAlgorithm(algorithm);
            using var mlDsa = MLDsa.GenerateKey(mlDsaAlg);
            var key = new MlDsaSecurityKey(mlDsa);

            int expectedBits = mlDsaAlg.PublicKeySizeInBytes * 8;
            Assert.Equal(expectedBits, key.KeySize);
        }

        [Fact]
        public void HasPrivateKey_WithPrivateKey_ReturnsTrue()
        {
            using var mlDsa = MLDsa.GenerateKey(MLDsaAlgorithm.MLDsa44);
            var key = new MlDsaSecurityKey(mlDsa);

#pragma warning disable CS0618 // Type or member is obsolete
            Assert.True(key.HasPrivateKey);
#pragma warning restore CS0618
            Assert.Equal(PrivateKeyStatus.Exists, key.PrivateKeyStatus);
        }

        [Fact]
        public void HasPrivateKey_WithPublicKeyOnly_ReturnsFalse()
        {
            using var privateKey = MLDsa.GenerateKey(MLDsaAlgorithm.MLDsa44);
            byte[] publicKeyBytes = privateKey.ExportMLDsaPublicKey();
            using var publicOnly = MLDsa.ImportMLDsaPublicKey(MLDsaAlgorithm.MLDsa44, publicKeyBytes);
            var key = new MlDsaSecurityKey(publicOnly);

#pragma warning disable CS0618 // Type or member is obsolete
            Assert.False(key.HasPrivateKey);
#pragma warning restore CS0618
            Assert.Equal(PrivateKeyStatus.DoesNotExist, key.PrivateKeyStatus);
        }

        [Fact]
        public void CanComputeJwkThumbprint_ReturnsTrue()
        {
            Assert.True(KeyingMaterial.MlDsa44Key.CanComputeJwkThumbprint());
            Assert.True(KeyingMaterial.MlDsa65Key.CanComputeJwkThumbprint());
            Assert.True(KeyingMaterial.MlDsa87Key.CanComputeJwkThumbprint());
        }

        [Fact]
        public void ComputeJwkThumbprint_IsDeterministic()
        {
            byte[] thumbprint1 = KeyingMaterial.MlDsa44Key.ComputeJwkThumbprint();
            byte[] thumbprint2 = KeyingMaterial.MlDsa44Key.ComputeJwkThumbprint();

            Assert.Equal(thumbprint1, thumbprint2);
        }

        [Fact]
        public void ComputeJwkThumbprint_PublicAndPrivateKeysMatch()
        {
            // A key's thumbprint should be the same whether computed from the private or public key
            // since thumbprint only uses public key material.
            byte[] privateThumbprint = KeyingMaterial.MlDsa44Key.ComputeJwkThumbprint();
            byte[] publicThumbprint = KeyingMaterial.MlDsa44Key_Public.ComputeJwkThumbprint();

            Assert.Equal(privateThumbprint, publicThumbprint);
        }

        [Fact]
        public void ComputeJwkThumbprint_DifferentKeysProduceDifferentThumbprints()
        {
            byte[] thumbprint44 = KeyingMaterial.MlDsa44Key.ComputeJwkThumbprint();
            byte[] thumbprint65 = KeyingMaterial.MlDsa65Key.ComputeJwkThumbprint();
            byte[] thumbprint87 = KeyingMaterial.MlDsa87Key.ComputeJwkThumbprint();

            Assert.NotEqual(thumbprint44, thumbprint65);
            Assert.NotEqual(thumbprint44, thumbprint87);
            Assert.NotEqual(thumbprint65, thumbprint87);
        }

        [Theory]
        [InlineData("ML-DSA-44")]
        [InlineData("ML-DSA-65")]
        [InlineData("ML-DSA-87")]
        public void ConstructFromJsonWebKey_RoundTrips(string algorithm)
        {
            // Create a key, convert to JWK, then create a new key from the JWK
            var mlDsaAlg = MlDsaAdapter.GetMLDsaAlgorithm(algorithm);
            using var originalMlDsa = MLDsa.GenerateKey(mlDsaAlg);
            var originalKey = new MlDsaSecurityKey(originalMlDsa);

            var jwk = JsonWebKeyConverter.ConvertFromMlDsaSecurityKey(originalKey);
            Assert.True(JsonWebKeyConverter.TryConvertToSecurityKey(jwk, out SecurityKey roundTrippedKey));

            var mlDsaKey = Assert.IsType<MlDsaSecurityKey>(roundTrippedKey);
            Assert.Equal(originalKey.KeySize, mlDsaKey.KeySize);
            Assert.Equal(PrivateKeyStatus.Exists, mlDsaKey.PrivateKeyStatus);

            // Verify the public keys match
            byte[] originalPub = originalMlDsa.ExportMLDsaPublicKey();
            byte[] roundTrippedPub = mlDsaKey.MLDsa.ExportMLDsaPublicKey();
            Assert.Equal(originalPub, roundTrippedPub);
        }

        [Theory]
        [InlineData("ML-DSA-44")]
        [InlineData("ML-DSA-65")]
        [InlineData("ML-DSA-87")]
        public void X509SecurityKey_MlDsa_KeySize(string algorithm)
        {
            var (x509Key, expectedAlg) = GetX509MlDsaKey(algorithm);
            Assert.Equal(expectedAlg.PublicKeySizeInBytes * 8, x509Key.KeySize);
        }

        [Theory]
        [InlineData("ML-DSA-44")]
        [InlineData("ML-DSA-65")]
        [InlineData("ML-DSA-87")]
        public void X509SecurityKey_MlDsa_CanComputeJwkThumbprint(string algorithm)
        {
            var (x509Key, _) = GetX509MlDsaKey(algorithm);

            Assert.True(x509Key.CanComputeJwkThumbprint());
            byte[] thumbprint = x509Key.ComputeJwkThumbprint();
            Assert.NotNull(thumbprint);
            Assert.True(thumbprint.Length > 0);
        }

        [Theory]
        [InlineData("ML-DSA-44")]
        [InlineData("ML-DSA-65")]
        [InlineData("ML-DSA-87")]
        public void X509SecurityKey_MlDsa_JwkThumbprint_IsDeterministic(string algorithm)
        {
            var (x509Key, _) = GetX509MlDsaKey(algorithm);

            byte[] thumbprint1 = x509Key.ComputeJwkThumbprint();
            byte[] thumbprint2 = x509Key.ComputeJwkThumbprint();
            Assert.Equal(thumbprint1, thumbprint2);
        }

        private static (X509SecurityKey key, MLDsaAlgorithm alg) GetX509MlDsaKey(string algorithm)
        {
            return algorithm switch
            {
                "ML-DSA-44" => (KeyingMaterial.X509MlDsa44Key, MLDsaAlgorithm.MLDsa44),
                "ML-DSA-65" => (KeyingMaterial.X509MlDsa65Key, MLDsaAlgorithm.MLDsa65),
                "ML-DSA-87" => (KeyingMaterial.X509MlDsa87Key, MLDsaAlgorithm.MLDsa87),
                _ => throw new ArgumentException(algorithm)
            };
        }

        #region JWK Negative Tests

        [Fact]
        public void JwkMissingAlg_FailsConversion()
        {
            var jwk = new JsonWebKey
            {
                Kty = JsonWebAlgorithmsKeyTypes.Akp,
                Pub = Base64UrlEncoder.Encode(new byte[1312]) // dummy public key
            };

            Assert.False(JsonWebKeyConverter.TryConvertToSecurityKey(jwk, out _));
        }

        [Fact]
        public void JwkMissingPub_ThrowsOnConstruction()
        {
            var jwk = new JsonWebKey
            {
                Kty = JsonWebAlgorithmsKeyTypes.Akp,
                Alg = SecurityAlgorithms.MlDsa44
            };

            Assert.Throws<ArgumentException>(() => new MlDsaSecurityKey(jwk, false));
        }

        [Fact]
        public void JwkInvalidAlg_FailsConversion()
        {
            var jwk = new JsonWebKey
            {
                Kty = JsonWebAlgorithmsKeyTypes.Akp,
                Alg = "UNSUPPORTED-ALG",
                Pub = Base64UrlEncoder.Encode(new byte[1312])
            };

            Assert.False(JsonWebKeyConverter.TryConvertToSecurityKey(jwk, out _));
        }

        #endregion

        #region Algorithm Mismatch Tests

        [Fact]
        public void SignWithMismatchedAlgorithm_FailsKeySizeValidation()
        {
            // ML-DSA-44 key (10496 bits) is too small for ML-DSA-65 (requires 15616 bits)
            // Key size validation is opt-in via ValidKeySize() — same pattern as RSA/ECDSA tests
            var provider = new AsymmetricSignatureProvider(
                KeyingMaterial.MlDsa44Key,
                SecurityAlgorithms.MlDsa65,
                false);

            Assert.Throws<ArgumentOutOfRangeException>(() => provider.ValidKeySize());
        }

        #endregion

        #region Public-Key-Only Signing Tests

        [Fact]
        public void SignWithPublicKeyOnly_Throws()
        {
            // Creating a signing provider with a public-only key should fail at construction
            using var privateKey = MLDsa.GenerateKey(MLDsaAlgorithm.MLDsa44);
            byte[] publicKeyBytes = privateKey.ExportMLDsaPublicKey();
            using var publicOnly = MLDsa.ImportMLDsaPublicKey(MLDsaAlgorithm.MLDsa44, publicKeyBytes);
            var publicOnlyKey = new MlDsaSecurityKey(publicOnly);

            Assert.Throws<InvalidOperationException>(() =>
                new AsymmetricSignatureProvider(publicOnlyKey, SecurityAlgorithms.MlDsa44, true));
        }

        [Fact]
        public void VerifyWithPublicKeyOnly_Succeeds()
        {
            // Verifying should work with a public-only key
            byte[] data = new byte[] { 1, 2, 3, 4, 5, 6, 7, 8 };
            var signingProvider = new AsymmetricSignatureProvider(KeyingMaterial.MlDsa44Key, SecurityAlgorithms.MlDsa44, true);
            byte[] signature = signingProvider.Sign(data);

            var verifyProvider = new AsymmetricSignatureProvider(KeyingMaterial.MlDsa44Key_Public, SecurityAlgorithms.MlDsa44, false);
            Assert.True(verifyProvider.Verify(data, signature));
        }

        #endregion

        #region Signature Correctness Tests

        [Theory]
        [InlineData("ML-DSA-44")]
        [InlineData("ML-DSA-65")]
        [InlineData("ML-DSA-87")]
        public void TamperedSignature_FailsVerification(string algorithm)
        {
            byte[] data = new byte[] { 1, 2, 3, 4, 5, 6, 7, 8 };
            var key = GetMlDsaKey(algorithm);
            var signingProvider = new AsymmetricSignatureProvider(key, algorithm, true);
            byte[] signature = signingProvider.Sign(data);

            // Tamper with one byte of the signature
            signature[0] ^= 0xFF;

            var verifyProvider = new AsymmetricSignatureProvider(GetMlDsaPublicKey(algorithm), algorithm, false);
            Assert.False(verifyProvider.Verify(data, signature));
        }

        [Fact]
        public void CrossKeyVerification_Fails()
        {
            // Signature from MlDsa44 key should not verify with a different MlDsa44 key
            byte[] data = new byte[] { 10, 20, 30, 40 };
            var signingProvider = new AsymmetricSignatureProvider(KeyingMaterial.MlDsa44Key, SecurityAlgorithms.MlDsa44, true);
            byte[] signature = signingProvider.Sign(data);

            // Create a completely different key pair
            using var differentMlDsa = MLDsa.GenerateKey(MLDsaAlgorithm.MLDsa44);
            var differentKey = new MlDsaSecurityKey(differentMlDsa);
            var verifyProvider = new AsymmetricSignatureProvider(differentKey, SecurityAlgorithms.MlDsa44, false);
            Assert.False(verifyProvider.Verify(data, signature));
        }

        #endregion

        #region JWK JSON Serialization Round-Trip

        [Theory]
        [InlineData("ML-DSA-44")]
        [InlineData("ML-DSA-65")]
        [InlineData("ML-DSA-87")]
        public void JwkJsonSerialization_RoundTrips(string algorithm)
        {
            var mlDsaAlg = MlDsaAdapter.GetMLDsaAlgorithm(algorithm);
            using var mlDsa = MLDsa.GenerateKey(mlDsaAlg);
            var key = new MlDsaSecurityKey(mlDsa);

            // Convert to JWK
            var originalJwk = JsonWebKeyConverter.ConvertFromMlDsaSecurityKey(key);

            // Serialize to JSON using the custom serializer
            string json = JsonWebKeySerializer.Write(originalJwk);

            // Deserialize back
            var parsedJwk = new JsonWebKey(json);

            // Verify all key properties survived
            Assert.Equal(JsonWebAlgorithmsKeyTypes.Akp, parsedJwk.Kty);
            Assert.Equal(algorithm, parsedJwk.Alg);
            Assert.Equal(originalJwk.Pub, parsedJwk.Pub);
            Assert.Equal(originalJwk.Priv, parsedJwk.Priv);
            Assert.True(parsedJwk.HasPrivateKey);

            // Verify the parsed JWK can create a working key
            Assert.True(JsonWebKeyConverter.TryConvertToSecurityKey(parsedJwk, out SecurityKey roundTrippedKey));
            var mlDsaKey = Assert.IsType<MlDsaSecurityKey>(roundTrippedKey);
            Assert.Equal(key.KeySize, mlDsaKey.KeySize);
        }

        [Theory]
        [InlineData("ML-DSA-44")]
        [InlineData("ML-DSA-65")]
        [InlineData("ML-DSA-87")]
        public void JwkJsonSerialization_PublicKeyOnly_RoundTrips(string algorithm)
        {
            var mlDsaAlg = MlDsaAdapter.GetMLDsaAlgorithm(algorithm);
            using var mlDsa = MLDsa.GenerateKey(mlDsaAlg);
            byte[] publicKeyBytes = mlDsa.ExportMLDsaPublicKey();
            using var publicOnly = MLDsa.ImportMLDsaPublicKey(mlDsaAlg, publicKeyBytes);
            var key = new MlDsaSecurityKey(publicOnly);

            var originalJwk = JsonWebKeyConverter.ConvertFromMlDsaSecurityKey(key);
            string json = JsonWebKeySerializer.Write(originalJwk);
            var parsedJwk = new JsonWebKey(json);

            Assert.Equal(JsonWebAlgorithmsKeyTypes.Akp, parsedJwk.Kty);
            Assert.Equal(algorithm, parsedJwk.Alg);
            Assert.Equal(originalJwk.Pub, parsedJwk.Pub);
            Assert.Null(parsedJwk.Priv);
            Assert.False(parsedJwk.HasPrivateKey);
        }

        #endregion

        #region End-to-End JWT Tests

        [Theory]
        [InlineData("ML-DSA-44")]
        [InlineData("ML-DSA-65")]
        [InlineData("ML-DSA-87")]
        public async System.Threading.Tasks.Task JwtCreateAndValidate_EndToEnd(string algorithm)
        {
            var signingKey = GetMlDsaKey(algorithm);
            var verifyKey = GetMlDsaPublicKey(algorithm);

            var handler = new JsonWebTokenHandler();
            var descriptor = new SecurityTokenDescriptor
            {
                Issuer = "https://test-issuer.example.com",
                Audience = "https://test-audience.example.com",
                SigningCredentials = new SigningCredentials(signingKey, algorithm),
                Claims = new System.Collections.Generic.Dictionary<string, object>
                {
                    { "sub", "test-user" },
                    { "name", "Test User" }
                }
            };

            string token = handler.CreateToken(descriptor);
            Assert.False(string.IsNullOrEmpty(token));

            // Validate
            var validationParams = new TokenValidationParameters
            {
                ValidIssuer = "https://test-issuer.example.com",
                ValidAudience = "https://test-audience.example.com",
                IssuerSigningKey = verifyKey,
                ValidateLifetime = false
            };

            var result = await handler.ValidateTokenAsync(token, validationParams);
            Assert.True(result.IsValid, $"Token validation failed: {result.Exception?.Message}");
            Assert.Equal("test-user", result.Claims["sub"]);
        }

        [Theory]
        [InlineData("ML-DSA-44")]
        [InlineData("ML-DSA-65")]
        [InlineData("ML-DSA-87")]
        public async System.Threading.Tasks.Task JwtCreateAndValidate_WithJsonWebKey(string algorithm)
        {
            var signingJwk = GetMlDsaJsonWebKey(algorithm);
            var verifyJwk = GetMlDsaJsonWebKeyPublic(algorithm);

            var handler = new JsonWebTokenHandler();
            var descriptor = new SecurityTokenDescriptor
            {
                Issuer = "https://test-issuer.example.com",
                Audience = "https://test-audience.example.com",
                SigningCredentials = new SigningCredentials(signingJwk, algorithm),
                Claims = new System.Collections.Generic.Dictionary<string, object>
                {
                    { "sub", "jwk-test-user" }
                }
            };

            string token = handler.CreateToken(descriptor);
            Assert.False(string.IsNullOrEmpty(token));

            var validationParams = new TokenValidationParameters
            {
                ValidIssuer = "https://test-issuer.example.com",
                ValidAudience = "https://test-audience.example.com",
                IssuerSigningKey = verifyJwk,
                ValidateLifetime = false
            };

            var result = await handler.ValidateTokenAsync(token, validationParams);
            Assert.True(result.IsValid, $"Token validation failed: {result.Exception?.Message}");
        }

        #endregion

        #region X509 ML-DSA End-to-End JWT Tests

        // GetMLDsaPrivateKey() throws PlatformNotSupportedException on .NET 6.
        private static bool CanExtractMlDsaPrivateKeyFromX509()
        {
            try
            {
#pragma warning disable SYSLIB5006
                using var key = KeyingMaterial.MlDsa44Cert.GetMLDsaPrivateKey();
#pragma warning restore SYSLIB5006
                return key != null;
            }
            catch (PlatformNotSupportedException)
            {
                return false;
            }
        }

        [Theory]
        [InlineData("ML-DSA-44")]
        [InlineData("ML-DSA-65")]
        [InlineData("ML-DSA-87")]
        public async System.Threading.Tasks.Task JwtCreateAndValidate_WithX509SecurityKey(string algorithm)
        {
            if (!CanExtractMlDsaPrivateKeyFromX509())
                return; // skip on platforms that can't extract ML-DSA private keys from X509

            var (x509Key, _) = GetX509MlDsaKey(algorithm);

            var handler = new JsonWebTokenHandler();
            var descriptor = new SecurityTokenDescriptor
            {
                Issuer = "https://test-issuer.example.com",
                Audience = "https://test-audience.example.com",
                SigningCredentials = new SigningCredentials(x509Key, algorithm),
                Claims = new System.Collections.Generic.Dictionary<string, object>
                {
                    { "sub", "x509-test-user" }
                }
            };

            string token = handler.CreateToken(descriptor);
            Assert.False(string.IsNullOrEmpty(token));

            // Validate using the same X509 key (public key only path)
            var validationParams = new TokenValidationParameters
            {
                ValidIssuer = "https://test-issuer.example.com",
                ValidAudience = "https://test-audience.example.com",
                IssuerSigningKey = x509Key,
                ValidateLifetime = false
            };

            var result = await handler.ValidateTokenAsync(token, validationParams);
            Assert.True(result.IsValid, $"Token validation failed: {result.Exception?.Message}");
            Assert.Equal("x509-test-user", result.Claims["sub"]);
        }

        [Theory]
        [InlineData("ML-DSA-44")]
        [InlineData("ML-DSA-65")]
        [InlineData("ML-DSA-87")]
        public async System.Threading.Tasks.Task JwtCreateWithX509_ValidateWithMlDsaKey(string algorithm)
        {
            if (!CanExtractMlDsaPrivateKeyFromX509())
                return; // skip on platforms that can't extract ML-DSA private keys from X509

            var (x509Key, _) = GetX509MlDsaKey(algorithm);

            var handler = new JsonWebTokenHandler();
            var descriptor = new SecurityTokenDescriptor
            {
                Issuer = "https://test-issuer.example.com",
                Audience = "https://test-audience.example.com",
                SigningCredentials = new SigningCredentials(x509Key, algorithm),
                Claims = new System.Collections.Generic.Dictionary<string, object>
                {
                    { "sub", "cross-key-user" }
                }
            };

            string token = handler.CreateToken(descriptor);

            // Validate using an MlDsaSecurityKey created from the X509 certificate's public key
#pragma warning disable SYSLIB5006
            using var mlDsaPub = x509Key.Certificate.GetMLDsaPublicKey();
#pragma warning restore SYSLIB5006
            var mlDsaKey = new MlDsaSecurityKey(mlDsaPub);

            var validationParams = new TokenValidationParameters
            {
                ValidIssuer = "https://test-issuer.example.com",
                ValidAudience = "https://test-audience.example.com",
                IssuerSigningKey = mlDsaKey,
                ValidateLifetime = false
            };

            var result = await handler.ValidateTokenAsync(token, validationParams);
            Assert.True(result.IsValid, $"Token validation failed: {result.Exception?.Message}");
            Assert.Equal("cross-key-user", result.Claims["sub"]);
        }

        #endregion

        #region Helpers

        private static MlDsaSecurityKey GetMlDsaKey(string algorithm) => algorithm switch
        {
            "ML-DSA-44" => KeyingMaterial.MlDsa44Key,
            "ML-DSA-65" => KeyingMaterial.MlDsa65Key,
            "ML-DSA-87" => KeyingMaterial.MlDsa87Key,
            _ => throw new ArgumentException(algorithm)
        };

        private static MlDsaSecurityKey GetMlDsaPublicKey(string algorithm) => algorithm switch
        {
            "ML-DSA-44" => KeyingMaterial.MlDsa44Key_Public,
            "ML-DSA-65" => KeyingMaterial.MlDsa65Key_Public,
            "ML-DSA-87" => KeyingMaterial.MlDsa87Key_Public,
            _ => throw new ArgumentException(algorithm)
        };

        private static JsonWebKey GetMlDsaJsonWebKey(string algorithm) => algorithm switch
        {
            "ML-DSA-44" => KeyingMaterial.JsonWebKeyMlDsa44,
            "ML-DSA-65" => KeyingMaterial.JsonWebKeyMlDsa65,
            "ML-DSA-87" => KeyingMaterial.JsonWebKeyMlDsa87,
            _ => throw new ArgumentException(algorithm)
        };

        private static JsonWebKey GetMlDsaJsonWebKeyPublic(string algorithm) => algorithm switch
        {
            "ML-DSA-44" => KeyingMaterial.JsonWebKeyMlDsa44_Public,
            "ML-DSA-65" => KeyingMaterial.JsonWebKeyMlDsa65_Public,
            "ML-DSA-87" => KeyingMaterial.JsonWebKeyMlDsa87_Public,
            _ => throw new ArgumentException(algorithm)
        };

        #endregion
    }
}

#pragma warning restore CS3016 // Arrays as attribute arguments is not CLS-compliant
