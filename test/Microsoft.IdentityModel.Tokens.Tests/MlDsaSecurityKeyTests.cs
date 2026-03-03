// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System;
using System.Security.Cryptography;
using Microsoft.IdentityModel.TestUtils;
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

#if NET10_0_OR_GREATER
        [Fact]
        public void X509SecurityKey_MlDsa44_Properties()
        {
            var x509Key = KeyingMaterial.X509MlDsa44Key;
            Assert.Equal(MLDsaAlgorithm.MLDsa44.PublicKeySizeInBytes * 8, x509Key.KeySize);
#pragma warning disable CS0618
            Assert.True(x509Key.HasPrivateKey);
#pragma warning restore CS0618
            Assert.Equal(PrivateKeyStatus.Exists, x509Key.PrivateKeyStatus);
        }

        [Fact]
        public void X509SecurityKey_MlDsa65_Properties()
        {
            var x509Key = KeyingMaterial.X509MlDsa65Key;
            Assert.Equal(MLDsaAlgorithm.MLDsa65.PublicKeySizeInBytes * 8, x509Key.KeySize);
#pragma warning disable CS0618
            Assert.True(x509Key.HasPrivateKey);
#pragma warning restore CS0618
            Assert.Equal(PrivateKeyStatus.Exists, x509Key.PrivateKeyStatus);
        }

        [Fact]
        public void X509SecurityKey_MlDsa87_Properties()
        {
            var x509Key = KeyingMaterial.X509MlDsa87Key;
            Assert.Equal(MLDsaAlgorithm.MLDsa87.PublicKeySizeInBytes * 8, x509Key.KeySize);
#pragma warning disable CS0618
            Assert.True(x509Key.HasPrivateKey);
#pragma warning restore CS0618
            Assert.Equal(PrivateKeyStatus.Exists, x509Key.PrivateKeyStatus);
        }

        [Theory]
        [InlineData("ML-DSA-44")]
        [InlineData("ML-DSA-65")]
        [InlineData("ML-DSA-87")]
        public void X509SecurityKey_MlDsa_CanComputeJwkThumbprint(string algorithm)
        {
            var x509Key = algorithm switch
            {
                "ML-DSA-44" => KeyingMaterial.X509MlDsa44Key,
                "ML-DSA-65" => KeyingMaterial.X509MlDsa65Key,
                "ML-DSA-87" => KeyingMaterial.X509MlDsa87Key,
                _ => throw new ArgumentException(algorithm)
            };

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
            var x509Key = algorithm switch
            {
                "ML-DSA-44" => KeyingMaterial.X509MlDsa44Key,
                "ML-DSA-65" => KeyingMaterial.X509MlDsa65Key,
                "ML-DSA-87" => KeyingMaterial.X509MlDsa87Key,
                _ => throw new ArgumentException(algorithm)
            };

            byte[] thumbprint1 = x509Key.ComputeJwkThumbprint();
            byte[] thumbprint2 = x509Key.ComputeJwkThumbprint();
            Assert.Equal(thumbprint1, thumbprint2);
        }
#endif
    }
}

#pragma warning restore CS3016 // Arrays as attribute arguments is not CLS-compliant
