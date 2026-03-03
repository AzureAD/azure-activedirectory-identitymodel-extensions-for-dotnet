// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma warning disable SYSLIB5006 // ML-DSA types are experimental

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
    }
}

#pragma warning restore CS3016 // Arrays as attribute arguments is not CLS-compliant
