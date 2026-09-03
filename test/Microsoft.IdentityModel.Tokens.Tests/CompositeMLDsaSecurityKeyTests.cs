// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.TestUtils;
using Microsoft.IdentityModel.Tokens;
using Xunit;

#pragma warning disable CS3016 // Arrays as attribute arguments is not CLS-compliant
#pragma warning disable SYSLIB5006 // CompositeMLDsa is experimental

namespace Microsoft.IdentityModel.Tokens.Tests
{
    [CollectionDefinition(nameof(CompositeMLDsaSecurityKeyTests), DisableParallelization = true)]
    public class CompositeMLDsaSecurityKeyTestCollection
    {
    }

    [Collection(nameof(CompositeMLDsaSecurityKeyTests))]
    public class CompositeMLDsaSecurityKeyTests : IDisposable
    {
        public CompositeMLDsaSecurityKeyTests()
        {
            AppContext.SetSwitch(AppContextSwitches.EnableCompositeMLDsaDraftSwitch, true);
        }

        public void Dispose()
        {
            AppContextSwitches.ResetAllSwitches();
        }

        private static readonly string[] _allAlgorithms = new[]
        {
            SecurityAlgorithms.MlDsa44WithECDsaP256,
            SecurityAlgorithms.MlDsa65WithECDsaP256,
            SecurityAlgorithms.MlDsa87WithECDsaP384
        };

        #region Constructor Tests

        [CompositeMLDsaFact(SecurityAlgorithms.MlDsa44WithECDsaP256)]
        public void Constructor_NullCompositeMLDsa_ThrowsArgumentNullException()
        {
            var ee = ExpectedException.ArgumentNullException("compositeMLDsa");
            try
            {
                var key = new CompositeMLDsaSecurityKey((CompositeMLDsa)null);
                ee.ProcessNoException();
            }
            catch (Exception ex)
            {
                ee.ProcessException(ex);
            }
        }

        [CompositeMLDsaFact(SecurityAlgorithms.MlDsa44WithECDsaP256)]
        public void Constructor_ValidCompositeMLDsa_Succeeds()
        {
            using var composite = CompositeMLDsa.GenerateKey(CompositeMLDsaAlgorithm.MLDsa44WithECDsaP256);
            var key = new CompositeMLDsaSecurityKey(composite);

            Assert.NotNull(key.CompositeMLDsa);
            Assert.True(key.KeySize > 0);
        }

        #endregion

        #region KeySize Tests

        [CompositeMLDsaTheory(SecurityAlgorithms.MlDsa44WithECDsaP256)]
        [InlineData(SecurityAlgorithms.MlDsa44WithECDsaP256, 1377 * 8)]
        [InlineData(SecurityAlgorithms.MlDsa65WithECDsaP256, 2017 * 8)]
        [InlineData(SecurityAlgorithms.MlDsa87WithECDsaP384, 2689 * 8)]
        public void KeySize_MatchesExpectedBits(string algorithm, int expectedBits)
        {
            if (!CompositeMLDsaKeyingMaterial.IsAlgorithmSupported(algorithm)) return;
            var key = CompositeMLDsaKeyingMaterial.GetPrivateKey(algorithm);
            Assert.Equal(expectedBits, key.KeySize);
        }

        #endregion

        #region PrivateKeyStatus Tests

        [CompositeMLDsaFact(SecurityAlgorithms.MlDsa44WithECDsaP256)]
        public void PrivateKeyStatus_WithPrivateKey_ReturnsExists()
        {
            var key = CompositeMLDsaKeyingMaterial.CompositeMLDsa44ES256Key;
#pragma warning disable CS0618
            Assert.True(key.HasPrivateKey);
#pragma warning restore CS0618
            Assert.Equal(PrivateKeyStatus.Exists, key.PrivateKeyStatus);
        }

        [CompositeMLDsaFact(SecurityAlgorithms.MlDsa44WithECDsaP256)]
        public void PrivateKeyStatus_PublicKeyOnly_ReturnsDoesNotExist()
        {
            var key = CompositeMLDsaKeyingMaterial.CompositeMLDsa44ES256Key_Public;
#pragma warning disable CS0618
            Assert.False(key.HasPrivateKey);
#pragma warning restore CS0618
            Assert.Equal(PrivateKeyStatus.DoesNotExist, key.PrivateKeyStatus);
        }

        #endregion

        #region JWK Thumbprint Tests

        [CompositeMLDsaFact(SecurityAlgorithms.MlDsa44WithECDsaP256)]
        public void CanComputeJwkThumbprint_ReturnsTrue()
        {
            foreach (var alg in _allAlgorithms)
            {
                if (!CompositeMLDsaKeyingMaterial.IsAlgorithmSupported(alg)) continue;
                Assert.True(CompositeMLDsaKeyingMaterial.GetPrivateKey(alg).CanComputeJwkThumbprint());
            }
        }

        [CompositeMLDsaFact(SecurityAlgorithms.MlDsa44WithECDsaP256)]
        public void ComputeJwkThumbprint_IsDeterministic()
        {
            var key = CompositeMLDsaKeyingMaterial.CompositeMLDsa44ES256Key;
            byte[] t1 = key.ComputeJwkThumbprint();
            byte[] t2 = key.ComputeJwkThumbprint();
            Assert.Equal(t1, t2);
        }

        [CompositeMLDsaFact(SecurityAlgorithms.MlDsa44WithECDsaP256)]
        public void ComputeJwkThumbprint_PrivateAndPublicMatch()
        {
            byte[] privThumb = CompositeMLDsaKeyingMaterial.CompositeMLDsa44ES256Key.ComputeJwkThumbprint();
            byte[] pubThumb = CompositeMLDsaKeyingMaterial.CompositeMLDsa44ES256Key_Public.ComputeJwkThumbprint();
            Assert.Equal(privThumb, pubThumb);
        }

        [CompositeMLDsaFact(SecurityAlgorithms.MlDsa44WithECDsaP256)]
        public void ComputeJwkThumbprint_DifferentAlgorithmsDiffer()
        {
            if (!CompositeMLDsaKeyingMaterial.IsAlgorithmSupported(SecurityAlgorithms.MlDsa65WithECDsaP256)) return;

            byte[] t44 = CompositeMLDsaKeyingMaterial.CompositeMLDsa44ES256Key.ComputeJwkThumbprint();
            byte[] t65 = CompositeMLDsaKeyingMaterial.CompositeMLDsa65ES256Key.ComputeJwkThumbprint();
            Assert.NotEqual(t44, t65);
        }

        #endregion

        #region JWK Round-Trip Tests

        [CompositeMLDsaTheory(SecurityAlgorithms.MlDsa44WithECDsaP256)]
        [InlineData(SecurityAlgorithms.MlDsa44WithECDsaP256)]
        [InlineData(SecurityAlgorithms.MlDsa65WithECDsaP256)]
        [InlineData(SecurityAlgorithms.MlDsa87WithECDsaP384)]
        public void JwkRoundTrip_PrivateKey(string algorithm)
        {
            if (!CompositeMLDsaKeyingMaterial.IsAlgorithmSupported(algorithm)) return;

            var originalKey = CompositeMLDsaKeyingMaterial.GetPrivateKey(algorithm);
            var jwk = JsonWebKeyConverter.ConvertFromCompositeMLDsaSecurityKey(originalKey);

            Assert.Equal(JsonWebAlgorithmsKeyTypes.Akp, jwk.Kty);
            Assert.Equal(algorithm, jwk.Alg);
            Assert.NotNull(jwk.Pub);
            Assert.NotNull(jwk.Priv);
            Assert.True(jwk.HasPrivateKey);

            Assert.True(JsonWebKeyConverter.TryConvertToSecurityKey(jwk, out SecurityKey roundTripped));
            var compositeKey = Assert.IsType<CompositeMLDsaSecurityKey>(roundTripped);

            Assert.Equal(PrivateKeyStatus.Exists, compositeKey.PrivateKeyStatus);
            Assert.Equal(originalKey.KeySize, compositeKey.KeySize);

            // Verify public keys match
            byte[] origPub = originalKey.CompositeMLDsa.ExportCompositeMLDsaPublicKey();
            byte[] rtPub = compositeKey.CompositeMLDsa.ExportCompositeMLDsaPublicKey();
            Assert.Equal(origPub, rtPub);
        }

        [CompositeMLDsaTheory(SecurityAlgorithms.MlDsa44WithECDsaP256)]
        [InlineData(SecurityAlgorithms.MlDsa44WithECDsaP256)]
        [InlineData(SecurityAlgorithms.MlDsa65WithECDsaP256)]
        [InlineData(SecurityAlgorithms.MlDsa87WithECDsaP384)]
        public void JwkRoundTrip_PublicKey(string algorithm)
        {
            if (!CompositeMLDsaKeyingMaterial.IsAlgorithmSupported(algorithm)) return;

            var originalKey = CompositeMLDsaKeyingMaterial.GetPublicKey(algorithm);
            var jwk = JsonWebKeyConverter.ConvertFromCompositeMLDsaSecurityKey(originalKey);

            Assert.Equal(JsonWebAlgorithmsKeyTypes.Akp, jwk.Kty);
            Assert.Equal(algorithm, jwk.Alg);
            Assert.NotNull(jwk.Pub);
            Assert.Null(jwk.Priv);

            Assert.True(JsonWebKeyConverter.TryConvertToSecurityKey(jwk, out SecurityKey roundTripped));
            var compositeKey = Assert.IsType<CompositeMLDsaSecurityKey>(roundTripped);
            Assert.Equal(PrivateKeyStatus.DoesNotExist, compositeKey.PrivateKeyStatus);
        }

        #endregion

        #region JWK Negative Tests

        [CompositeMLDsaFact(SecurityAlgorithms.MlDsa44WithECDsaP256)]
        public void JwkMissingPub_ThrowsOnConstruction()
        {
            var jwk = new JsonWebKey
            {
                Kty = JsonWebAlgorithmsKeyTypes.Akp,
                Alg = SecurityAlgorithms.MlDsa44WithECDsaP256
            };

            Assert.Throws<ArgumentException>(() => new CompositeMLDsaSecurityKey(jwk, false));
        }

        [CompositeMLDsaFact(SecurityAlgorithms.MlDsa44WithECDsaP256)]
        public void JwkWithMismatchedPubPriv_FailsConversion()
        {
            using var keyA = CompositeMLDsa.GenerateKey(CompositeMLDsaAlgorithm.MLDsa44WithECDsaP256);
            using var keyB = CompositeMLDsa.GenerateKey(CompositeMLDsaAlgorithm.MLDsa44WithECDsaP256);

            byte[] privA = keyA.ExportCompositeMLDsaPrivateKey();
            byte[] pubB = keyB.ExportCompositeMLDsaPublicKey();

            var jwk = new JsonWebKey
            {
                Kty = JsonWebAlgorithmsKeyTypes.Akp,
                Alg = SecurityAlgorithms.MlDsa44WithECDsaP256,
                Pub = Base64UrlEncoder.Encode(pubB),
                Priv = Base64UrlEncoder.Encode(privA)
            };

            CryptographicOperations.ZeroMemory(privA);

            Assert.False(JsonWebKeyConverter.TryConvertToSecurityKey(jwk, out _));
        }

        #endregion

        #region End-to-End JWT Tests

        [CompositeMLDsaTheory(SecurityAlgorithms.MlDsa44WithECDsaP256)]
        [InlineData(SecurityAlgorithms.MlDsa44WithECDsaP256)]
        [InlineData(SecurityAlgorithms.MlDsa65WithECDsaP256)]
        [InlineData(SecurityAlgorithms.MlDsa87WithECDsaP384)]
        public void JsonWebTokenHandler_SignVerify_RoundTrip(string algorithm)
        {
            if (!CompositeMLDsaKeyingMaterial.IsAlgorithmSupported(algorithm)) return;

            var signingKey = CompositeMLDsaKeyingMaterial.GetPrivateKey(algorithm);
            var verifyKey = CompositeMLDsaKeyingMaterial.GetPublicKey(algorithm);

            var handler = new JsonWebTokenHandler();
            var token = handler.CreateToken(new SecurityTokenDescriptor
            {
                Subject = new CaseSensitiveClaimsIdentity(new[] { new Claim("sub", "test") }),
                SigningCredentials = new SigningCredentials(signingKey, algorithm)
            });

            var result = handler.ValidateToken(token, new TokenValidationParameters
            {
                ValidateAudience = false,
                ValidateIssuer = false,
                ValidateLifetime = false,
                IssuerSigningKey = verifyKey
            });

            Assert.True(result.IsValid, $"Token validation failed: {result.Exception?.Message}");
        }

        [CompositeMLDsaTheory(SecurityAlgorithms.MlDsa44WithECDsaP256)]
        [InlineData(SecurityAlgorithms.MlDsa44WithECDsaP256)]
        [InlineData(SecurityAlgorithms.MlDsa65WithECDsaP256)]
        [InlineData(SecurityAlgorithms.MlDsa87WithECDsaP384)]
        public void JwtSecurityTokenHandler_SignVerify_RoundTrip(string algorithm)
        {
            if (!CompositeMLDsaKeyingMaterial.IsAlgorithmSupported(algorithm)) return;

            var signingKey = CompositeMLDsaKeyingMaterial.GetPrivateKey(algorithm);
            var verifyKey = CompositeMLDsaKeyingMaterial.GetPublicKey(algorithm);

            var handler = new JwtSecurityTokenHandler();
            var token = handler.CreateEncodedJwt(new SecurityTokenDescriptor
            {
                Subject = new CaseSensitiveClaimsIdentity(new[] { new Claim("sub", "test") }),
                SigningCredentials = new SigningCredentials(signingKey, algorithm)
            });

            var principal = handler.ValidateToken(token, new TokenValidationParameters
            {
                ValidateAudience = false,
                ValidateIssuer = false,
                ValidateLifetime = false,
                IssuerSigningKey = verifyKey
            }, out _);

            Assert.NotNull(principal);
        }

        [CompositeMLDsaTheory(SecurityAlgorithms.MlDsa44WithECDsaP256)]
        [InlineData(SecurityAlgorithms.MlDsa44WithECDsaP256, SecurityAlgorithms.MlDsa65WithECDsaP256)]
        [InlineData(SecurityAlgorithms.MlDsa44WithECDsaP256, SecurityAlgorithms.MlDsa87WithECDsaP384)]
        public void Verify_WithWrongKey_Fails(string signingAlgorithm, string wrongAlgorithm)
        {
            if (!CompositeMLDsaKeyingMaterial.IsAlgorithmSupported(signingAlgorithm)) return;
            if (!CompositeMLDsaKeyingMaterial.IsAlgorithmSupported(wrongAlgorithm)) return;

            var signingKey = CompositeMLDsaKeyingMaterial.GetPrivateKey(signingAlgorithm);
            var wrongKey = CompositeMLDsaKeyingMaterial.GetPublicKey(wrongAlgorithm);

            var handler = new JsonWebTokenHandler();
            var token = handler.CreateToken(new SecurityTokenDescriptor
            {
                Subject = new CaseSensitiveClaimsIdentity(new[] { new Claim("sub", "test") }),
                SigningCredentials = new SigningCredentials(signingKey, signingAlgorithm)
            });

            var result = handler.ValidateToken(token, new TokenValidationParameters
            {
                ValidateAudience = false,
                ValidateIssuer = false,
                ValidateLifetime = false,
                IssuerSigningKey = wrongKey
            });

            Assert.False(result.IsValid);
        }

        #endregion

        #region Concurrency Tests

        [CompositeMLDsaFact(SecurityAlgorithms.MlDsa44WithECDsaP256)]
        public void ConcurrentSign_DoesNotThrow()
        {
            var key = CompositeMLDsaKeyingMaterial.CompositeMLDsa44ES256Key;
            var signingCredentials = new SigningCredentials(key, SecurityAlgorithms.MlDsa44WithECDsaP256);
            var handler = new JsonWebTokenHandler();

            var exceptions = new System.Collections.Concurrent.ConcurrentBag<Exception>();
            var tasks = new Task[8];

            for (int i = 0; i < tasks.Length; i++)
            {
                tasks[i] = Task.Run(() =>
                {
                    try
                    {
                        handler.CreateToken(new SecurityTokenDescriptor
                        {
                            Subject = new CaseSensitiveClaimsIdentity(new[] { new Claim("sub", "test") }),
                            SigningCredentials = signingCredentials
                        });
                    }
                    catch (Exception ex)
                    {
                        exceptions.Add(ex);
                    }
                });
            }

            Task.WaitAll(tasks);
            Assert.Empty(exceptions);
        }

        [CompositeMLDsaFact(SecurityAlgorithms.MlDsa44WithECDsaP256)]
        public void ConcurrentVerify_NonExportableKey_SerializesPooledAdapters()
        {
            using var composite = new NonExportableCompositeMLDsa();
            var key = new CompositeMLDsaSecurityKey(composite);
            var factory = new CryptoProviderFactory
            {
                CacheSignatureProviders = false,
                SignatureProviderObjectPoolCacheSize = 8
            };
            key.CryptoProviderFactory = factory;

            using var provider = new AsymmetricSignatureProvider(
                key,
                SecurityAlgorithms.MlDsa44WithECDsaP256,
                willCreateSignatures: false);

            byte[] signature = new byte[CompositeMLDsaAlgorithm.MLDsa44WithECDsaP256.MaxSignatureSizeInBytes];
            RunConcurrently(() => provider.Verify(new byte[] { 1, 2, 3 }, signature));

            Assert.Equal(1, composite.MaximumConcurrentOperations);
            Assert.Equal(8, composite.TotalOperations);
            Assert.Equal(1, composite.MaximumConcurrentExports);
            Assert.Equal(8, composite.TotalExports);
        }

        [CompositeMLDsaFact(SecurityAlgorithms.MlDsa44WithECDsaP256)]
        public void ConcurrentSign_NonExportableKey_SerializesPooledAdapters()
        {
            using var composite = new NonExportableCompositeMLDsa();
            var key = new CompositeMLDsaSecurityKey(composite);
            var factory = new CryptoProviderFactory
            {
                CacheSignatureProviders = false,
                SignatureProviderObjectPoolCacheSize = 8
            };
            key.CryptoProviderFactory = factory;

            using var provider = new AsymmetricSignatureProvider(
                key,
                SecurityAlgorithms.MlDsa44WithECDsaP256,
                willCreateSignatures: true);

            // Provider construction probes the key for private material.
            composite.ResetTracking();

            RunConcurrently(() => provider.Sign(new byte[] { 1, 2, 3 }));

            Assert.Equal(1, composite.MaximumConcurrentOperations);
            Assert.Equal(8, composite.TotalOperations);
            Assert.Equal(1, composite.MaximumConcurrentExports);
            Assert.Equal(8, composite.TotalExports);
        }

        #endregion

        #region AppSwitch Tests

        [CompositeMLDsaFact(SecurityAlgorithms.MlDsa44WithECDsaP256)]
        public void IsSupportedAlgorithm_SwitchOff_ReturnsFalse()
        {
            AppContextSwitches.ResetAllSwitches();

            foreach (string alg in _allAlgorithms)
                Assert.False(SupportedAlgorithms.IsSupportedCompositeMLDsaAlgorithm(alg));

            // Re-enable for subsequent tests in this class instance.
            AppContext.SetSwitch(AppContextSwitches.EnableCompositeMLDsaDraftSwitch, true);
        }

        [CompositeMLDsaFact(SecurityAlgorithms.MlDsa44WithECDsaP256)]
        public void IsSupportedAlgorithm_SwitchOn_ReturnsTrue()
        {
            foreach (string alg in _allAlgorithms)
                Assert.True(SupportedAlgorithms.IsSupportedCompositeMLDsaAlgorithm(alg));
        }

        [CompositeMLDsaFact(SecurityAlgorithms.MlDsa44WithECDsaP256)]
        public void IsSupportedAlgorithm_ExistingKey_SwitchOff_ReturnsFalse()
        {
            // Simulate a key materialised while the switch was on, then switch turned off.
            // IsSupportedAlgorithm must not bypass the gate for an already-constructed key.
            using var composite = CompositeMLDsa.GenerateKey(CompositeMLDsaAlgorithm.MLDsa44WithECDsaP256);
            var key = new CompositeMLDsaSecurityKey(composite);

            AppContextSwitches.ResetAllSwitches();

            Assert.False(SupportedAlgorithms.IsSupportedAlgorithm(SecurityAlgorithms.MlDsa44WithECDsaP256, key));

            AppContext.SetSwitch(AppContextSwitches.EnableCompositeMLDsaDraftSwitch, true);
        }

        [CompositeMLDsaFact(SecurityAlgorithms.MlDsa44WithECDsaP256)]
        public void CreateForVerifying_CachedProvider_SwitchOff_Throws()
        {
            CompositeMLDsaSecurityKey key = CompositeMLDsaKeyingMaterial.CompositeMLDsa44ES256Key_Public;
            var factory = new CryptoProviderFactory(CryptoProviderCacheTests.CreateCacheForTesting())
            {
                CacheSignatureProviders = true
            };

            SignatureProvider provider = factory.CreateForVerifying(
                key,
                SecurityAlgorithms.MlDsa44WithECDsaP256,
                cacheProvider: true);

            Assert.True(provider.IsCached);
            factory.ReleaseSignatureProvider(provider);

            AppContext.SetSwitch(AppContextSwitches.EnableCompositeMLDsaDraftSwitch, false);
            try
            {
                Assert.Throws<NotSupportedException>(() =>
                    factory.CreateForVerifying(
                        key,
                        SecurityAlgorithms.MlDsa44WithECDsaP256,
                        cacheProvider: true));
            }
            finally
            {
                AppContext.SetSwitch(AppContextSwitches.EnableCompositeMLDsaDraftSwitch, true);
            }
        }

        #endregion

        private sealed class NonExportableCompositeMLDsa : CompositeMLDsa
        {
            private int _activeOperations;
            private int _activeExports;
            private int _maximumConcurrentOperations;
            private int _maximumConcurrentExports;
            private int _totalOperations;
            private int _totalExports;

            public NonExportableCompositeMLDsa()
                : base(CompositeMLDsaAlgorithm.MLDsa44WithECDsaP256)
            {
            }

            public int MaximumConcurrentOperations => _maximumConcurrentOperations;

            public int MaximumConcurrentExports => _maximumConcurrentExports;

            public int TotalOperations => _totalOperations;

            public int TotalExports => _totalExports;

            public void ResetTracking()
            {
                Volatile.Write(ref _activeOperations, 0);
                Volatile.Write(ref _activeExports, 0);
                Volatile.Write(ref _maximumConcurrentOperations, 0);
                Volatile.Write(ref _maximumConcurrentExports, 0);
                Volatile.Write(ref _totalOperations, 0);
                Volatile.Write(ref _totalExports, 0);
            }

            protected override int SignDataCore(
                ReadOnlySpan<byte> data,
                ReadOnlySpan<byte> context,
                Span<byte> destination)
            {
                TrackOperation();
                try
                {
                    Thread.Sleep(20);
                    destination.Clear();
                    return Algorithm.MaxSignatureSizeInBytes;
                }
                finally
                {
                    Interlocked.Decrement(ref _activeOperations);
                }
            }

            protected override bool VerifyDataCore(
                ReadOnlySpan<byte> data,
                ReadOnlySpan<byte> context,
                ReadOnlySpan<byte> signature)
            {
                TrackOperation();
                try
                {
                    Thread.Sleep(20);
                    return true;
                }
                finally
                {
                    Interlocked.Decrement(ref _activeOperations);
                }
            }

            protected override int ExportCompositeMLDsaPublicKeyCore(Span<byte> destination)
            {
                TrackExport();
                try
                {
                    Thread.Sleep(20);
                    throw new CryptographicException("The key is non-exportable.");
                }
                finally
                {
                    Interlocked.Decrement(ref _activeExports);
                }
            }

            protected override int ExportCompositeMLDsaPrivateKeyCore(Span<byte> destination)
            {
                TrackExport();
                try
                {
                    Thread.Sleep(20);
                    throw new CryptographicException("The key is non-exportable.");
                }
                finally
                {
                    Interlocked.Decrement(ref _activeExports);
                }
            }

            protected override bool TryExportPkcs8PrivateKeyCore(Span<byte> destination, out int bytesWritten)
            {
                bytesWritten = 0;
                return false;
            }

            private void TrackOperation()
            {
                Interlocked.Increment(ref _totalOperations);
                int activeOperations = Interlocked.Increment(ref _activeOperations);
                int maximumConcurrentOperations = Volatile.Read(ref _maximumConcurrentOperations);

                while (activeOperations > maximumConcurrentOperations)
                {
                    int observed = Interlocked.CompareExchange(
                        ref _maximumConcurrentOperations,
                        activeOperations,
                        maximumConcurrentOperations);

                    if (observed == maximumConcurrentOperations)
                        break;

                    maximumConcurrentOperations = observed;
                }
            }

            private void TrackExport()
            {
                Interlocked.Increment(ref _totalExports);
                int activeExports = Interlocked.Increment(ref _activeExports);
                int maximumConcurrentExports = Volatile.Read(ref _maximumConcurrentExports);

                while (activeExports > maximumConcurrentExports)
                {
                    int observed = Interlocked.CompareExchange(
                        ref _maximumConcurrentExports,
                        activeExports,
                        maximumConcurrentExports);

                    if (observed == maximumConcurrentExports)
                        break;

                    maximumConcurrentExports = observed;
                }
            }
        }

        private static void RunConcurrently(Action operation)
        {
            const int operationCount = 8;
            using var ready = new CountdownEvent(operationCount);
            using var start = new ManualResetEventSlim();
            var tasks = new Task[operationCount];

            for (int i = 0; i < tasks.Length; i++)
            {
                tasks[i] = Task.Factory.StartNew(
                    () =>
                    {
                        ready.Signal();
                        start.Wait();
                        operation();
                    },
                    CancellationToken.None,
                    TaskCreationOptions.LongRunning,
                    TaskScheduler.Default);
            }

            Assert.True(ready.Wait(TimeSpan.FromSeconds(10)), "Concurrent operations did not become ready.");
            start.Set();
            Task.WaitAll(tasks);
        }
    }
}
