// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System;
using System.Collections.Generic;
using System.Linq;
using System.Reflection;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.IdentityModel.TestUtils;
using Xunit;

using ALG = Microsoft.IdentityModel.Tokens.SecurityAlgorithms;
using EE = Microsoft.IdentityModel.TestUtils.ExpectedException;

#pragma warning disable CS3016 // Arrays as attribute arguments is not CLS-compliant

namespace Microsoft.IdentityModel.Tokens.Tests
{
    /// <summary>
    /// Tests for CryptoProviderCache with SignatureProviders
    /// </summary>
    public class CryptoProviderCacheTests
    {
        [Theory]
        [InlineData(false, false, false)]
        [InlineData(false, false, true)]
        [InlineData(false, true, false)]
        [InlineData(false, true, true)]
        [InlineData(true, false, false)]
        [InlineData(true, false, true)]
        [InlineData(true, true, false)]
        [InlineData(true, true, true)]
        public void RetirementDisposesAfterLastRelease(bool asymmetric, bool signing, bool releaseBeforeRemoval)
        {
            // Arrange
            using (var cache = new InMemoryCryptoProviderCache())
            {
                var factory = new CryptoProviderFactory(cache);
                SecurityKey key = asymmetric ? KeyingMaterial.RsaSecurityKey_2048 : Default.SymmetricSigningKey256;
                string algorithm = asymmetric ? ALG.RsaSha256 : ALG.HmacSha256;
                SignatureProvider first = signing ? factory.CreateForSigning(key, algorithm) : factory.CreateForVerifying(key, algorithm);
                SignatureProvider second = signing ? factory.CreateForSigning(key, algorithm) : factory.CreateForVerifying(key, algorithm);
                byte[] input = { 1, 2, 3 };
                byte[] signature;
                using (SignatureProvider signer = factory.CreateForSigning(key, algorithm, false))
                {
                    signature = signer.Sign(input);
                    if (signing)
                        first.Sign(input);
                    else
                        Assert.True(first.Verify(input, signature));
                }

                Assert.Same(first, second);
                if (releaseBeforeRemoval)
                {
                    factory.ReleaseSignatureProvider(first);
                    factory.ReleaseSignatureProvider(second);
                    Assert.False(IsProviderDisposed(first));
                }

                // Act
                Assert.True(cache.TryRemove(first));
                if (!releaseBeforeRemoval)
                {
                    Assert.False(IsProviderDisposed(first));
                    factory.ReleaseSignatureProvider(first);
                    Assert.False(IsProviderDisposed(second));
                    if (signing)
                        second.Sign(input);
                    else
                        Assert.True(second.Verify(input, signature));

                    factory.ReleaseSignatureProvider(second);
                }

                // Assert
                Assert.Null(first.CryptoProviderCache);
                Assert.Equal(0, first.RefCount);
                Assert.True(IsProviderDisposed(first));
            }
        }

        [Theory]
        [InlineData(false)]
        [InlineData(true)]
        public void RetirementOnCapacityEvictionNeedsNoFurtherTraffic(bool signing)
        {
            // Arrange
            using (var cache = new InMemoryCryptoProviderCache(new CryptoProviderCacheOptions { SizeLimit = 11 }))
            {
                var factory = new CryptoProviderFactory(cache);
                var providers = new List<RetirementSignatureProvider>();
                try
                {
                    for (int i = 0; i < 12; i++)
                    {
                        byte[] bytes = new byte[32];
                        BitConverter.GetBytes(i).CopyTo(bytes, 0);
                        var provider = new RetirementSignatureProvider(new SymmetricSecurityKey(bytes), signing);
                        providers.Add(provider);
                        Assert.True(cache.TryAdd(provider));
                        factory.ReleaseSignatureProvider(provider);
                    }

                    // Act / Assert
                    Assert.True(SpinWait.SpinUntil(() => providers.Any(provider => provider.DisposeCalls > 0), TimeSpan.FromSeconds(5)));
                    cache.Dispose();
                    Assert.True(SpinWait.SpinUntil(() => cache.TaskCount == 0, TimeSpan.FromSeconds(5)));
                    Assert.All(providers.Where(provider => provider.CryptoProviderCache == null),
                        provider => Assert.Equal(1, provider.DisposeCalls));
                }
                finally
                {
                    foreach (RetirementSignatureProvider provider in providers)
                        provider.Dispose();
                }
            }
        }

        [Fact]
        public async Task RetirementWinsAgainstPausedFactoryLookup()
        {
            // Arrange
            using (var cache = new RetirementPausingCache())
            using (var found = new ManualResetEventSlim())
            using (var resume = new ManualResetEventSlim())
            {
                var factory = new CryptoProviderFactory(cache);
                SignatureProvider original = factory.CreateForSigning(Default.SymmetricSigningKey256, ALG.HmacSha256);
                int pause = 1;
                cache.AfterLookup = provider =>
                {
                    if (Interlocked.Exchange(ref pause, 0) == 1)
                    {
                        found.Set();
                        Assert.True(resume.Wait(TimeSpan.FromSeconds(10)));
                    }
                };

                Task<SignatureProvider> acquisition = Task.Run(() => factory.CreateForSigning(original.Key, original.Algorithm));
                try
                {
                    Assert.True(found.Wait(TimeSpan.FromSeconds(10)));

                    // Act
                    Assert.True(cache.TryRemove(original));
                    factory.ReleaseSignatureProvider(original);
                }
                finally
                {
                    resume.Set();
                }

                SignatureProvider replacement = await acquisition;
                try
                {
                    // Assert
                    Assert.NotSame(original, replacement);
                    Assert.True(IsProviderDisposed(original));
                    Assert.False(IsProviderDisposed(replacement));
                    replacement.Sign(new byte[] { 1, 2, 3 });
                }
                finally
                {
                    factory.ReleaseSignatureProvider(replacement);
                    cache.TryRemove(replacement);
                }
            }
        }

        [Fact]
        public async Task RetirementStaleRemovalPreservesReplacement()
        {
            // Arrange
            using (var cache = new RetirementPausingCache())
            using (var entered = new ManualResetEventSlim())
            using (var resume = new ManualResetEventSlim())
            {
                var original = new RetirementSignatureProvider(Default.SymmetricSigningKey256, true);
                var replacement = new RetirementSignatureProvider(Default.SymmetricSigningKey256, true);
                Assert.True(cache.TryAdd(original));
                int pause = 1;
                cache.BeforeCacheKey = provider =>
                {
                    if (ReferenceEquals(provider, original) && Interlocked.Exchange(ref pause, 0) == 1)
                    {
                        entered.Set();
                        Assert.True(resume.Wait(TimeSpan.FromSeconds(10)));
                    }
                };

                Task<bool> removal = Task.Run(() => cache.TryRemove(original));
                try
                {
                    Assert.True(entered.Wait(TimeSpan.FromSeconds(10)));

                    // Act
                    Assert.True(cache.TryRemove(original));
                    Assert.True(cache.TryAdd(replacement));
                }
                finally
                {
                    resume.Set();
                }

                // Assert
                Assert.False(await removal);
                Assert.True(cache.TryGetSignatureProvider(replacement.Key, replacement.Algorithm,
                    replacement.GetType().ToString(), true, out SignatureProvider found));
                Assert.Same(replacement, found);
                var factory = new CryptoProviderFactory(cache);
                factory.ReleaseSignatureProvider(original);
                cache.TryRemove(replacement);
                factory.ReleaseSignatureProvider(replacement);
                Assert.Equal(1, original.DisposeCalls);
                Assert.Equal(1, replacement.DisposeCalls);
            }
        }

        private static bool IsProviderDisposed(SignatureProvider provider)
        {
            return (bool)provider.GetType().GetField("_disposed", BindingFlags.Instance | BindingFlags.NonPublic).GetValue(provider);
        }

        [Theory]
        [InlineData(false)]
        [InlineData(true)]
        public void RetirementPreservesIdleCachedProviderAndRawLookup(bool signing)
        {
            // Arrange
            using (var cache = new InMemoryCryptoProviderCache())
            {
                var factory = new CryptoProviderFactory(cache);
                SignatureProvider original = signing
                    ? factory.CreateForSigning(Default.SymmetricSigningKey256, ALG.HmacSha256)
                    : factory.CreateForVerifying(Default.SymmetricSigningKey256, ALG.HmacSha256);
                factory.ReleaseSignatureProvider(original);

                // Act
                Assert.True(cache.TryGetSignatureProvider(original.Key, original.Algorithm,
                    original.GetType().ToString(), signing, out SignatureProvider found));
                Assert.Equal(0, original.RefCount);
                Assert.False(IsProviderDisposed(original));
                SignatureProvider acquired = signing
                    ? factory.CreateForSigning(original.Key, original.Algorithm)
                    : factory.CreateForVerifying(original.Key, original.Algorithm);

                // Assert
                Assert.Same(original, found);
                Assert.Same(original, acquired);
                Assert.Equal(1, acquired.RefCount);
                Assert.True(cache.TryRemove(acquired));
                Assert.False(IsProviderDisposed(acquired));
                factory.ReleaseSignatureProvider(acquired);
                Assert.True(IsProviderDisposed(acquired));
            }
        }

        [Theory]
        [InlineData(false)]
        [InlineData(true)]
        public void RetirementConcurrentPublicationHasOneOwner(bool signing)
        {
            // Arrange
            using (var cache = new InMemoryCryptoProviderCache())
            using (var otherCache = new InMemoryCryptoProviderCache())
            {
                var factory = new CryptoProviderFactory(cache);
                RetirementSignatureProvider[] providers = Enumerable.Range(0, 32)
                    .Select(_ => new RetirementSignatureProvider(Default.SymmetricSigningKey256, signing)).ToArray();
                int published = 0;

                // Act
                Parallel.ForEach(providers, provider =>
                {
                    if (cache.TryAdd(provider))
                        Interlocked.Increment(ref published);
                });

                // Assert
                Assert.Equal(1, published);
                RetirementSignatureProvider winner = Assert.Single(providers, provider => provider.CryptoProviderCache != null);
                Assert.False(otherCache.TryAdd(winner));
                Assert.False(cache.TryAdd(winner));
                Assert.Same(cache, winner.CryptoProviderCache);
                Assert.True(winner.IsCached);
                RetirementSignatureProvider republished = providers.First(provider => !ReferenceEquals(provider, winner));
                Assert.Null(republished.CryptoProviderCache);
                Assert.False(republished.IsCached);
                Assert.True(otherCache.TryAdd(republished));
                Assert.True(republished.IsCached);
                foreach (RetirementSignatureProvider provider in providers)
                {
                    factory.ReleaseSignatureProvider(provider);
                    Assert.Equal(ReferenceEquals(provider, winner) || ReferenceEquals(provider, republished) ? 0 : 1, provider.DisposeCalls);
                }

                Assert.True(cache.TryRemove(winner));
                Assert.Equal(1, winner.DisposeCalls);
                Assert.True(otherCache.TryRemove(republished));
                Assert.Equal(1, republished.DisposeCalls);
                Assert.False(cache.TryAdd(winner));
                Assert.False(otherCache.TryAdd(winner));
            }
        }

        [Fact]
        public void RetirementRacesCrossCacheAdmission()
        {
            // Arrange
            using (var cache = new InMemoryCryptoProviderCache())
            using (var otherCache = new InMemoryCryptoProviderCache())
            {
                var factory = new CryptoProviderFactory(cache);
                for (int iteration = 0; iteration < 1000; iteration++)
                {
                    var provider = new RetirementSignatureProvider(Default.SymmetricSigningKey256, true);
                    Assert.True(cache.TryAdd(provider));
                    factory.ReleaseSignatureProvider(provider);
                    bool published = false;

                    // Act
                    Parallel.Invoke(
                        () => Assert.True(cache.TryRemove(provider)),
                        () => published = otherCache.TryAdd(provider));

                    // Assert
                    Assert.False(published);
                    Assert.Null(provider.CryptoProviderCache);
                    Assert.True(provider.IsCached);
                    Assert.Equal(1, provider.DisposeCalls);
                    Assert.False(provider.TryAddRef());
                }
            }
        }

        [Fact]
        public void RetirementFinalReleaseRacesRemoval()
        {
            // Arrange
            using (var cache = new InMemoryCryptoProviderCache())
            {
                var factory = new CryptoProviderFactory(cache);
                for (int iteration = 0; iteration < 100; iteration++)
                {
                    var provider = new RetirementSignatureProvider(Default.SymmetricSigningKey256, true);
                    Assert.True(cache.TryAdd(provider));
                    for (int i = 1; i < 32; i++)
                        provider.AddRef();

                    // Act
                    Parallel.Invoke(
                        () => Parallel.For(0, 32, _ => factory.ReleaseSignatureProvider(provider)),
                        () => Assert.True(cache.TryRemove(provider)));

                    // Assert
                    Assert.Equal(0, provider.RefCount);
                    Assert.Equal(1, provider.DisposeCalls);
                    Assert.False(provider.TryAddRef());
                }
            }
        }

        [Fact]
        public void RetirementLastReleaseDoesNotDependOnCacheWorker()
        {
            // Arrange
            using (var cache = new InMemoryCryptoProviderCache())
            {
                var factory = new CryptoProviderFactory(cache);
                var retired = new RetirementSignatureProvider(Default.SymmetricSigningKey256, true);
                var active = new RetirementSignatureProvider(Default.SymmetricSigningKey256, false);
                Assert.True(cache.TryAdd(retired));
                Assert.True(cache.TryAdd(active));
                Assert.True(cache.TryRemove(retired));

                // Act
                cache.Dispose();
                factory.ReleaseSignatureProvider(retired);
                factory.ReleaseSignatureProvider(active);

                // Assert
                Assert.Equal(1, retired.DisposeCalls);
                Assert.Equal(0, active.DisposeCalls);
                Assert.Same(cache, active.CryptoProviderCache);
                Assert.True(cache.TryRemove(active));
                Assert.Equal(1, active.DisposeCalls);
            }
        }

        [Theory]
        [InlineData(false)]
        [InlineData(true)]
        public void RetirementDisposalFailureDoesNotBlockOtherProviders(bool releaseBeforeRemoval)
        {
            // Arrange
            using (var cache = new InMemoryCryptoProviderCache())
            {
                var factory = new CryptoProviderFactory(cache);
                var throwing = new RetirementSignatureProvider(Default.SymmetricSigningKey256, true, true);
                var healthy = new RetirementSignatureProvider(Default.SymmetricSigningKey256, false);
                Assert.True(cache.TryAdd(throwing));
                Assert.True(cache.TryAdd(healthy));
                if (releaseBeforeRemoval)
                {
                    factory.ReleaseSignatureProvider(throwing);
                    factory.ReleaseSignatureProvider(healthy);
                }

                // Act
                Assert.True(cache.TryRemove(throwing));
                Assert.True(cache.TryRemove(healthy));
                if (!releaseBeforeRemoval)
                {
                    factory.ReleaseSignatureProvider(throwing);
                    factory.ReleaseSignatureProvider(healthy);
                }

                // Assert
                Assert.Equal(1, throwing.DisposeCalls);
                Assert.Equal(1, healthy.DisposeCalls);
                Assert.False(cache.TryRemove(throwing));
                Assert.False(throwing.TryAddRef());
            }
        }

        [Theory]
        [InlineData(false, false)]
        [InlineData(false, true)]
        [InlineData(true, false)]
        [InlineData(true, true)]
        public void RetirementCustomProviderPreservesReleaseOwner(bool cached, bool signing)
        {
            // Arrange
            using (var cache = new InMemoryCryptoProviderCache())
            {
                var custom = new RetirementCryptoProvider();
                var factory = new CryptoProviderFactory(cache) { CustomCryptoProvider = custom, CacheCustomProviders = cached };
                SignatureProvider first = signing
                    ? factory.CreateForSigning(Default.SymmetricSigningKey256, ALG.HmacSha256)
                    : factory.CreateForVerifying(Default.SymmetricSigningKey256, ALG.HmacSha256);
                SignatureProvider second = signing
                    ? factory.CreateForSigning(first.Key, first.Algorithm)
                    : factory.CreateForVerifying(first.Key, first.Algorithm);

                // Act
                if (cached)
                {
                    Assert.Same(first, second);
                    Assert.True(cache.TryRemove(first));
                }
                else
                {
                    Assert.NotSame(first, second);
                }

                factory.ReleaseSignatureProvider(first);
                factory.ReleaseSignatureProvider(second);

                // Assert
                Assert.Equal(cached ? 0 : 2, custom.ReleaseCalls);
                Assert.Equal(1, ((RetirementSignatureProvider)first).DisposeCalls);
                Assert.Equal(1, ((RetirementSignatureProvider)second).DisposeCalls);
            }
        }

        [Theory]
        [InlineData(false)]
        [InlineData(true)]
        public void RetirementOnSigningFailureReturnsOperatorBeforeDisposal(bool asymmetric)
        {
            // Arrange
            using (var cache = new InMemoryCryptoProviderCache())
            {
                var factory = new CryptoProviderFactory(cache);
                SecurityKey key = asymmetric ? KeyingMaterial.RsaSecurityKey_2048 : Default.SymmetricSigningKey256;
                string algorithm = asymmetric ? ALG.RsaSha256 : ALG.HmacSha256;
                SignatureProvider provider = factory.CreateForSigning(key, algorithm);

                // Act
                Assert.ThrowsAny<ArgumentException>(() => provider.Sign(new byte[] { 1 }, 1, 1));

                // Assert
                Assert.Null(provider.CryptoProviderCache);
                Assert.False(IsProviderDisposed(provider));
                factory.ReleaseSignatureProvider(provider);
                Assert.True(IsProviderDisposed(provider));
            }
        }

#if NET6_0_OR_GREATER
        [Theory]
        [InlineData(false)]
        [InlineData(true)]
        public void RetirementPreservesCallerOwnedAsymmetricKey(bool ecdsa)
        {
            // Arrange
            using (var cache = new InMemoryCryptoProviderCache())
            using (AsymmetricAlgorithm primitive = ecdsa ? ECDsa.Create(ECCurve.NamedCurves.nistP256) : RSA.Create(2048))
            {
                var factory = new CryptoProviderFactory(cache);
                SecurityKey key = ecdsa ? new ECDsaSecurityKey((ECDsa)primitive) : new RsaSecurityKey((RSA)primitive);
                string algorithm = ecdsa ? ALG.EcdsaSha256 : ALG.RsaSha256;
                SignatureProvider provider = factory.CreateForSigning(key, algorithm);
                byte[] input = { 1, 2, 3 };
                provider.Sign(input);

                // Act
                factory.ReleaseSignatureProvider(provider);
                Assert.True(cache.TryRemove(provider));

                // Assert
                Assert.True(IsProviderDisposed(provider));
                if (ecdsa)
                {
                    var callerKey = (ECDsa)primitive;
                    byte[] signature = callerKey.SignData(input, HashAlgorithmName.SHA256);
                    Assert.True(callerKey.VerifyData(input, signature, HashAlgorithmName.SHA256));
                }
                else
                {
                    var callerKey = (RSA)primitive;
                    byte[] signature = callerKey.SignData(input, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
                    Assert.True(callerKey.VerifyData(input, signature, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1));
                }
            }
        }
#endif

        [Fact]
        public void RetirementDisposalCanPublishReplacement()
        {
            // Arrange
            using (var cache = new InMemoryCryptoProviderCache())
            {
                var factory = new CryptoProviderFactory(cache);
                var original = new RetirementSignatureProvider(Default.SymmetricSigningKey256, true);
                var replacement = new RetirementSignatureProvider(Default.SymmetricSigningKey256, true);
                original.OnDispose = () => Assert.True(cache.TryAdd(replacement));
                Assert.True(cache.TryAdd(original));
                factory.ReleaseSignatureProvider(original);

                // Act
                Assert.True(cache.TryRemove(original));

                // Assert
                Assert.Equal(1, original.DisposeCalls);
                Assert.Same(cache, replacement.CryptoProviderCache);
                Assert.True(cache.TryGetSignatureProvider(replacement.Key, replacement.Algorithm,
                    replacement.GetType().ToString(), true, out SignatureProvider found));
                Assert.Same(replacement, found);
                factory.ReleaseSignatureProvider(replacement);
                Assert.True(cache.TryRemove(replacement));
                Assert.Equal(1, replacement.DisposeCalls);
            }
        }

        private sealed class RetirementSignatureProvider : SignatureProvider
        {
            private int _disposeCalls;
            private readonly bool _throwOnDispose;

            public RetirementSignatureProvider(SecurityKey key, bool signing, bool throwOnDispose = false) : base(key, ALG.HmacSha256)
            {
                WillCreateSignatures = signing;
                _throwOnDispose = throwOnDispose;
            }

            public int DisposeCalls => Volatile.Read(ref _disposeCalls);

            public Action OnDispose { get; set; }

            protected override void Dispose(bool disposing)
            {
                Interlocked.Increment(ref _disposeCalls);
                OnDispose?.Invoke();
                if (_throwOnDispose)
                    throw new InvalidOperationException("Test provider disposal failure.");
            }

            public override byte[] Sign(byte[] input) => input;

            public override bool Verify(byte[] input, byte[] signature) => true;
        }

        private sealed class RetirementCryptoProvider : ICryptoProvider
        {
            public int ReleaseCalls { get; private set; }

            public object Create(string algorithm, params object[] args) =>
                new RetirementSignatureProvider((SecurityKey)args[0], (bool)args[1]);

            public bool IsSupportedAlgorithm(string algorithm, params object[] args) => algorithm == ALG.HmacSha256;

            public void Release(object cryptoInstance)
            {
                ReleaseCalls++;
                ((SignatureProvider)cryptoInstance).Dispose();
            }
        }

        private sealed class RetirementPausingCache : InMemoryCryptoProviderCache
        {
            public Action<SignatureProvider> AfterLookup { get; set; }

            public Action<SignatureProvider> BeforeCacheKey { get; set; }

            protected override string GetCacheKey(SignatureProvider provider)
            {
                BeforeCacheKey?.Invoke(provider);
                return base.GetCacheKey(provider);
            }

            public override bool TryGetSignatureProvider(SecurityKey key, string algorithm, string providerType, bool signing, out SignatureProvider provider)
            {
                bool found = base.TryGetSignatureProvider(key, algorithm, providerType, signing, out provider);
                if (found)
                    AfterLookup?.Invoke(provider);

                return found;
            }
        }

        public static Func<CryptoProviderCache> CreateCacheForTesting = new Func<CryptoProviderCache>(() =>
        {
            return new InMemoryCryptoProviderCache(new CryptoProviderCacheOptions(), TaskCreationOptions.None, 50);
        });

        [Fact]
        public void CryptoProviderCacheOptions()
        {
            var options = new CryptoProviderCacheOptions();

            Assert.Throws<ArgumentOutOfRangeException>(() => options.SizeLimit = 0);
            Assert.Throws<ArgumentOutOfRangeException>(() => options.SizeLimit = -1);
            Assert.Throws<ArgumentOutOfRangeException>(() => options.SizeLimit = 10);
            options.SizeLimit = 11;
        }

        /// <summary>
        /// Tests that a cache key generated from a <see cref="SignatureProvider"/> or a set of components are equal.
        /// </summary>
        /// <param name="theoryData"></param>
        [Theory, MemberData(nameof(GetCacheKeyTheoryData), DisableDiscoveryEnumeration = true)]
        public void GetCacheKey(CryptoProviderCacheTheoryData theoryData)
        {
            var context = TestUtilities.WriteHeader($"{this}.GetCacheKey", theoryData);

            try
            {
                var keyFromComponents = theoryData.InMemoryCryptoProviderCachePublic.GetCacheKeyPublic(theoryData.SecurityKey, theoryData.Algorithm, theoryData.TypeofProvider);
                var keyFromProvider = theoryData.InMemoryCryptoProviderCachePublic.GetCacheKeyPublic(theoryData.SignatureProvider);
                if (keyFromProvider.Equals(keyFromComponents) != theoryData.ShouldCacheKeysMatch)
                    context.Diffs.Add($"theoryData.CacheKeysMatch:{Environment.NewLine}keyFromComponents: '{keyFromComponents}'{Environment.NewLine}!={Environment.NewLine}keyFromProvider:    '{keyFromProvider}'.");

                theoryData.ExpectedException.ProcessNoException(context);
            }
            catch (Exception ex)
            {
                theoryData.ExpectedException.ProcessException(ex, context);
            }

            TestUtilities.AssertFailIfErrors(context);
        }

        public static TheoryData<CryptoProviderCacheTheoryData> GetCacheKeyTheoryData
        {
            get
            {
                var theoryData = new TheoryData<CryptoProviderCacheTheoryData>
                {
                    new CryptoProviderCacheTheoryData
                    {
                        Algorithm = ALG.RsaSha384,
                        ExpectedException = EE.ArgumentNullException(),
                        First = true,
                        SecurityKey = Default.AsymmetricSigningKey,
                        TestId = "SignatureProviderNULL",
                        TypeofProvider = typeof(AsymmetricSignatureProvider).ToString()
                    },
                    new CryptoProviderCacheTheoryData
                    {
                        Algorithm = Default.AsymmetricSigningAlgorithm,
                        ExpectedException = EE.ArgumentNullException(),
                        TestId = "SecurityKeyNULL",
                        TypeofProvider = typeof(AsymmetricSignatureProvider).ToString()
                    },
                    new CryptoProviderCacheTheoryData
                    {
                        ExpectedException = EE.ArgumentNullException(),
                        SecurityKey = Default.AsymmetricSigningKey,
                        SignatureProvider = new AsymmetricSignatureProvider(Default.AsymmetricSigningKey, Default.AsymmetricSigningAlgorithm, true),
                        TestId = "AlgorithmNULL",
                        TypeofProvider = typeof(AsymmetricSignatureProvider).ToString()
                    },
                    new CryptoProviderCacheTheoryData
                    {
                        Algorithm = string.Empty,
                        ExpectedException = EE.ArgumentNullException(),
                        SecurityKey = Default.AsymmetricSigningKey,
                        SignatureProvider = new AsymmetricSignatureProvider(Default.AsymmetricSigningKey, Default.AsymmetricSigningAlgorithm, true),
                        TestId = "AlgorithmString.Empty",
                        TypeofProvider = typeof(AsymmetricSignatureProvider).ToString()
                    },
                    new CryptoProviderCacheTheoryData
                    {
                        Algorithm = ALG.RsaSha384,
                        ExpectedException = EE.ArgumentNullException(),
                        SecurityKey = Default.AsymmetricSigningKey,
                        SignatureProvider = new AsymmetricSignatureProvider(Default.AsymmetricSigningKey, Default.AsymmetricSigningAlgorithm, true),
                        TestId = "TypeofProviderNULL"
                    },
                    new CryptoProviderCacheTheoryData
                    {
                        Algorithm = ALG.RsaSha384,
                        ExpectedException = EE.ArgumentNullException(),
                        SecurityKey = Default.AsymmetricSigningKey,
                        SignatureProvider = new AsymmetricSignatureProvider(Default.AsymmetricSigningKey, Default.AsymmetricSigningAlgorithm, true),
                        TestId = "TypeofProviderString.Empty",
                        TypeofProvider = string.Empty
                    },
                    new CryptoProviderCacheTheoryData
                    {
                        Algorithm = Default.AsymmetricSigningAlgorithm,
                        SecurityKey = Default.AsymmetricSigningKey,
                        SignatureProvider = new AsymmetricSignatureProvider(Default.AsymmetricSigningKey, Default.AsymmetricSigningAlgorithm, true),
                        TestId = "AsymmetricSignatureProvider1",
                        TypeofProvider = typeof(AsymmetricSignatureProvider).ToString()
                    },
                    new CryptoProviderCacheTheoryData
                    {
                        Algorithm = Default.AsymmetricSigningAlgorithm,
                        SecurityKey = Default.AsymmetricSigningKey,
                        SignatureProvider = new AsymmetricSignatureProvider(Default.AsymmetricSigningKey, Default.AsymmetricSigningAlgorithm, false),
                        TestId = "AsymmetricSignatureProvider2",
                        TypeofProvider = typeof(AsymmetricSignatureProvider).ToString()
                    },
                    new CryptoProviderCacheTheoryData
                    {
                        Algorithm = ALG.RsaSha384,
                        SecurityKey = Default.AsymmetricSigningKey,
                        ShouldCacheKeysMatch = false,
                        SignatureProvider = new AsymmetricSignatureProvider(Default.AsymmetricSigningKey, ALG.RsaSha256, false),
                        TestId = "AlgorithmDifferent",
                        TypeofProvider = typeof(AsymmetricSignatureProvider).ToString()
                    },
                    new CryptoProviderCacheTheoryData
                    {
                        Algorithm = ALG.HmacSha512,
                        SecurityKey = Default.AsymmetricSigningKey,
                        ShouldCacheKeysMatch = false,
                        SignatureProvider = new AsymmetricSignatureProvider(Default.AsymmetricSigningKey, Default.AsymmetricSigningAlgorithm, false),
                        TestId = "TypeofProviderDifferent",
                        TypeofProvider = typeof(SymmetricSignatureProvider).ToString()
                    },
                    new CryptoProviderCacheTheoryData
                    {
                        Algorithm = ALG.RsaSha384,
                        SecurityKey = Default.AsymmetricSigningKey,
                        ShouldCacheKeysMatch = true,
                        SignatureProvider = new AsymmetricSignatureProvider(Default.AsymmetricSigningKey, ALG.RsaSha384, false),
                        TestId = "WillCreateSignaturesDifferent",
                        TypeofProvider = typeof(AsymmetricSignatureProvider).ToString()
                    }
                };

                return theoryData;
            }
        }

        [Theory, MemberData(nameof(TryAddTheoryData), DisableDiscoveryEnumeration = true)]
        public void TryAdd(CryptoProviderCacheTheoryData theoryData)
        {
            var context = TestUtilities.WriteHeader($"{this}.TryAdd", theoryData);

            try
            {
                bool shouldCreate = CryptoProviderFactory.ShouldCacheSignatureProvider(theoryData.SignatureProvider);

                var added = theoryData.CryptoProviderCache.TryAdd(theoryData.SignatureProvider);
                if (theoryData.Added != added && shouldCreate)
                    context.Diffs.Add($"theoryData.Added:'{theoryData.Added}' != theoryData.CryptoProviderCache.TryAdd(theoryData.SignatureProvider)");

                theoryData.ExpectedException.ProcessNoException(context);
            }
            catch (Exception ex)
            {
                theoryData.ExpectedException.ProcessException(ex, context);
            }

            TestUtilities.AssertFailIfErrors(context);
        }

        public static TheoryData<CryptoProviderCacheTheoryData> TryAddTheoryData
        {
            get
            {
                var sharedCache = CreateCacheForTesting();

                var theoryData = new TheoryData<CryptoProviderCacheTheoryData>
                {
                    new CryptoProviderCacheTheoryData
                    {
                        ExpectedException = EE.ArgumentNullException(),
                        First = true,
                        TestId = "SignatureProviderNULL"
                    },
                    new CryptoProviderCacheTheoryData
                    {
                        Added = true,
                        CryptoProviderCache = sharedCache,
                        SignatureProvider = new SymmetricSignatureProvider(Default.SymmetricSigningKey256, ALG.HmacSha256),
                        TestId = "SymmetricSignatureProviderAdded"
                    },
                    new CryptoProviderCacheTheoryData
                    {
                        Added = false,
                        CryptoProviderCache = sharedCache,
                        SignatureProvider = new SymmetricSignatureProvider(Default.SymmetricSigningKey256, ALG.HmacSha256),
                        TestId = "SymmetricSignatureProviderAddedSecondTime"
                    },
                    new CryptoProviderCacheTheoryData
                    {
                        Added = true,
                        CryptoProviderCache = sharedCache,
                        SignatureProvider = new AsymmetricSignatureProvider(Default.AsymmetricSigningKey, Default.AsymmetricSigningAlgorithm),
                        TestId = "AsymmetricSignatureProviderAdded"
                    },
                    new CryptoProviderCacheTheoryData
                    {
                        Added = false,
                        CryptoProviderCache = sharedCache,
                        SignatureProvider = new AsymmetricSignatureProvider(Default.AsymmetricSigningKey, Default.AsymmetricSigningAlgorithm),
                        TestId = "AsymmetricSignatureProviderAddedSecondTime"
                    },
                    new CryptoProviderCacheTheoryData
                    {
                        Added = true,
                        CryptoProviderCache = sharedCache,
                        SignatureProvider = new AsymmetricSignatureProvider(KeyingMaterial.RsaSecurityKey1, ALG.RsaSha256, false),
                        TestId = nameof(KeyingMaterial.RsaSecurityKey_2048)
                    },
                    // test signing signature provider
                    new CryptoProviderCacheTheoryData
                    {
                        Added = true,
                        CryptoProviderCache = sharedCache,
                        SignatureProvider = new AsymmetricSignatureProvider(KeyingMaterial.RsaSecurityKey_2048, ALG.RsaSha256, true),
                        TestId = nameof(KeyingMaterial.RsaSecurityKey_2048)
                    },
                    new CryptoProviderCacheTheoryData
                    {
                        Added = true,
                        CryptoProviderCache = sharedCache,
                        SignatureProvider = new AsymmetricSignatureProvider(KeyingMaterial.DefaultX509Key_2048_Public, ALG.RsaSha256, false),
                        TestId = nameof(KeyingMaterial.DefaultX509Key_2048_Public)
                    },
                    new CryptoProviderCacheTheoryData
                    {
                        Added = true,
                        CryptoProviderCache = sharedCache,
                        SignatureProvider = new AsymmetricSignatureProvider(KeyingMaterial.JsonWebKeyRsa_2048_Public, ALG.RsaSha256, false),
                        TestId = nameof(KeyingMaterial.JsonWebKeyRsa_2048_Public)
                    },
                    // test symmetric signature provider
                    new CryptoProviderCacheTheoryData
                    {
                        Added = true,
                        CryptoProviderCache = sharedCache,
                        SignatureProvider = new SymmetricSignatureProvider(KeyingMaterial.DefaultSymmetricSecurityKey_384, ALG.HmacSha384, true),
                        TestId = nameof(KeyingMaterial.DefaultSymmetricSecurityKey_256)
                    },
#if NET472 || NET
                    // ecdsa signature provider should be added to the cache on NET472 and NET.
                    new CryptoProviderCacheTheoryData
                    {
                        Added = true,
                        CryptoProviderCache = sharedCache,
                        SignatureProvider = new AsymmetricSignatureProvider(KeyingMaterial.Ecdsa256Key_Public, ALG.EcdsaSha256, false),
                        TestId = nameof(KeyingMaterial.Ecdsa256Key_Public)
                    },
#else
                    // ecdsa signature provider should NOT be added to the cache on NET461.
                    new CryptoProviderCacheTheoryData
                    {
                        Added = false,
                        CryptoProviderCache = sharedCache,
                        SignatureProvider = new AsymmetricSignatureProvider(KeyingMaterial.Ecdsa256Key_Public, ALG.EcdsaSha256, false),
                        TestId = nameof(KeyingMaterial.Ecdsa256Key_Public)
                    },
#endif
                };

                return theoryData;
            }
        }

        /// <summary>
        /// Tests that a cache key generated from a <see cref="SignatureProvider"/> or a set of components are equal.
        /// </summary>
        /// <param name="theoryData"></param>
        [Theory, MemberData(nameof(TryGetSignatureProviderTheoryData), DisableDiscoveryEnumeration = true)]
        public void TryGetSignatureProvider(CryptoProviderCacheTheoryData theoryData)
        {
            var context = TestUtilities.WriteHeader($"{this}.TryGetSignatureProvider", theoryData);

            try
            {
                var providerFound = theoryData.CryptoProviderCache.TryGetSignatureProvider(theoryData.SecurityKey, theoryData.Algorithm, theoryData.TypeofProvider, theoryData.WillCreateSignatures, out SignatureProvider signatureProvider);
                if (theoryData.Found != providerFound)
                    context.Diffs.Add($"theoryData.Found: '{theoryData.Found}' != theoryData.CryptoProviderCache.TryGetSignatureProvider: '{providerFound}'");
            }
            catch (Exception ex)
            {
                theoryData.ExpectedException.ProcessException(ex, context);
            }

            TestUtilities.AssertFailIfErrors(context);
        }

        public static TheoryData<CryptoProviderCacheTheoryData> TryGetSignatureProviderTheoryData
        {
            get
            {
                var cryptoProviderCache = CreateCacheForTesting();

                var theoryData = new TheoryData<CryptoProviderCacheTheoryData>
                {
                    new CryptoProviderCacheTheoryData
                    {
                        Algorithm = ALG.RsaSha256,
                        CryptoProviderCache = cryptoProviderCache,
                        ExpectedException = EE.ArgumentNullException(),
                        First = true,
                        TestId = "SecurityKeyNULL",
                        TypeofProvider = typeof(AsymmetricSignatureProvider).ToString()
                    },
                    new CryptoProviderCacheTheoryData
                    {
                        CryptoProviderCache = cryptoProviderCache,
                        ExpectedException = EE.ArgumentNullException(),
                        SecurityKey = Default.AsymmetricSigningKey,
                        TestId = "AlgorithmNULL",
                        TypeofProvider = typeof(AsymmetricSignatureProvider).ToString()
                    },
                    new CryptoProviderCacheTheoryData
                    {
                        Algorithm = string.Empty,
                        CryptoProviderCache = cryptoProviderCache,
                        ExpectedException = EE.ArgumentNullException(),
                        SecurityKey = Default.AsymmetricSigningKey,
                        TestId = "AlgorithmString.Empty",
                        TypeofProvider = typeof(AsymmetricSignatureProvider).ToString()
                    },
                    new CryptoProviderCacheTheoryData
                    {
                        Algorithm = ALG.RsaSha256,
                        CryptoProviderCache = cryptoProviderCache,
                        ExpectedException = EE.ArgumentNullException(),
                        SecurityKey = Default.AsymmetricSigningKey,
                        TestId = "TypeofProviderNULL"
                    },
                    new CryptoProviderCacheTheoryData
                    {
                        Algorithm = ALG.RsaSha256,
                        CryptoProviderCache = cryptoProviderCache,
                        ExpectedException = EE.ArgumentNullException(),
                        SecurityKey = Default.AsymmetricSigningKey,
                        TestId = "TypeofProviderString.Empty",
                        TypeofProvider = string.Empty
                    },
                };

                // Test different methods of finding

                var derivedKey = new DerivedSecurityKey("kid", 256);
                var derivedKey2 = new DerivedSecurityKey("kid2", 256);
                var signatureProvider = new CustomSignatureProvider(derivedKey, ALG.RsaSha256, true);
                cryptoProviderCache.TryAdd(signatureProvider);
                theoryData.Add(new CryptoProviderCacheTheoryData
                {
                    Algorithm = ALG.RsaSha256,
                    CryptoProviderCache = cryptoProviderCache,
                    Found = true,
                    SecurityKey = derivedKey,
                    TestId = "SignatureProviderFound",
                    TypeofProvider = typeof(CustomSignatureProvider).ToString(),
                    WillCreateSignatures = true
                });
                theoryData.Add(new CryptoProviderCacheTheoryData
                {
                    Algorithm = ALG.RsaSha256,
                    CryptoProviderCache = cryptoProviderCache,
                    Found = false,
                    SecurityKey = derivedKey,
                    TestId = "SignatureProviderTypeMismatch",
                    TypeofProvider = typeof(SignatureProviderForTestingCache).ToString(),
                    WillCreateSignatures = true
                });
                theoryData.Add(new CryptoProviderCacheTheoryData
                {
                    Algorithm = ALG.RsaSha256,
                    CryptoProviderCache = cryptoProviderCache,
                    Found = false,
                    SecurityKey = derivedKey2,
                    TestId = "SignatureProviderKeyIdMismatch",
                    TypeofProvider = typeof(CustomSignatureProvider).ToString(),
                    WillCreateSignatures = true
                });
                theoryData.Add(new CryptoProviderCacheTheoryData
                {
                    Algorithm = ALG.RsaSha384,
                    CryptoProviderCache = cryptoProviderCache,
                    Found = false,
                    SecurityKey = derivedKey,
                    TestId = "SignatureProviderAlgorithmMismatch",
                    TypeofProvider = typeof(CustomSignatureProvider).ToString(),
                    WillCreateSignatures = true
                });
                theoryData.Add(new CryptoProviderCacheTheoryData
                {
                    Algorithm = ALG.RsaSha256,
                    CryptoProviderCache = cryptoProviderCache,
                    Found = false,
                    SecurityKey = derivedKey,
                    TestId = "SignatureProviderWillCreateSignaturesMismatch",
                    TypeofProvider = typeof(CustomSignatureProvider).ToString(),
                    WillCreateSignatures = false
                });

                return theoryData;
            }
        }

        /// <summary>
        /// Checks that the Dispose() method is properly called on the InMemoryCryptoProviderCache.
        /// </summary>
        [Fact]
        public void CryptoProviderCacheDispose()
        {
            TestUtilities.WriteHeader($"{this}.CryptoProviderCacheDispose");
            var context = new CompareContext();
            var cache = new InMemoryCryptoProviderCachePublic();

            cache.Dispose();

            if (!cache.DisposeCalled)
                context.AddDiff("InMemoryCryptoProviderCachePublic was not properly disposed of.");

            TestUtilities.AssertFailIfErrors(context);
        }

        [Theory, MemberData(nameof(TryRemoveTheoryData), DisableDiscoveryEnumeration = true)]
        public void TryRemove(CryptoProviderCacheTheoryData theoryData)
        {
            var context = TestUtilities.WriteHeader($"{this}.TryRemove", theoryData);

            try
            {
                if (theoryData.Removed != theoryData.CryptoProviderCache.TryRemove(theoryData.SignatureProvider))
                    context.Diffs.Add($"theoryData.Removed:'{theoryData.Removed}' != theoryData.CryptoProviderCache.TryRemove(theoryData.SignatureProvider)");

                theoryData.ExpectedException.ProcessNoException(context);
            }
            catch (Exception ex)
            {
                theoryData.ExpectedException.ProcessException(ex, context);
            }

            TestUtilities.AssertFailIfErrors(context);
        }

        public static TheoryData<CryptoProviderCacheTheoryData> TryRemoveTheoryData
        {
            get
            {
                var cache = CreateCacheForTesting();

                var theoryData = new TheoryData<CryptoProviderCacheTheoryData>
                {
                    new CryptoProviderCacheTheoryData
                    {
                        CryptoProviderCache = cache,
                        ExpectedException = EE.ArgumentNullException(),
                        First = true,
                        TestId = "SignatureProviderNULL"
                    },
                    new CryptoProviderCacheTheoryData
                    {
                        CryptoProviderCache = cache,
                        Removed = false,
                        SignatureProvider = new SymmetricSignatureProvider(Default.SymmetricSigningKey256, ALG.HmacSha256),
                        TestId = "EmptyCache"
                    },
                    new CryptoProviderCacheTheoryData
                    {
                        CryptoProviderCache = cache,
                        Removed = false,
                        SignatureProvider = new CustomSignatureProvider(new DerivedSecurityKey(null, 256), ALG.HmacSha256),
                        TestId = "KeyIdnull"
                    },
                    new CryptoProviderCacheTheoryData
                    {
                        CryptoProviderCache = cache,
                        Removed = false,
                        SignatureProvider = new CustomSignatureProvider(new DerivedSecurityKey(string.Empty, 256), ALG.HmacSha256),
                        TestId = "KeyIdString.empty"
                    },
                    new CryptoProviderCacheTheoryData
                    {
                        CryptoProviderCache = cache,
                        Removed = false,
                        SignatureProvider = new CustomSignatureProvider(new DerivedSecurityKey("kid", 256), ALG.HmacSha256),
                        TestId = "CryptoProviderFactorynull"
                    },
                    new CryptoProviderCacheTheoryData
                    {
                        CryptoProviderCache = cache,
                        Removed = false,
                        SignatureProvider = new CustomSignatureProvider(new DerivedSecurityKey("kid", 256), ALG.HmacSha256){CryptoProviderCache = cache},
                        TestId = "CryptoProvider!=ReferenceEquals"
                    }
                };

                // SignatureProvider found and removed
                var cryptoProviderCache = CreateCacheForTesting();

                var signatureProvider = new CustomSignatureProvider(new DerivedSecurityKey("kid", 256), ALG.HmacSha256);
                cryptoProviderCache.TryAdd(signatureProvider);
                theoryData.Add(new CryptoProviderCacheTheoryData
                {
                    CryptoProviderCache = cryptoProviderCache,
                    SignatureProvider = signatureProvider,
                    TestId = "SignatureProviderRemoved"
                });

                // SignatureProvider was removed above, so should not be found
                theoryData.Add(new CryptoProviderCacheTheoryData
                {
                    CryptoProviderCache = cryptoProviderCache,
                    Removed = false,
                    SignatureProvider = signatureProvider,
                    TestId = "SignatureProviderWasNotRemoved"
                });

                cryptoProviderCache = CreateCacheForTesting();

                signatureProvider = new CustomSignatureProvider(new DerivedSecurityKey("kid", 256), ALG.HmacSha256);
                cryptoProviderCache.TryAdd(signatureProvider);

                // signatureprovider with different algorithm
                theoryData.Add(new CryptoProviderCacheTheoryData
                {
                    CryptoProviderCache = cryptoProviderCache,
                    Removed = false,
                    SignatureProvider = new CustomSignatureProvider(new DerivedSecurityKey("kid", 256), ALG.HmacSha384),
                    TestId = "AlgorithmNotMatched"
                });

                // signatureprovider with different kid
                theoryData.Add(new CryptoProviderCacheTheoryData
                {
                    CryptoProviderCache = cryptoProviderCache,
                    Removed = false,
                    SignatureProvider = new CustomSignatureProvider(new DerivedSecurityKey("kid2", 256), ALG.HmacSha256),
                    TestId = "KeyIdNotMatched"
                });

                // signatureprovider with different type, the remove will fail
                signatureProvider = new CustomSignatureProvider(new DerivedSecurityKey("kid", 256), ALG.HmacSha256);
                cryptoProviderCache.TryAdd(signatureProvider);
                theoryData.Add(new CryptoProviderCacheTheoryData
                {
                    CryptoProviderCache = cryptoProviderCache,
                    Removed = false,
                    SignatureProvider = new SignatureProviderForTestingCache(new DerivedSecurityKey("kid", 256), ALG.HmacSha256) { CryptoProviderCache = cryptoProviderCache },
                    TestId = "SignatureProviderTypeNotMatched"
                });

                theoryData.Add(new CryptoProviderCacheTheoryData
                {
                    CryptoProviderCache = cryptoProviderCache,
                    Removed = false,
                    SignatureProvider = new CustomSignatureProvider(new DerivedSecurityKey("kid", 256), ALG.HmacSha256, false) { CryptoProviderCache = cryptoProviderCache },
                    TestId = "SignatureProviderTypeMatchedWillCreateSignaturesDifferent"
                });

                return theoryData;
            }
        }
    }

    public class SignatureProviderForTestingCache : CustomSignatureProvider
    {
        public SignatureProviderForTestingCache(SecurityKey key, string algorithm)
            : base(key, algorithm)
        {
        }
    }

    public class CryptoProviderCacheTheoryData : TheoryDataBase, IDisposable
    {
        public bool Added { get; set; } = true;

        public string Algorithm { get; set; }

#if NET
        public CryptoProviderCache CryptoProviderCache { get; set; }
#elif NET462 || NET472
        public CryptoProviderCache CryptoProviderCache { get; set; }
#endif

        public bool Found { get; set; }

        public InMemoryCryptoProviderCachePublic InMemoryCryptoProviderCachePublic { get; set; } = new InMemoryCryptoProviderCachePublic();

        public bool Removed { get; set; } = true;

        public SecurityKey SecurityKey { get; set; }

        public bool ShouldCacheKeysMatch { get; set; } = true;

        public SignatureProvider SignatureProvider { get; set; }

        public string TypeofProvider { get; set; }

        public bool WillCreateSignatures { get; set; }

        public void Dispose()
        {
            InMemoryCryptoProviderCachePublic?.Dispose();
        }
    }

    public class InMemoryCryptoProviderCachePublic : InMemoryCryptoProviderCache
    {
        public InMemoryCryptoProviderCachePublic() : base(new CryptoProviderCacheOptions(), TaskCreationOptions.None, 50)
        { }

        public bool DisposeCalled { get; set; }

        public string GetCacheKeyPublic(SignatureProvider signatureProvider)
        {
            return base.GetCacheKey(signatureProvider);
        }

        public string GetCacheKeyPublic(SecurityKey securityKey, string algorithm, string typeofProvider)
        {
            return base.GetCacheKey(securityKey, algorithm, typeofProvider);
        }

        protected override void Dispose(bool disposing)
        {
            DisposeCalled = true;
            base.Dispose(disposing);
        }
    }
}

#pragma warning restore CS3016 // Arrays as attribute arguments is not CLS-compliant
