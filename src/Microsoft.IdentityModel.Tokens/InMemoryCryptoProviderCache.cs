//------------------------------------------------------------------------------
//
// Copyright (c) Microsoft Corporation.
// All rights reserved.
//
// This code is licensed under the MIT License.
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files(the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and / or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions :
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
// THE SOFTWARE.
//
//------------------------------------------------------------------------------

using System;
using System.Globalization;
using Microsoft.IdentityModel.Logging;
#if NETSTANDARD2_0 
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Options;
#endif

namespace Microsoft.IdentityModel.Tokens
{
    /// <summary>
    /// Defines a cache for crypto providers.
    /// Current support is limited to <see cref="SignatureProvider"/> only.
    /// </summary>
#if NETSTANDARD2_0
    public class InMemoryCryptoProviderCache : CryptoProviderCache, IDisposable
#elif NET45 || NET461 || NET472
    public class InMemoryCryptoProviderCache: CryptoProviderCache
#endif
    {
        internal CryptoProviderCacheOptions _cryptoProviderCacheOptions;
#if NETSTANDARD2_0 
        private readonly MemoryCache _signingSignatureProviders;
        private readonly MemoryCache _verifyingSignatureProviders;
        private bool _disposed = false;
#elif NET45 || NET461 || NET472
        private readonly ILRUCache<string, SignatureProvider> _signingSignatureProviders;
        private readonly ILRUCache<string, SignatureProvider> _verifyingSignatureProviders;
#endif

        /// <summary>
        /// Creates a new instance of <see cref="InMemoryCryptoProviderCache"/> using the default <see cref="CryptoProviderCacheOptions"/>.
        /// </summary>
        public InMemoryCryptoProviderCache() : this(new CryptoProviderCacheOptions())
        {
        }

        /// <summary>
        /// Creates a new instance of <see cref="InMemoryCryptoProviderCache"/> using the specified <paramref name="cryptoProviderCacheOptions"/>.
        /// </summary>
        /// <param name="cryptoProviderCacheOptions">The options used to configure the <see cref="InMemoryCryptoProviderCache"/>.</param>
        public InMemoryCryptoProviderCache(CryptoProviderCacheOptions cryptoProviderCacheOptions)
        {
            if (cryptoProviderCacheOptions == null)
                throw LogHelper.LogArgumentNullException(nameof(cryptoProviderCacheOptions));

            _cryptoProviderCacheOptions = cryptoProviderCacheOptions;
#if NETSTANDARD2_0
            _signingSignatureProviders = new MemoryCache(Options.Create(new MemoryCacheOptions() { SizeLimit = _cryptoProviderCacheOptions.SizeLimit }));
            _verifyingSignatureProviders = new MemoryCache(Options.Create(new MemoryCacheOptions() { SizeLimit = _cryptoProviderCacheOptions.SizeLimit }));
#elif NET45 || NET461 || NET472
            // THE CODE BELOW IS FOR TESTING ONLY.
            if (!cryptoProviderCacheOptions.UseLockingCache)
            {
                _signingSignatureProviders = new EventBasedLRUCache<string, SignatureProvider>(cryptoProviderCacheOptions.SizeLimit, StringComparer.Ordinal);
                _verifyingSignatureProviders = new EventBasedLRUCache<string, SignatureProvider>(cryptoProviderCacheOptions.SizeLimit, StringComparer.Ordinal);
            }
            else
            {
                _signingSignatureProviders = new LockingLRUCache<string, SignatureProvider>(cryptoProviderCacheOptions.SizeLimit, StringComparer.Ordinal);
                _verifyingSignatureProviders = new LockingLRUCache<string, SignatureProvider>(cryptoProviderCacheOptions.SizeLimit, StringComparer.Ordinal);
            }
#endif
        }

        /// <summary>
        /// Returns the cache key to use when looking up an entry into the cache for a <see cref="SignatureProvider" />
        /// </summary>
        /// <param name="signatureProvider">the <see cref="SignatureProvider"/> to create the key for.</param>
        /// <exception cref="ArgumentNullException">if signatureProvider is null.</exception>
        /// <returns>the cache key to use for finding a <see cref="SignatureProvider"/>.</returns>
        protected override string GetCacheKey(SignatureProvider signatureProvider)
        {
            if (signatureProvider == null)
                throw LogHelper.LogArgumentNullException(nameof(signatureProvider));

            return GetCacheKeyPrivate(signatureProvider.Key, signatureProvider.Algorithm, signatureProvider.GetType().ToString());
        }

        /// <summary>
        /// Returns the 'key' that will be used to find a crypto provider in this cache.
        /// </summary>
        /// <param name="securityKey">the key that is used to by the crypto provider.</param>
        /// <param name="algorithm">the algorithm that is used by the crypto provider.</param>
        /// <param name="typeofProvider">the typeof the crypto provider obtained by calling object.GetType().</param>
        /// <exception cref="ArgumentNullException">if securityKey is null.</exception>
        /// <exception cref="ArgumentNullException">if algorithm is null or empty string.</exception>
        /// <exception cref="ArgumentNullException">if typeofProvider is null or empty string.</exception>
        /// <returns>the cache key to use for finding a crypto provider.</returns>
        protected override string GetCacheKey(SecurityKey securityKey, string algorithm, string typeofProvider)
        {
            if (securityKey == null)
                throw LogHelper.LogArgumentNullException(nameof(securityKey));

            if (string.IsNullOrEmpty(algorithm))
                throw LogHelper.LogArgumentNullException(nameof(algorithm));

            if (string.IsNullOrEmpty(typeofProvider))
                throw LogHelper.LogArgumentNullException(nameof(typeofProvider));

            return GetCacheKeyPrivate(securityKey, algorithm, typeofProvider);
        }

        private static string GetCacheKeyPrivate(SecurityKey securityKey, string algorithm, string typeofProvider)
        {
            return string.Format(CultureInfo.InvariantCulture,
                                 "{0}-{1}-{2}-{3}",
                                 securityKey.GetType(),
                                 securityKey.InternalId,
                                 algorithm,
                                 typeofProvider);
        }

        /// <summary>
        /// Trys to adds a <see cref="SignatureProvider"/> to this cache.
        /// </summary>
        /// <param name="signatureProvider"><see cref="SignatureProvider"/> to cache.</param>
        /// <exception cref="ArgumentNullException">if signatureProvider is null.</exception>
        /// <returns>
        /// <c>true</c> if the <see cref="SignatureProvider"/> was added, <c>false</c> if the cache already contained the <see cref="SignatureProvider"/> or if <see cref="SignatureProvider"/> should not be cached.
        /// </returns>
        /// <remarks>if the <see cref="SignatureProvider"/> is added <see cref="SignatureProvider.CryptoProviderCache"/> will be set to 'this'.</remarks>
        public override bool TryAdd(SignatureProvider signatureProvider)
        {
            if (signatureProvider == null)
                throw LogHelper.LogArgumentNullException(nameof(signatureProvider));

            var cacheKey = GetCacheKey(signatureProvider);
#if NETSTANDARD2_0 
            MemoryCache signatureProviderCache;
#elif NET45 || NET461 || NET472
            ILRUCache<string, SignatureProvider> signatureProviderCache;
#endif
            // Determine if we are caching a signing or a verifying SignatureProvider.
            if (signatureProvider.WillCreateSignatures)
                signatureProviderCache = _signingSignatureProviders;
            else
                signatureProviderCache = _verifyingSignatureProviders;

#if NETSTANDARD2_0 
            // The cache does NOT already have a crypto provider associated with this key.
            if (!signatureProviderCache.TryGetValue(cacheKey, out _))
            {
                signatureProviderCache.Set(cacheKey, signatureProvider, new MemoryCacheEntryOptions
                {
                    SlidingExpiration = TimeSpan.FromDays(1),
                    Size = 1,
                });
                signatureProvider.CryptoProviderCache = this;
                return true;
            }
#elif NET45 || NET461 || NET472
            // The cache does NOT already have a crypto provider associated with this key.
            if (!signatureProviderCache.Contains(cacheKey))
            {
                signatureProviderCache.SetValue(cacheKey, signatureProvider);
                signatureProvider.CryptoProviderCache = this;
                return true;
            }
#endif

            return false;
        }

        /// <summary>
        /// Trys to find a <see cref="SignatureProvider"/> to this cache.
        /// </summary>
        /// <param name="securityKey">the key that is used to by the crypto provider.</param>
        /// <param name="algorithm">the algorithm that is used by the crypto provider.</param>
        /// <param name="typeofProvider">the typeof the crypto provider obtained by calling object.GetType().</param>
        /// <param name="willCreateSignatures">a bool to indicate if the <see cref="SignatureProvider"/> will be used to sign.</param>
        /// <param name="signatureProvider">the <see cref="SignatureProvider"/> if found.</param>
        /// <exception cref="ArgumentNullException">if securityKey is null.</exception>
        /// <exception cref="ArgumentNullException">if algorithm is null or empty string.</exception>
        /// <exception cref="ArgumentNullException">if typeofProvider is null or empty string.</exception>
        /// <returns>true if a <see cref="SignatureProvider"/> was found, false otherwise.</returns>
        public override bool TryGetSignatureProvider(SecurityKey securityKey, string algorithm, string typeofProvider, bool willCreateSignatures, out SignatureProvider signatureProvider)
        {
            if (securityKey == null)
                throw LogHelper.LogArgumentNullException(nameof(securityKey));

            if (string.IsNullOrEmpty(algorithm))
                throw LogHelper.LogArgumentNullException(nameof(algorithm));

            if (string.IsNullOrEmpty(typeofProvider))
                throw LogHelper.LogArgumentNullException(nameof(typeofProvider));

            var cacheKey = GetCacheKeyPrivate(securityKey, algorithm, typeofProvider);
            if (willCreateSignatures)
#if NETSTANDARD2_0
                return _signingSignatureProviders.TryGetValue(cacheKey, out signatureProvider);
#elif NET45 || NET461 || NET472
                return _signingSignatureProviders.TryGetValue(cacheKey, out signatureProvider);
#endif
            else
#if NETSTANDARD2_0 
                return _verifyingSignatureProviders.TryGetValue(cacheKey, out signatureProvider);
#elif NET45 || NET461 || NET472
                return _verifyingSignatureProviders.TryGetValue(cacheKey, out signatureProvider);
#endif
        }

        /// <summary>
        /// Trys to remove a <see cref="SignatureProvider"/> from this cache.
        /// </summary>
        /// <param name="signatureProvider"><see cref="SignatureProvider"/> to remove.</param>
        /// <exception cref="ArgumentNullException">if signatureProvider is null.</exception>
        /// <returns>true if the <see cref="SignatureProvider"/> was removed, false if the <see cref="SignatureProvider"/> was not found.</returns>
        /// <remarks>if the <see cref="SignatureProvider"/> is removed <see cref="SignatureProvider.CryptoProviderCache"/> will be set to null.</remarks>
        public override bool TryRemove(SignatureProvider signatureProvider)
        {
            if (signatureProvider == null)
                throw LogHelper.LogArgumentNullException(nameof(signatureProvider));

            if (!ReferenceEquals(signatureProvider.CryptoProviderCache, this))
                return false;

            var cacheKey = GetCacheKey(signatureProvider);
#if NETSTANDARD2_0 
            MemoryCache signatureProviderCache;
#elif NET45 || NET461 || NET472
            ILRUCache<string, SignatureProvider> signatureProviderCache;
#endif
            // Determine if we are caching a signing or a verifying SignatureProvider.
            if (signatureProvider.WillCreateSignatures)
                signatureProviderCache = _signingSignatureProviders;
            else
                signatureProviderCache = _verifyingSignatureProviders;

            try
            {
#if NET45 || NET461 || NET472
                if (signatureProviderCache.TryRemove(cacheKey, out SignatureProvider provider))
                {
                    provider.CryptoProviderCache = null;
                    return true;
                }
                else
                {
                    return false; 
                }
#elif NETSTANDARD2_0
                if (signatureProviderCache.TryGetValue(cacheKey, out SignatureProvider provider))
                {
                    signatureProviderCache.Remove(cacheKey);
                    provider.CryptoProviderCache = null;
                    return true;
                }
                else
                {
                    return false;
                }
#endif
            }
            catch (Exception ex)
            {
                LogHelper.LogWarning(LogHelper.FormatInvariant(LogMessages.IDX10699, cacheKey, ex));
                return false;
            }
        }

#if NETSTANDARD2_0
        /// <summary>
        /// Calls <see cref="Dispose(bool)"/> and <see cref="GC.SuppressFinalize"/>
        /// </summary>
        public void Dispose()
        {
            // Dispose of unmanaged resources.
            Dispose(true);
            // Suppress finalization.
            GC.SuppressFinalize(this);
        }

        /// <summary>
        /// If <paramref name="disposing"/> is true, this method disposes of <see cref="_signingSignatureProviders"/> and <see cref="_verifyingSignatureProviders"/>.
        /// </summary>
        /// <param name="disposing">True if called from the <see cref="Dispose()"/> method, false otherwise.</param>
        protected virtual void Dispose(bool disposing)
        {
            if (!_disposed)
            {
                _disposed = true;
                if (disposing)
                {
                    _signingSignatureProviders.Dispose();
                    _verifyingSignatureProviders.Dispose();
                }
            }
        }
#endif

        #region FOR TESTING TO BE REMOVED OR INTERNAL BEFORE RELEASE
        /// <summary>
        /// FOR TESTING ONLY.
        /// </summary>
#if NETSTANDARD2_0
        public static long LinkedListCountSigning()
        {
            return 0;
#elif NET45 || NET461 || NET472
        public long LinkedListCountSigning()
        {
            return _signingSignatureProviders.LinkedListCount;
#endif
        }

        /// <summary>
        /// FOR TESTING ONLY.
        /// </summary>
#if NETSTANDARD2_0
        public static long LinkedListCountVerifying()
        {
            return 0;
#elif NET45 || NET461 || NET472
        public long LinkedListCountVerifying()
        {
            return _verifyingSignatureProviders.LinkedListCount;
#endif
        }

        /// <summary>
        /// FOR TESTING ONLY.
        /// </summary>
        public long MapCountSigning()
        {
#if NETSTANDARD2_0
            return _signingSignatureProviders.Count;
#elif NET45 || NET461 || NET472
            return _signingSignatureProviders.MapCount;
#endif
        }

        /// <summary>
        /// FOR TESTING ONLY.
        /// </summary>
        public long MapCountVerifying()
        {
#if NETSTANDARD2_0
            return _signingSignatureProviders.Count;
#elif NET45 || NET461 || NET472
            return _verifyingSignatureProviders.MapCount;
#endif
        }

        /// <summary>
        /// FOR TESTING ONLY.
        /// </summary>
#if NETSTANDARD2_0
        public static long EventQueueCountSigning()
        {
            return 0;
#elif NET45 || NET461 || NET472
        public long EventQueueCountSigning()
        {
            return _signingSignatureProviders.EventQueueCount;
#endif
        }

        /// <summary>
        /// FOR TESTING ONLY.
        /// </summary>
#if NETSTANDARD2_0
        public static long EventQueueCountVerifying()
        {
            return 0;
#elif NET45 || NET461 || NET472
        public long EventQueueCountVerifying()
        {
            return _verifyingSignatureProviders.EventQueueCount;
#endif
        }
    #endregion
    }
}
