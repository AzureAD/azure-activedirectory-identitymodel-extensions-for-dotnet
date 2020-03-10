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
using System.Collections.Concurrent;
using System.Globalization;
using Microsoft.IdentityModel.Logging;

namespace Microsoft.IdentityModel.Tokens
{
    /// <summary>
    /// Defines a cache for crypto providers.
    /// Current support is limited to <see cref="SignatureProvider"/> only.
    /// </summary>
    public class InMemoryCryptoProviderCache : CryptoProviderCache
    {
        private ConcurrentDictionary<string, SignatureProvider> _signingSignatureProviders = new ConcurrentDictionary<string, SignatureProvider>();
        private ConcurrentDictionary<string, SignatureProvider> _verifyingSignatureProviders = new ConcurrentDictionary<string, SignatureProvider>();

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

        private string GetCacheKeyPrivate(SecurityKey securityKey, string algorithm, string typeofProvider)
        {
            return string.Format(CultureInfo.InvariantCulture,
                                 "{0}-{1}-{2}-{3}",
                                 securityKey.GetType(),
                                 securityKey.InternalId,
                                 algorithm,
                                 typeofProvider);
        }

        /// <summary>
        /// For some security key types, in some runtimes, it's not possible to extract public key material and create an <see cref="SecurityKey.InternalId"/>.
        /// In these cases, <see cref="SecurityKey.InternalId"/> will be an empty string, and these keys should not be cached.
        /// </summary>
        /// <param name="signatureProvider"><see cref="SignatureProvider"/> to be examined.</param>
        /// <returns><c>True</c> if <paramref name="signatureProvider"/> should be cached, <c>false</c> otherwise.</returns>
        private bool ShouldCacheSignatureProvider(SignatureProvider signatureProvider)
        {
            return signatureProvider.Key.InternalId.Length != 0;
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

            if (!ShouldCacheSignatureProvider(signatureProvider))
                return false;

            var cacheKey = GetCacheKey(signatureProvider);
            if (signatureProvider.WillCreateSignatures)
            {
                if (_signingSignatureProviders.TryAdd(cacheKey, signatureProvider))
                {
                    signatureProvider.CryptoProviderCache = this;
                    return true;
                }
            }
            else
            {
                if (_verifyingSignatureProviders.TryAdd(cacheKey, signatureProvider))
                {
                    signatureProvider.CryptoProviderCache = this;
                    return true;
                }
            }

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
                return _signingSignatureProviders.TryGetValue(cacheKey, out signatureProvider);
            else
                return _verifyingSignatureProviders.TryGetValue(cacheKey, out signatureProvider);
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
            if (signatureProvider.WillCreateSignatures)
            {
                if (_signingSignatureProviders.TryRemove(cacheKey, out SignatureProvider provider))
                {
                    provider.CryptoProviderCache = null;
                    return true;
                }
            }
            else
            {
                if (_verifyingSignatureProviders.TryRemove(cacheKey, out SignatureProvider provider))
                {
                    provider.CryptoProviderCache = null;
                    return true;
                }
            }

            return false;
        }
    }
}
