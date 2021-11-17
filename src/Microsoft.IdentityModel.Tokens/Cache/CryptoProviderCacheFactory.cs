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
// all copies or substantial portions of the Software.CryptoProviderCacheOptions
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
using Microsoft.IdentityModel.Logging;

namespace Microsoft.IdentityModel.Tokens
{
    /// <summary>
    /// The factory that creates the <see cref="InMemoryCryptoProviderCache"/> and the signature provider caches it contains (_signingSignatureProviders and _verifyingSignatureProviders) based on the <see cref="CryptoProviderCacheOptions"/>.
    /// </summary>
    internal class CryptoProviderCacheFactory
    {
        internal static CryptoProviderCache Create() => Create(new CryptoProviderCacheOptions());

        /// <summary>
        /// Create a new instance of <see cref="InMemoryCryptoProviderCache"/> and the _signingSignatureProviders and _verifyingSignatureProviders caches based on the cache type in _cryptoProviderCacheOptions.
        /// </summary>
        /// <param name="cryptoProviderCacheOptions">Specifies the options which can be used to configure the internal cryptoprovider cache.</param>
        /// <returns>A new instance of CryptoProviderCache.</returns>
        internal static CryptoProviderCache Create(CryptoProviderCacheOptions cryptoProviderCacheOptions)
        {
            if (cryptoProviderCacheOptions == null)
                throw LogHelper.LogArgumentNullException(nameof(cryptoProviderCacheOptions));

            IProviderCache<string, SignatureProvider> signingProvidersCache;
            IProviderCache<string, SignatureProvider> verifyingProvidersCache;

            // Create the signature provider caches based on the ProviderCacheType.
            signingProvidersCache = CreateSignatureProviderCache(cryptoProviderCacheOptions);
            verifyingProvidersCache = CreateSignatureProviderCache(cryptoProviderCacheOptions);

            return new InMemoryCryptoProviderCache(cryptoProviderCacheOptions, signingProvidersCache, verifyingProvidersCache);
        }

        /// <summary>
        /// Create a new instance of SignatureProvider cache based on the cache type in _cryptoProviderCacheOptions.
        /// </summary>
        /// <param name="cryptoProviderCacheOptions">Specifies the options which can be used to configure the internal cryptoprovider cache.</param>
        /// <returns>A new instance of SignatureProvider.</returns>
        internal static IProviderCache<string, SignatureProvider> CreateSignatureProviderCache(CryptoProviderCacheOptions cryptoProviderCacheOptions)
        {
            if (cryptoProviderCacheOptions.CacheType == ProviderCacheType.LRU)
            {
                return new EventBasedLRUCache<string, SignatureProvider>(cryptoProviderCacheOptions, StringComparer.Ordinal) { OnItemRemoved = (SignatureProvider signatureProvider) => signatureProvider.CryptoProviderCache = null };
            }
            else
            {
                return new MaximumSizeCache<string, SignatureProvider>(cryptoProviderCacheOptions, StringComparer.Ordinal) { OnItemRemoved = (SignatureProvider signatureProvider) => signatureProvider.CryptoProviderCache = null };
            }
        }
    }
}
