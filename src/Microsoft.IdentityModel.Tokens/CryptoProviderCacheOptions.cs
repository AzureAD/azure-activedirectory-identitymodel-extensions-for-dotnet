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
    /// Specifies the CryptoProviderCacheOptions which can be used to configure the internal cryptoprovider cache.
    /// For the netstandard2.0 target we are using the Microsoft.Extensions.Caching.Memory.MemoryCache class:
    /// https://docs.microsoft.com/en-us/dotnet/api/microsoft.extensions.caching.memory.memorycache
    /// For the net45, net461, and net472 desktop targets we are using our own simple LRU caching implementation.
    /// See <see cref="EventBasedLRUCache{TKey, TValue}"/> for more details.
    /// We recommend upgrading to netstandard2.0 for a more comprehensive caching experience.
    /// Any property on these CryptoProviderCacheOptions that corresponds directly to a property 
    /// used by Microsoft.Extensions.Caching.Memory.MemoryCache has the same name.
    /// </summary>
    public class CryptoProviderCacheOptions
    {
        private int _sizeLimit = DefaultSizeLimit;

        /// <summary>
        /// Default value for <see cref="SizeLimit"/>.
        /// </summary>
        public static readonly int DefaultSizeLimit = 1000;

        /// <summary>
        /// Gets or sets the size of the cache (in number of items). 
        /// 20% of the cache will be evicted whenever the cache gets to 95% of this size.
        /// On the netstandard2.0 target, items will be evicted in the following order:
        /// 1) All expired items.
        /// 2) Least recently used items.
        /// 3) Items with the earliest absolute expiration.
        /// On the net45, net461, and net472 targets, only #2 (least recently used items) will be
        /// taken into consideration.
        /// </summary>
        public int SizeLimit
        {
            get
            {
                return _sizeLimit;
            }
            set
            {
                _sizeLimit = (value > 10) ? value : throw LogHelper.LogExceptionMessage(new ArgumentOutOfRangeException(nameof(SizeLimit), LogHelper.FormatInvariant(LogMessages.IDX10901, value)));
            }
        }
    }
}
