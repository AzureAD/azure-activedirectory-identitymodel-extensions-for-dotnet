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
using System.ComponentModel;
using Microsoft.IdentityModel.Logging;

namespace Microsoft.IdentityModel.Tokens
{
    /// <summary>
    /// Specifies the CryptoProviderCacheOptions which can be used to configure the internal cryptoprovider cache.
    /// We are using our own simple LRU caching implementation across all targets. 
    /// See <see cref="EventBasedLRUCache{TKey, TValue}"/> for more details.
    /// </summary>
    public class CryptoProviderCacheOptions
    {
        /// <summary>
        /// Default value for <see cref="SizeLimit"/>.
        /// </summary>
        public static readonly int DefaultSizeLimit = 1000;

        private int _sizeLimit = DefaultSizeLimit;
        /// <summary>
        /// Gets or sets the size of the cache (in number of items). 
        /// 20% of the cache will be evicted whenever the cache gets to 95% of this size.
        /// Items will be evicted from least recently used to most recently used.
        /// </summary>
        public int SizeLimit
        {
            get => _sizeLimit;
            set => _sizeLimit = (value > 10) ? value : throw LogHelper.LogExceptionMessage(new ArgumentOutOfRangeException(nameof(SizeLimit), LogHelper.FormatInvariant(LogMessages.IDX10901, value)));
        }

        /// <summary>
        /// The default percentage of the cache to be removed when _maxCapacityPercentage is reached
        /// </summary>
        public const double DefaultCompactionPercentage = .20;

        private const double MinCompactionPercentageValue = DefaultCompactionPercentage;
        private const double MaxCompactionPercentageValue = 0.9;
        private double _compactionPercentage = DefaultCompactionPercentage;
        /// <summary>
        /// Gets or sets the percentage of the cache to be removed when _maxCapacityPercentage is reached.
        /// </summary>
        public double CompactionPercentage
        {
            get => _compactionPercentage;
            set => _compactionPercentage = (value >= MinCompactionPercentageValue && value <= MaxCompactionPercentageValue) ? value : throw LogHelper.LogExceptionMessage(new ArgumentOutOfRangeException(nameof(CompactionPercentage), LogHelper.FormatInvariant(LogMessages.IDX10903, MinCompactionPercentageValue, MaxCompactionPercentageValue, value)));
        }

        /// <summary>
        /// Default percentage of _capacity, when reached, _compactionPercentage% of the cache will be removed.
        /// </summary>
        public const double DefaultMaxCapacityPercentage = .95;

        private const double MinCapacityPercentageValue = 0.5;
        private const double MaxCapacityPercentageValue = 1.0;
        private double _maxCapacityPercentage = DefaultMaxCapacityPercentage;
        /// <summary>
        /// Gets or sets the percentage of _capacity, when reached, _compactionPercentage% of the cache will be removed.
        /// </summary>
        public double MaxCapacityPercentage
        {
            get => _maxCapacityPercentage;
            set => _maxCapacityPercentage = (value >= MinCapacityPercentageValue && value <= MaxCapacityPercentageValue) ? value : throw LogHelper.LogExceptionMessage(new ArgumentOutOfRangeException(nameof(MaxCapacityPercentage), LogHelper.FormatInvariant(LogMessages.IDX10904, MinCapacityPercentageValue, MaxCapacityPercentageValue, value)));
        }

        /// <summary>
        /// The default value of the period to wait to remove expired items, in seconds.
        /// </summary>
        public const int DefaultRemoveExpiredValuesIntervalInSeconds = 300;

        private int _removeExpiredValuesIntervalInSeconds = DefaultRemoveExpiredValuesIntervalInSeconds;
        /// <summary>
        /// Gets or sets the period to wait to remove expired items, in seconds.
        /// </summary>
        public int RemoveExpiredValuesIntervalInSeconds
        {
            get => _removeExpiredValuesIntervalInSeconds;
            set => _removeExpiredValuesIntervalInSeconds = (value > 0) ? value : throw LogHelper.LogExceptionMessage(new ArgumentOutOfRangeException(nameof(RemoveExpiredValuesIntervalInSeconds), LogHelper.FormatInvariant(LogMessages.IDX10905, value)));
        }

        /// <summary>
        /// Gets or sets the whether or not to remove expired items.
        /// </summary>
        public bool RemoveExpiredValues { get; set; } = false;

        /// <summary>
        /// The desired cache type for caching providers. Defaults to LRU.
        /// </summary>
        public ProviderCacheType CacheType { get; set; } = ProviderCacheType.LRU;
    }
}
