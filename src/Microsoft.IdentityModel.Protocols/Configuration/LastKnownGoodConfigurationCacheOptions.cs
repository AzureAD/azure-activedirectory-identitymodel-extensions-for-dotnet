// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System;
using System.Collections.Generic;
using Microsoft.IdentityModel.Logging;
using Microsoft.IdentityModel.Tokens;
using Microsoft.IdentityModel.Tokens.Configuration;

namespace Microsoft.IdentityModel.Protocols.Configuration
{
    /// <summary>
    /// Specifies the LastKnownGoodConfigurationCacheOptions which can be used to configure the internal LKG configuration cache.
    /// See <see cref="EventBasedLRUCache{TKey, TValue}"/> for more details.
    /// </summary>
    public class LastKnownGoodConfigurationCacheOptions
    {
        private IEqualityComparer<BaseConfiguration> _baseConfigurationComparer = new BaseConfigurationComparer();
        private int _lastKnownGoodConfigurationSizeLimit = DefaultLastKnownGoodConfigurationSizeLimit;

        /// <summary>
        /// 10 is the default size limit of the cache (in number of items) for last known good configuration.
        /// </summary>
        public static readonly int DefaultLastKnownGoodConfigurationSizeLimit = LKGConfigurationCacheOptions.DefaultLastKnownGoodConfigurationSizeLimit;

        /// <summary>
        /// Gets or sets the BaseConfgiurationComparer that to compare <see cref="BaseConfiguration"/>.
        /// </summary>
        public IEqualityComparer<BaseConfiguration> BaseConfigurationComparer
        {
            get { return _baseConfigurationComparer; }
            set
            {
                _baseConfigurationComparer = value ?? throw LogHelper.LogExceptionMessage(new ArgumentNullException(nameof(value)));
            }
        }

        /// <summary>
        /// The size limit of the cache (in number of items) for last known good configuration.
        /// </summary>
        public int LastKnownGoodConfigurationSizeLimit
        {
            get { return _lastKnownGoodConfigurationSizeLimit; }
            set
            {
                _lastKnownGoodConfigurationSizeLimit = (value > 0) ? value : throw LogHelper.LogExceptionMessage(new ArgumentOutOfRangeException(nameof(value)));
            }
        }

        /// <summary>
        /// Defines an implicit conversion of a <see cref="LastKnownGoodConfigurationCacheOptions"/> object to an <see cref="LKGConfigurationCacheOptions"/> object.
        /// See https://learn.microsoft.com/en-us/dotnet/csharp/language-reference/operators/user-defined-conversion-operators for more details.
        /// </summary>
        /// <param name="options">the <see cref="LastKnownGoodConfigurationCacheOptions"/> object to be converted</param>
        public static implicit operator LKGConfigurationCacheOptions(LastKnownGoodConfigurationCacheOptions options)
        {
            if (options == null)
            {
                return null;
            }

            return options.ToLKGConfigurationCacheOptions();
        }

        /// <summary>
        /// Converts this to a <see cref="LKGConfigurationCacheOptions"/> object.
        /// Rule CA2225 requires an alternative member named ToLKGConfigurationCacheOptions(), see https://learn.microsoft.com/en-us/dotnet/fundamentals/code-analysis/quality-rules/ca2225.
        /// </summary>
        /// <returns>an <see cref="LKGConfigurationCacheOptions"/> object</returns>
        public LKGConfigurationCacheOptions ToLKGConfigurationCacheOptions()
        {
            return new LKGConfigurationCacheOptions
            {
                BaseConfigurationComparer = this.BaseConfigurationComparer,
                LastKnownGoodConfigurationSizeLimit = this.LastKnownGoodConfigurationSizeLimit
            };
        }
    }
}
