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
using System.Threading;
using System.Threading.Tasks;
using Microsoft.IdentityModel.Logging;

namespace Microsoft.IdentityModel.Tokens
{
    /// <summary>
    /// Represents a generic configuration manager.
    /// </summary>
    public abstract class BaseConfigurationManager
    {
        private TimeSpan _automaticRefreshInterval = DefaultAutomaticRefreshInterval;
        private TimeSpan _refreshInterval = DefaultRefreshInterval;

        /// <summary>
        /// Gets or sets the <see cref="TimeSpan"/> that controls how often an automatic metadata refresh should occur.
        /// </summary>
        public TimeSpan AutomaticRefreshInterval
        {
            get { return _automaticRefreshInterval; }
            set
            {
                if (value < MinimumAutomaticRefreshInterval)
                    throw LogHelper.LogExceptionMessage(new ArgumentOutOfRangeException(nameof(value), LogHelper.FormatInvariant(LogMessages.IDX10108, MinimumAutomaticRefreshInterval, value)));

                _automaticRefreshInterval = value;
            }
        }

        /// <summary>
        /// The most recently retrieved configuration.
        /// </summary>
        public BaseConfiguration CurrentConfiguration { get; set; }

        /// <summary>
        /// 12 hours is the default time interval that afterwards, <see cref="GetBaseConfigurationAsync(CancellationToken)"/> will obtain new configuration.
        /// </summary>
        public static readonly TimeSpan DefaultAutomaticRefreshInterval = new TimeSpan(0, 12, 0, 0);

        /// <summary>
        /// 5 minutes is the default time interval that must pass for <see cref="RequestRefresh"/> to obtain a new configuration.
        /// </summary>
        public static readonly TimeSpan DefaultRefreshInterval = new TimeSpan(0, 0, 5, 0);

        /// <summary>
        /// The last known good configuration or LKG (a configuration retrieved in the past that we were able to successfully validate a token against).
        /// </summary>
        public BaseConfiguration LastKnownGoodConfiguration { get; set; }

        /// <summary>
        /// The metadata address to retrieve the configuration from.
        /// </summary>
        public string MetadataAddress { get; set; }

        /// <summary>
        /// 5 minutes is the minimum value for automatic refresh. <see cref="AutomaticRefreshInterval"/> can not be set less than this value.
        /// </summary>
        public static readonly TimeSpan MinimumAutomaticRefreshInterval = new TimeSpan(0, 0, 5, 0);

        /// <summary>
        /// 1 second is the minimum time interval that must pass for <see cref="RequestRefresh"/> to  obtain new configuration.
        /// </summary>
        public static readonly TimeSpan MinimumRefreshInterval = new TimeSpan(0, 0, 0, 1);

        /// <summary>
        /// The minimum time between retrievals, in the event that a retrieval failed, or that a refresh was explicitly requested.
        /// </summary>
        public TimeSpan RefreshInterval
        {
            get { return _refreshInterval; }
            set
            {
                if (value < MinimumRefreshInterval)
                    throw LogHelper.LogExceptionMessage(new ArgumentOutOfRangeException(nameof(value), LogHelper.FormatInvariant(LogMessages.IDX10107, MinimumRefreshInterval, value)));

                _refreshInterval = value;
            }
        }

        /// <summary>
        /// Indicates whether the last known good configuraton (LKG) can be used, false by default.
        /// </summary>
        public bool UseLastKnownGoodConfiguration { get; set; } = false;

        /// <summary>
        /// Obtains an updated version of <see cref="BaseConfiguration"/> if the appropriate refresh interval has passed.
        /// This method may return a cached version of the configuration.
        /// </summary>
        /// <param name="cancel">CancellationToken</param>
        /// <returns>Configuration of type Configuration.</returns>
        public abstract Task<BaseConfiguration> GetBaseConfigurationAsync(CancellationToken cancel);

        /// <summary>
        /// Indicate that the configuration may be stale (as indicated by failing to process incoming tokens).
        /// </summary>
        public abstract void RequestRefresh();
    }
}
