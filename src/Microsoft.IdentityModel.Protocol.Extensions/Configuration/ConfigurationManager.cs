//-----------------------------------------------------------------------
// Copyright (c) Microsoft Open Technologies, Inc.
// All Rights Reserved
// Apache License 2.0
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
// 
// http://www.apache.org/licenses/LICENSE-2.0
// 
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//-----------------------------------------------------------------------

using System;
using System.Diagnostics.Contracts;
using System.Globalization;
using System.IdentityModel;
using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;

namespace Microsoft.IdentityModel.Protocols
{
    /// <summary>
    /// Manages the retrieval of Configuration data.
    /// </summary>
    /// <typeparam name="T">must be a class.</typeparam>
    [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Design", "CA1001:TypesThatOwnDisposableFieldsShouldBeDisposable")]
    public class ConfigurationManager<T> : IConfigurationManager<T> where T : class
    {
        /// <summary>
        /// 5 days is the default time interval that afterwards, <see cref="GetConfigurationAsync()"/> will obtain new configuration.
        /// </summary>
        public static readonly TimeSpan DefaultAutomaticRefreshInterval = new TimeSpan(5, 0, 0, 0);

        /// <summary>
        /// 30 seconds is the default time interval that must pass for <see cref="RequestRefresh"/> to obtain a new configuration.
        /// </summary>
        public static readonly TimeSpan DefaultRefreshInterval = new TimeSpan(0, 0, 0, 30);

        /// <summary>
        /// 5 minutes is the minimum value for automatic refresh. <see cref="AutomaticRefreshInterval"/> can not be set less than this value.
        /// </summary>
        public static readonly TimeSpan MinimumAutomaticRefreshInterval = new TimeSpan(0, 0, 5, 0);

        /// <summary>
        /// 1 second is the minimum time interval that must pass for <see cref="RequestRefresh"/> to obtain new configuration.
        /// </summary>
        public static readonly TimeSpan MinimumRefreshInterval = new TimeSpan(0, 0, 0, 1);

        private TimeSpan _automaticRefreshInterval = DefaultAutomaticRefreshInterval;
        private TimeSpan _refreshInterval = DefaultRefreshInterval;
        private DateTimeOffset _syncAfter = DateTimeOffset.MinValue;
        private DateTimeOffset _lastRefresh = DateTimeOffset.MinValue;

        private readonly SemaphoreSlim _refreshLock;
        private readonly string _metadataAddress;
        private readonly IDocumentRetriever _docRetriever;
        private readonly IConfigurationRetriever<T> _configRetriever;
        private T _currentConfiguration;

        /// <summary>
        /// Instantiaties a new <see cref="ConfigurationManager{T}"/> that manages automatic and controls refreshing on configuration data.
        /// </summary>
        /// <param name="metadataAddress">the address to obtain configuration.</param>
        public ConfigurationManager(string metadataAddress)
            : this(metadataAddress, new GenericDocumentRetriever())
        {
        }

        /// <summary>
        /// Instantiaties a new <see cref="ConfigurationManager{T}"/> that manages automatic and controls refreshing on configuration data.
        /// </summary>
        /// <param name="metadataAddress">the address to obtain configuration.</param>
        /// <param name="httpClient">the client to use when obtaining configuration.</param>
        public ConfigurationManager(string metadataAddress, HttpClient httpClient)
            : this(metadataAddress, new HttpDocumentRetriever(httpClient))
        {
        }

        /// <summary>
        /// Instantiaties a new <see cref="ConfigurationManager{T}"/> that manages automatic and controls refreshing on configuration data.
        /// </summary>
        /// <param name="metadataAddress">the address to obtain configuration.</param>
        /// <param name="docRetriever">the <see cref="IDocumentRetriever"/> that reaches out to obtain the configuration.</param>
        public ConfigurationManager(string metadataAddress, IDocumentRetriever docRetriever)
        {
            if (!typeof(T).Equals(typeof(WsFederationConfiguration)) && (!typeof(T).Equals(typeof(OpenIdConnectConfiguration))))
            {
                throw new NotImplementedException(typeof(T).FullName);
            }

            if (string.IsNullOrWhiteSpace(metadataAddress))
            {
                throw new ArgumentNullException("metadataAddress");
            }

            if (docRetriever == null)
            {
                throw new ArgumentNullException("retriever");
            }

            _metadataAddress = metadataAddress;
            _docRetriever = docRetriever;
            _configRetriever = GetConfigurationRetriever();
            _refreshLock = new SemaphoreSlim(1);
        }

        /// <summary>
        /// Gets or sets the <see cref="TimeSpan"/> that controls how often an automatic metadata refresh should occur.
        /// </summary>
        public TimeSpan AutomaticRefreshInterval
        {
            get { return _automaticRefreshInterval; }
            set
            {
                if (value < MinimumAutomaticRefreshInterval)
                {
                    throw new ArgumentOutOfRangeException("value", value, string.Format(CultureInfo.InvariantCulture, ErrorMessages.IDX10107, MinimumAutomaticRefreshInterval, value));
                }
                _automaticRefreshInterval = value;
            }
        }

        /// <summary>
        /// The minimum time between retrievals, in the event that a retrieval failed, or that a refresh was explicitly requested.
        /// </summary>
        public TimeSpan RefreshInterval
        {
            get { return _refreshInterval; }
            set
            {
                if (value < MinimumRefreshInterval)
                {
                    throw new ArgumentOutOfRangeException("value", value, string.Format(CultureInfo.InvariantCulture, ErrorMessages.IDX10106, MinimumRefreshInterval, value));
                }
                _refreshInterval = value;
            }
        }

        /// <summary>
        /// Gets the current <see cref="IConfigurationRetriever{T}"/> that is used to obtain configuration.
        /// </summary>
        /// <returns>Configuration of type T.</returns>
        private static IConfigurationRetriever<T> GetConfigurationRetriever()
        {
            if (typeof(T).Equals(typeof(WsFederationConfiguration)))
            {
                return (IConfigurationRetriever<T>)new WsFederationConfigurationRetriever();
            }
            if (typeof(T).Equals(typeof(OpenIdConnectConfiguration)))
            {
                return (IConfigurationRetriever<T>)new OpenIdConnectConfigurationRetriever();
            }
            throw new NotImplementedException(typeof(T).FullName);
        }

        /// <summary>
        /// Obtains an updated version of Configuration.
        /// </summary>
        /// <returns>Configuration of type T.</returns>
        /// <remarks>If the time since the last call is less than <see cref="AutomaticRefreshInterval"/> then <see cref="IConfigurationRetriever{T}.GetConfigurationAsync"/> is not called and the current Configuration is returned.</remarks>
        public async Task<T> GetConfigurationAsync()
        {
            return await GetConfigurationAsync(CancellationToken.None);
        }

        /// <summary>
        /// Obtains an updated version of Configuration.
        /// </summary>
        /// <param name="cancel">CancellationToken</param>
        /// <returns>Configuration of type T.</returns>
        /// <remarks>If the time since the last call is less than <see cref="AutomaticRefreshInterval"/> then <see cref="IConfigurationRetriever{T}.GetConfigurationAsync"/> is not called and the current Configuration is returned.</remarks>
        public async Task<T> GetConfigurationAsync(CancellationToken cancel)
        {
            DateTimeOffset now = DateTimeOffset.UtcNow;
            if (_currentConfiguration != null && _syncAfter > now)
            {
                return _currentConfiguration;
            }

            await _refreshLock.WaitAsync(cancel);
            try
            {
                Exception retrieveEx = null;
                if (_syncAfter <= now)
                {
                    try
                    {
                        // Don't use the individual CT here, this is a shared operation that shouldn't be affected by an individual's cancellation.
                        // The transport should have it's own timeouts, etc..

                        _currentConfiguration = await _configRetriever.GetConfigurationAsync(_metadataAddress, _docRetriever, CancellationToken.None).ConfigureAwait(false);
                        Contract.Assert(_currentConfiguration != null);
                        _lastRefresh = now;
                        _syncAfter = DateTimeUtil.Add(now.UtcDateTime, _automaticRefreshInterval);
                    }
                    catch (Exception ex)
                    {
                        retrieveEx = ex;
                        _syncAfter = DateTimeUtil.Add(now.UtcDateTime, _automaticRefreshInterval < _refreshInterval ? _automaticRefreshInterval : _refreshInterval);
                    }
                }

                if (_currentConfiguration == null)
                {
                    throw new InvalidOperationException(string.Format(CultureInfo.InvariantCulture, ErrorMessages.IDX10803, _metadataAddress ?? "null"), retrieveEx);
                }

                // Stale metadata is better than no metadata
                return _currentConfiguration;
            }
            finally
            {
                _refreshLock.Release();
            }
        }

        /// <summary>
        /// Requests that then next call to <see cref="GetConfigurationAsync()"/> obtain new configuration.
        /// <para>if the last refresh was greater than <see cref="RefreshInterval"/> then the next call to <see cref="GetConfigurationAsync()"/> will retrieve new configuration.</para>
        /// <para>if <see cref="RefreshInterval"/> == <see cref="TimeSpan.MaxValue"/> then this method is essentially an no-op.</para>
        /// </summary>
        public void RequestRefresh()
        {
            DateTimeOffset now = DateTimeOffset.UtcNow;
            if (now >= DateTimeUtil.Add(_lastRefresh.UtcDateTime, RefreshInterval))
            {
                _syncAfter = now;
            }
        }
    }
}
