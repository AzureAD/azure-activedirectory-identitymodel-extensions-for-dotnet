using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.IdentityModel.Tokens;
using Microsoft.Extensions.Caching.Distributed;
using Microsoft.Extensions.Caching.Redis;
using Microsoft.IdentityModel.Logging;
using System.Net.Http;

namespace Microsoft.IdentityModel.Protocols.Configuration
{
    /// <summary>
    /// 
    /// </summary>
    /// <typeparam name="T"></typeparam>
    public class DistributedConfigurationManager<T> :
        BaseConfigurationManager,
        IDistributedConfigurationManager<T>,
        IDisposable
        where T : class
    {
        private DateTimeOffset _syncAfter = DateTimeOffset.MinValue;
        private DateTimeOffset _lastRefresh = DateTimeOffset.MinValue;
        private bool _isFirstRefreshRequest = true;

        private readonly SemaphoreSlim _refreshLock;
        private readonly IDocumentRetriever _docRetriever;
        private readonly IDistributedConfigurationRetriever<T> _distributedConfigurationRetriever;
        private readonly IConfigurationValidator<T> _configValidator;
        private readonly DistributedConfigurationOptions _distributedConfigurationOptions;
        private readonly IDistributedCache _l2Cache = new RedisCache(new RedisCacheOptions());
        private readonly IConfigurationDeserializer<T> _configurationDeserializer;
        private T _currentConfiguration;
        private Exception _fetchMetadataFailure;
        private TimeSpan _bootstrapRefreshInterval = TimeSpan.FromSeconds(1);

        private bool _disposed = false; // To detect redundant calls

        /// <summary>
        /// Instantiates a new <see cref="ConfigurationManager{T}"/> that manages automatic and controls refreshing on configuration data.
        /// </summary>
        /// <param name="metadataAddress">The address to obtain configuration.</param>
        /// <param name="configRetriever">The <see cref="IDistributedConfigurationRetriever{T}"/></param>
        /// <param name="configurationDeserializer">The <see cref="IConfigurationDeserializer{T}"/></param>
        public DistributedConfigurationManager(
            string metadataAddress,
            IDistributedConfigurationRetriever<T> configRetriever,
            IConfigurationDeserializer<T> configurationDeserializer)
            : this(metadataAddress, configRetriever, new HttpDocumentRetriever(), new LastKnownGoodConfigurationCacheOptions(), new DistributedConfigurationOptions(), configurationDeserializer)
        {
        }

        /// <summary>
        /// Instantiates a new <see cref="ConfigurationManager{T}"/> that manages automatic and controls refreshing on configuration data.
        /// </summary>
        /// <param name="metadataAddress">The address to obtain configuration.</param>
        /// <param name="configRetriever">The <see cref="IDistributedConfigurationRetriever{T}"/></param>
        /// <param name="httpClient">The client to use when obtaining configuration.</param>
        /// <param name="configurationDeserializer">The <see cref="IConfigurationDeserializer{T}"/></param>
        public DistributedConfigurationManager(
            string metadataAddress,
            IDistributedConfigurationRetriever<T> configRetriever,
            HttpClient httpClient,
            IConfigurationDeserializer<T> configurationDeserializer)
            : this(metadataAddress, configRetriever, new HttpDocumentRetriever(httpClient), new LastKnownGoodConfigurationCacheOptions(), new DistributedConfigurationOptions(), configurationDeserializer)
        {
        }

        /// <summary>
        /// Instantiates a new <see cref="ConfigurationManager{T}"/> that manages automatic and controls refreshing on configuration data.
        /// </summary>
        /// <param name="metadataAddress">The address to obtain configuration.</param>
        /// <param name="configRetriever">The <see cref="IDistributedConfigurationRetriever{T}"/></param>
        /// <param name="docRetriever">The <see cref="IDocumentRetriever"/> that reaches out to obtain the configuration.</param>
        /// <param name="configurationDeserializer">The <see cref="IConfigurationDeserializer{T}"/></param>
        /// <exception cref="ArgumentNullException">If 'metadataAddress' is null or empty.</exception>
        /// <exception cref="ArgumentNullException">If 'configRetriever' is null.</exception>
        /// <exception cref="ArgumentNullException">If 'docRetriever' is null.</exception>
        public DistributedConfigurationManager(
            string metadataAddress,
            IDistributedConfigurationRetriever<T> configRetriever,
            IDocumentRetriever docRetriever,
            IConfigurationDeserializer<T> configurationDeserializer)
            : this(metadataAddress, configRetriever, docRetriever, new LastKnownGoodConfigurationCacheOptions(), new DistributedConfigurationOptions(), configurationDeserializer)
        {
        }

        /// <summary>
        /// Instantiates a new <see cref="ConfigurationManager{T}"/> that manages automatic and controls refreshing on configuration data.
        /// </summary>
        /// <param name="metadataAddress">The address to obtain configuration.</param>
        /// <param name="configurationRetriever">The <see cref="IDistributedConfigurationRetriever{T}"/></param>
        /// <param name="docRetriever">The <see cref="IDocumentRetriever"/> that reaches out to obtain the configuration.</param>
        /// <param name="lkgCacheOptions">The <see cref="LastKnownGoodConfigurationCacheOptions"/></param>
        /// <param name="distributedConfigurationOptions">The <see cref="DistributedConfigurationOptions"/></param>
        /// <param name="configurationDeserializer">The <see cref="IConfigurationDeserializer{T}"/></param>
        /// <exception cref="ArgumentNullException">If 'metadataAddress' is null or empty.</exception>
        /// <exception cref="ArgumentNullException">If 'configRetriever' is null.</exception>
        /// <exception cref="ArgumentNullException">If 'docRetriever' is null.</exception>
        /// <exception cref="ArgumentNullException">If 'lkgCacheOptions' is null.</exception>
        public DistributedConfigurationManager(
            string metadataAddress,
            IDistributedConfigurationRetriever<T> configurationRetriever,
            IDocumentRetriever docRetriever,
            LastKnownGoodConfigurationCacheOptions lkgCacheOptions,
            DistributedConfigurationOptions distributedConfigurationOptions,
            IConfigurationDeserializer<T> configurationDeserializer)
            : base(lkgCacheOptions)
        {
            if (string.IsNullOrWhiteSpace(metadataAddress))
                throw LogHelper.LogArgumentNullException(nameof(metadataAddress));

            if (_distributedConfigurationRetriever == null)
                throw LogHelper.LogArgumentNullException(nameof(_distributedConfigurationRetriever));

            if (docRetriever == null)
                throw LogHelper.LogArgumentNullException(nameof(docRetriever));

            MetadataAddress = metadataAddress;
            _docRetriever = docRetriever;
            _distributedConfigurationRetriever = configurationRetriever;
            _refreshLock = new SemaphoreSlim(1);
            _distributedConfigurationOptions = distributedConfigurationOptions;
            _configurationDeserializer = configurationDeserializer;
            _configurationDeserializer = configurationDeserializer;
        }

        /// <summary>
        /// Instantiates a new <see cref="ConfigurationManager{T}"/> with configuration validator that manages automatic and controls refreshing on configuration data.
        /// </summary>
        /// <param name="metadataAddress">The address to obtain configuration.</param>
        /// <param name="configRetriever">The <see cref="IDistributedConfigurationRetriever{T}"/></param>
        /// <param name="docRetriever">The <see cref="IDocumentRetriever"/> that reaches out to obtain the configuration.</param>
        /// <param name="configValidator">The <see cref="IConfigurationValidator{T}"/></param>
        /// <param name="configurationDeserializer">The <see cref="IConfigurationDeserializer{T}"/></param>
        /// <exception cref="ArgumentNullException">If 'configValidator' is null.</exception>
        public DistributedConfigurationManager(
            string metadataAddress,
            IDistributedConfigurationRetriever<T> configRetriever,
            IDocumentRetriever docRetriever,
            IConfigurationValidator<T> configValidator,
            IConfigurationDeserializer<T> configurationDeserializer)
            : this(metadataAddress, configRetriever, docRetriever, configValidator, new LastKnownGoodConfigurationCacheOptions(), new DistributedConfigurationOptions(), configurationDeserializer)
        {
        }

        /// <summary>
        /// Instantiates a new <see cref="ConfigurationManager{T}"/> with configuration validator that manages automatic and controls refreshing on configuration data.
        /// </summary>
        /// <param name="metadataAddress">The address to obtain configuration.</param>
        /// <param name="configRetriever">The <see cref="IDistributedConfigurationRetriever{T}"/></param>
        /// <param name="docRetriever">The <see cref="IDocumentRetriever"/> that reaches out to obtain the configuration.</param>
        /// <param name="configValidator">The <see cref="IConfigurationValidator{T}"/></param>
        /// <param name="lkgCacheOptions">The <see cref="LastKnownGoodConfigurationCacheOptions"/></param>
        /// <param name="distributedConfigurationOptions">The <see cref="DistributedConfigurationOptions"/></param>
        /// <param name="configurationDeserializer">The <see cref="IConfigurationDeserializer{T}"/></param>
        /// <exception cref="ArgumentNullException">If 'configValidator' is null.</exception>
        public DistributedConfigurationManager(
            string metadataAddress,
            IDistributedConfigurationRetriever<T> configRetriever,
            IDocumentRetriever docRetriever,
            IConfigurationValidator<T> configValidator,
            LastKnownGoodConfigurationCacheOptions lkgCacheOptions,
            DistributedConfigurationOptions distributedConfigurationOptions,
            IConfigurationDeserializer<T> configurationDeserializer)
            : this(metadataAddress, configRetriever, docRetriever, lkgCacheOptions, distributedConfigurationOptions, configurationDeserializer)
        {
            if (configValidator == null)
                throw LogHelper.LogArgumentNullException(nameof(configValidator));

            _configValidator = configValidator;
        }

        /// <summary>
        /// Obtains an updated version of Configuration.
        /// </summary>
        /// <returns>Configuration of type T.</returns>
        /// <remarks>If the time since the last call is less than <see cref="BaseConfigurationManager.AutomaticRefreshInterval"/> then <see cref="IConfigurationRetriever{T}.GetConfigurationAsync"/> is not called and the current Configuration is returned.</remarks>
        public async Task<T> GetConfigurationAsync()
        {
            return await GetConfigurationAsync(CancellationToken.None).ConfigureAwait(false);
        }

        private async Task<T> GetConfigurationFromL2CacheAsync(CancellationToken cancel)
        {
            var cachedConfigString = await _l2Cache.GetStringAsync(MetadataAddress, cancel).ConfigureAwait(true);
            T configuration = null;
            if (cachedConfigString != null)
            {
                configuration = _configurationDeserializer.Deserialize(new Span<byte>(Encoding.UTF8.GetBytes(cachedConfigString)));

                if (_configValidator != null)
                {
                    ConfigurationValidationResult result = _configValidator.Validate(configuration);
                    if (!result.Succeeded)
                        configuration = null;
                }
            }
            return configuration;
        }

        /// <summary>
        /// Obtains an updated version of Configuration.
        /// </summary>
        /// <param name="cancel">CancellationToken</param>
        /// <returns>Configuration of type T.</returns>
        /// <remarks>If the time since the last call is less than <see cref="BaseConfigurationManager.AutomaticRefreshInterval"/> then <see cref="IConfigurationRetriever{T}.GetConfigurationAsync"/> is not called and the current Configuration is returned.</remarks>
        public async Task<T> GetConfigurationAsync(CancellationToken cancel)
        {
            bool shouldRefreshCache = _syncAfter <= DateTimeOffset.UtcNow;

            if (!shouldRefreshCache)
            {
                if (_currentConfiguration == null)
                    _currentConfiguration = await GetConfigurationFromL2CacheAsync(cancel).ConfigureAwait(true);
                return _currentConfiguration;
            }

            await _refreshLock.WaitAsync(cancel).ConfigureAwait(false);
            try
            {
                if (shouldRefreshCache)
                {
                    try
                    {
                        // Don't use the individual CT here, this is a shared operation that shouldn't be affected by an individual's cancellation.
                        // The transport should have it's own timeouts, etc..
                        T configuration = await _distributedConfigurationRetriever.GetConfigurationAsync(MetadataAddress, _docRetriever, CancellationToken.None).ConfigureAwait(false);

                        if (_configValidator != null)
                        {
                            ConfigurationValidationResult result = _configValidator.Validate(configuration);
                            if (!result.Succeeded)
                                throw LogHelper.LogExceptionMessage(new InvalidConfigurationException(LogHelper.FormatInvariant(LogMessages.IDX20810, result.ErrorMessage)));
                        }

                        _lastRefresh = DateTimeOffset.UtcNow;
                        // Add a random amount between 0 and 5% of AutomaticRefreshInterval jitter to avoid spike traffic to IdentityProvider.
                        _syncAfter = DateTimeUtil.Add(DateTime.UtcNow, AutomaticRefreshInterval +
                            TimeSpan.FromSeconds(new Random().Next((int)AutomaticRefreshInterval.TotalSeconds / 20)));
                        _currentConfiguration = configuration;
                        
                    }
                    catch (Exception ex)
                    {
                        _fetchMetadataFailure = ex;

                        if (_currentConfiguration == null) // Throw an exception if there's no configuration to return.
                        {
                            if (_bootstrapRefreshInterval < RefreshInterval)
                            {
                                // Adopt exponential backoff for bootstrap refresh interval with a decorrelated jitter if it is not longer than the refresh interval.
                                TimeSpan _bootstrapRefreshIntervalWithJitter = TimeSpan.FromSeconds(new Random().Next((int)_bootstrapRefreshInterval.TotalSeconds));
                                _bootstrapRefreshInterval += _bootstrapRefreshInterval;
                                _syncAfter = DateTimeUtil.Add(DateTime.UtcNow, _bootstrapRefreshIntervalWithJitter);
                            }
                            else
                            {
                                _syncAfter = DateTimeUtil.Add(DateTime.UtcNow, AutomaticRefreshInterval < RefreshInterval ? AutomaticRefreshInterval : RefreshInterval);
                            }

                            throw LogHelper.LogExceptionMessage(
                                new InvalidOperationException(
                                    LogHelper.FormatInvariant(LogMessages.IDX20803, LogHelper.MarkAsNonPII(MetadataAddress ?? "null"), LogHelper.MarkAsNonPII(_syncAfter), LogHelper.MarkAsNonPII(ex)), ex));
                        }
                        else
                        {
                            _syncAfter = DateTimeUtil.Add(DateTime.UtcNow, AutomaticRefreshInterval < RefreshInterval ? AutomaticRefreshInterval : RefreshInterval);

                            LogHelper.LogExceptionMessage(
                                new InvalidOperationException(
                                    LogHelper.FormatInvariant(LogMessages.IDX20806, LogHelper.MarkAsNonPII(MetadataAddress ?? "null"), LogHelper.MarkAsNonPII(ex)), ex));
                        }
                    }
                }

                // Stale metadata is better than no metadata
                if (_currentConfiguration != null)
                    return _currentConfiguration;
                else
                    throw LogHelper.LogExceptionMessage(
                        new InvalidOperationException(
                            LogHelper.FormatInvariant(
                                LogMessages.IDX20803,
                                LogHelper.MarkAsNonPII(MetadataAddress ?? "null"),
                                LogHelper.MarkAsNonPII(_syncAfter),
                                LogHelper.MarkAsNonPII(_fetchMetadataFailure)),
                            _fetchMetadataFailure));
            }
            finally
            {
                _refreshLock.Release();
            }
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="cancellationToken"></param>
        /// <returns></returns>
        public Task SetConfigurationAsync(CancellationToken cancellationToken)
        {
            return Task.CompletedTask;
        }

        /// <summary>
        /// Obtains an updated version of Configuration.
        /// </summary>
        /// <param name="cancel">CancellationToken</param>
        /// <returns>Configuration of type BaseConfiguration    .</returns>
        /// <remarks>If the time since the last call is less than <see cref="BaseConfigurationManager.AutomaticRefreshInterval"/> then <see cref="IConfigurationRetriever{T}.GetConfigurationAsync"/> is not called and the current Configuration is returned.</remarks>
        public override async Task<BaseConfiguration> GetBaseConfigurationAsync(CancellationToken cancel)
        {
            var obj = await GetConfigurationAsync(cancel).ConfigureAwait(false);
            if (obj is BaseConfiguration)
                return obj as BaseConfiguration;
            return null;
        }

        /// <summary>
        /// Requests that then next call to <see cref="GetConfigurationAsync()"/> obtain new configuration.
        /// <para>If it is a first force refresh or the last refresh was greater than <see cref="BaseConfigurationManager.RefreshInterval"/> then the next call to <see cref="GetConfigurationAsync()"/> will retrieve new configuration.</para>
        /// <para>If <see cref="BaseConfigurationManager.RefreshInterval"/> == <see cref="TimeSpan.MaxValue"/> then this method does nothing.</para>
        /// </summary>
        public override void RequestRefresh()
        {
            DateTimeOffset now = DateTimeOffset.UtcNow;
            if (_isFirstRefreshRequest)
            {
                _syncAfter = now;
                _isFirstRefreshRequest = false;
            }
            else if (now >= DateTimeUtil.Add(_lastRefresh.UtcDateTime, RefreshInterval))
            {
                _syncAfter = now;
            }
        }

        /// <summary>
        /// 
        /// </summary>
        public void Dispose()
        {
            Dispose(true);
            GC.SuppressFinalize(this); // Prevent finalizer from running
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="disposing"></param>
        protected virtual void Dispose(bool disposing)
        {
            if (!_disposed)
            {
                if (disposing)
                {
                    // Dispose managed state (managed objects).
                    _refreshLock?.Dispose();
                }

                // Free unmanaged resources (unmanaged objects) and override a finalizer below.
                // Set large fields to null.

                _disposed = true;
            }
        }

        /// <summary>
        /// 12 hours is the default time interval that afterwards, <see cref="GetBaseConfigurationAsync(CancellationToken)"/> will obtain new configuration.
        /// </summary>
        public new static readonly TimeSpan DefaultAutomaticRefreshInterval = BaseConfigurationManager.DefaultAutomaticRefreshInterval;

        /// <summary>
        /// 5 minutes is the default time interval that must pass for <see cref="RequestRefresh"/> to obtain a new configuration.
        /// </summary>
        public new static readonly TimeSpan DefaultRefreshInterval = BaseConfigurationManager.DefaultRefreshInterval;

        /// <summary>
        /// 5 minutes is the minimum value for automatic refresh. <see cref="MinimumAutomaticRefreshInterval"/> can not be set less than this value.
        /// </summary>
        public new static readonly TimeSpan MinimumAutomaticRefreshInterval = BaseConfigurationManager.MinimumAutomaticRefreshInterval;

        /// <summary>
        /// 1 second is the minimum time interval that must pass for <see cref="MinimumRefreshInterval"/> to  obtain new configuration.
        /// </summary>
        public new static readonly TimeSpan MinimumRefreshInterval = BaseConfigurationManager.MinimumRefreshInterval;
    }
}


