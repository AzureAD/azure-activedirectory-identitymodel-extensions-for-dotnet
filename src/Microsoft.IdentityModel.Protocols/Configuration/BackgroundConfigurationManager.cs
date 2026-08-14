// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System;
using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.IdentityModel.Logging;
using Microsoft.IdentityModel.Protocols.Configuration;
using Microsoft.IdentityModel.Tokens;

namespace Microsoft.IdentityModel.Protocols
{
    /// <summary>
    /// Proof-of-concept configuration manager that performs synchronous retrieval on a dedicated thread.
    /// </summary>
    /// <typeparam name="T">The configuration type.</typeparam>
    public class BackgroundConfigurationManager<T> :
        BaseConfigurationManager,
        IConfigurationManager<T> where T : class
    {
        private readonly object _configurationStateLock = new();
        private readonly SemaphoreSlim _configurationNullLock = new(1);
        private readonly SemaphoreSlim _refreshLock = new(1);
        private readonly DedicatedThreadRetriever<T> _dedicatedThreadRetriever;
        private int _blockingRefreshRequested;
        private T _currentConfiguration;
        private DateTimeOffset _syncAfter = DateTimeOffset.MinValue;

        /// <summary>
        /// Instantiates a new <see cref="BackgroundConfigurationManager{T}"/>.
        /// </summary>
        public BackgroundConfigurationManager(string metadataAddress, IConfigurationRetriever<T> configRetriever)
            : this(metadataAddress, configRetriever, new HttpDocumentRetriever(), new LastKnownGoodConfigurationCacheOptions())
        {
        }

        /// <summary>
        /// Instantiates a new <see cref="BackgroundConfigurationManager{T}"/>.
        /// </summary>
        public BackgroundConfigurationManager(string metadataAddress, IConfigurationRetriever<T> configRetriever, HttpClient httpClient)
            : this(metadataAddress, configRetriever, new HttpDocumentRetriever(httpClient), new LastKnownGoodConfigurationCacheOptions())
        {
        }

        /// <summary>
        /// Instantiates a new <see cref="BackgroundConfigurationManager{T}"/>.
        /// </summary>
        public BackgroundConfigurationManager(string metadataAddress, IConfigurationRetriever<T> configRetriever, IDocumentRetriever docRetriever)
            : this(metadataAddress, configRetriever, docRetriever, new LastKnownGoodConfigurationCacheOptions())
        {
        }

        /// <summary>
        /// Instantiates a new <see cref="BackgroundConfigurationManager{T}"/>.
        /// </summary>
        public BackgroundConfigurationManager(
            string metadataAddress,
            IConfigurationRetriever<T> configRetriever,
            IDocumentRetriever docRetriever,
            LastKnownGoodConfigurationCacheOptions lkgCacheOptions)
            : base(lkgCacheOptions)
        {
            if (string.IsNullOrWhiteSpace(metadataAddress))
                throw LogHelper.LogArgumentNullException(nameof(metadataAddress));
            if (configRetriever is null)
                throw LogHelper.LogArgumentNullException(nameof(configRetriever));
            if (docRetriever is null)
                throw LogHelper.LogArgumentNullException(nameof(docRetriever));

            MetadataAddress = metadataAddress;
            _dedicatedThreadRetriever = new DedicatedThreadRetriever<T>(
                metadataAddress,
                configRetriever,
                docRetriever);
            _dedicatedThreadRetriever.Attach(() => MetadataAddress, UpdateConfiguration, ReportFailure);
        }

        /// <summary>
        /// Instantiates a new <see cref="BackgroundConfigurationManager{T}"/>.
        /// </summary>
        public BackgroundConfigurationManager(
            string metadataAddress,
            IConfigurationRetriever<T> configRetriever,
            IDocumentRetriever docRetriever,
            IConfigurationValidator<T> configValidator)
            : this(metadataAddress, configRetriever, docRetriever, configValidator, new LastKnownGoodConfigurationCacheOptions())
        {
        }

        /// <summary>
        /// Instantiates a new <see cref="BackgroundConfigurationManager{T}"/>.
        /// </summary>
        public BackgroundConfigurationManager(
            string metadataAddress,
            IConfigurationRetriever<T> configRetriever,
            IDocumentRetriever docRetriever,
            IConfigurationValidator<T> configValidator,
            LastKnownGoodConfigurationCacheOptions lkgCacheOptions)
            : base(lkgCacheOptions)
        {
            if (string.IsNullOrWhiteSpace(metadataAddress))
                throw LogHelper.LogArgumentNullException(nameof(metadataAddress));
            if (configRetriever is null)
                throw LogHelper.LogArgumentNullException(nameof(configRetriever));
            if (docRetriever is null)
                throw LogHelper.LogArgumentNullException(nameof(docRetriever));
            if (configValidator is null)
                throw LogHelper.LogArgumentNullException(nameof(configValidator));

            MetadataAddress = metadataAddress;
            _dedicatedThreadRetriever = new DedicatedThreadRetriever<T>(
                metadataAddress,
                configRetriever,
                docRetriever,
                configValidator);
            _dedicatedThreadRetriever.Attach(() => MetadataAddress, UpdateConfiguration, ReportFailure);
        }

        /// <summary>
        /// Instantiates a new <see cref="BackgroundConfigurationManager{T}"/> using an existing dedicated retriever.
        /// </summary>
        public BackgroundConfigurationManager(
            string metadataAddress,
            DedicatedThreadRetriever<T> dedicatedThreadRetriever)
            : this(metadataAddress, dedicatedThreadRetriever, new LastKnownGoodConfigurationCacheOptions())
        {
        }

        /// <summary>
        /// Instantiates a new <see cref="BackgroundConfigurationManager{T}"/> using an existing dedicated retriever.
        /// </summary>
        public BackgroundConfigurationManager(
            string metadataAddress,
            DedicatedThreadRetriever<T> dedicatedThreadRetriever,
            LastKnownGoodConfigurationCacheOptions lkgCacheOptions)
            : base(lkgCacheOptions)
        {
            if (string.IsNullOrWhiteSpace(metadataAddress))
                throw LogHelper.LogArgumentNullException(nameof(metadataAddress));
            if (dedicatedThreadRetriever is null)
                throw LogHelper.LogArgumentNullException(nameof(dedicatedThreadRetriever));

            MetadataAddress = metadataAddress;
            _dedicatedThreadRetriever = dedicatedThreadRetriever;
            _dedicatedThreadRetriever.Attach(() => MetadataAddress, UpdateConfiguration, ReportFailure);
        }

        /// <summary>
        /// Gets the current configuration asynchronously, refreshing it as needed.
        /// </summary>
        public Task<T> GetConfigurationAsync()
        {
            return GetConfigurationAsync(CancellationToken.None);
        }

        /// <summary>
        /// Gets the current configuration asynchronously, refreshing it as needed.
        /// </summary>
        public virtual async Task<T> GetConfigurationAsync(CancellationToken cancel)
        {
            bool updateConfigAsBlocking = AppContextSwitches.UpdateConfigAsBlocking;
            ReadConfigurationState(out T currentConfiguration, out DateTimeOffset syncAfter);

            if (currentConfiguration is not null &&
                syncAfter > DateTimeOffset.UtcNow &&
                (!updateConfigAsBlocking || Volatile.Read(ref _blockingRefreshRequested) == 0))
            {
                return currentConfiguration;
            }

            if (updateConfigAsBlocking)
                return await GetConfigurationWithBlockingAsync(cancel).ConfigureAwait(false);

            return await GetConfigurationNonBlockingAsync(cancel).ConfigureAwait(false);
        }

        private async Task<T> GetConfigurationNonBlockingAsync(CancellationToken cancel)
        {
            T currentConfiguration = ReadCurrentConfiguration();
            if (currentConfiguration is null)
            {
                await _configurationNullLock.WaitAsync(cancel).ConfigureAwait(false);
                try
                {
                    currentConfiguration = ReadCurrentConfiguration();
                    if (currentConfiguration is not null)
                        return currentConfiguration;

                    try
                    {
                        T configuration = await _dedicatedThreadRetriever
                            .RequestRefreshAndWaitAsync(cancel)
                            .ConfigureAwait(false);
                        return configuration;
                    }
                    catch (Exception ex)
                    {
                        throw CreateNoMetadataException(ex);
                    }
                }
                finally
                {
                    _configurationNullLock.Release();
                }
            }

            _dedicatedThreadRetriever.RequestRefresh();
            return currentConfiguration;
        }

        private async Task<T> GetConfigurationWithBlockingAsync(CancellationToken cancel)
        {
            await _refreshLock.WaitAsync(cancel).ConfigureAwait(false);
            try
            {
                ReadConfigurationState(out T currentConfiguration, out DateTimeOffset syncAfter);
                int refreshRequestGeneration = Volatile.Read(ref _blockingRefreshRequested);
                bool refreshRequested = refreshRequestGeneration != 0;
                if (currentConfiguration is not null &&
                    syncAfter > DateTimeOffset.UtcNow &&
                    !refreshRequested)
                {
                    return currentConfiguration;
                }

                try
                {
                    T configuration = await _dedicatedThreadRetriever
                        .RequestRefreshAndWaitAsync(cancel)
                        .ConfigureAwait(false);
                    AcknowledgeBlockingRefresh(refreshRequestGeneration);
                    return configuration;
                }
#pragma warning disable CA1031 // Warm refresh failures continue with stale metadata.
                catch (Exception ex)
#pragma warning restore CA1031
                {
                    AcknowledgeBlockingRefresh(refreshRequestGeneration);
                    if (currentConfiguration is null)
                        throw CreateNoMetadataException(ex);

                    return currentConfiguration;
                }
            }
            finally
            {
                _refreshLock.Release();
            }
        }

        /// <inheritdoc/>
        public override async Task<BaseConfiguration> GetBaseConfigurationAsync(CancellationToken cancel)
        {
            T configuration = await GetConfigurationAsync(cancel).ConfigureAwait(false);
            return configuration as BaseConfiguration;
        }

        /// <inheritdoc/>
        public override void RequestRefresh()
        {
            if (AppContextSwitches.UpdateConfigAsBlocking)
            {
                lock (_configurationStateLock)
                    _syncAfter = DateTimeOffset.UtcNow;

                Interlocked.Increment(ref _blockingRefreshRequested);
            }
            else
                _dedicatedThreadRetriever.RequestRefresh();
        }

        private void AcknowledgeBlockingRefresh(int refreshRequestGeneration)
        {
            if (refreshRequestGeneration != 0)
            {
                Interlocked.CompareExchange(
                    ref _blockingRefreshRequested,
                    0,
                    refreshRequestGeneration);
            }
        }

        private void UpdateConfiguration(T configuration, DateTimeOffset retrievalTime)
        {
            lock (_configurationStateLock)
            {
                _currentConfiguration = configuration;
                _syncAfter = DateTimeUtil.Add(
                    retrievalTime.UtcDateTime,
                    AutomaticRefreshInterval +
                    TimeSpan.FromSeconds(new Random().Next((int)AutomaticRefreshInterval.TotalSeconds / 20)));
            }
        }

        private void ReportFailure(Exception exception)
        {
            lock (_configurationStateLock)
            {
                if (_currentConfiguration is not null)
                {
                    _syncAfter = DateTimeUtil.Add(
                        DateTime.UtcNow,
                        AutomaticRefreshInterval < RefreshInterval ? AutomaticRefreshInterval : RefreshInterval);
                }
            }

            LogHelper.LogExceptionMessage(
                new InvalidOperationException(
                    LogHelper.FormatInvariant(
                        LogMessages.IDX20806,
                        LogHelper.MarkAsNonPII(MetadataAddress ?? "null"),
                        exception),
                    exception));
        }

        private T ReadCurrentConfiguration()
        {
            lock (_configurationStateLock)
                return _currentConfiguration;
        }

        private void ReadConfigurationState(out T currentConfiguration, out DateTimeOffset syncAfter)
        {
            lock (_configurationStateLock)
            {
                currentConfiguration = _currentConfiguration;
                syncAfter = _syncAfter;
            }
        }

        private Exception CreateNoMetadataException(Exception exception)
        {
            return LogHelper.LogExceptionMessage(
                new InvalidOperationException(
                    LogHelper.FormatInvariant(
                        LogMessages.IDX20803,
                        LogHelper.MarkAsNonPII(MetadataAddress ?? "null"),
                        LogHelper.MarkAsNonPII(DateTimeOffset.MinValue),
                        LogHelper.MarkAsNonPII(exception)),
                    exception));
        }

        /// <summary>
        /// 12 hours is the default automatic refresh interval.
        /// </summary>
        public new static readonly TimeSpan DefaultAutomaticRefreshInterval = BaseConfigurationManager.DefaultAutomaticRefreshInterval;

        /// <summary>
        /// 5 minutes is the default refresh interval.
        /// </summary>
        public new static readonly TimeSpan DefaultRefreshInterval = BaseConfigurationManager.DefaultRefreshInterval;

        /// <summary>
        /// 5 minutes is the minimum automatic refresh interval.
        /// </summary>
        public new static readonly TimeSpan MinimumAutomaticRefreshInterval = BaseConfigurationManager.MinimumAutomaticRefreshInterval;

        /// <summary>
        /// 1 second is the minimum refresh interval.
        /// </summary>
        public new static readonly TimeSpan MinimumRefreshInterval = BaseConfigurationManager.MinimumRefreshInterval;
    }
}
