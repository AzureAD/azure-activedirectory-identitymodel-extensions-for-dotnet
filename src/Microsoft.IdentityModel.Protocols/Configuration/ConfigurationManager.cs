// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System;
using System.Net.Http;
using System.Runtime.CompilerServices;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.IdentityModel.Logging;
using Microsoft.IdentityModel.Protocols.Configuration;
using Microsoft.IdentityModel.Tokens;
using Microsoft.IdentityModel.Telemetry;

namespace Microsoft.IdentityModel.Protocols
{
    /// <summary>
    /// Manages the retrieval of Configuration data.
    /// </summary>
    /// <typeparam name="T">The type of <see cref="IDocumentRetriever"/>.</typeparam>
    [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Design", "CA1001:TypesThatOwnDisposableFieldsShouldBeDisposable")]
    public partial class ConfigurationManager<T> : BaseConfigurationManager, IConfigurationManager<T> where T : class
    {
#pragma warning disable IDE0044 // Add readonly modifier
#pragma warning disable CS0649 // Unused, it gets used in tests.
        internal Action _onBackgroundTaskFinish;
#pragma warning restore CS0649 // Unused
#pragma warning restore IDE0044 // Add readonly modifier

        private DateTime _syncAfter = DateTime.MinValue;
        private DateTime SyncAfter
        {
            get => _syncAfter;
            set => AtomicUpdateDateTime(ref _syncAfter, ref value);
        }

        private DateTime _lastRequestRefresh = DateTime.MinValue;
        private DateTime LastRequestRefresh
        {
            get => _lastRequestRefresh;
            set => AtomicUpdateDateTime(ref _lastRequestRefresh, ref value);
        }

        private bool _isFirstRefreshRequest = true;
        private readonly SemaphoreSlim _configurationNullLock = new SemaphoreSlim(1);

        private readonly IDocumentRetriever _docRetriever;
        private readonly IConfigurationRetriever<T> _configRetriever;
        private readonly IConfigurationValidator<T> _configValidator;
        private T _currentConfiguration;

        // task states are used to ensure the call to 'update config' (UpdateCurrentConfiguration) is a singleton. Uses Interlocked.CompareExchange.
        // metadata is not being obtained
        private const int ConfigurationRetrieverIdle = 0;
        // metadata is being retrieved
        private const int ConfigurationRetrieverRunning = 1;
        private int _configurationRetrieverState = ConfigurationRetrieverIdle;

        private readonly TimeProvider _timeProvider = TimeProvider.System;
        internal ITelemetryClient TelemetryClient = new TelemetryClient();

        // If a refresh is requested, then do the refresh as a blocking operation
        // not on a background thread. RequestRefresh signals that the app is explicitly
        // requesting a refresh, so it should be done immediately so the next
        // call to GetConfiguration will return new configuration if the minimum
        // refresh interval has passed.
        private bool _refreshRequested;

        // Wait handle used to signal a background task to update the configuration.
        // Handle starts unset, and AutoResetEvent.Set() sets it, this indicates that
        // the background refresh task should immediately run.
        private readonly AutoResetEvent _updateMetadataEvent = new(false);

        // Background task that updates the configuration. Signaled with _updateMetadataEvent.
        // Task should be started with EnsureBackgroundRefreshTaskIsRunning.
        private Task _updateMetadataTask;

        private readonly CancellationTokenSource _backgroundRefreshTaskCancellationTokenSource;

        /// <summary>
        /// Requests that background tasks be shutdown.
        /// This only applies if 'Switch.Microsoft.IdentityModel.UpdateConfigAsBlocking' is not set or set to false.
        /// Note that this does not influence <see cref="GetConfigurationAsync(CancellationToken)"/>.
        /// If the background task stops, the next time the task would be signaled, the task will be
        /// restarted unless <see cref="ShutdownBackgroundTask"/> is called.
        /// If using a background task, the <see cref="Configuration"/> cannot
        /// be used after calling this method.
        /// </summary>
        public void ShutdownBackgroundTask()
        {
            _backgroundRefreshTaskCancellationTokenSource.Cancel();
        }

        /// <summary>
        /// Instantiates a new <see cref="ConfigurationManager{T}"/> that manages automatic and controls refreshing on configuration data.
        /// </summary>
        /// <param name="metadataAddress">The address to obtain configuration.</param>
        /// <param name="configRetriever">The <see cref="IConfigurationRetriever{T}"/></param>
        public ConfigurationManager(string metadataAddress, IConfigurationRetriever<T> configRetriever)
            : this(metadataAddress, configRetriever, new HttpDocumentRetriever(), new LastKnownGoodConfigurationCacheOptions())
        {
        }

        /// <summary>
        /// Instantiates a new <see cref="ConfigurationManager{T}"/> that manages automatic and controls refreshing on configuration data.
        /// </summary>
        /// <param name="metadataAddress">The address to obtain configuration.</param>
        /// <param name="configRetriever">The <see cref="IConfigurationRetriever{T}"/></param>
        /// <param name="httpClient">The client to use when obtaining configuration.</param>
        public ConfigurationManager(string metadataAddress, IConfigurationRetriever<T> configRetriever, HttpClient httpClient)
            : this(metadataAddress, configRetriever, new HttpDocumentRetriever(httpClient), new LastKnownGoodConfigurationCacheOptions())
        {
        }

        /// <summary>
        /// Instantiates a new <see cref="ConfigurationManager{T}"/> that manages automatic and controls refreshing on configuration data.
        /// </summary>
        /// <param name="metadataAddress">The address to obtain configuration.</param>
        /// <param name="configRetriever">The <see cref="IConfigurationRetriever{T}"/></param>
        /// <param name="docRetriever">The <see cref="IDocumentRetriever"/> that reaches out to obtain the configuration.</param>
        /// <exception cref="ArgumentNullException">If 'metadataAddress' is null or empty.</exception>
        /// <exception cref="ArgumentNullException">If 'configRetriever' is null.</exception>
        /// <exception cref="ArgumentNullException">If 'docRetriever' is null.</exception>
        public ConfigurationManager(string metadataAddress, IConfigurationRetriever<T> configRetriever, IDocumentRetriever docRetriever)
            : this(metadataAddress, configRetriever, docRetriever, new LastKnownGoodConfigurationCacheOptions())
        {
        }

        /// <summary>
        /// Instantiates a new <see cref="ConfigurationManager{T}"/> that manages automatic and controls refreshing on configuration data.
        /// </summary>
        /// <param name="metadataAddress">The address to obtain configuration.</param>
        /// <param name="configRetriever">The <see cref="IConfigurationRetriever{T}"/></param>
        /// <param name="docRetriever">The <see cref="IDocumentRetriever"/> that reaches out to obtain the configuration.</param>
        /// <param name="lkgCacheOptions">The <see cref="LastKnownGoodConfigurationCacheOptions"/></param>
        /// <exception cref="ArgumentNullException">If 'metadataAddress' is null or empty.</exception>
        /// <exception cref="ArgumentNullException">If 'configRetriever' is null.</exception>
        /// <exception cref="ArgumentNullException">If 'docRetriever' is null.</exception>
        /// <exception cref="ArgumentNullException">If 'lkgCacheOptions' is null.</exception>
        public ConfigurationManager(string metadataAddress, IConfigurationRetriever<T> configRetriever, IDocumentRetriever docRetriever, LastKnownGoodConfigurationCacheOptions lkgCacheOptions)
            : base(lkgCacheOptions)
        {
            if (string.IsNullOrWhiteSpace(metadataAddress))
                throw LogHelper.LogArgumentNullException(nameof(metadataAddress));

            if (configRetriever == null)
                throw LogHelper.LogArgumentNullException(nameof(configRetriever));

            if (docRetriever == null)
                throw LogHelper.LogArgumentNullException(nameof(docRetriever));

            MetadataAddress = metadataAddress;
            _docRetriever = docRetriever;
            _configRetriever = configRetriever;
            _backgroundRefreshTaskCancellationTokenSource = new CancellationTokenSource();

            if (!AppContextSwitches.UpdateConfigAsBlocking)
                EnsureBackgroundRefreshTaskIsRunning();
        }

        /// <summary>
        /// Instantiates a new <see cref="ConfigurationManager{T}"/> with configuration validator that manages automatic and controls refreshing on configuration data.
        /// </summary>
        /// <param name="metadataAddress">The address to obtain configuration.</param>
        /// <param name="configRetriever">The <see cref="IConfigurationRetriever{T}"/></param>
        /// <param name="docRetriever">The <see cref="IDocumentRetriever"/> that reaches out to obtain the configuration.</param>
        /// <param name="configValidator">The <see cref="IConfigurationValidator{T}"/></param>
        /// <exception cref="ArgumentNullException">If 'configValidator' is null.</exception>
        public ConfigurationManager(string metadataAddress, IConfigurationRetriever<T> configRetriever, IDocumentRetriever docRetriever, IConfigurationValidator<T> configValidator)
            : this(metadataAddress, configRetriever, docRetriever, configValidator, new LastKnownGoodConfigurationCacheOptions())
        {
        }

        /// <summary>
        /// Instantiates a new <see cref="ConfigurationManager{T}"/> with configuration validator that manages automatic and controls refreshing on configuration data.
        /// </summary>
        /// <param name="metadataAddress">The address to obtain configuration.</param>
        /// <param name="configRetriever">The <see cref="IConfigurationRetriever{T}"/></param>
        /// <param name="docRetriever">The <see cref="IDocumentRetriever"/> that reaches out to obtain the configuration.</param>
        /// <param name="configValidator">The <see cref="IConfigurationValidator{T}"/></param>
        /// <param name="lkgCacheOptions">The <see cref="LastKnownGoodConfigurationCacheOptions"/></param>
        /// <exception cref="ArgumentNullException">If 'configValidator' is null.</exception>
        public ConfigurationManager(string metadataAddress, IConfigurationRetriever<T> configRetriever, IDocumentRetriever docRetriever, IConfigurationValidator<T> configValidator, LastKnownGoodConfigurationCacheOptions lkgCacheOptions)
            : this(metadataAddress, configRetriever, docRetriever, lkgCacheOptions)
        {
            if (configValidator == null)
                throw LogHelper.LogArgumentNullException(nameof(configValidator));

            _configValidator = configValidator;
        }

        /// <summary>
        /// Obtains an updated version of Configuration.
        /// </summary>
        /// <returns>Configuration of type <typeparamref name="T"/>.</returns>
        /// <remarks>
        /// If the time since the last call is less than <see cref="BaseConfigurationManager.AutomaticRefreshInterval"/>
        /// then <see cref="IConfigurationRetriever{T}.GetConfigurationAsync"/> is not called and the current Configuration is returned.
        /// If the configuration is not able to be updated, but a previous configuration was previously retrieved, the previous configuration is returned.
        /// </remarks>
        /// <exception cref="InvalidOperationException" >Throw if the configuration is unable to be retrieved.</exception>
        /// <exception cref="InvalidConfigurationException" >Throw if the configuration fails to be validated by the <see cref="IConfigurationValidator{T}"/>.</exception>
        public async Task<T> GetConfigurationAsync()
        {
            return await GetConfigurationAsync(CancellationToken.None).ConfigureAwait(false);
        }

        /// <summary>
        /// Obtains an updated version of Configuration.
        /// </summary>
        /// <param name="cancel">CancellationToken</param>
        /// <returns>Configuration of type <typeparamref name="T"/>.</returns>
        /// <remarks>
        /// If the time since the last call is less than <see cref="BaseConfigurationManager.AutomaticRefreshInterval"/>
        /// then <see cref="IConfigurationRetriever{T}.GetConfigurationAsync"/> is not called and the current Configuration is returned.
        /// If the configuration is not able to be updated, but a previous configuration was previously retrieved, the previous configuration is returned.
        /// </remarks>
        /// <exception cref="InvalidOperationException" >Throw if the configuration is unable to be retrieved.</exception>
        /// <exception cref="InvalidConfigurationException" >Throw if the configuration fails to be validated by the <see cref="IConfigurationValidator{T}"/>.</exception>
        public virtual async Task<T> GetConfigurationAsync(CancellationToken cancel)
        {
            if (_currentConfiguration != null && SyncAfter > _timeProvider.GetUtcNow())
                return _currentConfiguration;

            if (AppContextSwitches.UpdateConfigAsBlocking)
                return await GetConfigurationWithBlockingAsync(cancel).ConfigureAwait(false);
            else
                return await GetConfigurationWithBackgroundTaskUpdatesAsync(cancel).ConfigureAwait(false);
        }

        private async Task<T> GetConfigurationWithBackgroundTaskUpdatesAsync(CancellationToken cancel)
        {
            Exception fetchMetadataFailure = null;

            // LOGIC
            // if configuration == null => configuration has never been retrieved.
            //   reach out to the metadata endpoint. Since multiple threads could be calling this method
            //   we need to ensure that only one thread is actually fetching the metadata.
            // else
            //   if task is running, return the current configuration
            //   else kick off task to update current configuration
            if (_currentConfiguration == null)
            {
                await _configurationNullLock.WaitAsync(cancel).ConfigureAwait(false);
                if (_currentConfiguration != null)
                {
                    _configurationNullLock.Release();
                    return _currentConfiguration;
                }

#pragma warning disable CA1031 // Do not catch general exception types
                try
                {
                    // Don't use the individual CT here, this is a shared operation that shouldn't be affected by an individual's cancellation.
                    // The transport should have its own timeouts, etc.
                    T configuration = await _configRetriever.GetConfigurationAsync(
                        MetadataAddress,
                        _docRetriever,
                        CancellationToken.None).ConfigureAwait(false);

                    if (_configValidator != null)
                    {
                        ConfigurationValidationResult result = _configValidator.Validate(configuration);
                        // in this case we have never had a valid configuration, so we will throw an exception if the validation fails
                        if (!result.Succeeded)
                        {
                            var ex = new InvalidConfigurationException(
                                LogHelper.FormatInvariant(
                                    LogMessages.IDX20810,
                                    result.ErrorMessage));

                            throw LogHelper.LogExceptionMessage(ex);
                        }
                    }

                    TelemetryClient.IncrementConfigurationRefreshRequestCounter(
                        MetadataAddress,
                        TelemetryConstants.Protocols.FirstRefresh);

                    UpdateConfiguration(configuration);
                }
                catch (Exception ex)
                {
                    fetchMetadataFailure = ex;
                    TelemetryClient.IncrementConfigurationRefreshRequestCounter(
                        MetadataAddress,
                        TelemetryConstants.Protocols.FirstRefresh,
                        ex);

                    LogHelper.LogExceptionMessage(
                        new InvalidOperationException(
                             LogHelper.FormatInvariant(
                                LogMessages.IDX20806,
                                LogHelper.MarkAsNonPII(MetadataAddress ?? "null"),
                                LogHelper.MarkAsNonPII(ex)),
                            ex));
                }
                finally
                {
                    _configurationNullLock.Release();
                }
#pragma warning restore CA1031 // Do not catch general exception types
            }
            else
            {
                if (Interlocked.CompareExchange(ref _configurationRetrieverState, ConfigurationRetrieverRunning, ConfigurationRetrieverIdle) == ConfigurationRetrieverIdle)
                {
                    if (SyncAfter <= _timeProvider.GetUtcNow())
                    {
                        EnsureBackgroundRefreshTaskIsRunning();
                        _updateMetadataEvent.Set();
                    }
                    else
                    {
                        Interlocked.Exchange(ref _configurationRetrieverState, ConfigurationRetrieverIdle);
                    }
                }
            }

            // If metadata exists return it.
            if (_currentConfiguration != null)
                return _currentConfiguration;

            throw LogHelper.LogExceptionMessage(
                new InvalidOperationException(
                    LogHelper.FormatInvariant(
                        LogMessages.IDX20803,
                        LogHelper.MarkAsNonPII(MetadataAddress ?? "null"),
                        LogHelper.MarkAsNonPII(SyncAfter),
                        LogHelper.MarkAsNonPII(fetchMetadataFailure)),
                    fetchMetadataFailure));
        }

        private void EnsureBackgroundRefreshTaskIsRunning()
        {
            if (_backgroundRefreshTaskCancellationTokenSource.IsCancellationRequested)
                return;

            if (_updateMetadataTask == null || _updateMetadataTask.Status != TaskStatus.Running)
                _updateMetadataTask = Task.Run(UpdateCurrentConfigurationUsingSignals);
        }

        private void TelemetryForUpdate()
        {
            var updateMode = _refreshRequested ? TelemetryConstants.Protocols.Manual : TelemetryConstants.Protocols.Automatic;

            if (_refreshRequested)
                _refreshRequested = false;

            try
            {
                TelemetryClient.IncrementConfigurationRefreshRequestCounter(
                    MetadataAddress,
                    updateMode);
            }
#pragma warning disable CA1031 // Do not catch general exception types
            catch
            { }
#pragma warning restore CA1031 // Do not catch general exception types
        }

        private void UpdateCurrentConfigurationUsingSignals()
        {
            try
            {
                while (!_backgroundRefreshTaskCancellationTokenSource.IsCancellationRequested)
                {
                    if (_updateMetadataEvent.WaitOne(500))
                    {
                        UpdateCurrentConfiguration();
                        _onBackgroundTaskFinish?.Invoke();
                    }
                }
            }
            catch (Exception ex)
            {
                TelemetryClient.LogBackgroundConfigurationRefreshFailure(MetadataAddress, ex);
            }
        }

        /// <summary>
        /// This should be called when the configuration needs to be updated either from RequestRefresh or AutomaticRefresh
        /// The Caller should first check the state checking state using:
        ///   if (Interlocked.CompareExchange(ref _configurationRetrieverState, ConfigurationRetrieverRunning, ConfigurationRetrieverIdle) == ConfigurationRetrieverIdle).
        /// </summary>
        private void UpdateCurrentConfiguration()
        {
            TelemetryForUpdate();
#pragma warning disable CA1031 // Do not catch general exception types
            long startTimestamp = _timeProvider.GetTimestamp();

            try
            {
                T configuration = _configRetriever.GetConfigurationAsync(
                    MetadataAddress,
                    _docRetriever,
                    CancellationToken.None).ConfigureAwait(false).GetAwaiter().GetResult();

                var elapsedTime = _timeProvider.GetElapsedTime(startTimestamp);
                TelemetryClient.LogConfigurationRetrievalDuration(
                    MetadataAddress,
                    elapsedTime);

                if (_configValidator == null)
                {
                    UpdateConfiguration(configuration);
                }
                else
                {
                    ConfigurationValidationResult result = _configValidator.Validate(configuration);

                    if (!result.Succeeded)
                        LogHelper.LogExceptionMessage(
                            new InvalidConfigurationException(
                                LogHelper.FormatInvariant(
                                    LogMessages.IDX20810,
                                    result.ErrorMessage)));
                    else
                        UpdateConfiguration(configuration);
                }
            }
            catch (Exception ex)
            {
                var elapsedTime = _timeProvider.GetElapsedTime(startTimestamp);
                TelemetryClient.LogConfigurationRetrievalDuration(
                    MetadataAddress,
                    elapsedTime,
                    ex);

                LogHelper.LogExceptionMessage(
                    new InvalidOperationException(
                        LogHelper.FormatInvariant(
                            LogMessages.IDX20806,
                            LogHelper.MarkAsNonPII(MetadataAddress ?? "null"),
                            ex),
                        ex));
            }
            finally
            {
                Interlocked.Exchange(ref _configurationRetrieverState, ConfigurationRetrieverIdle);
            }
#pragma warning restore CA1031 // Do not catch general exception types
        }

        private void UpdateConfiguration(T configuration)
        {
            _currentConfiguration = configuration;
            var newSyncTime = DateTimeUtil.Add(_timeProvider.GetUtcNow().UtcDateTime, AutomaticRefreshInterval +
                TimeSpan.FromSeconds(new Random().Next((int)AutomaticRefreshInterval.TotalSeconds / 20)));
            SyncAfter = newSyncTime;
        }

        private static void AtomicUpdateDateTime(ref DateTime field, ref DateTime value)
        {
            // DateTime's backing data is safe to treat as a long if the Kind is not local.
            // time will always be updated to a UTC time.
            // See the implementation of ToBinary on DateTime.
            Interlocked.Exchange(
                ref Unsafe.As<DateTime, long>(ref field),
                Unsafe.As<DateTime, long>(ref value));
        }

        /// <summary>
        /// Obtains an updated version of Configuration.
        /// </summary>
        /// <param name="cancel">CancellationToken</param>
        /// <returns>Configuration of type BaseConfiguration.</returns>
        /// <remarks>If the time since the last call is less than <see cref="BaseConfigurationManager.AutomaticRefreshInterval"/> then <see cref="IConfigurationRetriever{T}.GetConfigurationAsync"/> is not called and the current Configuration is returned.</remarks>
        public override async Task<BaseConfiguration> GetBaseConfigurationAsync(CancellationToken cancel)
        {
            T obj = await GetConfigurationAsync(cancel).ConfigureAwait(false);
            return obj as BaseConfiguration;
        }

        /// <summary>
        /// Triggers updating metadata when:
        /// <para>1. Called the first time.</para>
        /// <para>2. The time between when this method was called and DateTimeOffset.Now is greater than <see cref="BaseConfigurationManager.RefreshInterval"/>.</para>
        /// <para>If <see cref="BaseConfigurationManager.RefreshInterval"/> == <see cref="TimeSpan.MaxValue"/> then this method does nothing.</para>
        /// </summary>
        public override void RequestRefresh()
        {
            if (AppContextSwitches.UpdateConfigAsBlocking)
            {
                RequestRefreshBlocking();
            }
            else
            {
                RequestRefreshBackgroundThread();
            }
        }

        private void RequestRefreshBackgroundThread()
        {
            DateTime now = _timeProvider.GetUtcNow().UtcDateTime;

            if (now >= DateTimeUtil.Add(LastRequestRefresh, RefreshInterval) || _isFirstRefreshRequest)
            {
                _isFirstRefreshRequest = false;

                if (Interlocked.CompareExchange(ref _configurationRetrieverState, ConfigurationRetrieverRunning, ConfigurationRetrieverIdle) == ConfigurationRetrieverIdle)
                {
                    _refreshRequested = true;
                    LastRequestRefresh = now;
                    EnsureBackgroundRefreshTaskIsRunning();
                    _updateMetadataEvent.Set();
                }
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
