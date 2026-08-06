// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.IdentityModel.Logging;
using Microsoft.IdentityModel.Protocols.Configuration;
using Microsoft.IdentityModel.Telemetry;
using Microsoft.IdentityModel.Tokens;

namespace Microsoft.IdentityModel.Protocols
{
    /// <summary>
    /// Manages the retrieval of Configuration data.
    /// </summary>
    /// <typeparam name="T">The type of <see cref="IDocumentRetriever"/>.</typeparam>
    [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Design", "CA1001:TypesThatOwnDisposableFieldsShouldBeDisposable")]
    public partial class ConfigurationManager<T> : BaseConfigurationManager, IConfigurationManager<T>, IConfigurationManagerSync<T> where T : class
    {
        internal Action _onBackgroundTaskFinish;

        private DateTimeOffset _syncAfter = DateTimeOffset.MinValue;
        private DateTimeOffset _lastRequestRefresh = DateTimeOffset.MinValue;
        private bool _isFirstRefreshRequest = true;
        private readonly SemaphoreSlim _configurationNullLock = new SemaphoreSlim(1);

        private readonly IConfigurationValidator<T> _configValidator;
        private T _currentConfiguration;

        // Tracks the most recent fetch failure for the blocking path. Promoted from a local in
        // GetConfigurationWithBlockingAsync/GetConfigurationWithBlockingSync so the original exception (e.g. an IOException carrying
        // HttpDocumentRetriever.StatusCode/ResponseContent in its Data dictionary) is preserved across
        // calls that arrive within the backoff window (_syncAfter > now) and skip the fetch.
        private Exception _fetchMetadataFailure;

        // task states are used to ensure the call to 'update config' (UpdateCurrentConfiguration) is a singleton. Uses Interlocked.CompareExchange.
        // metadata is not being obtained
        private const int ConfigurationRetrieverIdle = 0;
        // metadata is being retrieved
        private const int ConfigurationRetrieverRunning = 1;
        private int _configurationRetrieverState = ConfigurationRetrieverIdle;

        private readonly SemaphoreSlim _refreshLock = new(1, 1);
        private TimeSpan _bootstrapRefreshInterval = TimeSpan.FromSeconds(1);

        /// <summary>
        /// Used to track the type of request for signaling the event handler and for telemetry.
        /// </summary>
        private bool _refreshRequested;

        internal TimeProvider TimeProvider = TimeProvider.System;
        internal ITelemetryClient TelemetryClient = new TelemetryClient();

        /// <summary>
        /// Gets or sets the optional configuration event handler.
        /// </summary>
        public IConfigurationEventHandler<T> ConfigurationEventHandler { get; set; }

        /// <summary>
        /// Gets or sets the optional synchronous configuration event handler.
        /// </summary>
        public IConfigurationEventHandlerSync<T> ConfigurationEventHandlerSync { get; set; }

        /// <summary>
        /// Triggers updating metadata when:
        /// <para>1. Called the first time.</para>
        /// <para>2. The time between when this method was called and DateTimeOffset.Now is greater than <see cref="BaseConfigurationManager.RefreshInterval"/>.</para>
        /// <para>If <see cref="BaseConfigurationManager.RefreshInterval"/> == <see cref="TimeSpan.MaxValue"/> then this method does nothing.</para>
        /// </summary>
        /// <remarks>
        /// If the strategy is configured to be blocking through the switch 'Switch.Microsoft.IdentityModel.UpdateConfigAsBlocking',
        /// then this method will not update the configuration, instead it will request the next call to <see cref="GetConfigurationAsync()"/> or <see cref="GetConfigurationSync()"/>
        /// should request new configuration.
        /// </remarks>
        public override void RequestRefresh()
        {
            if (AppContextSwitches.UpdateConfigAsBlocking)
                RequestRefreshBlocking();
            else
                RequestRefreshBackgroundThread();
        }

        private void RequestRefreshBackgroundThread()
        {
            DateTimeOffset now = TimeProvider.GetUtcNow();

            if (now >= DateTimeUtil.Add(_lastRequestRefresh.UtcDateTime, RefreshInterval) || _isFirstRefreshRequest)
            {
                TelemetryClient.IncrementConfigurationRefreshRequestCounter(
                    MetadataAddress,
                    TelemetryConstants.Protocols.Manual,
                    TelemetryConstants.Protocols.ConfigurationSourceUnknown);

                _isFirstRefreshRequest = false;
                if (Interlocked.CompareExchange(ref _configurationRetrieverState, ConfigurationRetrieverRunning, ConfigurationRetrieverIdle) == ConfigurationRetrieverIdle)
                {
                    if (ConfigurationEventHandlerSync != null || _configRetrieverAsync == null || _docRetrieverAsync == null)
                        _ = Task.Run(_updateCurrentConfigurationWithBypassSync, CancellationToken.None);
                    else
                        _ = Task.Run(_updateCurrentConfigurationWithBypassAsync, CancellationToken.None);

                    _lastRequestRefresh = now;
                }
            }
        }

        private void RequestRefreshBlocking()
        {
            DateTime now = TimeProvider.GetUtcNow().UtcDateTime;

            if (now >= DateTimeUtil.Add(_lastRequestRefresh.UtcDateTime, RefreshInterval) || _isFirstRefreshRequest)
            {
                _refreshRequested = true;
                _syncAfter = now;
                _isFirstRefreshRequest = false;
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

        private void UpdateConfiguration(T configuration, DateTimeOffset retrievalTime, ConfigurationRetrievalContext context)
        {
            _currentConfiguration = configuration;
            _syncAfter = DateTimeUtil.Add(retrievalTime.UtcDateTime, AutomaticRefreshInterval +
                TimeSpan.FromSeconds(new Random().Next((int)AutomaticRefreshInterval.TotalSeconds / 20)));

            // runs the correct event handler based on sync/async
            IConfigurationEventHandlerSync<T> eventHandlerSync = ConfigurationEventHandlerSync;

            if (eventHandlerSync != null)
            {
                _ = Task.Run(() =>
                {
                    try
                    {
                        if (eventHandlerSync is IConfigurationEventHandlerContextAwareSync<T> contextAwareSync)
                            contextAwareSync.AfterUpdate(MetadataAddress, configuration, context);
                        else
                            eventHandlerSync.AfterUpdate(MetadataAddress, configuration);
                    }
                    catch (Exception ex)
                    {
                        LogHelper.LogExceptionMessage(
                            new InvalidOperationException(
                                LogHelper.FormatInvariant(
                                   LogMessages.IDX20813,
                                    LogHelper.MarkAsNonPII(MetadataAddress ?? "null"),
                                    ex),
                                ex));
                    }
                });
            }

            IConfigurationEventHandler<T> eventHandler = ConfigurationEventHandler;

            // Prefer the synchronous handler when both properties reference handlers.
            if (eventHandlerSync == null && eventHandler != null)
            {
                _ = Task.Run(async () =>
                {
                    try
                    {
                        if (eventHandler is IConfigurationEventHandlerContextAware<T> contextAware)
                            await contextAware.AfterUpdateAsync(MetadataAddress, configuration, context).ConfigureAwait(false);
                        else
                            await eventHandler.AfterUpdateAsync(MetadataAddress, configuration).ConfigureAwait(false);
                    }
                    catch (Exception ex)
                    {
                        LogHelper.LogExceptionMessage(
                            new InvalidOperationException(
                                LogHelper.FormatInvariant(
                                   LogMessages.IDX20813,
                                    LogHelper.MarkAsNonPII(MetadataAddress ?? "null"),
                                    ex),
                                ex));
                    }
                });
            }
        }

        private void TelemetryForUpdateBlocking(string configurationSource)
        {
            string updateMode;

            if (_currentConfiguration is null)
                updateMode = TelemetryConstants.Protocols.FirstRefresh;
            else
                updateMode = _refreshRequested ? TelemetryConstants.Protocols.Manual : TelemetryConstants.Protocols.Automatic;

            try
            {
                TelemetryClient.IncrementConfigurationRefreshRequestCounter(
                    MetadataAddress,
                    updateMode,
                    configurationSource);
            }
#pragma warning disable CA1031 // Do not catch general exception types
            catch
            { }
#pragma warning restore CA1031 // Do not catch general exception types
        }

        // Shared retrieval helpers used by both the synchronous (ConfigurationManager_Sync.cs)
        // and asynchronous (ConfigurationManager_Async.cs) partials. They contain only synchronous
        // logic (no await), so a single implementation can be reused by both pipelines.

        /// <summary>
        /// Validates the configuration obtained on the very first (bootstrap) retrieval and throws if it is invalid.
        /// Called by <c>GetConfigurationNonBlockingSync</c> (ConfigurationManager_Sync.cs) and
        /// <c>GetConfigurationNonBlockingAsync</c> (ConfigurationManager_Async.cs).
        /// </summary>
        private void ThrowIfFirstRetrievalInvalid(T configuration)
        {
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
        }

        /// <summary>
        /// Builds (and logs) the "no metadata could be obtained" <see cref="InvalidOperationException"/> (IDX20803).
        /// Called by <c>GetConfigurationNonBlockingSync</c>/<c>GetConfigurationWithBlockingSync</c>
        /// (ConfigurationManager_Sync.cs), <c>GetConfigurationNonBlockingAsync</c>/<c>GetConfigurationWithBlockingAsync</c>
        /// (ConfigurationManager_Async.cs), and <see cref="HandleBlockingRetrievalException"/>.
        /// </summary>
        private Exception CreateNoMetadataException(Exception fetchMetadataFailure)
        {
            return LogHelper.LogExceptionMessage(
                new InvalidOperationException(
                    LogHelper.FormatInvariant(
                        LogMessages.IDX20803,
                        LogHelper.MarkAsNonPII(MetadataAddress ?? "null"),
                        LogHelper.MarkAsNonPII(_syncAfter),
                        LogHelper.MarkAsNonPII(fetchMetadataFailure)),
                    fetchMetadataFailure));
        }

        /// <summary>
        /// Logs a failure that occurred during the non-blocking (bootstrap) retrieval path (IDX20806).
        /// Called by <c>GetConfigurationNonBlockingSync</c> (ConfigurationManager_Sync.cs) and
        /// <c>GetConfigurationNonBlockingAsync</c> (ConfigurationManager_Async.cs).
        /// </summary>
        private void LogNonBlockingRetrievalException(Exception ex)
        {
            TelemetryClient.IncrementConfigurationRefreshRequestCounter(
                MetadataAddress,
                TelemetryConstants.Protocols.FirstRefresh,
                TelemetryConstants.Protocols.ConfigurationSourceRetriever,
                ex);

            LogHelper.LogExceptionMessage(
                new InvalidOperationException(
                     LogHelper.FormatInvariant(
                        LogMessages.IDX20806,
                        LogHelper.MarkAsNonPII(MetadataAddress ?? "null"),
                        LogHelper.MarkAsNonPII(ex)),
                    ex));
        }

        /// <summary>
        /// Handles a failure that occurred during the blocking retrieval path. Updates <c>_syncAfter</c>
        /// (using exponential bootstrap backoff when no configuration exists yet), records telemetry, and
        /// either throws IDX20803 when there is no cached configuration or logs IDX20806 when stale
        /// configuration can be served. Called by <c>GetConfigurationWithBlockingSync</c>
        /// (ConfigurationManager_Sync.cs) and <c>GetConfigurationWithBlockingAsync</c> (ConfigurationManager_Async.cs).
        /// </summary>
        private void HandleBlockingRetrievalException(Exception ex, long startTimestamp)
        {
            _fetchMetadataFailure = ex;

            if (_currentConfiguration == null)
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
                    _syncAfter = DateTimeUtil.Add(
                        TimeProvider.GetUtcNow().UtcDateTime,
                        AutomaticRefreshInterval < RefreshInterval ? AutomaticRefreshInterval : RefreshInterval);
                }

                TelemetryClient.IncrementConfigurationRefreshRequestCounter(
                    MetadataAddress,
                    TelemetryConstants.Protocols.FirstRefresh,
                    TelemetryConstants.Protocols.ConfigurationSourceRetriever,
                    ex);

                throw CreateNoMetadataException(ex);
            }
            else
            {
                _syncAfter = DateTimeUtil.Add(
                    TimeProvider.GetUtcNow().UtcDateTime,
                    AutomaticRefreshInterval < RefreshInterval ? AutomaticRefreshInterval : RefreshInterval);

                var elapsedTime = TimeProvider.GetElapsedTime(startTimestamp);

                TelemetryClient.LogConfigurationRetrievalDuration(
                    MetadataAddress,
                    TelemetryConstants.Protocols.ConfigurationSourceRetriever,
                    elapsedTime,
                    ex);

                LogHelper.LogExceptionMessage(
                    new InvalidOperationException(
                        LogHelper.FormatInvariant(LogMessages.IDX20806, LogHelper.MarkAsNonPII(MetadataAddress ?? "null"), LogHelper.MarkAsNonPII(ex)), ex));
            }
        }

        /// <summary>
        /// Validates the configuration returned by an event handler and records telemetry. Returns the
        /// handler result when it is present and valid, otherwise <see cref="ConfigurationEventHandlerResult{T}.NoResult"/>.
        /// Called by <c>HandleBeforeRetrieveSync</c> (ConfigurationManager_Sync.cs) and
        /// <c>HandleBeforeRetrieveAsync</c> (ConfigurationManager_Async.cs).
        /// </summary>
        private ConfigurationEventHandlerResult<T> ValidateHandlerResult(ConfigurationEventHandlerResult<T> handlerResult, long beforeHandlerTimestamp)
        {
            if (handlerResult != null && handlerResult.Configuration != null)
            {
                var handlerElapsedTime = TimeProvider.GetElapsedTime(beforeHandlerTimestamp);
                TelemetryClient.LogConfigurationRetrievalDuration(
                    MetadataAddress,
                    TelemetryConstants.Protocols.ConfigurationSourceHandler,
                    handlerElapsedTime);

                // Validate configuration from handler
                if (_configValidator != null)
                {
                    ConfigurationValidationResult result = _configValidator.Validate(handlerResult.Configuration);
                    if (!result.Succeeded)
                    {
                        // Just log the error and proceed to fetch from endpoint
                        LogHelper.LogExceptionMessage(
                            new InvalidConfigurationException(
                                LogHelper.FormatInvariant(
                                    LogMessages.IDX20812,
                                    result.ErrorMessage)));

                        return ConfigurationEventHandlerResult<T>.NoResult;
                    }
                }

                // No validator configured, return configuration
                return handlerResult;
            }

            return ConfigurationEventHandlerResult<T>.NoResult;
        }

        /// <summary>
        /// Logs a failure that occurred while invoking the configuration event handler (IDX20811).
        /// Called by <c>HandleBeforeRetrieveSync</c> (ConfigurationManager_Sync.cs) and
        /// <c>HandleBeforeRetrieveAsync</c> (ConfigurationManager_Async.cs).
        /// </summary>
        private void LogHandlerRetrievalException(Exception ex, long beforeHandlerTimestamp)
        {
            var handlerErrorElapsedTime = TimeProvider.GetElapsedTime(beforeHandlerTimestamp);
            TelemetryClient.LogConfigurationRetrievalDuration(
                MetadataAddress,
                TelemetryConstants.Protocols.ConfigurationSourceHandler,
                handlerErrorElapsedTime,
                ex);

            LogHelper.LogExceptionMessage(
                new InvalidOperationException(
                    LogHelper.FormatInvariant(
                        LogMessages.IDX20811,
                        LogHelper.MarkAsNonPII(MetadataAddress ?? "null"),
                        ex),
                    ex));
        }
    }
}
