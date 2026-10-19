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
    public partial class ConfigurationManager<T> where T : class
    {
        private readonly SemaphoreSlim _refreshLock = new(1, 1);
        private TimeSpan _bootstrapRefreshInterval = TimeSpan.FromSeconds(1);

        /// <summary>
        /// Used to track the type of request for signaling the event handler and for telemetry.
        /// </summary>
        private int _refreshRequested;

        private async Task<T> GetConfigurationWithBlockingAsync(CancellationToken cancel)
        {
            await _refreshLock.WaitAsync(cancel).ConfigureAwait(false);

            long startTimestamp = TimeProvider.GetTimestamp();

            try
            {
                if (new DateTimeOffset(Interlocked.Read(ref _syncAfter), TimeSpan.Zero) <= TimeProvider.GetUtcNow())
                {
                    var retrievalContext = new ConfigurationRetrievalContext { BypassCache = Volatile.Read(ref _refreshRequested) == 1 };

                    try
                    {
                        // Check if event handler can provide configuration
                        // If provided configuration is valid, skip regular retriaval process and update current configuration.
                        if (ConfigurationEventHandler != null)
                        {
                            ConfigurationEventHandlerResult<T> configurationRetrieved =
                                await HandleBeforeRetrieveAsync(retrievalContext, cancel).ConfigureAwait(false);

                            // replicate the behavior of successful retrieval from endpoint
                            if (configurationRetrieved != null && configurationRetrieved.Configuration != null)
                            {
                                TelemetryForUpdateBlocking(TelemetryConstants.Protocols.ConfigurationSourceHandler);

                                Interlocked.Exchange(ref _refreshRequested, 0);

                                UpdateConfiguration(configurationRetrieved.Configuration, configurationRetrieved.RetrievalTime, retrievalContext);

                                _fetchMetadataFailure = null;

                                return Volatile.Read(ref _currentConfiguration);
                            }
                        }

                        // Don't use the individual CT here, this is a shared operation that shouldn't be affected by an individual's cancellation.
                        // The transport should have it's own timeouts, etc..
                        var configuration = await _configRetriever.GetConfigurationAsync(MetadataAddress, _docRetriever, CancellationToken.None).ConfigureAwait(false);

                        var elapsedTime = TimeProvider.GetElapsedTime(startTimestamp);
                        TelemetryClient.LogConfigurationRetrievalDuration(
                            MetadataAddress,
                            TelemetryConstants.Protocols.ConfigurationSourceRetriever,
                            elapsedTime);

                        if (_configValidator != null)
                        {
                            ConfigurationValidationResult result = _configValidator.Validate(configuration);
                            if (!result.Succeeded)
                                throw LogHelper.LogExceptionMessage(new InvalidConfigurationException(LogHelper.FormatInvariant(LogMessages.IDX20810, result.ErrorMessage)));
                        }

                        Interlocked.Exchange(ref _lastRequestRefresh, TimeProvider.GetUtcNow().Ticks);

                        TelemetryForUpdateBlocking(TelemetryConstants.Protocols.ConfigurationSourceRetriever);

                        Interlocked.Exchange(ref _refreshRequested, 0);

                        UpdateConfiguration(configuration, TimeProvider.GetUtcNow(), retrievalContext);

                        _fetchMetadataFailure = null;
                    }
                    catch (Exception ex)
                    {
                        _fetchMetadataFailure = ex;

                        if (Volatile.Read(ref _currentConfiguration) == null)
                        {
                            if (_bootstrapRefreshInterval < RefreshInterval)
                            {
                                // Adopt exponential backoff for bootstrap refresh interval with a decorrelated jitter if it is not longer than the refresh interval.
                                TimeSpan _bootstrapRefreshIntervalWithJitter = TimeSpan.FromSeconds(new Random().Next((int)_bootstrapRefreshInterval.TotalSeconds));
                                _bootstrapRefreshInterval += _bootstrapRefreshInterval;

                                Interlocked.Exchange(ref _syncAfter, DateTimeUtil.Add(TimeProvider.GetUtcNow().UtcDateTime, _bootstrapRefreshIntervalWithJitter).Ticks);
                            }
                            else
                            {
                                Interlocked.Exchange(ref _syncAfter,
                                    DateTimeUtil.Add(TimeProvider.GetUtcNow().UtcDateTime,
                                        AutomaticRefreshInterval < RefreshInterval ? AutomaticRefreshInterval : RefreshInterval).Ticks);
                            }

                            TelemetryClient.IncrementConfigurationRefreshRequestCounter(
                                MetadataAddress,
                                TelemetryConstants.Protocols.FirstRefresh,
                                TelemetryConstants.Protocols.ConfigurationSourceRetriever,
                                ex);

                            throw LogHelper.LogExceptionMessage(
                                new InvalidOperationException(
                                    LogHelper.FormatInvariant(LogMessages.IDX20803, LogHelper.MarkAsNonPII(MetadataAddress ?? "null"), LogHelper.MarkAsNonPII(new DateTimeOffset(Interlocked.Read(ref _syncAfter), TimeSpan.Zero)), LogHelper.MarkAsNonPII(ex)), ex));
                        }
                        else
                        {
                            Interlocked.Exchange(ref _syncAfter,
                                DateTimeUtil.Add(TimeProvider.GetUtcNow().UtcDateTime,
                                    AutomaticRefreshInterval < RefreshInterval ? AutomaticRefreshInterval : RefreshInterval).Ticks);

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
                }

                // Stale metadata is better than no metadata
                if (Volatile.Read(ref _currentConfiguration) != null)
                    return Volatile.Read(ref _currentConfiguration);
                else
                    throw LogHelper.LogExceptionMessage(
                        new InvalidOperationException(
                            LogHelper.FormatInvariant(
                                LogMessages.IDX20803,
                                LogHelper.MarkAsNonPII(MetadataAddress ?? "null"),
                                LogHelper.MarkAsNonPII(new DateTimeOffset(Interlocked.Read(ref _syncAfter), TimeSpan.Zero)),
                                LogHelper.MarkAsNonPII(_fetchMetadataFailure)),
                            _fetchMetadataFailure));
            }
            finally
            {
                _refreshLock.Release();
            }
        }

        private void RequestRefreshBlocking()
        {
            DateTimeOffset now = TimeProvider.GetUtcNow();
            var lastRefresh = new DateTimeOffset(Interlocked.Read(ref _lastRequestRefresh), TimeSpan.Zero);

            if (now >= DateTimeUtil.Add(lastRefresh.UtcDateTime, RefreshInterval) || Volatile.Read(ref _isFirstRefreshRequest) == 1)
            {
                Interlocked.Exchange(ref _refreshRequested, 1);
                Interlocked.Exchange(ref _syncAfter, now.Ticks);
                Interlocked.Exchange(ref _isFirstRefreshRequest, 0);
            }
        }

        private void TelemetryForUpdateBlocking(string configurationSource)
        {
            string updateMode;

            if (Volatile.Read(ref _currentConfiguration) is null)
                updateMode = TelemetryConstants.Protocols.FirstRefresh;
            else
                updateMode = Volatile.Read(ref _refreshRequested) == 1 ? TelemetryConstants.Protocols.Manual : TelemetryConstants.Protocols.Automatic;

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
    }
}
