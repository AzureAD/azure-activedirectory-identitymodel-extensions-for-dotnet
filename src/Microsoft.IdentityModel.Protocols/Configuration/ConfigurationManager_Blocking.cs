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
        /// Only used to track the type of request for telemetry.
        /// </summary>
        private bool _refreshRequested;

        private async Task<T> GetConfigurationWithBlockingAsync(CancellationToken cancel)
        {
            Exception _fetchMetadataFailure = null;
            await _refreshLock.WaitAsync(cancel).ConfigureAwait(false);

            long startTimestamp = TimeProvider.GetTimestamp();

            try
            {
                if (_syncAfter <= TimeProvider.GetUtcNow())
                {
                    try
                    {
                        // Check if event handler can provide configuration
                        if (ConfigurationEventHandler != null)
                        {
                            var configurationRetrieved = await HandleBeforeRetrieveAsync(cancel).ConfigureAwait(false);
                            if (configurationRetrieved)
                                return _currentConfiguration;
                        }

                        // Don't use the individual CT here, this is a shared operation that shouldn't be affected by an individual's cancellation.
                        // The transport should have it's own timeouts, etc..
                        var configuration = await _configRetriever.GetConfigurationAsync(MetadataAddress, _docRetriever, CancellationToken.None).ConfigureAwait(false);

                        var elapsedTime = TimeProvider.GetElapsedTime(startTimestamp);
                        TelemetryClient.LogConfigurationRetrievalDuration(
                            MetadataAddress,
                            elapsedTime);

                        if (_configValidator != null)
                        {
                            ConfigurationValidationResult result = _configValidator.Validate(configuration);
                            if (!result.Succeeded)
                                throw LogHelper.LogExceptionMessage(new InvalidConfigurationException(LogHelper.FormatInvariant(LogMessages.IDX20810, result.ErrorMessage)));
                        }

                        _lastRequestRefresh = TimeProvider.GetUtcNow().UtcDateTime;

                        TelemetryForUpdateBlocking();

                        if (_refreshRequested)
                            _refreshRequested = false;

                        UpdateConfiguration(configuration);
                    }
                    catch (Exception ex)
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
                                ex);

                            throw LogHelper.LogExceptionMessage(
                                new InvalidOperationException(
                                    LogHelper.FormatInvariant(LogMessages.IDX20803, LogHelper.MarkAsNonPII(MetadataAddress ?? "null"), LogHelper.MarkAsNonPII(_syncAfter), LogHelper.MarkAsNonPII(ex)), ex));
                        }
                        else
                        {
                            _syncAfter = DateTimeUtil.Add(
                                TimeProvider.GetUtcNow().UtcDateTime,
                                AutomaticRefreshInterval < RefreshInterval ? AutomaticRefreshInterval : RefreshInterval);

                            var elapsedTime = TimeProvider.GetElapsedTime(startTimestamp);

                            TelemetryClient.LogConfigurationRetrievalDuration(
                                MetadataAddress,
                                elapsedTime,
                                ex);

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

        private async Task<bool> HandleBeforeRetrieveAsync(CancellationToken cancel = default)
        {
            long beforeHandlerTimestamp = TimeProvider.GetTimestamp();
            try
            {
                var cachedResult = await ConfigurationEventHandler.BeforeRetrieveAsync(MetadataAddress).ConfigureAwait(false);
                if (cachedResult != null && cachedResult.Configuration != null)
                {
                    var handlerElapsedTime = TimeProvider.GetElapsedTime(beforeHandlerTimestamp);
                    TelemetryClient.LogConfigurationRetrievalDuration(
                        MetadataAddress,
                        handlerElapsedTime);// TODO new dimension for source

                    // Validate configuration from handler
                    if (_configValidator != null)
                    {
                        ConfigurationValidationResult result = _configValidator.Validate(cachedResult.Configuration);
                        if (!result.Succeeded)
                        {
                            // Just log the error and proceed to fetch from endpoint
                            LogHelper.LogExceptionMessage(
                                new InvalidConfigurationException(
                                    LogHelper.FormatInvariant(
                                        LogMessages.IDX20810, // TODO new log message
                                        result.ErrorMessage)));

                            return false;
                        }
                    }

                    // No validator configured, use configuration
                    TelemetryClient.IncrementConfigurationRefreshRequestCounter(
                        MetadataAddress,
                        TelemetryConstants.Protocols.FirstRefresh); // TODO new dimension for source

                    UpdateConfiguration(cachedResult.Configuration);
                    return true;
                }
            }
            catch (Exception ex)
            {
                var handlerErrorElapsedTime = TimeProvider.GetElapsedTime(beforeHandlerTimestamp);
                TelemetryClient.LogConfigurationRetrievalDuration(
                    MetadataAddress,
                    handlerErrorElapsedTime,
                    ex); // TODO new dimension for source

                // Log but don't fail - proceed to fetch from endpoint
                // TODO check error
                LogHelper.LogExceptionMessage(
                    new InvalidOperationException(
                        LogHelper.FormatInvariant(
                            "Failed to retrieve configuration from event handler. MetadataAddress: '{0}', Exception: '{1}'.",
                            LogHelper.MarkAsNonPII(MetadataAddress ?? "null"),
                            ex),
                        ex));
            }

            return false;
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

        private void TelemetryForUpdateBlocking()
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
                    updateMode);
            }
#pragma warning disable CA1031 // Do not catch general exception types
            catch
            { }
#pragma warning restore CA1031 // Do not catch general exception types
        }
    }
}
