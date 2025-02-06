// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System.Threading.Tasks;
using System.Threading;
using System;
using Microsoft.IdentityModel.Logging;
using Microsoft.IdentityModel.Protocols.Configuration;
using Microsoft.IdentityModel.Tokens;
using Microsoft.IdentityModel.Telemetry;

namespace Microsoft.IdentityModel.Protocols
{
    partial class ConfigurationManager<T> where T : class
    {
        private readonly SemaphoreSlim _refreshLock = new(1);

        private TimeSpan _bootstrapRefreshInterval = TimeSpan.FromSeconds(1);

        private async Task<T> GetConfigurationWithBlockingAsync(CancellationToken cancel)
        {
            Exception _fetchMetadataFailure = null;
            await _refreshLock.WaitAsync(cancel).ConfigureAwait(false);

            long startTimestamp = _timeProvider.GetTimestamp();

            try
            {
                if (SyncAfter <= _timeProvider.GetUtcNow())
                {
                    try
                    {
                        // Don't use the individual CT here, this is a shared operation that shouldn't be affected by an individual's cancellation.
                        // The transport should have it's own timeouts, etc..
                        var configuration = await _configRetriever.GetConfigurationAsync(MetadataAddress, _docRetriever, CancellationToken.None).ConfigureAwait(false);

                        var elapsedTime = _timeProvider.GetElapsedTime(startTimestamp);
                        TelemetryClient.LogConfigurationRetrievalDuration(
                            MetadataAddress,
                            elapsedTime);

                        if (_configValidator != null)
                        {
                            ConfigurationValidationResult result = _configValidator.Validate(configuration);
                            if (!result.Succeeded)
                                throw LogHelper.LogExceptionMessage(new InvalidConfigurationException(LogHelper.FormatInvariant(LogMessages.IDX20810, result.ErrorMessage)));
                        }

                        LastRequestRefresh = _timeProvider.GetUtcNow().UtcDateTime;
                        TelemetryForUpdateBlocking();
                        UpdateConfiguration(configuration);
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
                                _syncAfter = DateTimeUtil.Add(
                                    _timeProvider.GetUtcNow().UtcDateTime,
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
                                _timeProvider.GetUtcNow().UtcDateTime,
                                AutomaticRefreshInterval < RefreshInterval ? AutomaticRefreshInterval : RefreshInterval);

                            var elapsedTime = _timeProvider.GetElapsedTime(startTimestamp);

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

        private void RequestRefreshBlocking()
        {
            DateTime now = _timeProvider.GetUtcNow().UtcDateTime;

            if (now >= DateTimeUtil.Add(LastRequestRefresh, RefreshInterval) || _isFirstRefreshRequest)
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
            {
                updateMode = TelemetryConstants.Protocols.FirstRefresh;
            }
            else
            {
                updateMode = _refreshRequested ? TelemetryConstants.Protocols.Manual : TelemetryConstants.Protocols.Automatic;

                if (_refreshRequested)
                    _refreshRequested = false;
            }

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
