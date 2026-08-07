// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.IdentityModel.Logging;
using Microsoft.IdentityModel.Protocols.Configuration;
using Microsoft.IdentityModel.Telemetry;
using Microsoft.IdentityModel.Tokens;

namespace Microsoft.IdentityModel.Protocols;

/// <summary>
/// Asynchronous retrieval methods for <see cref="ConfigurationManager{T}"/>.
/// </summary>
public partial class ConfigurationManager<T> : BaseConfigurationManager, IConfigurationManager<T>, IConfigurationManagerSync<T> where T : class
{
    private readonly IDocumentRetriever _docRetrieverAsync;
    private readonly IConfigurationRetriever<T> _configRetrieverAsync;

    private readonly Func<Task> _updateCurrentConfigurationWithBypassAsync;
    private readonly Func<Task> _updateCurrentConfigurationWithoutBypassAsync;

    /// <summary>
    /// Obtains an updated version of Configuration.
    /// </summary>
    /// <returns>Configuration of type <typeparamref name="T"/>.</returns>
    /// <remarks>If the time since the last call is less than <see cref="BaseConfigurationManager.AutomaticRefreshInterval"/> then <see cref="IConfigurationRetriever{T}.GetConfigurationAsync"/> is not called and the current Configuration is returned.</remarks>
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
    /// <para>
    /// If the time since the last call is less than <see cref="BaseConfigurationManager.AutomaticRefreshInterval"/>
    /// then <see cref="IConfigurationRetriever{T}.GetConfigurationAsync"/> is not called and the current Configuration is returned.
    /// By default, this method blocks until the configuration is retrieved the first time. After the configuration was retrieved once,
    /// updates will happen in the background. Failures to retrieve the configuration on the background thread will be logged.
    /// </para>
    /// <para>
    /// If this operation is configured to be blocking through the switch 'Switch.Microsoft.IdentityModel.UpdateConfigAsBlocking'
    /// then this method will block each time the configuration needs to be updated or hasn't been retrieved. If the configuration
    /// cannot be initially retrieved an exception will be thrown. If the configuration has been retrieved, but cannot be updated,
    /// then the exception will be logged and the current configuration will be returned.
    /// </para>
    /// <para>
    /// By using the app context switch you choose what works best for you when there is a signing key update:
    /// either block requests from being validated until the new key is retrieved, or allow requests to be validated
    /// with the current key until the new key is retrieved. If blocking, a service receiving high concurrent request
    /// may experience thread starvation.
    /// </para>
    /// </remarks>
    public virtual async Task<T> GetConfigurationAsync(CancellationToken cancel)
    {
        if (_configRetrieverAsync == null || _docRetrieverAsync == null)
            throw LogHelper.LogExceptionMessage(new NotSupportedException(LogMessages.IDX20815));

        if (_currentConfiguration != null && _syncAfter > TimeProvider.GetUtcNow())
            return _currentConfiguration;

        if (AppContextSwitches.UpdateConfigAsBlocking)
            return await GetConfigurationWithBlockingAsync(cancel).ConfigureAwait(false);
        else
            return await GetConfigurationNonBlockingAsync(cancel).ConfigureAwait(false);
    }

    private async Task<T> GetConfigurationNonBlockingAsync(CancellationToken cancel)
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

            try
            {
                var retrievalContext = new ConfigurationRetrievalContext { BypassCache = false };

                // Check if event handler can provide configuration.
                // If provided configuration is valid, skip regular retriaval process and update current configuration.
                if (ConfigurationEventHandler != null)
                {
                    var configurationRetrieved = await HandleBeforeRetrieveAsync(retrievalContext, cancel).ConfigureAwait(false);

                    // replicate the behavior of successful retrieval from endpoint
                    if (configurationRetrieved != null && configurationRetrieved.Configuration != null)
                    {
                        TelemetryClient.IncrementConfigurationRefreshRequestCounter(
                            MetadataAddress,
                            TelemetryConstants.Protocols.FirstRefresh,
                            TelemetryConstants.Protocols.ConfigurationSourceHandler);

                        UpdateConfiguration(configurationRetrieved.Configuration, configurationRetrieved.RetrievalTime, retrievalContext);
                        return _currentConfiguration;
                    }
                }

                T configuration = await _configRetrieverAsync.GetConfigurationAsync(
                    MetadataAddress,
                    _docRetrieverAsync,
                    CancellationToken.None).ConfigureAwait(false);

                ThrowIfFirstRetrievalInvalid(configuration);

                TelemetryClient.IncrementConfigurationRefreshRequestCounter(
                    MetadataAddress,
                    TelemetryConstants.Protocols.FirstRefresh,
                    TelemetryConstants.Protocols.ConfigurationSourceRetriever);

                UpdateConfiguration(configuration, TimeProvider.GetUtcNow(), retrievalContext);
            }
#pragma warning disable CA1031 // Do not catch general exception types
            catch (Exception ex)
            {
                fetchMetadataFailure = ex;
                LogNonBlockingRetrievalException(ex);
            }
#pragma warning restore CA1031 // Do not catch general exception types
            finally
            {
                _configurationNullLock.Release();
            }
        }
        else
        {
            if (Interlocked.CompareExchange(ref _configurationRetrieverState, ConfigurationRetrieverRunning, ConfigurationRetrieverIdle) == ConfigurationRetrieverIdle)
            {
                TelemetryClient.IncrementConfigurationRefreshRequestCounter(
                    MetadataAddress,
                    TelemetryConstants.Protocols.Automatic,
                    TelemetryConstants.Protocols.ConfigurationSourceUnknown);

                _ = Task.Run(_updateCurrentConfigurationWithoutBypassAsync, CancellationToken.None);
            }
        }

        // If metadata exists return it.
        if (_currentConfiguration != null)
            return _currentConfiguration;

        throw CreateNoMetadataException(fetchMetadataFailure);
    }

    private async Task<T> GetConfigurationWithBlockingAsync(CancellationToken cancel)
    {
        await _refreshLock.WaitAsync(cancel).ConfigureAwait(false);

        long startTimestamp = TimeProvider.GetTimestamp();

        try
        {
            if (_syncAfter <= TimeProvider.GetUtcNow())
            {
                var retrievalContext = new ConfigurationRetrievalContext { BypassCache = _refreshRequested };
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

                            if (_refreshRequested)
                                _refreshRequested = false;

                            UpdateConfiguration(configurationRetrieved.Configuration, configurationRetrieved.RetrievalTime, retrievalContext);

                            _fetchMetadataFailure = null;

                            return _currentConfiguration;
                        }
                    }

                    var configuration = await _configRetrieverAsync.GetConfigurationAsync(MetadataAddress, _docRetrieverAsync, CancellationToken.None).ConfigureAwait(false);

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

                    _lastRequestRefresh = TimeProvider.GetUtcNow().UtcDateTime;

                    TelemetryForUpdateBlocking(TelemetryConstants.Protocols.ConfigurationSourceRetriever);

                    if (_refreshRequested)
                        _refreshRequested = false;

                    UpdateConfiguration(configuration, TimeProvider.GetUtcNow(), retrievalContext);

                    _fetchMetadataFailure = null;
                }
#pragma warning disable CA1031 // Do not catch general exception types
                catch (Exception ex)
                {
                    HandleBlockingRetrievalException(ex, startTimestamp);
                }
#pragma warning restore CA1031 // Do not catch general exception types
            }

            // Stale metadata is better than no metadata
            if (_currentConfiguration != null)
                return _currentConfiguration;
            else
                throw CreateNoMetadataException(_fetchMetadataFailure);
        }
        finally
        {
            _refreshLock.Release();
        }
    }

    /// <summary>
    /// This should be called when the configuration needs to be updated either from RequestRefresh or AutomaticRefresh
    /// The Caller should first check the state checking state using:
    ///   if (Interlocked.CompareExchange(ref _configurationRetrieverState, ConfigurationRetrieverRunning, ConfigurationRetrieverIdle) == ConfigurationRetrieverIdle).
    /// </summary>
    private async Task UpdateCurrentConfigurationAsync(bool bypassCache)
    {
        long startTimestamp = TimeProvider.GetTimestamp();
        var retrievalContext = new ConfigurationRetrievalContext { BypassCache = bypassCache };
        try
        {
            // Check if event handler can provide configuration
            // If provided configuration is valid, skip regular retriaval process and update current configuration.
            if (ConfigurationEventHandler != null)
            {
                ConfigurationEventHandlerResult<T> configurationRetrieved = await HandleBeforeRetrieveAsync(retrievalContext).ConfigureAwait(false);

                if (configurationRetrieved != null && configurationRetrieved.Configuration != null)
                {
                    UpdateConfiguration(configurationRetrieved.Configuration, configurationRetrieved.RetrievalTime, retrievalContext);

                    _onBackgroundTaskFinish?.Invoke();
                    return;
                }
            }

            T configuration = await _configRetrieverAsync.GetConfigurationAsync(
                MetadataAddress,
                _docRetrieverAsync,
                CancellationToken.None).ConfigureAwait(false);

            var elapsedTime = TimeProvider.GetElapsedTime(startTimestamp);
            TelemetryClient.LogConfigurationRetrievalDuration(
                MetadataAddress,
                TelemetryConstants.Protocols.ConfigurationSourceRetriever,
                elapsedTime);

            if (_configValidator == null)
            {
                UpdateConfiguration(configuration, TimeProvider.GetUtcNow(), retrievalContext);
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
                    UpdateConfiguration(configuration, TimeProvider.GetUtcNow(), retrievalContext);
            }
        }
#pragma warning disable CA1031 // Do not catch general exception types
        catch (Exception ex)
        {
            var elapsedTime = TimeProvider.GetElapsedTime(startTimestamp);
            TelemetryClient.LogConfigurationRetrievalDuration(
                MetadataAddress,
                TelemetryConstants.Protocols.ConfigurationSourceRetriever,
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
#pragma warning restore CA1031 // Do not catch general exception types
        finally
        {
            Interlocked.Exchange(ref _configurationRetrieverState, ConfigurationRetrieverIdle);
        }

        _onBackgroundTaskFinish?.Invoke();
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

    private async Task<ConfigurationEventHandlerResult<T>> HandleBeforeRetrieveAsync(ConfigurationRetrievalContext context, CancellationToken cancellationToken = default)
    {
        long beforeHandlerTimestamp = TimeProvider.GetTimestamp();

        try
        {
            ConfigurationEventHandlerResult<T> handlerResult;
            if (ConfigurationEventHandler is IConfigurationEventHandlerContextAware<T> contextAware)
            {
                handlerResult = await contextAware.BeforeRetrieveAsync(
                    MetadataAddress, context, cancellationToken).ConfigureAwait(false);
            }
            else
            {
                handlerResult = await ConfigurationEventHandler.BeforeRetrieveAsync(
                    MetadataAddress, cancellationToken).ConfigureAwait(false);
            }

            return ValidateHandlerResult(handlerResult, beforeHandlerTimestamp);
        }
        catch (Exception ex)
        {
            LogHandlerRetrievalException(ex, beforeHandlerTimestamp);
        }

        return ConfigurationEventHandlerResult<T>.NoResult;
    }
}
