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
/// Synchronous configuration retrieval.
/// </summary>
internal partial class ConfigurationManagerSync<T> : BaseConfigurationManager, IConfigurationManagerSync<T> where T : class
{
    private readonly IDocumentRetrieverSync _docRetrieverSync;
    private readonly IConfigurationRetrieverSync<T> _configRetrieverSync;

    private readonly Action _updateCurrentConfigurationWithBypassSync;
    private readonly Action _updateCurrentConfigurationWithoutBypassSync;

    /// <summary>
    /// Obtains an updated version of Configuration.
    /// </summary>
    /// <returns>Configuration of type <typeparamref name="T"/>.</returns>
    /// <remarks>If the time since the last call is less than <see cref="BaseConfigurationManager.AutomaticRefreshInterval"/> then <see cref="IConfigurationRetrieverSync{T}.GetConfigurationSync"/> is not called and the current Configuration is returned.</remarks>
    public T GetConfigurationSync()
    {
        return GetConfigurationSync(CancellationToken.None);
    }

    /// <summary>
    /// Obtains an updated version of Configuration.
    /// </summary>
    /// <param name="cancel">CancellationToken</param>
    /// <returns>Configuration of type <typeparamref name="T"/>.</returns>
    /// <remarks>
    /// <para>
    /// If the time since the last call is less than <see cref="BaseConfigurationManager.AutomaticRefreshInterval"/>
    /// then <see cref="IConfigurationRetrieverSync{T}.GetConfigurationSync"/> is not called the current Configuration is returned.
    /// This method blocks until the configuration is retrieved.
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
    public virtual T GetConfigurationSync(CancellationToken cancel)
    {
        if (_currentConfiguration != null && _syncAfter > TimeProvider.GetUtcNow())
            return _currentConfiguration;

        if (AppContextSwitches.UpdateConfigAsBlocking)
            return GetConfigurationWithBlockingSync(cancel);
        else
            return GetConfigurationNonBlockingSync(cancel);

    }

    private T GetConfigurationNonBlockingSync(CancellationToken cancel)
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
            _configurationNullLock.Wait(cancel);
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
                if (ConfigurationEventHandlerSync != null)
                {
                    var configurationRetrieved = HandleBeforeRetrieveSync(retrievalContext, cancel);

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

                T configuration = _configRetrieverSync.GetConfigurationSync(
                    MetadataAddress,
                    _docRetrieverSync,
                    CancellationToken.None);

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

                _ = Task.Run(_updateCurrentConfigurationWithoutBypassSync, CancellationToken.None);
            }
        }

        // If metadata exists return it.
        if (_currentConfiguration != null)
            return _currentConfiguration;

        throw CreateNoMetadataException(fetchMetadataFailure);
    }

    private T GetConfigurationWithBlockingSync(CancellationToken cancel)
    {
        _refreshLock.Wait(cancel);

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
                    if (ConfigurationEventHandlerSync != null)
                    {
                        ConfigurationEventHandlerResult<T> configurationRetrieved =
                            HandleBeforeRetrieveSync(retrievalContext, cancel);

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

                    var configuration = _configRetrieverSync.GetConfigurationSync(MetadataAddress, _docRetrieverSync, CancellationToken.None);

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
    private void UpdateCurrentConfigurationSync(bool bypassCache)
    {
        long startTimestamp = TimeProvider.GetTimestamp();
        var retrievalContext = new ConfigurationRetrievalContext { BypassCache = bypassCache };
        try
        {
            // Check if event handler can provide configuration
            // If provided configuration is valid, skip regular retrieval process and update current configuration.
            if (ConfigurationEventHandlerSync != null)
            {
                ConfigurationEventHandlerResult<T> configurationRetrieved = HandleBeforeRetrieveSync(retrievalContext);

                if (configurationRetrieved != null && configurationRetrieved.Configuration != null)
                {
                    UpdateConfiguration(configurationRetrieved.Configuration, configurationRetrieved.RetrievalTime, retrievalContext);

                    _onBackgroundTaskFinish?.Invoke();
                    return;
                }
            }

            T configuration = _configRetrieverSync.GetConfigurationSync(
                MetadataAddress,
                _docRetrieverSync,
                CancellationToken.None);

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
    /// <remarks>If the time since the last call is less than <see cref="BaseConfigurationManager.AutomaticRefreshInterval"/> then <see cref="IConfigurationRetrieverSync{T}.GetConfigurationSync"/> is not called and the current Configuration is returned.</remarks>
    public BaseConfiguration GetBaseConfigurationSync(CancellationToken cancel)
    {
        T obj = GetConfigurationSync(cancel);
        return obj as BaseConfiguration;
    }

    private ConfigurationEventHandlerResult<T> HandleBeforeRetrieveSync(ConfigurationRetrievalContext context, CancellationToken cancellationToken = default)
    {
        long beforeHandlerTimestamp = TimeProvider.GetTimestamp();

        try
        {
            ConfigurationEventHandlerResult<T> handlerResult;
            IConfigurationEventHandlerSync<T> eventHandlerSync = ConfigurationEventHandlerSync;

            if (eventHandlerSync is IConfigurationEventHandlerContextAwareSync<T> contextAware)
            {
                handlerResult = contextAware.BeforeRetrieve(
                    MetadataAddress, context, cancellationToken);
            }
            else if (eventHandlerSync != null)
            {
                handlerResult = eventHandlerSync.BeforeRetrieve(
                    MetadataAddress, cancellationToken);
            }
            else
            {
                return ConfigurationEventHandlerResult<T>.NoResult;
            }

            return ValidateHandlerResult(handlerResult, beforeHandlerTimestamp);
        }
#pragma warning disable CA1031
        catch (Exception ex)
        {
            LogHandlerRetrievalException(ex, beforeHandlerTimestamp);
        }
#pragma warning restore CA1031
        return ConfigurationEventHandlerResult<T>.NoResult;
    }
}
