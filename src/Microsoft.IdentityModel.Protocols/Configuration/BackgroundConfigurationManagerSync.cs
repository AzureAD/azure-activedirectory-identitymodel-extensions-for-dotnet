// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System;
using System.Threading;
using Microsoft.IdentityModel.Logging;
using Microsoft.IdentityModel.Protocols.Configuration;
using Microsoft.IdentityModel.Tokens;

namespace Microsoft.IdentityModel.Protocols;

internal class BackgroundConfigurationManagerSync<T> :
    BaseConfigurationManagerSync,
    IConfigurationManagerSync<T> where T : class
{
    private readonly object _configurationStateLock = new();
    private readonly SemaphoreSlim _configurationNullLock = new(1);
    private readonly SemaphoreSlim _refreshLock = new(1);
    private readonly DedicatedThreadRetriever<T> _dedicatedThreadRetriever;
    private int _blockingRefreshRequested;
    private T _currentConfiguration;
    private DateTimeOffset _syncAfter = DateTimeOffset.MinValue;

    internal BackgroundConfigurationManagerSync(
        string metadataAddress,
        IConfigurationRetrieverSync<T> configRetriever,
        IDocumentRetrieverSync docRetriever)
        : this(
            metadataAddress,
            DedicatedThreadRetriever<T>.CreateSync(metadataAddress, configRetriever, docRetriever),
            new LastKnownGoodConfigurationCacheOptions())
    {
    }

    internal BackgroundConfigurationManagerSync(
        string metadataAddress,
        IConfigurationRetrieverSync<T> configRetriever,
        IDocumentRetrieverSync docRetriever,
        IConfigurationValidator<T> configValidator)
        : this(
            metadataAddress,
            DedicatedThreadRetriever<T>.CreateSync(
                metadataAddress,
                configRetriever,
                docRetriever,
                configValidator),
            new LastKnownGoodConfigurationCacheOptions())
    {
    }

    internal BackgroundConfigurationManagerSync(
        string metadataAddress,
        DedicatedThreadRetriever<T> dedicatedThreadRetriever)
        : this(metadataAddress, dedicatedThreadRetriever, new LastKnownGoodConfigurationCacheOptions())
    {
    }

    internal BackgroundConfigurationManagerSync(
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

    public T GetConfigurationSync()
    {
        return GetConfigurationSync(CancellationToken.None);
    }

    public virtual T GetConfigurationSync(CancellationToken cancel)
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
            return GetConfigurationWithBlockingSync(cancel);

        return GetConfigurationNonBlockingSync(cancel);
    }

    private T GetConfigurationNonBlockingSync(CancellationToken cancel)
    {
        T currentConfiguration = ReadCurrentConfiguration();
        if (currentConfiguration is null)
        {
            _configurationNullLock.Wait(cancel);
            try
            {
                currentConfiguration = ReadCurrentConfiguration();
                if (currentConfiguration is not null)
                    return currentConfiguration;

                try
                {
                    return _dedicatedThreadRetriever.RequestRefreshAndWait(cancel);
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

    private T GetConfigurationWithBlockingSync(CancellationToken cancel)
    {
        _refreshLock.Wait(cancel);
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
                T configuration = _dedicatedThreadRetriever.RequestRefreshAndWait(cancel);
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

    internal override BaseConfiguration GetBaseConfigurationSync(CancellationToken cancellationToken)
    {
        return GetConfigurationSync(cancellationToken) as BaseConfiguration;
    }

    public override void RequestRefresh()
    {
        if (AppContextSwitches.UpdateConfigAsBlocking)
        {
            lock (_configurationStateLock)
                _syncAfter = DateTimeOffset.UtcNow;

            Interlocked.Increment(ref _blockingRefreshRequested);
        }
        else
        {
            _dedicatedThreadRetriever.RequestRefresh();
        }
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

    public new static readonly TimeSpan DefaultAutomaticRefreshInterval = BaseConfigurationManager.DefaultAutomaticRefreshInterval;
    public new static readonly TimeSpan DefaultRefreshInterval = BaseConfigurationManager.DefaultRefreshInterval;
    public new static readonly TimeSpan MinimumAutomaticRefreshInterval = BaseConfigurationManager.MinimumAutomaticRefreshInterval;
    public new static readonly TimeSpan MinimumRefreshInterval = BaseConfigurationManager.MinimumRefreshInterval;
}
