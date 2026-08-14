// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System;
using System.Threading;
using System.Threading.Tasks;
using Xunit;

namespace Microsoft.IdentityModel.Protocols.Tests;

public class BackgroundConfigurationManagerSyncAsyncConstructorsTests
{
    private const string MetadataAddress = "https://localhost/config";

    [Fact]
    public async Task Constructor_DualRetrievers_UsesAsyncPath()
    {
        // Arrange
        var configurationRetriever = new DualConfigurationRetriever();
        var documentRetriever = new DualDocumentRetriever();
        var dedicatedThreadRetriever = new DedicatedThreadRetriever<TestConfiguration>(
            MetadataAddress,
            configurationRetriever,
            documentRetriever);
        var configurationManager = new BackgroundConfigurationManager<TestConfiguration>(
            MetadataAddress,
            dedicatedThreadRetriever);

        // Act & Assert
        TestConfiguration configuration =
            await configurationManager.GetConfigurationAsync(CancellationToken.None);
        Assert.NotNull(configuration);
        Assert.Equal(1, configurationRetriever.AsyncCalls);
        Assert.Equal(0, configurationRetriever.SyncCalls);
    }

    [Fact]
    public void CreateSync_DualRetrievers_UsesSyncPath()
    {
        // Arrange
        var configurationRetriever = new DualConfigurationRetriever();
        var documentRetriever = new DualDocumentRetriever();
        DedicatedThreadRetriever<TestConfiguration> dedicatedThreadRetriever =
            DedicatedThreadRetriever<TestConfiguration>.CreateSync(
                MetadataAddress,
                configurationRetriever,
                documentRetriever);
        var configurationManager = new BackgroundConfigurationManagerSync<TestConfiguration>(
            MetadataAddress,
            dedicatedThreadRetriever);

        // Act
        TestConfiguration configuration =
            configurationManager.GetConfigurationSync(CancellationToken.None);

        // Assert
        Assert.NotNull(configuration);
        Assert.Equal(0, configurationRetriever.AsyncCalls);
        Assert.Equal(1, configurationRetriever.SyncCalls);
    }

    [Fact]
    public async Task Constructor_AsyncOnlyRetrievers_Succeeds()
    {
        // Arrange
        var dedicatedThreadRetriever = new DedicatedThreadRetriever<TestConfiguration>(
            MetadataAddress,
            new AsyncOnlyConfigurationRetriever(),
            new AsyncOnlyDocumentRetriever());
        var configurationManager = new BackgroundConfigurationManager<TestConfiguration>(
            MetadataAddress,
            dedicatedThreadRetriever);

        // Act
        TestConfiguration configuration =
            await configurationManager.GetConfigurationAsync(CancellationToken.None);

        // Assert
        Assert.NotNull(configuration);
    }

    [Fact]
    public void CreateSync_SyncOnlyRetrievers_Succeeds()
    {
        // Arrange
        DedicatedThreadRetriever<TestConfiguration> dedicatedThreadRetriever =
            DedicatedThreadRetriever<TestConfiguration>.CreateSync(
                MetadataAddress,
                new SyncOnlyConfigurationRetriever(),
                new SyncOnlyDocumentRetriever());
        var configurationManager = new BackgroundConfigurationManagerSync<TestConfiguration>(
            MetadataAddress,
            dedicatedThreadRetriever);

        // Act
        TestConfiguration configuration =
            configurationManager.GetConfigurationSync(CancellationToken.None);

        // Assert
        Assert.NotNull(configuration);
    }

    private sealed class TestConfiguration
    {
    }

    private sealed class AsyncOnlyConfigurationRetriever : IConfigurationRetriever<TestConfiguration>
    {
        public Task<TestConfiguration> GetConfigurationAsync(
            string address,
            IDocumentRetriever retriever,
            CancellationToken cancel)
        {
            return Task.FromResult(new TestConfiguration());
        }
    }

    private sealed class AsyncOnlyDocumentRetriever : IDocumentRetriever
    {
        public Task<string> GetDocumentAsync(string address, CancellationToken cancel)
        {
            return Task.FromResult("{}");
        }
    }

    private sealed class SyncOnlyConfigurationRetriever : IConfigurationRetrieverSync<TestConfiguration>
    {
        public TestConfiguration GetConfigurationSync(
            string address,
            IDocumentRetrieverSync retriever,
            CancellationToken cancel)
        {
            return new TestConfiguration();
        }
    }

    private sealed class SyncOnlyDocumentRetriever : IDocumentRetrieverSync
    {
        public string GetDocument(string address, CancellationToken cancel)
        {
            return "{}";
        }
    }

    private sealed class DualConfigurationRetriever :
        IConfigurationRetriever<TestConfiguration>,
        IConfigurationRetrieverSync<TestConfiguration>
    {
        private int _asyncCalls;
        private int _syncCalls;

        internal int AsyncCalls => Volatile.Read(ref _asyncCalls);

        internal int SyncCalls => Volatile.Read(ref _syncCalls);

        public Task<TestConfiguration> GetConfigurationAsync(
            string address,
            IDocumentRetriever retriever,
            CancellationToken cancel)
        {
            Interlocked.Increment(ref _asyncCalls);
            return Task.FromResult(new TestConfiguration());
        }

        public TestConfiguration GetConfigurationSync(
            string address,
            IDocumentRetrieverSync retriever,
            CancellationToken cancel)
        {
            Interlocked.Increment(ref _syncCalls);
            return new TestConfiguration();
        }
    }

    private sealed class DualDocumentRetriever : IDocumentRetriever, IDocumentRetrieverSync
    {
        public Task<string> GetDocumentAsync(string address, CancellationToken cancel)
        {
            return Task.FromResult("{}");
        }

        public string GetDocument(string address, CancellationToken cancel)
        {
            return "{}";
        }
    }
}
