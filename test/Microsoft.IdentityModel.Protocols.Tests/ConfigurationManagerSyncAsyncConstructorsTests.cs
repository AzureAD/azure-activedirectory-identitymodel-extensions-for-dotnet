// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.IdentityModel.Protocols.Configuration;
using Xunit;

namespace Microsoft.IdentityModel.Protocols.Tests;

/// <summary>
/// Tests that exercise the interaction between the synchronous and asynchronous retrieval pipelines
/// on <see cref="ConfigurationManager{T}"/> depending on which retriever contracts are supplied:
/// <list type="number">
/// <item>async-only retrievers: the asynchronous path works and the synchronous path is not supported (IDX20814).</item>
/// <item>sync-only retrievers (built through the CreateSync factories): the synchronous path works and the asynchronous path is not supported (IDX20815).</item>
/// <item>retrievers implementing both contracts: either path can be used.</item>
/// </list>
/// </summary>
public class ConfigurationManagerSyncAsyncConstructorsTests
{
    private const string MetadataAddress = "https://localhost/config";

    #region Case 1: async-only retrievers

    [Fact]
    public async Task AsyncOnlyRetrievers_AsynchronousRetrievalSucceeds()
    {
        // Arrange
        ConfigurationManager<TestConfiguration> manager = CreateAsyncOnly();

        // Act
        TestConfiguration configuration = await manager.GetConfigurationAsync(CancellationToken.None);

        // Assert
        Assert.NotNull(configuration);
    }

    [Fact]
    public void AsyncOnlyRetrievers_GetConfigurationSync_ThrowsNotSupported()
    {
        // Arrange
        ConfigurationManager<TestConfiguration> manager = CreateAsyncOnly();

        // Act
        Exception exception = Assert.ThrowsAny<Exception>(() => manager.GetConfigurationSync(CancellationToken.None));

        // Assert
        AssertRetrievalNotSupported(exception, "IDX20814");
    }

    [Fact]
    public void AsyncOnlyRetrievers_GetBaseConfigurationSync_ThrowsNotSupported()
    {
        // Arrange
        ConfigurationManager<TestConfiguration> manager = CreateAsyncOnly();

        // Act
        Exception exception = Assert.ThrowsAny<Exception>(() => manager.GetBaseConfigurationSync(CancellationToken.None));

        // Assert
        AssertRetrievalNotSupported(exception, "IDX20814");
    }

    #endregion

    #region Case 2: sync-only retrievers (and the CreateSync factories)

    [Fact]
    public void SyncOnlyRetrievers_SynchronousRetrievalSucceeds()
    {
        // Arrange
        ConfigurationManager<TestConfiguration> manager = CreateSyncOnly();

        // Act
        TestConfiguration configuration = manager.GetConfigurationSync(CancellationToken.None);

        // Assert
        Assert.NotNull(configuration);
    }

    [Fact]
    public async Task SyncOnlyRetrievers_GetConfigurationAsync_ThrowsNotSupported()
    {
        // Arrange
        ConfigurationManager<TestConfiguration> manager = CreateSyncOnly();

        // Act
        Exception exception = await Assert.ThrowsAnyAsync<Exception>(() => manager.GetConfigurationAsync(CancellationToken.None));

        // Assert
        AssertRetrievalNotSupported(exception, "IDX20815");
    }

    [Fact]
    public async Task SyncOnlyRetrievers_GetBaseConfigurationAsync_ThrowsNotSupported()
    {
        // Arrange
        ConfigurationManager<TestConfiguration> manager = CreateSyncOnly();

        // Act
        Exception exception = await Assert.ThrowsAnyAsync<Exception>(() => manager.GetBaseConfigurationAsync(CancellationToken.None));

        // Assert
        AssertRetrievalNotSupported(exception, "IDX20815");
    }

    [Fact]
    public void CreateSyncFactories_AllProduceWorkingSynchronousManager()
    {
        // Arrange
        IConfigurationRetrieverSync<TestConfiguration> configRetriever = new SyncOnlyConfigurationRetriever();
        IDocumentRetrieverSync docRetriever = new SyncOnlyDocumentRetriever();
        IConfigurationValidator<TestConfiguration> validator = new SucceedingConfigurationValidator();
        LastKnownGoodConfigurationCacheOptions lkgCacheOptions = new LastKnownGoodConfigurationCacheOptions();
        IConfigurationEventHandler<TestConfiguration> eventHandler = new NoOpConfigurationEventHandler();

        ConfigurationManager<TestConfiguration>[] managers =
        [
            ConfigurationManager<TestConfiguration>.CreateSync(MetadataAddress, configRetriever, docRetriever),
            ConfigurationManager<TestConfiguration>.CreateSync(MetadataAddress, configRetriever, docRetriever, lkgCacheOptions),
            ConfigurationManager<TestConfiguration>.CreateSync(MetadataAddress, configRetriever, docRetriever, validator),
            ConfigurationManager<TestConfiguration>.CreateSync(MetadataAddress, configRetriever, docRetriever, validator, lkgCacheOptions),
            ConfigurationManager<TestConfiguration>.CreateSync(MetadataAddress, configRetriever, docRetriever, validator, lkgCacheOptions, eventHandler),
        ];

        // Act & Assert
        foreach (ConfigurationManager<TestConfiguration> manager in managers)
        {
            TestConfiguration configuration = manager.GetConfigurationSync(CancellationToken.None);
            Assert.NotNull(configuration);
        }
    }

    [Fact]
    public void CreateSyncWithEventHandler_AssignsEventHandler()
    {
        // Arrange
        IConfigurationEventHandler<TestConfiguration> eventHandler = new NoOpConfigurationEventHandler();

        // Act
        ConfigurationManager<TestConfiguration> manager = ConfigurationManager<TestConfiguration>.CreateSync(
            MetadataAddress,
            new SyncOnlyConfigurationRetriever(),
            new SyncOnlyDocumentRetriever(),
            new SucceedingConfigurationValidator(),
            new LastKnownGoodConfigurationCacheOptions(),
            eventHandler);

        // Assert
        Assert.Same(eventHandler, manager.ConfigurationEventHandler);
    }

    #endregion

    #region Case 3: retrievers implementing both contracts

    [Fact]
    public async Task DualRetrievers_AsynchronousRetrievalSucceeds()
    {
        // Arrange
        ConfigurationManager<TestConfiguration> manager = CreateDual();

        // Act
        TestConfiguration configuration = await manager.GetConfigurationAsync(CancellationToken.None);

        // Assert
        Assert.NotNull(configuration);
    }

    [Fact]
    public void DualRetrievers_SynchronousRetrievalSucceeds()
    {
        // Arrange
        ConfigurationManager<TestConfiguration> manager = CreateDual();

        // Act
        TestConfiguration configuration = manager.GetConfigurationSync(CancellationToken.None);

        // Assert
        Assert.NotNull(configuration);
    }

    [Fact]
    public async Task DualRetrieversViaCreateSync_BothPathsSucceed()
    {
        // Arrange
        ConfigurationManager<TestConfiguration> manager = ConfigurationManager<TestConfiguration>.CreateSync(
            MetadataAddress,
            new DualConfigurationRetriever(),
            new DualDocumentRetriever());

        // Act
        TestConfiguration syncConfiguration = manager.GetConfigurationSync(CancellationToken.None);
        TestConfiguration asyncConfiguration = await manager.GetConfigurationAsync(CancellationToken.None);

        // Assert
        Assert.NotNull(syncConfiguration);
        Assert.NotNull(asyncConfiguration);
    }

    #endregion

    #region Mixed retriever contracts (one retriever implements both interfaces, the other only one)

    // These tests assert the guard requires BOTH retrievers to implement the target contract
    // (the condition is `_configRetriever* == null || _docRetriever* == null`).

    [Fact]
    public async Task Constructor_ConfigAsyncOnly_DocImplementsBoth_SyncThrows_AsyncWorks()
    {
        // Arrange: config retriever is async-only, doc retriever implements both.
        ConfigurationManager<TestConfiguration> manager = new ConfigurationManager<TestConfiguration>(
            MetadataAddress,
            new AsyncOnlyConfigurationRetriever(),
            new DualDocumentRetriever());

        // Act & Assert: sync path unavailable because the config retriever lacks the sync contract.
        Exception exception = Assert.ThrowsAny<Exception>(() => manager.GetConfigurationSync(CancellationToken.None));
        AssertRetrievalNotSupported(exception, "IDX20814");

        // Act & Assert: async path always works from a constructor.
        Assert.NotNull(await manager.GetConfigurationAsync(CancellationToken.None));
    }

    [Fact]
    public async Task Constructor_ConfigImplementsBoth_DocAsyncOnly_SyncThrows_AsyncWorks()
    {
        // Arrange: config retriever implements both, doc retriever is async-only.
        ConfigurationManager<TestConfiguration> manager = new ConfigurationManager<TestConfiguration>(
            MetadataAddress,
            new DualConfigurationRetriever(),
            new AsyncOnlyDocumentRetriever());

        // Act & Assert: sync path unavailable because the document retriever lacks the sync contract.
        Exception exception = Assert.ThrowsAny<Exception>(() => manager.GetConfigurationSync(CancellationToken.None));
        AssertRetrievalNotSupported(exception, "IDX20814");

        // Act & Assert
        Assert.NotNull(await manager.GetConfigurationAsync(CancellationToken.None));
    }

    [Fact]
    public async Task CreateSync_ConfigSyncOnly_DocImplementsBoth_AsyncThrows_SyncWorks()
    {
        // Arrange: config retriever is sync-only, doc retriever implements both.
        ConfigurationManager<TestConfiguration> manager = ConfigurationManager<TestConfiguration>.CreateSync(
            MetadataAddress,
            new SyncOnlyConfigurationRetriever(),
            new DualDocumentRetriever());

        // Act & Assert: async path unavailable because the config retriever lacks the async contract.
        Exception exception = await Assert.ThrowsAnyAsync<Exception>(() => manager.GetConfigurationAsync(CancellationToken.None));
        AssertRetrievalNotSupported(exception, "IDX20815");

        // Act & Assert: sync path always works from CreateSync.
        Assert.NotNull(manager.GetConfigurationSync(CancellationToken.None));
    }

    [Fact]
    public async Task CreateSync_ConfigImplementsBoth_DocSyncOnly_AsyncThrows_SyncWorks()
    {
        // Arrange: config retriever implements both, doc retriever is sync-only.
        ConfigurationManager<TestConfiguration> manager = ConfigurationManager<TestConfiguration>.CreateSync(
            MetadataAddress,
            new DualConfigurationRetriever(),
            new SyncOnlyDocumentRetriever());

        // Act & Assert: async path unavailable because the document retriever lacks the async contract.
        Exception exception = await Assert.ThrowsAnyAsync<Exception>(() => manager.GetConfigurationAsync(CancellationToken.None));
        AssertRetrievalNotSupported(exception, "IDX20815");

        // Act & Assert
        Assert.NotNull(manager.GetConfigurationSync(CancellationToken.None));
    }

    #endregion

    #region helpers

    private static ConfigurationManager<TestConfiguration> CreateAsyncOnly()
    {
        return new ConfigurationManager<TestConfiguration>(
            MetadataAddress,
            new AsyncOnlyConfigurationRetriever(),
            new AsyncOnlyDocumentRetriever());
    }

    private static ConfigurationManager<TestConfiguration> CreateSyncOnly()
    {
        return ConfigurationManager<TestConfiguration>.CreateSync(
            MetadataAddress,
            new SyncOnlyConfigurationRetriever(),
            new SyncOnlyDocumentRetriever());
    }

    private static ConfigurationManager<TestConfiguration> CreateDual()
    {
        return new ConfigurationManager<TestConfiguration>(
            MetadataAddress,
            new DualConfigurationRetriever(),
            new DualDocumentRetriever());
    }

    /// <summary>
    /// The first-retrieval failure path wraps the underlying <see cref="NotSupportedException"/> (carrying the
    /// IDX code) in an <see cref="InvalidOperationException"/> (IDX20803). Walk the exception chain and assert a
    /// <see cref="NotSupportedException"/> carrying <paramref name="expectedMessageCode"/> is present.
    /// </summary>
    private static void AssertRetrievalNotSupported(Exception exception, string expectedMessageCode)
    {
        Exception current = exception;
        while (current is not null)
        {
            if (current is NotSupportedException && current.Message.Contains(expectedMessageCode))
                return;

            current = current.InnerException;
        }

        Assert.Fail(
            $"Expected a {nameof(NotSupportedException)} containing '{expectedMessageCode}' somewhere in the exception chain, but was: {exception}");
    }

    #endregion

    #region test doubles

    private sealed class TestConfiguration
    {
    }

    private sealed class AsyncOnlyConfigurationRetriever : IConfigurationRetriever<TestConfiguration>
    {
        public Task<TestConfiguration> GetConfigurationAsync(string address, IDocumentRetriever retriever, CancellationToken cancel)
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
        public TestConfiguration GetConfigurationSync(string address, IDocumentRetrieverSync retriever, CancellationToken cancel)
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

    private sealed class DualConfigurationRetriever : IConfigurationRetriever<TestConfiguration>, IConfigurationRetrieverSync<TestConfiguration>
    {
        public Task<TestConfiguration> GetConfigurationAsync(string address, IDocumentRetriever retriever, CancellationToken cancel)
        {
            return Task.FromResult(new TestConfiguration());
        }

        public TestConfiguration GetConfigurationSync(string address, IDocumentRetrieverSync retriever, CancellationToken cancel)
        {
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

    private sealed class SucceedingConfigurationValidator : IConfigurationValidator<TestConfiguration>
    {
        public ConfigurationValidationResult Validate(TestConfiguration configuration)
        {
            return new ConfigurationValidationResult { Succeeded = true };
        }
    }

    private sealed class NoOpConfigurationEventHandler : IConfigurationEventHandler<TestConfiguration>
    {
        public Task<ConfigurationEventHandlerResult<TestConfiguration>> BeforeRetrieveAsync(string metadataAddress, CancellationToken cancellationToken = default)
        {
            return Task.FromResult(ConfigurationEventHandlerResult<TestConfiguration>.NoResult);
        }

        public Task AfterUpdateAsync(string metadataAddress, TestConfiguration configuration, CancellationToken cancellationToken = default)
        {
            return Task.CompletedTask;
        }
    }

    #endregion
}
