// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System;
using System.Reflection;
using System.Threading;
using System.Threading.Tasks;
using Xunit;

namespace Microsoft.IdentityModel.Protocols.Tests;

public class DedicatedThreadRetrieverTests
{
    private const string MetadataAddress = "https://localhost/config";

    [Fact]
    public void InterruptedWorker_RestartsOnNextRequest()
    {
        // Arrange
        var configurationRetriever = new CountingSyncConfigurationRetriever();
        DedicatedThreadRetriever<TestConfiguration> dedicatedThreadRetriever =
            DedicatedThreadRetriever<TestConfiguration>.CreateSync(
                MetadataAddress,
                configurationRetriever,
                new SyncDocumentRetriever());
        var configurationManager = new BackgroundConfigurationManagerSync<TestConfiguration>(
            MetadataAddress,
            dedicatedThreadRetriever);

        _ = configurationManager.GetConfigurationSync(CancellationToken.None);
        Thread firstWorker = GetWorker(dedicatedThreadRetriever);

        // Act
        firstWorker.Interrupt();
        Assert.True(SpinWait.SpinUntil(
            () => !firstWorker.IsAlive,
            TimeSpan.FromSeconds(10)));

        configurationManager.RequestRefresh();
        Assert.True(SpinWait.SpinUntil(
            () => configurationRetriever.CallCount == 2,
            TimeSpan.FromSeconds(10)));
        Thread secondWorker = GetWorker(dedicatedThreadRetriever);

        // Assert
        Assert.NotSame(firstWorker, secondWorker);
        Assert.True(secondWorker.IsAlive);
        Assert.Equal(2, configurationRetriever.CallCount);
    }

    [Fact]
    public async Task ConcurrentRequests_CoalesceIntoSingleRetrieval()
    {
        // Arrange
        var configurationRetriever = new BlockingAsyncConfigurationRetriever();
        var dedicatedThreadRetriever = new DedicatedThreadRetriever<TestConfiguration>(
            MetadataAddress,
            configurationRetriever,
            new AsyncDocumentRetriever());
        var configurationManager = new BackgroundConfigurationManager<TestConfiguration>(
            MetadataAddress,
            dedicatedThreadRetriever);

        // Act
        Task<TestConfiguration> firstTask =
            configurationManager.GetConfigurationAsync(CancellationToken.None);
        Assert.True(configurationRetriever.RetrievalStarted.Wait(TimeSpan.FromSeconds(10)));

        Task<TestConfiguration> secondTask =
            configurationManager.GetConfigurationAsync(CancellationToken.None);
        configurationRetriever.AllowRetrieval.Set();

        TestConfiguration[] configurations = await Task.WhenAll(firstTask, secondTask);

        // Assert
        Assert.Same(configurations[0], configurations[1]);
        Assert.Equal(1, configurationRetriever.CallCount);
    }

    [Fact]
    public async Task ConcurrentRefreshRequests_CoalesceIntoSingleRetrieval()
    {
        // Arrange
        var configurationRetriever = new BlockingAsyncConfigurationRetriever { BlockOnCall = 2 };
        var dedicatedThreadRetriever = new DedicatedThreadRetriever<TestConfiguration>(
            MetadataAddress,
            configurationRetriever,
            new AsyncDocumentRetriever());
        var configurationManager = new BackgroundConfigurationManager<TestConfiguration>(
            MetadataAddress,
            dedicatedThreadRetriever);
        _ = await configurationManager.GetConfigurationAsync(CancellationToken.None);
        configurationRetriever.RetrievalStarted.Reset();

        // Act
        configurationManager.RequestRefresh();
        Assert.True(configurationRetriever.RetrievalStarted.Wait(TimeSpan.FromSeconds(10)));
        configurationManager.RequestRefresh();
        configurationManager.RequestRefresh();
        configurationRetriever.AllowRetrieval.Set();
        Assert.True(SpinWait.SpinUntil(
            () => configurationRetriever.CompletedCallCount == 2,
            TimeSpan.FromSeconds(10)));

        // Assert
        Assert.Equal(2, configurationRetriever.CallCount);
    }

    [Fact]
    public async Task FailedRetrieval_AllowsSubsequentRequest()
    {
        // Arrange
        var configurationRetriever = new FailOnceAsyncConfigurationRetriever();
        var dedicatedThreadRetriever = new DedicatedThreadRetriever<TestConfiguration>(
            MetadataAddress,
            configurationRetriever,
            new AsyncDocumentRetriever());
        var configurationManager = new BackgroundConfigurationManager<TestConfiguration>(
            MetadataAddress,
            dedicatedThreadRetriever);

        // Act
        InvalidOperationException exception = await Assert.ThrowsAsync<InvalidOperationException>(
            () => configurationManager.GetConfigurationAsync(CancellationToken.None));
        TestConfiguration configuration =
            await configurationManager.GetConfigurationAsync(CancellationToken.None);

        // Assert
        Assert.Contains("IDX20803", exception.Message);
        Assert.Equal("retrieval failure", exception.InnerException?.Message);
        Assert.NotNull(configuration);
        Assert.Equal(2, configurationRetriever.CallCount);
    }

    private static Thread GetWorker(DedicatedThreadRetriever<TestConfiguration> dedicatedThreadRetriever)
    {
        FieldInfo workerField = typeof(DedicatedThreadRetriever<TestConfiguration>).GetField(
            "_worker",
            BindingFlags.Instance | BindingFlags.NonPublic);

        return Assert.IsType<Thread>(workerField.GetValue(dedicatedThreadRetriever));
    }

    private sealed class TestConfiguration
    {
    }

    private sealed class AsyncDocumentRetriever : IDocumentRetriever
    {
        public Task<string> GetDocumentAsync(string address, CancellationToken cancel)
        {
            return Task.FromResult("{}");
        }
    }

    private sealed class SyncDocumentRetriever : IDocumentRetrieverSync
    {
        public string GetDocument(string address, CancellationToken cancel)
        {
            return "{}";
        }
    }

    private sealed class CountingSyncConfigurationRetriever : IConfigurationRetrieverSync<TestConfiguration>
    {
        private int _callCount;

        internal int CallCount => Volatile.Read(ref _callCount);

        public TestConfiguration GetConfigurationSync(
            string address,
            IDocumentRetrieverSync retriever,
            CancellationToken cancel)
        {
            Interlocked.Increment(ref _callCount);
            return new TestConfiguration();
        }
    }

    private sealed class BlockingAsyncConfigurationRetriever : IConfigurationRetriever<TestConfiguration>
    {
        private int _callCount;
        private int _completedCallCount;

        internal ManualResetEventSlim AllowRetrieval { get; } = new(false);

        internal int BlockOnCall { get; set; } = 1;

        internal int CallCount => Volatile.Read(ref _callCount);

        internal int CompletedCallCount => Volatile.Read(ref _completedCallCount);

        internal ManualResetEventSlim RetrievalStarted { get; } = new(false);

        public Task<TestConfiguration> GetConfigurationAsync(
            string address,
            IDocumentRetriever retriever,
            CancellationToken cancel)
        {
            int callCount = Interlocked.Increment(ref _callCount);
            RetrievalStarted.Set();

            if (callCount == BlockOnCall)
                AllowRetrieval.Wait();

            Interlocked.Increment(ref _completedCallCount);
            return Task.FromResult(new TestConfiguration());
        }
    }

    private sealed class FailOnceAsyncConfigurationRetriever : IConfigurationRetriever<TestConfiguration>
    {
        private int _callCount;

        internal int CallCount => Volatile.Read(ref _callCount);

        public Task<TestConfiguration> GetConfigurationAsync(
            string address,
            IDocumentRetriever retriever,
            CancellationToken cancel)
        {
            if (Interlocked.Increment(ref _callCount) == 1)
                throw new InvalidOperationException("retrieval failure");

            return Task.FromResult(new TestConfiguration());
        }
    }
}
