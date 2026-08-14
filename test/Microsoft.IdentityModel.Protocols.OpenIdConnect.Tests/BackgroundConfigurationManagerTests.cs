// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.IdentityModel.Protocols.Configuration;
using Microsoft.IdentityModel.Protocols.OpenIdConnect.Configuration;
using Microsoft.IdentityModel.TestUtils;
using Microsoft.IdentityModel.Tokens;
using Xunit;

namespace Microsoft.IdentityModel.Protocols.OpenIdConnect.Tests;

[ResetAppContextSwitches]
[Collection(nameof(AppContextSwitches.UpdateConfigAsBlocking))]
public class BackgroundConfigurationManagerTests
{
    private const string MetadataAddress = "https://localhost/config";

    [Theory, MemberData(nameof(GetPublicMetadataTheoryData), DisableDiscoveryEnumeration = true)]
    public async Task GetPublicMetadata(BackgroundConfigurationManagerTheoryData<OpenIdConnectConfiguration> theoryData)
    {
        // Arrange
        var configurationManager = new BackgroundConfigurationManager<OpenIdConnectConfiguration>(
            theoryData.MetadataAddress,
            theoryData.ConfigurationRetriever,
            theoryData.DocumentRetriever,
            theoryData.ConfigurationValidator);

        // Act
        OpenIdConnectConfiguration configuration =
            await configurationManager.GetConfigurationAsync(CancellationToken.None);

        // Assert
        Assert.NotNull(configuration);
    }

    public static TheoryData<BackgroundConfigurationManagerTheoryData<OpenIdConnectConfiguration>> GetPublicMetadataTheoryData()
    {
        return new TheoryData<BackgroundConfigurationManagerTheoryData<OpenIdConnectConfiguration>>
        {
            new BackgroundConfigurationManagerTheoryData<OpenIdConnectConfiguration>("AccountsGoogleCom")
            {
                ConfigurationRetriever = new OpenIdConnectConfigurationRetriever(),
                ConfigurationValidator = new OpenIdConnectConfigurationValidator(),
                DocumentRetriever = new HttpDocumentRetriever(),
                MetadataAddress = OpenIdConfigData.AccountsGoogle
            },
            new BackgroundConfigurationManagerTheoryData<OpenIdConnectConfiguration>("AADCommonUrl")
            {
                ConfigurationRetriever = new OpenIdConnectConfigurationRetriever(),
                ConfigurationValidator = new OpenIdConnectConfigurationValidator(),
                DocumentRetriever = new HttpDocumentRetriever(),
                MetadataAddress = OpenIdConfigData.AADCommonUrl
            },
            new BackgroundConfigurationManagerTheoryData<OpenIdConnectConfiguration>("AADCommonUrlV1")
            {
                ConfigurationRetriever = new OpenIdConnectConfigurationRetriever(),
                ConfigurationValidator = new OpenIdConnectConfigurationValidator(),
                DocumentRetriever = new HttpDocumentRetriever(),
                MetadataAddress = OpenIdConfigData.AADCommonUrlV1
            },
            new BackgroundConfigurationManagerTheoryData<OpenIdConnectConfiguration>("AADCommonUrlV2")
            {
                ConfigurationRetriever = new OpenIdConnectConfigurationRetriever(),
                ConfigurationValidator = new OpenIdConnectConfigurationValidator(),
                DocumentRetriever = new HttpDocumentRetriever(),
                MetadataAddress = OpenIdConfigData.AADCommonUrlV2
            }
        };
    }

    [Theory, MemberData(nameof(ConstructorTheoryData), DisableDiscoveryEnumeration = true)]
    public void OpenIdConnectConstructor(BackgroundConfigurationManagerTheoryData<OpenIdConnectConfiguration> theoryData)
    {
        // Arrange
        var context = TestUtilities.WriteHeader($"{this}.OpenIdConnectConstructor", theoryData);

        // Act
        try
        {
            _ = new BackgroundConfigurationManager<OpenIdConnectConfiguration>(
                theoryData.MetadataAddress,
                theoryData.ConfigurationRetriever,
                theoryData.DocumentRetriever,
                theoryData.ConfigurationValidator);
            theoryData.ExpectedException.ProcessNoException(context);
        }
        catch (Exception ex)
        {
            theoryData.ExpectedException.ProcessException(ex, context);
        }

        // Assert
        TestUtilities.AssertFailIfErrors(context);
    }

    public static TheoryData<BackgroundConfigurationManagerTheoryData<OpenIdConnectConfiguration>> ConstructorTheoryData
    {
        get
        {
            return new TheoryData<BackgroundConfigurationManagerTheoryData<OpenIdConnectConfiguration>>
            {
                new BackgroundConfigurationManagerTheoryData<OpenIdConnectConfiguration>
                {
                    ConfigurationRetriever = new OpenIdConnectConfigurationRetriever(),
                    ConfigurationValidator = new OpenIdConnectConfigurationValidator(),
                    DocumentRetriever = new HttpDocumentRetriever(),
                    ExpectedException = ExpectedException.ArgumentNullException("IDX10000:"),
                    First = true,
                    MetadataAddress = null,
                    TestId = "MetadataAddress: NULL"
                },
                new BackgroundConfigurationManagerTheoryData<OpenIdConnectConfiguration>
                {
                    ConfigurationRetriever = null,
                    ConfigurationValidator = new OpenIdConnectConfigurationValidator(),
                    DocumentRetriever = new HttpDocumentRetriever(),
                    ExpectedException = ExpectedException.ArgumentNullException("IDX10000:"),
                    MetadataAddress = "OpenIdConnectMetadata.json",
                    TestId = "ConfigurationRetreiver: NULL"
                },
                new BackgroundConfigurationManagerTheoryData<OpenIdConnectConfiguration>
                {
                    ConfigurationRetriever = new OpenIdConnectConfigurationRetriever(),
                    ConfigurationValidator = new OpenIdConnectConfigurationValidator(),
                    DocumentRetriever = null,
                    ExpectedException = ExpectedException.ArgumentNullException("IDX10000:"),
                    MetadataAddress = "OpenIdConnectMetadata.json",
                    TestId = "DocumentRetriever: NULL"
                },
                new BackgroundConfigurationManagerTheoryData<OpenIdConnectConfiguration>
                {
                    ConfigurationRetriever = new OpenIdConnectConfigurationRetriever(),
                    ConfigurationValidator = null,
                    DocumentRetriever = new HttpDocumentRetriever(),
                    ExpectedException = ExpectedException.ArgumentNullException("IDX10000:"),
                    MetadataAddress = "OpenIdConnectMetadata.json",
                    TestId = "ConfigurationValidator: NULL"
                }
            };
        }
    }

    [Fact]
    public void Defaults()
    {
        // Arrange & Act & Assert
        Assert.Equal(TimeSpan.FromHours(12), BackgroundConfigurationManager<OpenIdConnectConfiguration>.DefaultAutomaticRefreshInterval);
        Assert.Equal(TimeSpan.FromMinutes(5), BackgroundConfigurationManager<OpenIdConnectConfiguration>.DefaultRefreshInterval);
        Assert.Equal(TimeSpan.FromMinutes(5), BackgroundConfigurationManager<OpenIdConnectConfiguration>.MinimumAutomaticRefreshInterval);
        Assert.Equal(TimeSpan.FromSeconds(1), BackgroundConfigurationManager<OpenIdConnectConfiguration>.MinimumRefreshInterval);
    }

    [Fact]
    public async Task CheckSyncAfter()
    {
        await CheckSyncAfterBody();
    }

    [Fact]
    public async Task CheckSyncAfter_Blocking()
    {
        AppContext.SetSwitch(AppContextSwitches.UpdateConfigAsBlockingSwitch, true);
        await CheckSyncAfterBody();
    }

    private static async Task CheckSyncAfterBody()
    {
        // Arrange
        var configurationRetriever = new CountingConfigurationRetriever();
        var configurationManager = CreateManager(configurationRetriever);
        OpenIdConnectConfiguration firstConfiguration =
            await configurationManager.GetConfigurationAsync(CancellationToken.None);

        // Act
        OpenIdConnectConfiguration secondConfiguration =
            await configurationManager.GetConfigurationAsync(CancellationToken.None);

        // Assert
        Assert.Same(firstConfiguration, secondConfiguration);
        Assert.Equal(1, configurationRetriever.CallCount);
    }

    [Fact]
    public async Task RequestRefresh()
    {
        await RequestRefreshBody(false);
    }

    [Fact]
    public async Task RequestRefresh_Blocking()
    {
        AppContext.SetSwitch(AppContextSwitches.UpdateConfigAsBlockingSwitch, true);
        await RequestRefreshBody(true);
    }

    private static async Task RequestRefreshBody(bool blocking)
    {
        // Arrange
        var configurationRetriever = new CountingConfigurationRetriever();
        var configurationManager = CreateManager(configurationRetriever);
        OpenIdConnectConfiguration firstConfiguration =
            await configurationManager.GetConfigurationAsync(CancellationToken.None);
        configurationManager.MetadataAddress = "https://localhost/updated";

        // Act
        configurationManager.RequestRefresh();
        if (!blocking)
        {
            Assert.True(SpinWait.SpinUntil(
                () => configurationRetriever.CallCount == 2,
                TimeSpan.FromSeconds(10)));
        }

        OpenIdConnectConfiguration secondConfiguration =
            await configurationManager.GetConfigurationAsync(CancellationToken.None);

        // Assert
        Assert.NotSame(firstConfiguration, secondConfiguration);
        Assert.Equal("issuer-2", secondConfiguration.Issuer);
        Assert.Equal("https://localhost/updated", configurationRetriever.LastAddress);
        Assert.Equal(2, configurationRetriever.CallCount);
    }

    [Fact]
    public async Task RequestRefreshDuringBlockingRetrieval_RemainsPending()
    {
        // Arrange
        AppContext.SetSwitch(AppContextSwitches.UpdateConfigAsBlockingSwitch, true);
        var configurationRetriever = new CountingConfigurationRetriever();
        var configurationManager = CreateManager(configurationRetriever);
        _ = await configurationManager.GetConfigurationAsync(CancellationToken.None);
        configurationRetriever.BlockRetrieval = true;
        configurationRetriever.RetrievalStarted.Reset();

        configurationManager.RequestRefresh();
        Task<OpenIdConnectConfiguration> firstRefresh =
            configurationManager.GetConfigurationAsync(CancellationToken.None);
        Assert.True(configurationRetriever.RetrievalStarted.Wait(TimeSpan.FromSeconds(10)));

        // Act
        configurationManager.RequestRefresh();
        configurationRetriever.AllowRetrieval.Set();
        OpenIdConnectConfiguration firstConfiguration = await firstRefresh;
        OpenIdConnectConfiguration secondConfiguration =
            await configurationManager.GetConfigurationAsync(CancellationToken.None);

        // Assert
        Assert.Equal("issuer-2", firstConfiguration.Issuer);
        Assert.Equal("issuer-3", secondConfiguration.Issuer);
        Assert.Equal(3, configurationRetriever.CallCount);
    }

    [Fact]
    public async Task GetBaseConfigurationAsync_ReturnsOpenIdConnectConfiguration()
    {
        // Arrange
        var configurationManager = CreateManager(new CountingConfigurationRetriever());

        // Act
        BaseConfiguration configuration =
            await configurationManager.GetBaseConfigurationAsync(CancellationToken.None);

        // Assert
        Assert.IsType<OpenIdConnectConfiguration>(configuration);
    }

    [Fact]
    public async Task VerifyInterlockGuardForGetConfigurationAsync()
    {
        // Arrange
        var configurationRetriever = new CountingConfigurationRetriever { BlockRetrieval = true };
        var configurationManager = CreateManager(configurationRetriever);

        // Act
        Task<OpenIdConnectConfiguration> firstTask =
            configurationManager.GetConfigurationAsync(CancellationToken.None);
        Assert.True(configurationRetriever.RetrievalStarted.Wait(TimeSpan.FromSeconds(10)));

        Task<OpenIdConnectConfiguration> secondTask =
            configurationManager.GetConfigurationAsync(CancellationToken.None);
        configurationRetriever.AllowRetrieval.Set();

        OpenIdConnectConfiguration[] configurations =
            await Task.WhenAll(firstTask, secondTask);

        // Assert
        Assert.Same(configurations[0], configurations[1]);
        Assert.Equal(1, configurationRetriever.CallCount);
    }

    [Fact]
    public async Task FetchMetadataFailureTest()
    {
        await FetchMetadataFailureTestBody();
    }

    [Fact]
    public async Task FetchMetadataFailureTest_Blocking()
    {
        AppContext.SetSwitch(AppContextSwitches.UpdateConfigAsBlockingSwitch, true);
        await FetchMetadataFailureTestBody();
    }

    private static async Task FetchMetadataFailureTestBody()
    {
        // Arrange
        var expectedException = new InvalidOperationException("retrieval failure");
        var configurationRetriever = new CountingConfigurationRetriever
        {
            ExceptionOnCall = 1,
            RetrievalException = expectedException
        };
        var configurationManager = CreateManager(configurationRetriever);

        // Act
        InvalidOperationException exception = await Assert.ThrowsAsync<InvalidOperationException>(
            () => configurationManager.GetConfigurationAsync(CancellationToken.None));

        // Assert
        Assert.Contains("IDX20803", exception.Message);
        Assert.Same(expectedException, exception.InnerException);
    }

    [Fact]
    public async Task AutomaticRefreshInterval()
    {
        await AutomaticRefreshIntervalBody(false);
    }

    [Fact]
    public async Task AutomaticRefreshInterval_Blocking()
    {
        AppContext.SetSwitch(AppContextSwitches.UpdateConfigAsBlockingSwitch, true);
        await AutomaticRefreshIntervalBody(true);
    }

    private static async Task AutomaticRefreshIntervalBody(bool blocking)
    {
        // Arrange
        var configurationRetriever = new CountingConfigurationRetriever();
        var configurationManager = CreateManager(configurationRetriever);
        OpenIdConnectConfiguration firstConfiguration =
            await configurationManager.GetConfigurationAsync(CancellationToken.None);
        TestUtilities.SetField(configurationManager, "_syncAfter", DateTimeOffset.MinValue);

        // Act
        OpenIdConnectConfiguration staleConfiguration =
            await configurationManager.GetConfigurationAsync(CancellationToken.None);
        if (!blocking)
        {
            Assert.True(SpinWait.SpinUntil(
                () => configurationRetriever.CallCount == 2,
                TimeSpan.FromSeconds(10)));
        }

        OpenIdConnectConfiguration refreshedConfiguration =
            await configurationManager.GetConfigurationAsync(CancellationToken.None);

        // Assert
        if (blocking)
            Assert.NotSame(firstConfiguration, staleConfiguration);
        else
            Assert.Same(firstConfiguration, staleConfiguration);

        Assert.Equal("issuer-2", refreshedConfiguration.Issuer);
    }

    [Fact]
    public async Task GetConfigurationAsync()
    {
        await GetConfigurationBody(false);
    }

    [Fact]
    public async Task GetConfigurationAsync_Blocking()
    {
        AppContext.SetSwitch(AppContextSwitches.UpdateConfigAsBlockingSwitch, true);
        await GetConfigurationBody(true);
    }

    private static async Task GetConfigurationBody(bool blocking)
    {
        // Arrange
        var configurationRetriever = new CountingConfigurationRetriever
        {
            ExceptionOnCall = 2,
            RetrievalException = new InvalidOperationException("retrieval failure")
        };
        var configurationManager = CreateManager(configurationRetriever);
        OpenIdConnectConfiguration firstConfiguration =
            await configurationManager.GetConfigurationAsync(CancellationToken.None);
        TestUtilities.SetField(configurationManager, "_syncAfter", DateTimeOffset.MinValue);

        // Act
        OpenIdConnectConfiguration secondConfiguration =
            await configurationManager.GetConfigurationAsync(CancellationToken.None);
        if (!blocking)
        {
            Assert.True(SpinWait.SpinUntil(
                () => configurationRetriever.CallCount == 2,
                TimeSpan.FromSeconds(10)));
            secondConfiguration =
                await configurationManager.GetConfigurationAsync(CancellationToken.None);
        }

        // Assert
        Assert.Same(firstConfiguration, secondConfiguration);
    }

    [Fact]
    public async Task ValidateOpenIdConnectConfigurationTests()
    {
        await ValidateOpenIdConnectConfigurationBody();
    }

    [Fact]
    public async Task ValidateOpenIdConnectConfigurationTests_Blocking()
    {
        AppContext.SetSwitch(AppContextSwitches.UpdateConfigAsBlockingSwitch, true);
        await ValidateOpenIdConnectConfigurationBody();
    }

    private static async Task ValidateOpenIdConnectConfigurationBody()
    {
        // Arrange
        var configurationManager = new BackgroundConfigurationManager<OpenIdConnectConfiguration>(
            MetadataAddress,
            new CountingConfigurationRetriever(),
            new AsyncDocumentRetriever(),
            new FailingConfigurationValidator());

        // Act
        InvalidOperationException exception = await Assert.ThrowsAsync<InvalidOperationException>(
            () => configurationManager.GetConfigurationAsync(CancellationToken.None));

        // Assert
        Assert.Contains("IDX20803", exception.Message);
        Assert.IsType<InvalidConfigurationException>(exception.InnerException);
    }

    private static BackgroundConfigurationManager<OpenIdConnectConfiguration> CreateManager(
        CountingConfigurationRetriever configurationRetriever)
    {
        return new BackgroundConfigurationManager<OpenIdConnectConfiguration>(
            MetadataAddress,
            configurationRetriever,
            new AsyncDocumentRetriever());
    }

    internal sealed class CountingConfigurationRetriever :
        IConfigurationRetriever<OpenIdConnectConfiguration>,
        IConfigurationRetrieverSync<OpenIdConnectConfiguration>
    {
        private int _callCount;

        internal int CallCount => Volatile.Read(ref _callCount);

        internal ManualResetEventSlim AllowRetrieval { get; } = new(false);

        internal bool BlockRetrieval { get; set; }

        internal int ExceptionOnCall { get; set; }

        internal string LastAddress { get; private set; }

        internal ManualResetEventSlim RetrievalStarted { get; } = new(false);

        internal Exception RetrievalException { get; set; }

        public Task<OpenIdConnectConfiguration> GetConfigurationAsync(
            string address,
            IDocumentRetriever retriever,
            CancellationToken cancel)
        {
            return Task.FromResult(Retrieve(address));
        }

        public OpenIdConnectConfiguration GetConfigurationSync(
            string address,
            IDocumentRetrieverSync retriever,
            CancellationToken cancel)
        {
            return Retrieve(address);
        }

        private OpenIdConnectConfiguration Retrieve(string address)
        {
            int callCount = Interlocked.Increment(ref _callCount);
            LastAddress = address;
            RetrievalStarted.Set();

            if (BlockRetrieval)
                AllowRetrieval.Wait();

            if (callCount == ExceptionOnCall)
                throw RetrievalException;

            return new OpenIdConnectConfiguration
            {
                Issuer = $"issuer-{callCount}"
            };
        }
    }

    internal sealed class AsyncDocumentRetriever : IDocumentRetriever, IDocumentRetrieverSync
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

    internal sealed class FailingConfigurationValidator : IConfigurationValidator<OpenIdConnectConfiguration>
    {
        public ConfigurationValidationResult Validate(OpenIdConnectConfiguration configuration)
        {
            return new ConfigurationValidationResult
            {
                ErrorMessage = "validation failure",
                Succeeded = false
            };
        }
    }

    public class BackgroundConfigurationManagerTheoryData<T> : TheoryDataBase where T : class
    {
        public BackgroundConfigurationManagerTheoryData()
        {
        }

        public BackgroundConfigurationManagerTheoryData(string testId)
            : base(testId)
        {
        }

        public TimeSpan AutomaticRefreshInterval { get; set; }

        public BackgroundConfigurationManager<T> ConfigurationManager { get; set; }

        public IConfigurationRetriever<T> ConfigurationRetriever { get; set; }

        public IConfigurationValidator<T> ConfigurationValidator { get; set; }

        public IDocumentRetriever DocumentRetriever { get; set; }

        public string ExpectedErrorMessage { get; set; }

        public T ExpectedConfiguration { get; set; }

        public T ExpectedUpdatedConfiguration { get; set; }

        public string MetadataAddress { get; set; }

        public bool PresetCurrentConfiguration { get; set; }

        public TimeSpan RefreshInterval { get; set; } = BaseConfigurationManager.DefaultRefreshInterval;

        public bool RequestRefresh { get; set; }

        public DateTimeOffset SyncAfter { get; set; } = DateTime.UtcNow;

        public string UpdatedMetadataAddress { get; set; }

        public bool WaitForEvent { get; set; }

        public override string ToString()
        {
            return $"{TestId}, {MetadataAddress}, {ExpectedException}";
        }
    }
}
