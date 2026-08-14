// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#if NET5_0_OR_GREATER

using System;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.IdentityModel.Protocols.Configuration;
using Microsoft.IdentityModel.TestUtils;
using Microsoft.IdentityModel.Tokens;
using Xunit;

using BCMTests = Microsoft.IdentityModel.Protocols.OpenIdConnect.Tests.BackgroundConfigurationManagerTests;

namespace Microsoft.IdentityModel.Protocols.OpenIdConnect.Tests;

[ResetAppContextSwitches]
[Collection(nameof(AppContextSwitches.UpdateConfigAsBlocking))]
public class BackgroundConfigurationManagerTestsSync
{
    private const string MetadataAddress = "https://localhost/config";

    [Theory, MemberData(nameof(BCMTests.GetPublicMetadataTheoryData), MemberType = typeof(BCMTests), DisableDiscoveryEnumeration = true)]
    public void GetPublicMetadata(BCMTests.BackgroundConfigurationManagerTheoryData<OpenIdConnectConfiguration> theoryData)
    {
        // Arrange
        DedicatedThreadRetriever<OpenIdConnectConfiguration> dedicatedThreadRetriever =
            DedicatedThreadRetriever<OpenIdConnectConfiguration>.CreateSync(
                theoryData.MetadataAddress,
                theoryData.ConfigurationRetriever is null ? null : new OpenIdConnectConfigurationRetrieverSync(),
                (IDocumentRetrieverSync)theoryData.DocumentRetriever,
                theoryData.ConfigurationValidator);
        var configurationManager = new BackgroundConfigurationManagerSync<OpenIdConnectConfiguration>(
            theoryData.MetadataAddress,
            dedicatedThreadRetriever);

        // Act
        OpenIdConnectConfiguration configuration =
            configurationManager.GetConfigurationSync(CancellationToken.None);

        // Assert
        Assert.NotNull(configuration);
    }

    [Theory]
    [InlineData(0)]
    [InlineData(1)]
    [InlineData(2)]
    public void OpenIdConnectConstructor(int nullParameter)
    {
        // Arrange
        string metadataAddress = nullParameter == 0 ? null : MetadataAddress;
        IConfigurationRetrieverSync<OpenIdConnectConfiguration> configurationRetriever =
            nullParameter == 1 ? null : new OpenIdConnectConfigurationRetrieverSync();
        IDocumentRetrieverSync documentRetriever =
            nullParameter == 2 ? null : new FileDocumentRetriever();

        // Act & Assert
        Assert.Throws<ArgumentNullException>(
            () => DedicatedThreadRetriever<OpenIdConnectConfiguration>.CreateSync(
                metadataAddress,
                configurationRetriever,
                documentRetriever));
    }

    [Fact]
    public void Defaults()
    {
        // Arrange & Act & Assert
        Assert.Equal(TimeSpan.FromHours(12), BackgroundConfigurationManagerSync<OpenIdConnectConfiguration>.DefaultAutomaticRefreshInterval);
        Assert.Equal(TimeSpan.FromMinutes(5), BackgroundConfigurationManagerSync<OpenIdConnectConfiguration>.DefaultRefreshInterval);
        Assert.Equal(TimeSpan.FromMinutes(5), BackgroundConfigurationManagerSync<OpenIdConnectConfiguration>.MinimumAutomaticRefreshInterval);
        Assert.Equal(TimeSpan.FromSeconds(1), BackgroundConfigurationManagerSync<OpenIdConnectConfiguration>.MinimumRefreshInterval);
    }

    [Fact]
    public void CheckSyncAfter()
    {
        CheckSyncAfterBody();
    }

    [Fact]
    public void CheckSyncAfter_Blocking()
    {
        AppContext.SetSwitch(AppContextSwitches.UpdateConfigAsBlockingSwitch, true);
        CheckSyncAfterBody();
    }

    private static void CheckSyncAfterBody()
    {
        // Arrange
        var configurationRetriever = new BCMTests.CountingConfigurationRetriever();
        BackgroundConfigurationManagerSync<OpenIdConnectConfiguration> configurationManager =
            CreateManager(configurationRetriever);
        OpenIdConnectConfiguration firstConfiguration =
            configurationManager.GetConfigurationSync(CancellationToken.None);

        // Act
        OpenIdConnectConfiguration secondConfiguration =
            configurationManager.GetConfigurationSync(CancellationToken.None);

        // Assert
        Assert.Same(firstConfiguration, secondConfiguration);
        Assert.Equal(1, configurationRetriever.CallCount);
    }

    [Fact]
    public void RequestRefresh()
    {
        RequestRefreshBody(false);
    }

    [Fact]
    public void RequestRefresh_Blocking()
    {
        AppContext.SetSwitch(AppContextSwitches.UpdateConfigAsBlockingSwitch, true);
        RequestRefreshBody(true);
    }

    private static void RequestRefreshBody(bool blocking)
    {
        // Arrange
        var configurationRetriever = new BCMTests.CountingConfigurationRetriever();
        BackgroundConfigurationManagerSync<OpenIdConnectConfiguration> configurationManager =
            CreateManager(configurationRetriever);
        OpenIdConnectConfiguration firstConfiguration =
            configurationManager.GetConfigurationSync(CancellationToken.None);
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
            configurationManager.GetConfigurationSync(CancellationToken.None);

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
        var configurationRetriever = new BCMTests.CountingConfigurationRetriever();
        var configurationManager = CreateManager(configurationRetriever);
        _ = configurationManager.GetConfigurationSync(CancellationToken.None);
        configurationRetriever.BlockRetrieval = true;
        configurationRetriever.RetrievalStarted.Reset();

        configurationManager.RequestRefresh();
        Task<OpenIdConnectConfiguration> firstRefresh = Task.Run(
            () => configurationManager.GetConfigurationSync(CancellationToken.None));
        Assert.True(configurationRetriever.RetrievalStarted.Wait(TimeSpan.FromSeconds(10)));

        // Act
        configurationManager.RequestRefresh();
        configurationRetriever.AllowRetrieval.Set();
        OpenIdConnectConfiguration firstConfiguration = await firstRefresh;
        OpenIdConnectConfiguration secondConfiguration =
            configurationManager.GetConfigurationSync(CancellationToken.None);

        // Assert
        Assert.Equal("issuer-2", firstConfiguration.Issuer);
        Assert.Equal("issuer-3", secondConfiguration.Issuer);
        Assert.Equal(3, configurationRetriever.CallCount);
    }

    [Fact]
    public void GetBaseConfigurationSync_ReturnsOpenIdConnectConfiguration()
    {
        // Arrange
        var configurationManager = CreateManager(new BCMTests.CountingConfigurationRetriever());

        // Act
        BaseConfiguration configuration =
            configurationManager.GetBaseConfigurationSync(CancellationToken.None);

        // Assert
        Assert.IsType<OpenIdConnectConfiguration>(configuration);
    }

    [Fact]
    public async Task VerifyInterlockGuardForGetConfigurationSync()
    {
        // Arrange
        var configurationRetriever = new BCMTests.CountingConfigurationRetriever { BlockRetrieval = true };
        var configurationManager = CreateManager(configurationRetriever);

        // Act
        Task<OpenIdConnectConfiguration> firstTask = Task.Run(
            () => configurationManager.GetConfigurationSync(CancellationToken.None));
        Assert.True(configurationRetriever.RetrievalStarted.Wait(TimeSpan.FromSeconds(10)));

        Task<OpenIdConnectConfiguration> secondTask = Task.Run(
            () => configurationManager.GetConfigurationSync(CancellationToken.None));
        configurationRetriever.AllowRetrieval.Set();
        Task allTasks = Task.WhenAll(firstTask, secondTask);
        Task completedTask = await Task.WhenAny(allTasks, Task.Delay(TimeSpan.FromSeconds(10)));
        Assert.Same(allTasks, completedTask);
        OpenIdConnectConfiguration firstConfiguration = await firstTask;
        OpenIdConnectConfiguration secondConfiguration = await secondTask;

        // Assert
        Assert.Same(firstConfiguration, secondConfiguration);
        Assert.Equal(1, configurationRetriever.CallCount);
    }

    [Fact]
    public void FetchMetadataFailureTest()
    {
        FetchMetadataFailureTestBody();
    }

    [Fact]
    public void FetchMetadataFailureTest_Blocking()
    {
        AppContext.SetSwitch(AppContextSwitches.UpdateConfigAsBlockingSwitch, true);
        FetchMetadataFailureTestBody();
    }

    private static void FetchMetadataFailureTestBody()
    {
        // Arrange
        var expectedException = new InvalidOperationException("retrieval failure");
        var configurationRetriever = new BCMTests.CountingConfigurationRetriever
        {
            ExceptionOnCall = 1,
            RetrievalException = expectedException
        };
        var configurationManager = CreateManager(configurationRetriever);

        // Act
        InvalidOperationException exception = Assert.Throws<InvalidOperationException>(
            () => configurationManager.GetConfigurationSync(CancellationToken.None));

        // Assert
        Assert.Contains("IDX20803", exception.Message);
        Assert.Same(expectedException, exception.InnerException);
    }

    [Fact]
    public void AutomaticRefreshInterval()
    {
        AutomaticRefreshIntervalBody(false);
    }

    [Fact]
    public void AutomaticRefreshInterval_Blocking()
    {
        AppContext.SetSwitch(AppContextSwitches.UpdateConfigAsBlockingSwitch, true);
        AutomaticRefreshIntervalBody(true);
    }

    private static void AutomaticRefreshIntervalBody(bool blocking)
    {
        // Arrange
        var configurationRetriever = new BCMTests.CountingConfigurationRetriever();
        var configurationManager = CreateManager(configurationRetriever);
        OpenIdConnectConfiguration firstConfiguration =
            configurationManager.GetConfigurationSync(CancellationToken.None);
        TestUtilities.SetField(configurationManager, "_syncAfter", DateTimeOffset.MinValue);

        // Act
        OpenIdConnectConfiguration staleConfiguration =
            configurationManager.GetConfigurationSync(CancellationToken.None);
        if (!blocking)
        {
            Assert.True(SpinWait.SpinUntil(
                () => configurationRetriever.CallCount == 2,
                TimeSpan.FromSeconds(10)));
        }

        OpenIdConnectConfiguration refreshedConfiguration =
            configurationManager.GetConfigurationSync(CancellationToken.None);

        // Assert
        if (blocking)
            Assert.NotSame(firstConfiguration, staleConfiguration);
        else
            Assert.Same(firstConfiguration, staleConfiguration);

        Assert.Equal("issuer-2", refreshedConfiguration.Issuer);
    }

    [Fact]
    public void GetConfigurationSync()
    {
        GetConfigurationBody(false);
    }

    [Fact]
    public void GetConfigurationSync_Blocking()
    {
        AppContext.SetSwitch(AppContextSwitches.UpdateConfigAsBlockingSwitch, true);
        GetConfigurationBody(true);
    }

    private static void GetConfigurationBody(bool blocking)
    {
        // Arrange
        var configurationRetriever = new BCMTests.CountingConfigurationRetriever
        {
            ExceptionOnCall = 2,
            RetrievalException = new InvalidOperationException("retrieval failure")
        };
        var configurationManager = CreateManager(configurationRetriever);
        OpenIdConnectConfiguration firstConfiguration =
            configurationManager.GetConfigurationSync(CancellationToken.None);
        TestUtilities.SetField(configurationManager, "_syncAfter", DateTimeOffset.MinValue);

        // Act
        OpenIdConnectConfiguration secondConfiguration =
            configurationManager.GetConfigurationSync(CancellationToken.None);
        if (!blocking)
        {
            Assert.True(SpinWait.SpinUntil(
                () => configurationRetriever.CallCount == 2,
                TimeSpan.FromSeconds(10)));
            secondConfiguration =
                configurationManager.GetConfigurationSync(CancellationToken.None);
        }

        // Assert
        Assert.Same(firstConfiguration, secondConfiguration);
    }

    [Fact]
    public void ValidateOpenIdConnectConfigurationTests()
    {
        ValidateOpenIdConnectConfigurationBody();
    }

    [Fact]
    public void ValidateOpenIdConnectConfigurationTests_Blocking()
    {
        AppContext.SetSwitch(AppContextSwitches.UpdateConfigAsBlockingSwitch, true);
        ValidateOpenIdConnectConfigurationBody();
    }

    private static void ValidateOpenIdConnectConfigurationBody()
    {
        // Arrange
        DedicatedThreadRetriever<OpenIdConnectConfiguration> dedicatedThreadRetriever =
            DedicatedThreadRetriever<OpenIdConnectConfiguration>.CreateSync(
                MetadataAddress,
                new BCMTests.CountingConfigurationRetriever(),
                new BCMTests.AsyncDocumentRetriever(),
                new BCMTests.FailingConfigurationValidator());
        var configurationManager = new BackgroundConfigurationManagerSync<OpenIdConnectConfiguration>(
            MetadataAddress,
            dedicatedThreadRetriever);

        // Act
        InvalidOperationException exception = Assert.Throws<InvalidOperationException>(
            () => configurationManager.GetConfigurationSync(CancellationToken.None));

        // Assert
        Assert.Contains("IDX20803", exception.Message);
        Assert.IsType<InvalidConfigurationException>(exception.InnerException);
    }

    private static BackgroundConfigurationManagerSync<OpenIdConnectConfiguration> CreateManager(
        BCMTests.CountingConfigurationRetriever configurationRetriever)
    {
        DedicatedThreadRetriever<OpenIdConnectConfiguration> dedicatedThreadRetriever =
            DedicatedThreadRetriever<OpenIdConnectConfiguration>.CreateSync(
                MetadataAddress,
                configurationRetriever,
                new BCMTests.AsyncDocumentRetriever());

        return new BackgroundConfigurationManagerSync<OpenIdConnectConfiguration>(
            MetadataAddress,
            dedicatedThreadRetriever);
    }
}

#endif
