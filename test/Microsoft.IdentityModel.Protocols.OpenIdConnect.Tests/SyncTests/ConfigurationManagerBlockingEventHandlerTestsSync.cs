// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System;
using System.Threading;
using Microsoft.Extensions.Time.Testing;
using Microsoft.IdentityModel.TestUtils;
using Microsoft.IdentityModel.Tokens;
using Xunit;

namespace Microsoft.IdentityModel.Protocols.OpenIdConnect.Tests;

/// <summary>
/// Synchronous mirror of <see cref="ConfigurationManagerBlockingEventHandlerTests"/>.
/// Tests for ConfigurationManager blocking path (UpdateConfigAsBlocking) with context-aware event handlers,
/// handler short-circuit paths, and error/edge cases, exercised through the synchronous GetConfigurationSync API.
/// </summary>
[ResetAppContextSwitches]
[Collection(nameof(AppContextSwitches.UpdateConfigAsBlocking))]
public class ConfigurationManagerBlockingEventHandlerTestsSync
{

    [Fact]
    public void Blocking_BypassCache_False_OnFirstRetrieval()
    {
        // Arrange
        var testContext = new CompareContext($"{this}.Blocking_BypassCache_False_OnFirstRetrieval");
        AppContext.SetSwitch(AppContextSwitches.UpdateConfigAsBlockingSwitch, true);

        var mockEventHandler = new MockConfigurationEventHandlerContextAware();
        var configurationManager = new ConfigurationManager<OpenIdConnectConfiguration>(
            "OpenIdConnectMetadata.json",
            new OpenIdConnectConfigurationRetriever(),
            new FileDocumentRetriever())
        {
            ConfigurationEventHandler = mockEventHandler
        };

        // Act
        configurationManager.GetConfigurationSync();

        // Assert
        if (mockEventHandler.LastContext == null)
            testContext.AddDiff("Context should have been provided.");
        else if (mockEventHandler.LastContext.BypassCache)
            testContext.AddDiff("BypassCache should be false on first retrieval (no RequestRefresh called).");

        TestUtilities.AssertFailIfErrors(testContext);
    }

    [Fact]
    public void Blocking_BypassCache_True_AfterRequestRefresh()
    {
        // Arrange
        var testContext = new CompareContext($"{this}.Blocking_BypassCache_True_AfterRequestRefresh");
        AppContext.SetSwitch(AppContextSwitches.UpdateConfigAsBlockingSwitch, true);

        var mockEventHandler = new MockConfigurationEventHandlerContextAware();
        var configurationManager = new ConfigurationManager<OpenIdConnectConfiguration>(
            "OpenIdConnectMetadata.json",
            new OpenIdConnectConfigurationRetriever(),
            new FileDocumentRetriever())
        {
            ConfigurationEventHandler = mockEventHandler
        };

        // First retrieval to populate configuration
        configurationManager.GetConfigurationSync();
        mockEventHandler.ContextAwareBeforeRetrieveAsyncCalled = false;
        mockEventHandler.LastContext = null;

        // Act — RequestRefresh in blocking mode sets _refreshRequested = true and _syncAfter = now
        configurationManager.RequestRefresh();
        configurationManager.GetConfigurationSync();

        // Assert
        if (!mockEventHandler.ContextAwareBeforeRetrieveAsyncCalled)
            testContext.AddDiff("Context-aware BeforeRetrieve should have been called after RequestRefresh.");

        if (mockEventHandler.LastContext == null)
            testContext.AddDiff("Context should have been provided.");
        else if (!mockEventHandler.LastContext.BypassCache)
            testContext.AddDiff("BypassCache should be true when RequestRefresh triggered the retrieval.");

        TestUtilities.AssertFailIfErrors(testContext);
    }

    [Fact]
    public void Blocking_BypassCache_ResetToFalse_AfterConsumed()
    {
        // Arrange
        var testContext = new CompareContext($"{this}.Blocking_BypassCache_ResetToFalse_AfterConsumed");
        AppContext.SetSwitch(AppContextSwitches.UpdateConfigAsBlockingSwitch, true);

        var timeProvider = new FakeTimeProvider();
        var mockEventHandler = new MockConfigurationEventHandlerContextAware();
        var configurationManager = new ConfigurationManager<OpenIdConnectConfiguration>(
            "OpenIdConnectMetadata.json",
            new OpenIdConnectConfigurationRetriever(),
            new FileDocumentRetriever())
        {
            ConfigurationEventHandler = mockEventHandler,
            TimeProvider = timeProvider
        };

        // First retrieval
        configurationManager.GetConfigurationSync();

        // RequestRefresh → BypassCache = true
        configurationManager.RequestRefresh();
        configurationManager.GetConfigurationSync();

        if (mockEventHandler.LastContext == null || !mockEventHandler.LastContext.BypassCache)
            testContext.AddDiff("BypassCache should be true after RequestRefresh.");

        // Reset tracking
        mockEventHandler.LastContext = null;

        // Advance time past AutomaticRefreshInterval to trigger another automatic refresh
        timeProvider.Advance(ConfigurationManager<OpenIdConnectConfiguration>.DefaultAutomaticRefreshInterval + TimeSpan.FromHours(1));

        // Act — this should be an automatic refresh, not a RequestRefresh
        configurationManager.GetConfigurationSync();

        // Assert — BypassCache should be false since _refreshRequested was consumed
        if (mockEventHandler.LastContext == null)
            testContext.AddDiff("Context should have been provided during automatic refresh.");
        else if (mockEventHandler.LastContext.BypassCache)
            testContext.AddDiff("BypassCache should be reset to false after the RequestRefresh was consumed.");

        TestUtilities.AssertFailIfErrors(testContext);
    }

    [Fact]
    public void Blocking_ContextAwareBeforeRetrieveSync_Called_InsteadOfBase()
    {
        // Arrange
        var testContext = new CompareContext($"{this}.Blocking_ContextAwareBeforeRetrieveSync_Called_InsteadOfBase");
        AppContext.SetSwitch(AppContextSwitches.UpdateConfigAsBlockingSwitch, true);

        var mockEventHandler = new MockConfigurationEventHandlerContextAware();
        var configurationManager = new ConfigurationManager<OpenIdConnectConfiguration>(
            "OpenIdConnectMetadata.json",
            new OpenIdConnectConfigurationRetriever(),
            new FileDocumentRetriever())
        {
            ConfigurationEventHandler = mockEventHandler
        };

        // Act
        configurationManager.GetConfigurationSync();

        // Assert
        if (!mockEventHandler.ContextAwareBeforeRetrieveAsyncCalled)
            testContext.AddDiff("Context-aware BeforeRetrieve should have been called.");

        if (mockEventHandler.BeforeRetrieveAsyncCalled)
            testContext.AddDiff("Base BeforeRetrieve should NOT have been called when context-aware interface is implemented.");

        TestUtilities.AssertFailIfErrors(testContext);
    }

    [Fact]
    public void Blocking_ContextAwareAfterUpdateAsync_Called_InsteadOfBase()
    {
        // Arrange
        var testContext = new CompareContext($"{this}.Blocking_ContextAwareAfterUpdateAsync_Called_InsteadOfBase");
        AppContext.SetSwitch(AppContextSwitches.UpdateConfigAsBlockingSwitch, true);

        var mockEventHandler = new MockConfigurationEventHandlerContextAware();
        var configurationManager = new ConfigurationManager<OpenIdConnectConfiguration>(
            "OpenIdConnectMetadata.json",
            new OpenIdConnectConfigurationRetriever(),
            new FileDocumentRetriever())
        {
            ConfigurationEventHandler = mockEventHandler
        };

        // Act
        configurationManager.GetConfigurationSync();

        // AfterUpdateAsync is fire-and-forget; poll for it
        PollForCondition(
            () => mockEventHandler.ContextAwareAfterUpdateAsyncCalled,
            TimeSpan.FromMilliseconds(100),
            TimeSpan.FromSeconds(10));

        // Assert
        if (!mockEventHandler.ContextAwareAfterUpdateAsyncCalled)
            testContext.AddDiff("Context-aware AfterUpdateAsync should have been called.");

        if (mockEventHandler.AfterUpdateAsyncCalled)
            testContext.AddDiff("Base AfterUpdateAsync should NOT have been called when context-aware interface is implemented.");

        TestUtilities.AssertFailIfErrors(testContext);
    }

    [Fact]
    public void BeforeRetrieveSync_ReturnsConfig_BypassCacheFalse_Propagated()
    {
        // Arrange
        var testContext = new CompareContext($"{this}.BeforeRetrieveSync_ReturnsConfig_BypassCacheFalse_Propagated");

        var preloadedConfig = new OpenIdConnectConfiguration
        {
            Issuer = "https://test.issuer.com",
            TokenEndpoint = "https://test.issuer.com/token"
        };

        var mockEventHandler = new MockConfigurationEventHandlerContextAware
        {
            ConfigurationToReturn = preloadedConfig,
            RetrievalTimeToReturn = DateTimeOffset.UtcNow
        };

        var configurationManager = new ConfigurationManager<OpenIdConnectConfiguration>(
            "OpenIdConnectMetadata.json",
            new OpenIdConnectConfigurationRetriever(),
            new FileDocumentRetriever())
        {
            ConfigurationEventHandler = mockEventHandler
        };

        // Act — first call, no RequestRefresh
        var configuration = configurationManager.GetConfigurationSync();

        // Assert — handler provided config, BypassCache should be false
        if (configuration == null)
            testContext.AddDiff("Configuration should not be null.");

        if (configuration.Issuer != "https://test.issuer.com")
            testContext.AddDiff($"Configuration should come from handler. Expected Issuer: 'https://test.issuer.com', Actual: '{configuration.Issuer}'");

        if (mockEventHandler.LastContext == null)
            testContext.AddDiff("Context should have been provided to BeforeRetrieve.");
        else if (mockEventHandler.LastContext.BypassCache)
            testContext.AddDiff("BypassCache should be false on first retrieval.");

        TestUtilities.AssertFailIfErrors(testContext);
    }

    [Fact]
    public void BeforeRetrieveSync_ReturnsConfig_AfterRequestRefresh_BypassCacheTrue()
    {
        // Arrange
        var testContext = new CompareContext($"{this}.BeforeRetrieveSync_ReturnsConfig_AfterRequestRefresh_BypassCacheTrue");

        var preloadedConfig = new OpenIdConnectConfiguration
        {
            Issuer = "https://test.issuer.com",
            TokenEndpoint = "https://test.issuer.com/token"
        };

        var mockEventHandler = new MockConfigurationEventHandlerContextAware
        {
            ConfigurationToReturn = preloadedConfig,
            RetrievalTimeToReturn = DateTimeOffset.UtcNow
        };

        var configurationManager = new ConfigurationManager<OpenIdConnectConfiguration>(
            "OpenIdConnectMetadata.json",
            new OpenIdConnectConfigurationRetriever(),
            new FileDocumentRetriever())
        {
            ConfigurationEventHandler = mockEventHandler
        };

        var resetEvent = ConfigurationManagerTests.SetupResetEvent(configurationManager);

        // First retrieval
        configurationManager.GetConfigurationSync();
        mockEventHandler.LastContext = null;

        // Act — RequestRefresh triggers background refresh with BypassCache=true
        configurationManager.RequestRefresh();
        ConfigurationManagerTests.WaitOrFail(resetEvent);

        // Assert
        if (mockEventHandler.LastContext == null)
            testContext.AddDiff("Context should have been provided after RequestRefresh.");
        else if (!mockEventHandler.LastContext.BypassCache)
            testContext.AddDiff("BypassCache should be true when RequestRefresh triggered the retrieval.");

        TestUtilities.AssertFailIfErrors(testContext);
    }

    [Fact]
    public void AfterUpdateAsync_ReceivesCorrectContext_WhenHandlerProvidedConfig()
    {
        // Arrange
        var testContext = new CompareContext($"{this}.AfterUpdateAsync_ReceivesCorrectContext_WhenHandlerProvidedConfig");

        var preloadedConfig = new OpenIdConnectConfiguration
        {
            Issuer = "https://test.issuer.com",
            TokenEndpoint = "https://test.issuer.com/token"
        };

        var mockEventHandler = new MockConfigurationEventHandlerContextAware
        {
            ConfigurationToReturn = preloadedConfig,
            RetrievalTimeToReturn = DateTimeOffset.UtcNow
        };

        var configurationManager = new ConfigurationManager<OpenIdConnectConfiguration>(
            "OpenIdConnectMetadata.json",
            new OpenIdConnectConfigurationRetriever(),
            new FileDocumentRetriever())
        {
            ConfigurationEventHandler = mockEventHandler
        };

        // Act — first call, handler provides config
        configurationManager.GetConfigurationSync();

        // Poll for fire-and-forget AfterUpdateAsync
        PollForCondition(
            () => mockEventHandler.ContextAwareAfterUpdateAsyncCalled,
            TimeSpan.FromMilliseconds(100),
            TimeSpan.FromSeconds(10));

        // Assert — AfterUpdateAsync should receive the same context object as BeforeRetrieve
        if (mockEventHandler.LastAfterUpdateContext == null)
            testContext.AddDiff("AfterUpdateAsync should have received a context.");
        else if (mockEventHandler.LastAfterUpdateContext.BypassCache)
            testContext.AddDiff("AfterUpdateAsync context BypassCache should be false on first retrieval.");

        if (mockEventHandler.LastContext != null && mockEventHandler.LastAfterUpdateContext != null)
        {
            if (!ReferenceEquals(mockEventHandler.LastContext, mockEventHandler.LastAfterUpdateContext))
                testContext.AddDiff("AfterUpdateAsync should receive the same context instance as BeforeRetrieve.");
        }

        TestUtilities.AssertFailIfErrors(testContext);
    }

    [Fact]
    public void ContextAware_BeforeRetrieveSync_Throws_FallsBackToEndpoint()
    {
        // Arrange
        var testContext = new CompareContext($"{this}.ContextAware_BeforeRetrieveSync_Throws_FallsBackToEndpoint");

        var mockEventHandler = new MockConfigurationEventHandlerContextAware
        {
            ThrowExceptionInBeforeRetrieve = true
        };

        var configurationManager = new ConfigurationManager<OpenIdConnectConfiguration>(
            "OpenIdConnectMetadata.json",
            new OpenIdConnectConfigurationRetriever(),
            new FileDocumentRetriever())
        {
            ConfigurationEventHandler = mockEventHandler
        };

        // Act — should fall back to endpoint retrieval
        var configuration = configurationManager.GetConfigurationSync();

        // Assert
        if (configuration == null)
            testContext.AddDiff("Configuration should not be null even when context-aware handler throws.");

        if (!mockEventHandler.ContextAwareBeforeRetrieveAsyncCalled)
            testContext.AddDiff("Context-aware BeforeRetrieve should have been called (even though it threw).");

        if (mockEventHandler.BeforeRetrieveAsyncCalled)
            testContext.AddDiff("Base BeforeRetrieve should NOT have been called; only context-aware overload should be invoked.");

        TestUtilities.AssertFailIfErrors(testContext);
    }

    [Fact]
    public void ContextAware_AfterUpdateAsync_Throws_NoCrashFireAndForget()
    {
        // Arrange
        var testContext = new CompareContext($"{this}.ContextAware_AfterUpdateAsync_Throws_NoCrashFireAndForget");

        var mockEventHandler = new MockConfigurationEventHandlerContextAware
        {
            ThrowExceptionInAfterUpdate = true
        };

        var configurationManager = new ConfigurationManager<OpenIdConnectConfiguration>(
            "OpenIdConnectMetadata.json",
            new OpenIdConnectConfigurationRetriever(),
            new FileDocumentRetriever())
        {
            ConfigurationEventHandler = mockEventHandler
        };

        // Act — should not throw even though AfterUpdateAsync throws
        var configuration = configurationManager.GetConfigurationSync();

        // Poll to confirm the callback was actually invoked (and threw)
        PollForCondition(
            () => mockEventHandler.ContextAwareAfterUpdateAsyncCalled,
            TimeSpan.FromMilliseconds(100),
            TimeSpan.FromSeconds(10));

        // Assert
        if (configuration == null)
            testContext.AddDiff("Configuration should not be null.");

        if (!mockEventHandler.ContextAwareAfterUpdateAsyncCalled)
            testContext.AddDiff("Context-aware AfterUpdateAsync should have been called even though it throws.");

        TestUtilities.AssertFailIfErrors(testContext);
    }

    [Fact]
    public void BaseHandler_AfterUpdateAsync_Called_ForNonContextAwareHandler()
    {
        // Arrange — use the base mock that only implements IConfigurationEventHandler<T>
        var testContext = new CompareContext($"{this}.BaseHandler_AfterUpdateAsync_Called_ForNonContextAwareHandler");

        var mockEventHandler = new MockConfigurationEventHandler();
        var configurationManager = new ConfigurationManager<OpenIdConnectConfiguration>(
            "OpenIdConnectMetadata.json",
            new OpenIdConnectConfigurationRetriever(),
            new FileDocumentRetriever())
        {
            ConfigurationEventHandler = mockEventHandler
        };

        // Act
        configurationManager.GetConfigurationSync();

        // Poll for fire-and-forget AfterUpdateAsync
        PollForCondition(
            () => mockEventHandler.AfterUpdateAsyncCalled,
            TimeSpan.FromMilliseconds(100),
            TimeSpan.FromSeconds(10));

        // Assert — base AfterUpdateAsync should be called for non-context-aware handler
        if (!mockEventHandler.AfterUpdateAsyncCalled)
            testContext.AddDiff("Base AfterUpdateAsync should have been called for non-context-aware handler.");

        if (mockEventHandler.AfterUpdateConfiguration == null)
            testContext.AddDiff("AfterUpdateAsync should have received non-null configuration.");

        TestUtilities.AssertFailIfErrors(testContext);
    }

    [Fact]
    public void AfterUpdateAsync_BypassCacheFalse_OnAutomaticRefresh()
    {
        // Arrange
        var testContext = new CompareContext($"{this}.AfterUpdateAsync_BypassCacheFalse_OnAutomaticRefresh");

        var timeProvider = new FakeTimeProvider();
        var mockEventHandler = new MockConfigurationEventHandlerContextAware();
        var configurationManager = new ConfigurationManager<OpenIdConnectConfiguration>(
            "OpenIdConnectMetadata.json",
            new OpenIdConnectConfigurationRetriever(),
            new FileDocumentRetriever())
        {
            ConfigurationEventHandler = mockEventHandler,
            TimeProvider = timeProvider
        };

        var resetEvent = ConfigurationManagerTests.SetupResetEvent(configurationManager);

        // First retrieval
        configurationManager.GetConfigurationSync();

        // Wait for fire-and-forget AfterUpdate from first retrieval
        PollForCondition(
            () => mockEventHandler.ContextAwareAfterUpdateAsyncCalled,
            TimeSpan.FromMilliseconds(100),
            TimeSpan.FromSeconds(10));

        // Reset tracking
        mockEventHandler.ContextAwareAfterUpdateAsyncCalled = false;
        mockEventHandler.LastAfterUpdateContext = null;

        // Advance time past AutomaticRefreshInterval
        timeProvider.Advance(ConfigurationManager<OpenIdConnectConfiguration>.DefaultAutomaticRefreshInterval + TimeSpan.FromHours(1));

        // Act — triggers automatic background refresh
        configurationManager.GetConfigurationSync();
        ConfigurationManagerTests.WaitOrFail(resetEvent);

        // Poll for the fire-and-forget AfterUpdate from automatic refresh
        PollForCondition(
            () => mockEventHandler.ContextAwareAfterUpdateAsyncCalled,
            TimeSpan.FromMilliseconds(100),
            TimeSpan.FromSeconds(10));

        // Assert
        if (mockEventHandler.LastAfterUpdateContext == null)
            testContext.AddDiff("AfterUpdateAsync context should have been provided during automatic refresh.");
        else if (mockEventHandler.LastAfterUpdateContext.BypassCache)
            testContext.AddDiff("AfterUpdateAsync BypassCache should be false on automatic refresh.");

        TestUtilities.AssertFailIfErrors(testContext);
    }

    [Fact]
    public void Blocking_MultipleRequestRefresh_OnlyOneBypassTrueRefreshFires()
    {
        // Arrange
        var testContext = new CompareContext($"{this}.Blocking_MultipleRequestRefresh_OnlyOneBypassTrueRefreshFires");
        AppContext.SetSwitch(AppContextSwitches.UpdateConfigAsBlockingSwitch, true);

        var timeProvider = new FakeTimeProvider();
        var mockEventHandler = new MockConfigurationEventHandlerContextAware();
        var configurationManager = new ConfigurationManager<OpenIdConnectConfiguration>(
            "OpenIdConnectMetadata.json",
            new OpenIdConnectConfigurationRetriever(),
            new FileDocumentRetriever())
        {
            ConfigurationEventHandler = mockEventHandler,
            TimeProvider = timeProvider
        };

        // First retrieval
        configurationManager.GetConfigurationSync();
        mockEventHandler.ContextAwareBeforeRetrieveAsyncCalled = false;
        mockEventHandler.LastContext = null;

        // Act — multiple rapid RequestRefresh calls in blocking mode
        // In blocking mode, RequestRefresh sets _refreshRequested = true and _syncAfter = now.
        // Calling it multiple times just sets the same flags repeatedly.
        configurationManager.RequestRefresh();
        configurationManager.RequestRefresh();
        configurationManager.RequestRefresh();

        // The next GetConfigurationSync should trigger exactly one refresh with BypassCache=true
        configurationManager.GetConfigurationSync();

        // Assert — one refresh with BypassCache=true
        if (!mockEventHandler.ContextAwareBeforeRetrieveAsyncCalled)
            testContext.AddDiff("Context-aware BeforeRetrieve should have been called.");

        if (mockEventHandler.LastContext == null)
            testContext.AddDiff("Context should have been provided.");
        else if (!mockEventHandler.LastContext.BypassCache)
            testContext.AddDiff("BypassCache should be true after RequestRefresh.");

        // Reset and verify that the next call without RequestRefresh has BypassCache=false
        mockEventHandler.LastContext = null;

        // Advance time past AutomaticRefreshInterval to trigger another refresh
        timeProvider.Advance(ConfigurationManager<OpenIdConnectConfiguration>.DefaultAutomaticRefreshInterval + TimeSpan.FromHours(1));

        configurationManager.GetConfigurationSync();

        if (mockEventHandler.LastContext == null)
            testContext.AddDiff("Context should have been provided during automatic refresh.");
        else if (mockEventHandler.LastContext.BypassCache)
            testContext.AddDiff("BypassCache should be false after the RequestRefresh was consumed — multiple calls should not stack.");

        TestUtilities.AssertFailIfErrors(testContext);
    }

    private static bool PollForCondition(Func<bool> condition, TimeSpan interval, TimeSpan timeout)
    {
        var startTime = DateTime.UtcNow;

        while (DateTime.UtcNow - startTime < timeout)
        {
            if (condition())
                return true;

            Thread.Sleep(interval);
        }

        return false;
    }
}
