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
/// Synchronous mirror of <see cref="ConfigurationManagerEventHandlerContextAwareTests"/>.
/// Tests for ConfigurationManager with IConfigurationEventHandlerContextAware exercised through the synchronous GetConfigurationSync API.
/// </summary>
[ResetAppContextSwitches]
[Collection(nameof(AppContextSwitches.UpdateConfigAsBlocking))]
public class ConfigurationManagerEventHandlerContextAwareTestsSync
{
    [Fact]
    public void ContextAwareBeforeRetrieveSync_Called_InsteadOfBase()
    {
        // Arrange
        var testContext = new CompareContext($"{this}.ContextAwareBeforeRetrieveSync_Called_InsteadOfBase");
        var documentRetriever = new FileDocumentRetriever();
        var configurationRetriever = new OpenIdConnectConfigurationRetrieverSync();
        var mockEventHandler = new MockConfigurationEventHandlerContextAware();

        var configurationManager = new ConfigurationManagerSync<OpenIdConnectConfiguration>(
            "OpenIdConnectMetadata.json",
            configurationRetriever,
            documentRetriever);

        configurationManager.ConfigurationEventHandlerSync = mockEventHandler;

        // Act
        configurationManager.GetConfigurationSync();

        // Assert — the manager should detect the context-aware interface and call its overload
        if (!mockEventHandler.ContextAwareBeforeRetrieveCalled)
            testContext.AddDiff("Context-aware BeforeRetrieve should have been called.");

        if (mockEventHandler.BeforeRetrieveCalled)
            testContext.AddDiff("Base BeforeRetrieve should NOT have been called when context-aware interface is implemented.");

        TestUtilities.AssertFailIfErrors(testContext);
    }

    [Fact]
    public void BypassCache_False_OnFirstRetrieval()
    {
        // Arrange
        var testContext = new CompareContext($"{this}.BypassCache_False_OnFirstRetrieval");
        var documentRetriever = new FileDocumentRetriever();
        var configurationRetriever = new OpenIdConnectConfigurationRetrieverSync();
        var mockEventHandler = new MockConfigurationEventHandlerContextAware();

        var configurationManager = new ConfigurationManagerSync<OpenIdConnectConfiguration>(
            "OpenIdConnectMetadata.json",
            configurationRetriever,
            documentRetriever);

        configurationManager.ConfigurationEventHandlerSync = mockEventHandler;

        // Act — first GetConfigurationSync, no RequestRefresh called
        configurationManager.GetConfigurationSync();

        // Assert
        if (mockEventHandler.LastContext == null)
            testContext.AddDiff("Context should have been provided.");
        else if (mockEventHandler.LastContext.BypassCache)
            testContext.AddDiff("BypassCache should be false on first retrieval (no RequestRefresh called).");

        TestUtilities.AssertFailIfErrors(testContext);
    }

    [Fact]
    public void BypassCache_False_OnAutomaticRefresh()
    {
        // Arrange
        var testContext = new CompareContext($"{this}.BypassCache_False_OnAutomaticRefresh");
        var documentRetriever = new FileDocumentRetriever();
        var configurationRetriever = new OpenIdConnectConfigurationRetrieverSync();
        var mockEventHandler = new MockConfigurationEventHandlerContextAware();
        var timeProvider = new FakeTimeProvider();

        var configurationManager = new ConfigurationManagerSync<OpenIdConnectConfiguration>(
            "OpenIdConnectMetadata.json",
            configurationRetriever,
            documentRetriever);

        configurationManager.ConfigurationEventHandlerSync = mockEventHandler;

        configurationManager.TimeProvider = timeProvider;

        var resetEvent = ConfigurationManagerTests.SetupResetEvent(configurationManager);

        // First retrieval to populate configuration
        configurationManager.GetConfigurationSync();
        mockEventHandler.ContextAwareBeforeRetrieveCalled = false;
        mockEventHandler.LastContext = null;

        // Advance time past AutomaticRefreshInterval to trigger automatic refresh
        timeProvider.Advance(ConfigurationManagerSync<OpenIdConnectConfiguration>.DefaultAutomaticRefreshInterval + TimeSpan.FromHours(1));

        // Act — this should trigger an automatic background refresh, not a RequestRefresh
        configurationManager.GetConfigurationSync();

        ConfigurationManagerTests.WaitOrFail(resetEvent);

        // Assert
        if (mockEventHandler.LastContext == null)
            testContext.AddDiff("Context should have been provided during automatic refresh.");
        else if (mockEventHandler.LastContext.BypassCache)
            testContext.AddDiff("BypassCache should be false on automatic refresh (no RequestRefresh called).");

        TestUtilities.AssertFailIfErrors(testContext);
    }

    [Fact]
    public void BypassCache_True_AfterRequestRefresh()
    {
        // Arrange
        var testContext = new CompareContext($"{this}.BypassCache_True_AfterRequestRefresh");
        var documentRetriever = new FileDocumentRetriever();
        var configurationRetriever = new OpenIdConnectConfigurationRetrieverSync();
        var mockEventHandler = new MockConfigurationEventHandlerContextAware();

        var configurationManager = new ConfigurationManagerSync<OpenIdConnectConfiguration>(
            "OpenIdConnectMetadata.json",
            configurationRetriever,
            documentRetriever);

        configurationManager.ConfigurationEventHandlerSync = mockEventHandler;

        var resetEvent = ConfigurationManagerTests.SetupResetEvent(configurationManager);

        // First retrieval to populate configuration
        configurationManager.GetConfigurationSync();
        mockEventHandler.ContextAwareBeforeRetrieveCalled = false;
        mockEventHandler.LastContext = null;

        // Act — RequestRefresh should signal BypassCache = true
        configurationManager.RequestRefresh();

        ConfigurationManagerTests.WaitOrFail(resetEvent);

        // Assert
        if (!mockEventHandler.ContextAwareBeforeRetrieveCalled)
            testContext.AddDiff("Context-aware BeforeRetrieve should have been called after RequestRefresh.");

        if (mockEventHandler.LastContext == null)
            testContext.AddDiff("Context should have been provided.");
        else if (!mockEventHandler.LastContext.BypassCache)
            testContext.AddDiff("BypassCache should be true when RequestRefresh triggered the retrieval.");

        TestUtilities.AssertFailIfErrors(testContext);
    }

    [Fact]
    public void BypassCache_ResetToFalse_AfterRequestRefreshIsConsumed()
    {
        // Arrange
        var testContext = new CompareContext($"{this}.BypassCache_ResetToFalse_AfterRequestRefreshIsConsumed");
        var documentRetriever = new FileDocumentRetriever();
        var configurationRetriever = new OpenIdConnectConfigurationRetrieverSync();
        var mockEventHandler = new MockConfigurationEventHandlerContextAware();
        var timeProvider = new FakeTimeProvider();

        var configurationManager = new ConfigurationManagerSync<OpenIdConnectConfiguration>(
            "OpenIdConnectMetadata.json",
            configurationRetriever,
            documentRetriever);

        configurationManager.ConfigurationEventHandlerSync = mockEventHandler;

        configurationManager.TimeProvider = timeProvider;

        var resetEvent = ConfigurationManagerTests.SetupResetEvent(configurationManager);

        // First retrieval
        configurationManager.GetConfigurationSync();

        // RequestRefresh — sets BypassCache = true
        configurationManager.RequestRefresh();
        ConfigurationManagerTests.WaitOrFail(resetEvent);

        if (!mockEventHandler.LastContext.BypassCache)
            testContext.AddDiff("BypassCache should be true after RequestRefresh.");

        // Reset tracking
        mockEventHandler.LastContext = null;

        // Advance time past AutomaticRefreshInterval to trigger another automatic refresh
        timeProvider.Advance(ConfigurationManagerSync<OpenIdConnectConfiguration>.DefaultAutomaticRefreshInterval + TimeSpan.FromHours(1));

        configurationManager.GetConfigurationSync();
        ConfigurationManagerTests.WaitOrFail(resetEvent);

        // Assert — BypassCache should be false now since this was an automatic refresh, not RequestRefresh
        if (mockEventHandler.LastContext == null)
            testContext.AddDiff("Context should have been provided during automatic refresh.");
        else if (mockEventHandler.LastContext.BypassCache)
            testContext.AddDiff("BypassCache should be reset to false after the RequestRefresh was consumed.");

        TestUtilities.AssertFailIfErrors(testContext);
    }

    [Fact]
    public void BaseHandler_StillWorks_WithoutContextAwareInterface()
    {
        // Arrange — use the original mock that only implements IConfigurationEventHandler<T>
        var testContext = new CompareContext($"{this}.BaseHandler_StillWorks_WithoutContextAwareInterface");
        var documentRetriever = new FileDocumentRetriever();
        var configurationRetriever = new OpenIdConnectConfigurationRetrieverSync();
        var mockEventHandler = new MockConfigurationEventHandler();

        var configurationManager = new ConfigurationManagerSync<OpenIdConnectConfiguration>(
            "OpenIdConnectMetadata.json",
            configurationRetriever,
            documentRetriever);

        configurationManager.ConfigurationEventHandlerSync = mockEventHandler;

        // Act
        configurationManager.GetConfigurationSync();

        // Assert — base BeforeRetrieve should still be called for non-context-aware handlers
        if (!mockEventHandler.BeforeRetrieveCalled)
            testContext.AddDiff("Base BeforeRetrieve should have been called for non-context-aware handler.");

        TestUtilities.AssertFailIfErrors(testContext);
    }

    [Fact]
    public void ContextAwareAfterUpdate_Called_InsteadOfBase()
    {
        // Arrange
        var testContext = new CompareContext($"{this}.ContextAwareAfterUpdate_Called_InsteadOfBase");
        var documentRetriever = new FileDocumentRetriever();
        var configurationRetriever = new OpenIdConnectConfigurationRetrieverSync();
        var mockEventHandler = new MockConfigurationEventHandlerContextAware();

        var configurationManager = new ConfigurationManagerSync<OpenIdConnectConfiguration>(
            "OpenIdConnectMetadata.json",
            configurationRetriever,
            documentRetriever);

        configurationManager.ConfigurationEventHandlerSync = mockEventHandler;

        // Act
        configurationManager.GetConfigurationSync();

        // Allow fire-and-forget AfterUpdate to complete
        Thread.Sleep(500);

        // Assert — the manager should detect the context-aware interface and call its AfterUpdate overload
        if (!mockEventHandler.ContextAwareAfterUpdateCalled)
            testContext.AddDiff("Context-aware AfterUpdate should have been called.");

        if (mockEventHandler.AfterUpdateCalled)
            testContext.AddDiff("Base AfterUpdate should NOT have been called when context-aware interface is implemented.");

        TestUtilities.AssertFailIfErrors(testContext);
    }

    [Fact]
    public void AfterUpdate_BypassCache_False_OnFirstRetrieval()
    {
        // Arrange
        var testContext = new CompareContext($"{this}.AfterUpdate_BypassCache_False_OnFirstRetrieval");
        var documentRetriever = new FileDocumentRetriever();
        var configurationRetriever = new OpenIdConnectConfigurationRetrieverSync();
        var mockEventHandler = new MockConfigurationEventHandlerContextAware();

        var configurationManager = new ConfigurationManagerSync<OpenIdConnectConfiguration>(
            "OpenIdConnectMetadata.json",
            configurationRetriever,
            documentRetriever);

        configurationManager.ConfigurationEventHandlerSync = mockEventHandler;

        // Act
        configurationManager.GetConfigurationSync();

        // Allow fire-and-forget AfterUpdate to complete
        Thread.Sleep(500);

        // Assert
        if (mockEventHandler.LastAfterUpdateContext == null)
            testContext.AddDiff("Context should have been provided to AfterUpdate.");
        else if (mockEventHandler.LastAfterUpdateContext.BypassCache)
            testContext.AddDiff("BypassCache should be false on first retrieval (no RequestRefresh called).");

        TestUtilities.AssertFailIfErrors(testContext);
    }

    [Fact]
    public void AfterUpdate_BypassCache_True_AfterRequestRefresh()
    {
        // Arrange
        var testContext = new CompareContext($"{this}.AfterUpdate_BypassCache_True_AfterRequestRefresh");
        var documentRetriever = new FileDocumentRetriever();
        var configurationRetriever = new OpenIdConnectConfigurationRetrieverSync();
        var mockEventHandler = new MockConfigurationEventHandlerContextAware();

        var configurationManager = new ConfigurationManagerSync<OpenIdConnectConfiguration>(
            "OpenIdConnectMetadata.json",
            configurationRetriever,
            documentRetriever);

        configurationManager.ConfigurationEventHandlerSync = mockEventHandler;

        var resetEvent = ConfigurationManagerTests.SetupResetEvent(configurationManager);

        // First retrieval to populate configuration
        configurationManager.GetConfigurationSync();
        mockEventHandler.ContextAwareAfterUpdateCalled = false;
        mockEventHandler.LastAfterUpdateContext = null;

        // Act — RequestRefresh should signal BypassCache = true
        configurationManager.RequestRefresh();

        ConfigurationManagerTests.WaitOrFail(resetEvent);

        // Allow fire-and-forget AfterUpdate to complete
        Thread.Sleep(500);

        // Assert
        if (!mockEventHandler.ContextAwareAfterUpdateCalled)
            testContext.AddDiff("Context-aware AfterUpdate should have been called after RequestRefresh.");

        if (mockEventHandler.LastAfterUpdateContext == null)
            testContext.AddDiff("Context should have been provided to AfterUpdate.");
        else if (!mockEventHandler.LastAfterUpdateContext.BypassCache)
            testContext.AddDiff("BypassCache should be true when RequestRefresh triggered the retrieval.");

        TestUtilities.AssertFailIfErrors(testContext);
    }
}
