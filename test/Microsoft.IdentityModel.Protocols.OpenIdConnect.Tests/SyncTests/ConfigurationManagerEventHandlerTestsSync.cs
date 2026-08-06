// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.IdentityModel.Logging;
using Microsoft.IdentityModel.Protocols.Configuration;
using Microsoft.IdentityModel.Protocols.OpenIdConnect.Configuration;
using Microsoft.IdentityModel.Telemetry;
using Microsoft.IdentityModel.Telemetry.Tests;
using Microsoft.IdentityModel.TestUtils;
using Microsoft.IdentityModel.Tokens;
using Xunit;

namespace Microsoft.IdentityModel.Protocols.OpenIdConnect.Tests
{
    /// <summary>
    /// Synchronous mirror of <see cref="ConfigurationManagerEventHandlerTests"/>.
    /// Tests for ConfigurationManager with IConfigurationEventHandler exercised through the synchronous GetConfigurationSync API.
    /// </summary>
    public class ConfigurationManagerEventHandlerTestsSync
    {
        [Fact]
        public void Constructor_WithConfigurationEventHandler_SetsPropertyCorrectlySync()
        {
            // Arrange
            var testContext = new CompareContext($"{this}.Constructor_WithConfigurationEventHandler_SetsPropertyCorrectly");
            var documentRetriever = new FileDocumentRetriever();
            var configurationRetriever = new OpenIdConnectConfigurationRetriever();
            var configurationValidator = new OpenIdConnectConfigurationValidator();
            var lkgCacheOptions = new LastKnownGoodConfigurationCacheOptions();
            var mockEventHandler = new MockConfigurationEventHandler();

            // Act
            var configurationManager = ConfigurationManager<OpenIdConnectConfiguration>.CreateSync(
                "OpenIdConnectMetadata.json",
                configurationRetriever,
                documentRetriever,
                configurationValidator,
                lkgCacheOptions,
                mockEventHandler);

            // Assert
            if (configurationManager.ConfigurationEventHandlerSync == null)
                testContext.AddDiff("ConfigurationEventHandlerSync should not be null after construction.");

            if (!ReferenceEquals(configurationManager.ConfigurationEventHandlerSync, mockEventHandler))
                testContext.AddDiff("ConfigurationEventHandlerSync should be the same instance as passed in constructor.");

            TestUtilities.AssertFailIfErrors(testContext);
        }

        [Fact]
        public void Constructor_WithNullConfigurationEventHandler_ThrowsArgumentNullException()
        {
            // Arrange
            var testContext = new CompareContext($"{this}.Constructor_WithNullConfigurationEventHandler_ThrowsArgumentNullException");
            var documentRetriever = new FileDocumentRetriever();
            var configurationRetriever = new OpenIdConnectConfigurationRetriever();
            var configurationValidator = new OpenIdConnectConfigurationValidator();
            var lkgCacheOptions = new LastKnownGoodConfigurationCacheOptions();

            // Act & Assert
            var exception = Assert.Throws<ArgumentNullException>(() =>
                ConfigurationManager<OpenIdConnectConfiguration>.CreateSync(
                    "OpenIdConnectMetadata.json",
                    configurationRetriever,
                    documentRetriever,
                    configurationValidator,
                    lkgCacheOptions,
                    null));

            if (!exception.Message.Contains("configurationEventHandler"))
                testContext.AddDiff($"Exception message should contain 'configurationEventHandler'. Actual: {exception.Message}");

            TestUtilities.AssertFailIfErrors(testContext);
        }

        [Fact]
        public void ConfigurationEventHandler_Property_GetSet()
        {
            // Arrange
            var testContext = new CompareContext($"{this}.ConfigurationEventHandler_Property_GetSet");
            var documentRetriever = new FileDocumentRetriever();
            var configurationRetriever = new OpenIdConnectConfigurationRetriever();

            var configurationManager = ConfigurationManager<OpenIdConnectConfiguration>.CreateSync(
                "OpenIdConnectMetadata.json",
                configurationRetriever,
                documentRetriever);

            // Initially should be null
            if (configurationManager.ConfigurationEventHandlerSync != null)
                testContext.AddDiff("ConfigurationEventHandlerSync should be null initially.");

            // Act - Set the property
            var mockEventHandler = new MockConfigurationEventHandler();
            configurationManager.ConfigurationEventHandlerSync = mockEventHandler;

            // Assert
            if (configurationManager.ConfigurationEventHandlerSync == null)
                testContext.AddDiff("ConfigurationEventHandlerSync should not be null after setting.");

            if (!ReferenceEquals(configurationManager.ConfigurationEventHandlerSync, mockEventHandler))
                testContext.AddDiff("ConfigurationEventHandlerSync should be the same instance as set.");

            // Act - Set to null
            configurationManager.ConfigurationEventHandlerSync = null;

            // Assert
            if (configurationManager.ConfigurationEventHandlerSync != null)
                testContext.AddDiff("ConfigurationEventHandlerSync should be null after setting to null.");

            TestUtilities.AssertFailIfErrors(testContext);
        }

        [Fact]
        public void BeforeRetrieveSync_Called_WhenGettingConfiguration()
        {
            // Arrange
            var testContext = new CompareContext($"{this}.BeforeRetrieveSync_Called_WhenGettingConfiguration");
            var documentRetriever = new FileDocumentRetriever();
            var configurationRetriever = new OpenIdConnectConfigurationRetriever();
            var mockEventHandler = new MockConfigurationEventHandler();
            var testTelemetryClient = new MockTelemetryClient();

            var configurationManager = ConfigurationManager<OpenIdConnectConfiguration>.CreateSync(
                "OpenIdConnectMetadata.json",
                configurationRetriever,
                documentRetriever);

            configurationManager.ConfigurationEventHandlerSync = mockEventHandler;

            configurationManager.TelemetryClient = testTelemetryClient;

            // Act
            _ = configurationManager.GetConfigurationSync();
            // Assert
            if (!mockEventHandler.BeforeRetrieveCalled)
                testContext.AddDiff("BeforeRetrieve should have been called.");

            if (mockEventHandler.BeforeRetrieveMetadataAddress != "OpenIdConnectMetadata.json")
                testContext.AddDiff($"BeforeRetrieve should have been called with correct metadata address. Expected: 'OpenIdConnectMetadata.json', Actual: '{mockEventHandler.BeforeRetrieveMetadataAddress}'");

            var expectedTagList = new Dictionary<string, object>
            {
                { TelemetryConstants.MetadataAddressTag, "OpenIdConnectMetadata.json" },
                { TelemetryConstants.IdentityModelVersionTag, IdentityModelTelemetryUtil.ClientVer },
                { TelemetryConstants.OperationStatusTag, TelemetryConstants.Protocols.FirstRefresh },
                { TelemetryConstants.ConfigurationSourceTag, TelemetryConstants.Protocols.ConfigurationSourceRetriever },
            };

            PollForCondition(
                () => expectedTagList.Count == testTelemetryClient.ExportedItems.Count,
                TimeSpan.FromMilliseconds(250),
                TimeSpan.FromSeconds(20));

            Assert.Equal(expectedTagList, testTelemetryClient.ExportedItems);

            TestUtilities.AssertFailIfErrors(testContext);
        }

        [Fact]
        public void BeforeRetrieveSync_ReturnsConfiguration_SkipsEndpointRetrieval()
        {
            // Arrange
            var testContext = new CompareContext($"{this}.BeforeRetrieveSync_ReturnsConfiguration_SkipsEndpointRetrieval");
            var documentRetriever = new MockDocumentRetriever(); // This will track if it's called
            var configurationRetriever = new OpenIdConnectConfigurationRetriever();
            var testTelemetryClient = new MockTelemetryClient();

            var preloadedConfig = new OpenIdConnectConfiguration
            {
                Issuer = "https://test.issuer.com",
                TokenEndpoint = "https://test.issuer.com/token"
            };

            var mockEventHandler = new MockConfigurationEventHandler
            {
                ConfigurationToReturn = preloadedConfig,
                RetrievalTimeToReturn = DateTimeOffset.UtcNow
            };

            var configurationManager = ConfigurationManager<OpenIdConnectConfiguration>.CreateSync(
                "OpenIdConnectMetadata.json",
                configurationRetriever,
                documentRetriever);

            configurationManager.ConfigurationEventHandlerSync = mockEventHandler;

            configurationManager.TelemetryClient = testTelemetryClient;

            // Act
            var configuration = configurationManager.GetConfigurationSync();

            // Assert
            if (configuration == null)
                testContext.AddDiff("Configuration should not be null.");

            if (configuration.Issuer != "https://test.issuer.com")
                testContext.AddDiff($"Configuration should be from event handler. Expected Issuer: 'https://test.issuer.com', Actual: '{configuration.Issuer}'");

            if (documentRetriever.GetDocumentCalled)
                testContext.AddDiff("Document retriever should not have been called when event handler returns configuration.");

            var expectedTagList = new Dictionary<string, object>
            {
                { TelemetryConstants.MetadataAddressTag, "OpenIdConnectMetadata.json" },
                { TelemetryConstants.IdentityModelVersionTag, IdentityModelTelemetryUtil.ClientVer },
                { TelemetryConstants.OperationStatusTag, TelemetryConstants.Protocols.FirstRefresh },
                { TelemetryConstants.ConfigurationSourceTag, TelemetryConstants.Protocols.ConfigurationSourceHandler },
            };

            PollForCondition(
                () => expectedTagList.Count == testTelemetryClient.ExportedItems.Count,
                TimeSpan.FromMilliseconds(250),
                TimeSpan.FromSeconds(20));

            Assert.Equal(expectedTagList, testTelemetryClient.ExportedItems);

            TestUtilities.AssertFailIfErrors(testContext);
        }

        [Fact]
        public void AfterUpdate_Called_AfterConfigurationUpdate()
        {
            // Arrange
            var testContext = new CompareContext($"{this}.AfterUpdate_Called_AfterConfigurationUpdate");
            var documentRetriever = new FileDocumentRetriever();
            var configurationRetriever = new OpenIdConnectConfigurationRetriever();
            var mockEventHandler = new MockConfigurationEventHandler();
            var testTelemetryClient = new MockTelemetryClient();

            var configurationManager = ConfigurationManager<OpenIdConnectConfiguration>.CreateSync(
                "OpenIdConnectMetadata.json",
                configurationRetriever,
                documentRetriever);

            configurationManager.ConfigurationEventHandlerSync = mockEventHandler;

            configurationManager.TelemetryClient = testTelemetryClient;

            // Act
            var configuration = configurationManager.GetConfigurationSync();

            // Wait a bit for the fire-and-forget AfterUpdate to be called
            Thread.Sleep(100);

            // Assert
            if (!mockEventHandler.AfterUpdateCalled)
                testContext.AddDiff("AfterUpdate should have been called after configuration update.");

            if (mockEventHandler.AfterUpdateMetadataAddress != "OpenIdConnectMetadata.json")
                testContext.AddDiff($"AfterUpdate should have been called with correct metadata address. Expected: 'OpenIdConnectMetadata.json', Actual: '{mockEventHandler.AfterUpdateMetadataAddress}'");

            if (mockEventHandler.AfterUpdateConfiguration == null)
                testContext.AddDiff("AfterUpdate should have been called with non-null configuration.");

            var expectedTagList = new Dictionary<string, object>
            {
                { TelemetryConstants.MetadataAddressTag, "OpenIdConnectMetadata.json" },
                { TelemetryConstants.IdentityModelVersionTag, IdentityModelTelemetryUtil.ClientVer },
                { TelemetryConstants.OperationStatusTag, TelemetryConstants.Protocols.FirstRefresh },
                { TelemetryConstants.ConfigurationSourceTag, TelemetryConstants.Protocols.ConfigurationSourceRetriever },
            };

            PollForCondition(
                () => expectedTagList.Count == testTelemetryClient.ExportedItems.Count,
                TimeSpan.FromMilliseconds(250),
                TimeSpan.FromSeconds(20));

            Assert.Equal(expectedTagList, testTelemetryClient.ExportedItems);

            TestUtilities.AssertFailIfErrors(testContext);
        }

        [Fact]
        public void BeforeRetrieveSync_ExceptionHandled_ContinuesWithEndpointRetrieval()
        {
            // Arrange
            var testContext = new CompareContext($"{this}.BeforeRetrieveSync_ExceptionHandled_ContinuesWithEndpointRetrieval");
            var documentRetriever = new FileDocumentRetriever();
            var configurationRetriever = new OpenIdConnectConfigurationRetriever();
            var mockEventHandler = new MockConfigurationEventHandler
            {
                ThrowExceptionInBeforeRetrieve = true
            };
            var testTelemetryClient = new MockTelemetryClient();

            var configurationManager = ConfigurationManager<OpenIdConnectConfiguration>.CreateSync(
                "OpenIdConnectMetadata.json",
                configurationRetriever,
                documentRetriever);

            configurationManager.ConfigurationEventHandlerSync = mockEventHandler;

            configurationManager.TelemetryClient = testTelemetryClient;

            // Act
            var configuration = configurationManager.GetConfigurationSync();

            // Assert
            if (configuration == null)
                testContext.AddDiff("Configuration should not be null even when event handler throws.");

            if (!mockEventHandler.BeforeRetrieveCalled)
                testContext.AddDiff("BeforeRetrieve should have been called even if it throws.");

            var expectedTagList = new Dictionary<string, object>
            {
                { TelemetryConstants.MetadataAddressTag, "OpenIdConnectMetadata.json" },
                { TelemetryConstants.IdentityModelVersionTag, IdentityModelTelemetryUtil.ClientVer },
                { TelemetryConstants.OperationStatusTag, TelemetryConstants.Protocols.FirstRefresh },
                { TelemetryConstants.ConfigurationSourceTag, TelemetryConstants.Protocols.ConfigurationSourceRetriever },
            };

            PollForCondition(
                () => expectedTagList.Count == testTelemetryClient.ExportedItems.Count,
                TimeSpan.FromMilliseconds(250),
                TimeSpan.FromSeconds(20));

            Assert.Equal(expectedTagList, testTelemetryClient.ExportedItems);

            TestUtilities.AssertFailIfErrors(testContext);
        }

        [Fact]
        public void ConfigurationEventHandler_WithValidator_ValidatesHandlerConfiguration()
        {
            // Arrange
            var testContext = new CompareContext($"{this}.ConfigurationEventHandler_WithValidator_ValidatesHandlerConfiguration");
            var documentRetriever = new FileDocumentRetriever();
            var configurationRetriever = new OpenIdConnectConfigurationRetriever();
            var configurationValidator = new OpenIdConnectConfigurationValidator { MinimumNumberOfKeys = 2 };
            var testTelemetryClient = new MockTelemetryClient();

            // Create config with only 1 key (invalid per validator)
            var invalidConfig = new OpenIdConnectConfiguration
            {
                Issuer = "https://test.issuer.com",
                TokenEndpoint = "https://test.issuer.com/token"
            };
            invalidConfig.SigningKeys.Add(new SymmetricSecurityKey(new byte[32]));

            var mockEventHandler = new MockConfigurationEventHandler
            {
                ConfigurationToReturn = invalidConfig,
                RetrievalTimeToReturn = DateTimeOffset.UtcNow
            };

            var configurationManager = ConfigurationManager<OpenIdConnectConfiguration>.CreateSync(
                "OpenIdConnectMetadata.json",
                configurationRetriever,
                documentRetriever,
                configurationValidator);

            configurationManager.ConfigurationEventHandlerSync = mockEventHandler;

            configurationManager.TelemetryClient = testTelemetryClient;

            // Act
            var configuration = configurationManager.GetConfigurationSync();

            // Assert
            // When handler returns invalid config, it should fall back to endpoint retrieval
            if (configuration == null)
                testContext.AddDiff("Configuration should not be null.");

            // The configuration should be from the file (endpoint), not from the handler
            if (configuration.Issuer == "https://test.issuer.com")
                testContext.AddDiff("Configuration should be from endpoint when handler returns invalid config.");

            var expectedTagList = new Dictionary<string, object>
            {
                { TelemetryConstants.MetadataAddressTag, "OpenIdConnectMetadata.json" },
                { TelemetryConstants.IdentityModelVersionTag, IdentityModelTelemetryUtil.ClientVer },
                { TelemetryConstants.OperationStatusTag, TelemetryConstants.Protocols.FirstRefresh },
                { TelemetryConstants.ConfigurationSourceTag, TelemetryConstants.Protocols.ConfigurationSourceRetriever },
            };

            PollForCondition(
                () => expectedTagList.Count == testTelemetryClient.ExportedItems.Count,
                TimeSpan.FromMilliseconds(250),
                TimeSpan.FromSeconds(20));

            Assert.Equal(expectedTagList, testTelemetryClient.ExportedItems);

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

        /// <summary>
        /// Mock document retriever to track calls
        /// </summary>
        private class MockDocumentRetriever : IDocumentRetriever, IDocumentRetrieverSync
        {
            public bool GetDocumentCalled { get; private set; }

            public Task<string> GetDocumentAsync(string address, CancellationToken cancel)
            {
                GetDocumentCalled = true;
                return Task.FromResult(string.Empty);
            }

            public string GetDocument(string address, CancellationToken cancel)
            {
                GetDocumentCalled = true;
                return string.Empty;
            }
        }
    }
}
