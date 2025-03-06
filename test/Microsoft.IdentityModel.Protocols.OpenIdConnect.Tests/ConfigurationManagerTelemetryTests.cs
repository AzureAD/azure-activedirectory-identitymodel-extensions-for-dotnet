// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System;
using System.Collections.Generic;
using System.IO;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Time.Testing;
using Microsoft.IdentityModel.Logging;
using Microsoft.IdentityModel.Protocols.Configuration;
using Microsoft.IdentityModel.Protocols.OpenIdConnect.Configuration;
using Microsoft.IdentityModel.Telemetry;
using Microsoft.IdentityModel.Telemetry.Tests;
using Microsoft.IdentityModel.TestUtils;
using Xunit;

namespace Microsoft.IdentityModel.Protocols.OpenIdConnect.Tests
{
    public class ConfigurationManagerTelemetryTests
    {
        [Fact]
        public async Task RequestRefresh_IntervalHasNotPassed_ExpectedCount()
        {
            // arrange
            var testTelemetryClient = new MockTelemetryClient();
            var configurationManager = new ConfigurationManager<OpenIdConnectConfiguration>(
                OpenIdConfigData.AccountsGoogle,
                new OpenIdConnectConfigurationRetriever(),
                new HttpDocumentRetriever(),
                new OpenIdConnectConfigurationValidator())
            {
                TelemetryClient = testTelemetryClient
            };
            var cancel = new CancellationToken();

            AutoResetEvent resetEvent = ConfigurationManagerTests.SetupResetEvent(configurationManager);

            var timeProvider = new FakeTimeProvider();
            configurationManager.TimeProvider = timeProvider;

            // act
            // Retrieve the configuration for the first time
            await configurationManager.GetConfigurationAsync(cancel);
            testTelemetryClient.ClearExportedItems();

            // Manually request a config refresh
            configurationManager.RequestRefresh();
            await configurationManager.GetConfigurationAsync(cancel);

            ConfigurationManagerTests.WaitOrFail(resetEvent);

            // Request a second refresh, but don't wait for the interval to pass
            configurationManager.RequestRefresh();
            await configurationManager.GetConfigurationAsync(cancel);

            // assert: There should be two calls here, first from the call to GetConfigurationAsync
            // the second from RequestRefresh, first request refresh always goes through
            Assert.Equal(2, testTelemetryClient.RequestRefreshCounter);
        }

        [Fact]
        public async Task RequestRefresh_ExpectedTagsExist()
        {
            // arrange
            var testTelemetryClient = new MockTelemetryClient();
            var configurationManager = new ConfigurationManager<OpenIdConnectConfiguration>(
                OpenIdConfigData.AccountsGoogle,
                new OpenIdConnectConfigurationRetriever(),
                new HttpDocumentRetriever(),
                new OpenIdConnectConfigurationValidator())
            {
                TelemetryClient = testTelemetryClient
            };
            var cancel = new CancellationToken();

            AutoResetEvent resetEvent = ConfigurationManagerTests.SetupResetEvent(configurationManager);

            var timeProvider = new FakeTimeProvider();
            configurationManager.TimeProvider = timeProvider;

            // act
            // Retrieve the configuration for the first time
            await configurationManager.GetConfigurationAsync(cancel);
            testTelemetryClient.ClearExportedItems();

            // Manually request a config refresh
            configurationManager.RequestRefresh();
            await configurationManager.GetConfigurationAsync(cancel);

            ConfigurationManagerTests.WaitOrFail(resetEvent);

            // assert
            var expectedCounterTagList = new Dictionary<string, object>
            {
                { TelemetryConstants.MetadataAddressTag, OpenIdConfigData.AccountsGoogle },
                { TelemetryConstants.IdentityModelVersionTag, IdentityModelTelemetryUtil.ClientVer },
                { TelemetryConstants.OperationStatusTag, TelemetryConstants.Protocols.Manual },
            };

            var expectedHistogramTagList = new Dictionary<string, object>
            {
                { TelemetryConstants.MetadataAddressTag, OpenIdConfigData.AccountsGoogle },
                { TelemetryConstants.IdentityModelVersionTag, IdentityModelTelemetryUtil.ClientVer }
            };

            Assert.Equal(expectedCounterTagList, testTelemetryClient.ExportedItems);
            Assert.Equal(expectedHistogramTagList, testTelemetryClient.ExportedHistogramItems);
        }

        [Theory, MemberData(nameof(GetConfiguration_ExpectedTagList_TheoryData), DisableDiscoveryEnumeration = true)]
        public async Task GetConfigurationAsync_ExpectedTagsExist(ConfigurationManagerTelemetryTheoryData<OpenIdConnectConfiguration> theoryData)
        {
            var testTelemetryClient = new MockTelemetryClient();

            var configurationManager = new ConfigurationManager<OpenIdConnectConfiguration>(
                theoryData.MetadataAddress,
                new OpenIdConnectConfigurationRetriever(),
                theoryData.DocumentRetriever,
                theoryData.ConfigurationValidator)
            {
                TelemetryClient = testTelemetryClient
            };

            AutoResetEvent resetEvent = ConfigurationManagerTests.SetupResetEvent(configurationManager);

            var timeProvider = new FakeTimeProvider();
            configurationManager.TimeProvider = timeProvider;

            try
            {
                await configurationManager.GetConfigurationAsync();
                if (theoryData.SyncAfter != null)
                {
                    testTelemetryClient.ClearExportedItems();
                    timeProvider.Advance((theoryData.SyncAfter - DateTimeOffset.UtcNow).Value);
                    await configurationManager.GetConfigurationAsync();

                    ConfigurationManagerTests.WaitOrFail(resetEvent);
                }
            }
            catch (Exception)
            {
                // Ignore exceptions
            }

            Assert.Equal(theoryData.ExpectedTagList, testTelemetryClient.ExportedItems);
        }

        public static TheoryData<ConfigurationManagerTelemetryTheoryData<OpenIdConnectConfiguration>> GetConfiguration_ExpectedTagList_TheoryData()
        {
            return new TheoryData<ConfigurationManagerTelemetryTheoryData<OpenIdConnectConfiguration>>
            {
                new ConfigurationManagerTelemetryTheoryData<OpenIdConnectConfiguration>("Success-retrieve from endpoint")
                {
                    MetadataAddress = OpenIdConfigData.AccountsGoogle,
                    ConfigurationValidator = new OpenIdConnectConfigurationValidator(),
                    ExpectedTagList = new Dictionary<string, object>
                    {
                        { TelemetryConstants.MetadataAddressTag, OpenIdConfigData.AccountsGoogle },
                        { TelemetryConstants.IdentityModelVersionTag, IdentityModelTelemetryUtil.ClientVer },
                        { TelemetryConstants.OperationStatusTag, TelemetryConstants.Protocols.FirstRefresh },
                    }
                },
                new ConfigurationManagerTelemetryTheoryData<OpenIdConnectConfiguration>("Failure-invalid metadata address")
                {
                    MetadataAddress = OpenIdConfigData.HttpsBadUri,
                    ConfigurationValidator = new OpenIdConnectConfigurationValidator(),
                    ExpectedTagList = new Dictionary<string, object>
                    {
                        { TelemetryConstants.MetadataAddressTag, OpenIdConfigData.HttpsBadUri },
                        { TelemetryConstants.IdentityModelVersionTag, IdentityModelTelemetryUtil.ClientVer },
                        { TelemetryConstants.OperationStatusTag, TelemetryConstants.Protocols.FirstRefresh },
                        { TelemetryConstants.ExceptionTypeTag, new IOException().GetType().ToString() },
                    }
                },
                new ConfigurationManagerTelemetryTheoryData<OpenIdConnectConfiguration>("Failure-invalid config")
                {
                    MetadataAddress = OpenIdConfigData.JsonFile,
                    DocumentRetriever = new FileDocumentRetriever(),
                    // The config being loaded has two keys; require three to force invalidity
                    ConfigurationValidator = new OpenIdConnectConfigurationValidator() { MinimumNumberOfKeys = 3 },
                    ExpectedTagList = new Dictionary<string, object>
                    {
                        { TelemetryConstants.MetadataAddressTag, OpenIdConfigData.JsonFile },
                        { TelemetryConstants.IdentityModelVersionTag, IdentityModelTelemetryUtil.ClientVer },
                        { TelemetryConstants.OperationStatusTag, TelemetryConstants.Protocols.FirstRefresh },
                        { TelemetryConstants.ExceptionTypeTag, new InvalidConfigurationException().GetType().ToString() },
                    }
                },
                new ConfigurationManagerTelemetryTheoryData<OpenIdConnectConfiguration>("Success-refresh")
                {
                    MetadataAddress = OpenIdConfigData.AADCommonUrl,
                    ConfigurationValidator = new OpenIdConnectConfigurationValidator(),
                    SyncAfter = DateTime.UtcNow + TimeSpan.FromDays(2),
                    ExpectedTagList = new Dictionary<string, object>
                    {
                        { TelemetryConstants.MetadataAddressTag, OpenIdConfigData.AADCommonUrl },
                        { TelemetryConstants.IdentityModelVersionTag, IdentityModelTelemetryUtil.ClientVer },
                        { TelemetryConstants.OperationStatusTag, TelemetryConstants.Protocols.Automatic },
                    }
                },
            };
        }
    }

    public class ConfigurationManagerTelemetryTheoryData<T> : TheoryDataBase where T : class
    {
        public ConfigurationManagerTelemetryTheoryData(string testId) : base(testId) { }

        public string MetadataAddress { get; set; }

        public IDocumentRetriever DocumentRetriever { get; set; } = new HttpDocumentRetriever();

        public IConfigurationValidator<T> ConfigurationValidator { get; set; }

        public DateTimeOffset? SyncAfter { get; set; } = null;

        public Dictionary<string, object> ExpectedTagList { get; set; }
    }
}
