// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System;
using System.Collections.Generic;
using System.IO;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.IdentityModel.Logging;
using Microsoft.IdentityModel.Protocols.Configuration;
using Microsoft.IdentityModel.Protocols.OpenIdConnect.Configuration;
using Microsoft.IdentityModel.TestUtils;
using Microsoft.IdentityModel.Telemetry;
using Microsoft.IdentityModel.Telemetry.Tests;
using Xunit;
using Microsoft.IdentityModel.Tokens;

namespace Microsoft.IdentityModel.Protocols.OpenIdConnect.Tests
{
    [ResetAppContextSwitches]
    public class ConfigurationManagerTelemetryTests
    {
        [Fact]
        public async Task RequestRefresh_ExpectedTagsExist()
        {
            await RequestRefresh_ExpectedTagsBody();
        }

        [Fact]
        public async Task RequestRefresh_ExpectedTagsExist_Blocking()
        {
            AppContext.SetSwitch(AppContextSwitches.UpdateConfigAsBlockingSwitch, true);
            await RequestRefresh_ExpectedTagsBody(true);
        }

        private static async Task RequestRefresh_ExpectedTagsBody(bool blocking = false)
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

            // act
            // Retrieve the configuration for the first time
            await configurationManager.GetConfigurationAsync(cancel);
            testTelemetryClient.ClearExportedItems();

            // Manually request a config refresh
            configurationManager.RequestRefresh();
            await configurationManager.GetConfigurationAsync(cancel);

            AutoResetEvent resetEvent = ConfigurationManagerTests.SetupResetEvent(configurationManager, blocking);

            if (!blocking)
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
            await GetConfigurationAsync_ExpectedTagList_Body(theoryData);
        }

        [Theory, MemberData(nameof(GetConfiguration_ExpectedTagList_TheoryData), DisableDiscoveryEnumeration = true)]
        public async Task GetConfigurationAsync_ExpectedTagsExist_Blocking(ConfigurationManagerTelemetryTheoryData<OpenIdConnectConfiguration> theoryData)
        {
            AppContext.SetSwitch(AppContextSwitches.UpdateConfigAsBlockingSwitch, true);
            await GetConfigurationAsync_ExpectedTagList_Body(theoryData, true);
        }

        private static async Task GetConfigurationAsync_ExpectedTagList_Body(
            ConfigurationManagerTelemetryTheoryData<OpenIdConnectConfiguration> theoryData,
            bool blocking = false)
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

            AutoResetEvent resetEvent = ConfigurationManagerTests.SetupResetEvent(configurationManager, blocking);

            try
            {
                await configurationManager.GetConfigurationAsync();
                if (theoryData.SyncAfter != null)
                {
                    testTelemetryClient.ClearExportedItems();
                    TestUtilities.SetField(configurationManager, "_syncAfter", theoryData.SyncAfter);
                    await configurationManager.GetConfigurationAsync();
                }

                if (!blocking)
                    ConfigurationManagerTests.WaitOrFail(resetEvent);
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
                    SyncAfter = DateTime.UtcNow - TimeSpan.FromDays(2),
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

        public DateTime? SyncAfter { get; set; } = null;

        public Dictionary<string, object> ExpectedTagList { get; set; }
    }
}
