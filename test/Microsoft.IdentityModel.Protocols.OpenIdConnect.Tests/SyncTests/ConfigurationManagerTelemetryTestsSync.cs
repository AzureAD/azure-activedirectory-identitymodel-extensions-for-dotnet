// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#if NET5_0_OR_GREATER

using System;
using System.Collections.Generic;
using System.Threading;
using Microsoft.Extensions.Time.Testing;
using Microsoft.IdentityModel.Logging;
using Microsoft.IdentityModel.Protocols.OpenIdConnect.Configuration;
using Microsoft.IdentityModel.Telemetry;
using Microsoft.IdentityModel.Telemetry.Tests;
using Microsoft.IdentityModel.TestUtils;
using Microsoft.IdentityModel.Tokens;
using Xunit;

namespace Microsoft.IdentityModel.Protocols.OpenIdConnect.Tests
{
    /// <summary>
    /// Synchronous mirror of <see cref="ConfigurationManagerTelemetryTests"/>.
    /// Exercises the telemetry emitted through the synchronous GetConfigurationSync API.
    /// Gated to net5+ because it relies on the synchronous HttpDocumentRetriever path.
    /// </summary>
    [ResetAppContextSwitches]
    [Collection(nameof(AppContextSwitches.UpdateConfigAsBlocking))]
    public class ConfigurationManagerTelemetryTestsSync
    {
        [Fact]
        public void RequestRefresh_ExpectedTagsExist()
        {
            RequestRefresh_ExpectedTagsBody();
        }

        [Fact]
        public void RequestRefresh_ExpectedTagsExist_Blocking()
        {
            AppContext.SetSwitch(AppContextSwitches.UpdateConfigAsBlockingSwitch, true);
            RequestRefresh_ExpectedTagsBody(true);
        }

        private static void RequestRefresh_ExpectedTagsBody(bool blocking = false)
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

            AutoResetEvent resetEvent = ConfigurationManagerTests.SetupResetEvent(configurationManager);

            // act
            // Retrieve the configuration for the first time
            configurationManager.GetConfigurationSync();
            testTelemetryClient.ClearExportedItems();

            // Manually request a config refresh
            configurationManager.RequestRefresh();
            configurationManager.GetConfigurationSync();

            if (!blocking)
                ConfigurationManagerTests.WaitOrFail(resetEvent);

            // assert
            var expectedCounterTagList = new Dictionary<string, object>
            {
                { TelemetryConstants.MetadataAddressTag, OpenIdConfigData.AccountsGoogle },
                { TelemetryConstants.IdentityModelVersionTag, IdentityModelTelemetryUtil.ClientVer },
                { TelemetryConstants.OperationStatusTag, TelemetryConstants.Protocols.Manual },
                // This tag is set to ConfigurationSourceRetriever for blocking, and ConfigurationSourceUnknown for non-blocking due to the difference in implementation.
                // On manual refreshes, we don't know the source of the configuration upfront , so we set it to Unknown.
                { TelemetryConstants.ConfigurationSourceTag, blocking == true ? TelemetryConstants.Protocols.ConfigurationSourceRetriever :TelemetryConstants.Protocols.ConfigurationSourceUnknown },
            };

            var expectedHistogramTagList = new Dictionary<string, object>
            {
                { TelemetryConstants.MetadataAddressTag, OpenIdConfigData.AccountsGoogle },
                { TelemetryConstants.IdentityModelVersionTag, IdentityModelTelemetryUtil.ClientVer },
                { TelemetryConstants.ConfigurationSourceTag, TelemetryConstants.Protocols.ConfigurationSourceRetriever  },
            };

            PollForCondition(
                () => expectedCounterTagList.Count == testTelemetryClient.ExportedItems.Count &&
                    expectedHistogramTagList.Count == testTelemetryClient.ExportedHistogramItems.Count,
                TimeSpan.FromMilliseconds(250),
                TimeSpan.FromSeconds(20));

            Assert.Equal(expectedCounterTagList, testTelemetryClient.ExportedItems);
            Assert.Equal(expectedHistogramTagList, testTelemetryClient.ExportedHistogramItems);
        }

        [Theory, MemberData(nameof(ConfigurationManagerTelemetryTests.GetConfiguration_ExpectedTagList_TheoryData), false, DisableDiscoveryEnumeration = true, MemberType = typeof(ConfigurationManagerTelemetryTests))]
        public void GetConfigurationSync_ExpectedTagsExist(ConfigurationManagerTelemetryTheoryData<OpenIdConnectConfiguration> theoryData)
        {
            GetConfigurationSync_ExpectedTagList_Body(theoryData);
        }

        [Theory, MemberData(nameof(ConfigurationManagerTelemetryTests.GetConfiguration_ExpectedTagList_TheoryData), true, DisableDiscoveryEnumeration = true, MemberType = typeof(ConfigurationManagerTelemetryTests))]
        public void GetConfigurationSync_ExpectedTagsExist_Blocking(ConfigurationManagerTelemetryTheoryData<OpenIdConnectConfiguration> theoryData)
        {
            AppContext.SetSwitch(AppContextSwitches.UpdateConfigAsBlockingSwitch, true);
            theoryData.ExpectedTagList[TelemetryConstants.ConfigurationSourceTag] = TelemetryConstants.Protocols.ConfigurationSourceRetriever;
            GetConfigurationSync_ExpectedTagList_Body(theoryData, true);
        }

        private static void GetConfigurationSync_ExpectedTagList_Body(
            ConfigurationManagerTelemetryTheoryData<OpenIdConnectConfiguration> theoryData,
            bool blocking = false)
        {
            var testTelemetryClient = new MockTelemetryClient();
            var timeProvider = new FakeTimeProvider();

            var configurationManager = new ConfigurationManager<OpenIdConnectConfiguration>(
                theoryData.MetadataAddress,
                new OpenIdConnectConfigurationRetriever(),
                theoryData.DocumentRetriever,
                theoryData.ConfigurationValidator)
            {
                TelemetryClient = testTelemetryClient,
                TimeProvider = timeProvider,
            };

            AutoResetEvent resetEvent = ConfigurationManagerTests.SetupResetEvent(configurationManager);

            try
            {
                _ = configurationManager.GetConfigurationSync();
                if (theoryData.AdjustTime.HasValue)
                {
                    testTelemetryClient.ClearExportedItems();
                    timeProvider.Advance(theoryData.AdjustTime.Value);
                    _ = configurationManager.GetConfigurationSync();

                    if (!blocking)
                        ConfigurationManagerTests.WaitOrFail(resetEvent);
                }
            }
            catch (Exception)
            {
                // Ignore exceptions
            }

            PollForCondition(
                () => theoryData.ExpectedTagList.Count == testTelemetryClient.ExportedItems.Count,
                TimeSpan.FromMilliseconds(250),
                TimeSpan.FromSeconds(20));

            DateTimeOffset syncAfter = (DateTimeOffset)TestUtilities.GetField(configurationManager, "_syncAfter");

            Assert.Equal(theoryData.ExpectedTagList, testTelemetryClient.ExportedItems);
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
}

#endif
