// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

// Ignore Spelling: Metadata Validator Retreiver

// The synchronous configuration retrieval path relies on IDocumentRetrieverSync.GetDocument.
// HttpDocumentRetriever only implements it on .NET 5.0 or greater, and several tests below use it,
// so the entire sync mirror is gated to NET5_0_OR_GREATER.
#if NET5_0_OR_GREATER

using System;
using System.Collections.Generic;
using System.Diagnostics.Tracing;
using System.IO;
using System.Net;
using System.Reflection;
using System.Threading;
using Microsoft.Extensions.Time.Testing;
using Microsoft.IdentityModel.Protocols.Configuration;
using Microsoft.IdentityModel.Protocols.OpenIdConnect.Configuration;
using Microsoft.IdentityModel.TestUtils;
using Microsoft.IdentityModel.Tokens;
using Xunit;

using CMTests = Microsoft.IdentityModel.Protocols.OpenIdConnect.Tests.ConfigurationManagerTests;

namespace Microsoft.IdentityModel.Protocols.OpenIdConnect.Tests
{
    /// <summary>
    /// Synchronous mirror of <see cref="ConfigurationManagerTests"/>. Each test calls the synchronous
    /// <see cref="ConfigurationManagerSync{T}.GetConfigurationSync(CancellationToken)"/> instead of the
    /// asynchronous <c>GetConfigurationAsync</c>. Theory data and shared helpers are reused from
    /// <see cref="ConfigurationManagerTests"/> where possible.
    /// </summary>
    [ResetAppContextSwitches]
    [Collection(nameof(AppContextSwitches.UpdateConfigAsBlocking))]
    public class ConfigurationManagerTestsSync
    {
        /// <summary>
        /// This test reaches out the the internet to fetch the OpenIdConnectConfiguration from the specified metadata address.
        /// </summary>
        [Theory, MemberData(nameof(CMTests.GetPublicMetadataTheoryData), MemberType = typeof(CMTests), DisableDiscoveryEnumeration = true)]
        public void GetPublicMetadata(ConfigurationManagerTests.ConfigurationManagerTheoryData<OpenIdConnectConfiguration> theoryData)
        {
            CompareContext context = TestUtilities.WriteHeader($"{this}.GetPublicMetadata", theoryData);
            try
            {
                var configurationManager = new ConfigurationManagerSync<OpenIdConnectConfiguration>(
                    theoryData.MetadataAddress,
                    theoryData.ConfigurationRetriever is null ? null : new OpenIdConnectConfigurationRetrieverSync(),
                    (IDocumentRetrieverSync)theoryData.DocumentRetriever,
                    theoryData.ConfigurationValidator);

                var configuration = configurationManager.GetConfigurationSync(CancellationToken.None);

                Assert.NotNull(configuration);
                theoryData.ExpectedException.ProcessNoException(context);
            }
            catch (Exception ex)
            {
                theoryData.ExpectedException.ProcessException(ex, context);
            }

            TestUtilities.AssertFailIfErrors(context);
        }

        [Theory, MemberData(nameof(CMTests.ConstructorTheoryData), MemberType = typeof(CMTests), DisableDiscoveryEnumeration = true)]
        public void OpenIdConnectConstructor(ConfigurationManagerTests.ConfigurationManagerTheoryData<OpenIdConnectConfiguration> theoryData)
        {
            var context = TestUtilities.WriteHeader($"{this}.OpenIdConnectConstructor", theoryData);
            try
            {
                var configurationManager = new ConfigurationManagerSync<OpenIdConnectConfiguration>(
                    theoryData.MetadataAddress,
                    theoryData.ConfigurationRetriever is null ? null : new OpenIdConnectConfigurationRetrieverSync(),
                    (IDocumentRetrieverSync)theoryData.DocumentRetriever,
                    theoryData.ConfigurationValidator);
                theoryData.ExpectedException.ProcessNoException();
            }
            catch (Exception ex)
            {
                theoryData.ExpectedException.ProcessException(ex);
            }

            TestUtilities.AssertFailIfErrors(context);
        }

        [Fact]
        public void Defaults()
        {
            TestUtilities.WriteHeader($"{this}.Defaults", "Defaults", true);

            Assert.Equal(ConfigurationManagerSync<OpenIdConnectConfiguration>.DefaultAutomaticRefreshInterval, new TimeSpan(0, 12, 0, 0));
            Assert.Equal(ConfigurationManagerSync<OpenIdConnectConfiguration>.DefaultRefreshInterval, new TimeSpan(0, 0, 5, 0));
            Assert.Equal(ConfigurationManagerSync<OpenIdConnectConfiguration>.MinimumAutomaticRefreshInterval, new TimeSpan(0, 0, 5, 0));
            Assert.Equal(ConfigurationManagerSync<OpenIdConnectConfiguration>.MinimumRefreshInterval, new TimeSpan(0, 0, 0, 1));
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

        [Fact]
        public void FetchMetadataFailure_Blocking_PreservesInnerExceptionDuringBackoffWindow()
        {
            AppContext.SetSwitch(AppContextSwitches.UpdateConfigAsBlockingSwitch, true);

            var context = new CompareContext($"{this}.{nameof(FetchMetadataFailure_Blocking_PreservesInnerExceptionDuringBackoffWindow)}");

            var documentRetriever = new HttpDocumentRetriever(
                HttpResponseMessageUtils.SetupHttpClientThatReturns("OpenIdConnectMetadata.json", HttpStatusCode.NotFound));
            var configManager = new ConfigurationManagerSync<OpenIdConnectConfiguration>(
                "https://example.invalid/.well-known/openid-configuration",
                new OpenIdConnectConfigurationRetrieverSync(),
                documentRetriever);

            // First call: fetch is attempted and fails. The thrown InvalidOperationException should
            // wrap the original IOException carrying the HTTP status code in its Data dictionary.
            Exception firstException = null;
            try
            {
                _ = configManager.GetConfigurationSync(CancellationToken.None);
            }
            catch (Exception ex)
            {
                firstException = ex;
            }

            if (firstException == null)
                context.AddDiff("Expected first GetConfigurationSync call to throw.");
            else
            {
                if (firstException.InnerException == null)
                    context.AddDiff("Expected first call's InvalidOperationException to wrap the underlying IOException.");
                else if (!ExceptionChainContainsStatusCode(firstException))
                    context.AddDiff("Expected first call's exception chain to contain HttpDocumentRetriever.StatusCode in Data.");
            }

            // Force the backoff window: ensure _syncAfter is in the future so the next call skips the fetch
            // and goes through the "stale metadata is better than no metadata" path. _currentConfiguration
            // is still null (bootstrap never succeeded), so the manager re-throws IDX20803.
            TestUtilities.SetField(configManager, "_syncAfter", DateTimeOffset.UtcNow.AddHours(1));

            Exception secondException = null;
            try
            {
                _ = configManager.GetConfigurationSync(CancellationToken.None);
            }
            catch (Exception ex)
            {
                secondException = ex;
            }

            if (secondException == null)
                context.AddDiff("Expected second GetConfigurationSync call (within backoff window) to throw.");
            else
            {
                if (secondException.InnerException == null)
                {
                    context.AddDiff(
                        "BUG: Second call within backoff window threw IDX20803 with a null InnerException. " +
                        "The original IOException (with HttpDocumentRetriever.StatusCode in Data) was lost " +
                        "because _fetchMetadataFailure is a local variable in GetConfigurationWithBlockingSync.");
                }
                else if (!ExceptionChainContainsStatusCode(secondException))
                {
                    context.AddDiff("Expected second call's exception chain to contain HttpDocumentRetriever.StatusCode in Data.");
                }
            }

            TestUtilities.AssertFailIfErrors(context);
        }

        private static bool ExceptionChainContainsStatusCode(Exception exception)
        {
            for (Exception current = exception; current != null; current = current.InnerException)
            {
                if (current.Data.Contains(HttpDocumentRetriever.StatusCode))
                    return true;
            }

            return false;
        }

        private void FetchMetadataFailureTestBody()
        {
            var context = new CompareContext($"{this}.FetchMetadataFailureTest");

            var documentRetriever = new HttpDocumentRetriever(HttpResponseMessageUtils.SetupHttpClientThatReturns("OpenIdConnectMetadata.json", HttpStatusCode.NotFound));
            var configManager = new ConfigurationManagerSync<OpenIdConnectConfiguration>("OpenIdConnectMetadata.json", new OpenIdConnectConfigurationRetrieverSync(), documentRetriever);

            // First time to fetch metadata
            try
            {
                _ = configManager.GetConfigurationSync();
            }
            catch (Exception firstFetchMetadataFailure)
            {
                if (firstFetchMetadataFailure.InnerException == null)
                    context.AddDiff($"Expected exception to contain inner exception for fetch metadata failure.");

                // Fetch metadata again during refresh interval, the exception should be same from above
                try
                {
                    _ = configManager.GetConfigurationSync();
                }
                catch (Exception secondFetchMetadataFailure)
                {
                    if (secondFetchMetadataFailure.InnerException == null)
                        context.AddDiff($"Expected exception to contain inner exception for fetch metadata failure.");

                    IdentityComparer.AreEqual(firstFetchMetadataFailure, secondFetchMetadataFailure, context);
                }
            }

            TestUtilities.AssertFailIfErrors(context);
        }

        [Fact]
        public void VerifyInterlockGuardForRequestRefresh()
        {
            ManualResetEvent waitEvent = new ManualResetEvent(false);
            ManualResetEvent signalEvent = new ManualResetEvent(false);
            InMemoryDocumentRetriever inMemoryDocumentRetriever = InMemoryDocumentRetrieverWithEvents(waitEvent, signalEvent);

            var configurationManager = new ConfigurationManagerSync<OpenIdConnectConfiguration>(
                    "AADCommonV1Json",
                    new OpenIdConnectConfigurationRetrieverSync(),
                    inMemoryDocumentRetriever);

            // populate the configurationManager with AADCommonV1Config
            TestUtilities.SetField(configurationManager, "_currentConfiguration", OpenIdConfigData.AADCommonV1Config);

            signalEvent.Reset();
            configurationManager.RequestRefresh();

            signalEvent.WaitOne();

            configurationManager.MetadataAddress = "AADCommonV2Json";
            TestUtilities.SetField(configurationManager, "_lastRequestRefresh", DateTimeOffset.MinValue);
            configurationManager.RequestRefresh();

            // Set the event to release the lock and let the previous retriever finish.
            waitEvent.Set();

            // Configuration should be AADCommonV1Config
            var configuration = configurationManager.GetConfigurationSync();
            Assert.True(configuration.Issuer.Equals(OpenIdConfigData.AADCommonV1Config.Issuer),
                    $"configuration.Issuer from configurationManager was not as expected," +
                    $"configuration.Issuer: '{configuration.Issuer}' != expected '{OpenIdConfigData.AADCommonV1Config.Issuer}'.");
        }

        [Fact]
        public void VerifyInterlockGuardForGetConfigurationSync()
        {
            ManualResetEvent waitEvent = new ManualResetEvent(false);
            ManualResetEvent signalEvent = new ManualResetEvent(false);

            InMemoryDocumentRetriever inMemoryDocumentRetriever = InMemoryDocumentRetrieverWithEvents(waitEvent, signalEvent);
            waitEvent.Set();

            var configurationManager = new ConfigurationManagerSync<OpenIdConnectConfiguration>(
                    "AADCommonV1Json",
                    new OpenIdConnectConfigurationRetrieverSync(),
                    inMemoryDocumentRetriever);

            OpenIdConnectConfiguration configuration = configurationManager.GetConfigurationSync();

            waitEvent.Reset();
            signalEvent.Reset();

            TestUtilities.SetField(configurationManager, "_syncAfter", DateTimeOffset.MinValue);
            configurationManager.GetConfigurationSync(CancellationToken.None);

            signalEvent.WaitOne();

            configurationManager.MetadataAddress = "AADCommonV2Json";
            configurationManager.GetConfigurationSync(CancellationToken.None);

            // Set the event to release the lock and let the previous retriever finish.
            waitEvent.Set();

            // Configuration should be AADCommonV1Config
            configuration = configurationManager.GetConfigurationSync();
            Assert.True(configuration.Issuer.Equals(OpenIdConfigData.AADCommonV1Config.Issuer),
                    $"configuration.Issuer from configurationManager was not as expected," +
                    $" configuration.Issuer: '{configuration.Issuer}' != expected: '{OpenIdConfigData.AADCommonV1Config.Issuer}'.");
        }

        [Fact]
        public void BootstrapRefreshIntervalTest()
        {
            var context = new CompareContext($"{this}.BootstrapRefreshIntervalTest");

            var documentRetriever = new HttpDocumentRetriever(
                HttpResponseMessageUtils.SetupHttpClientThatReturns("OpenIdConnectMetadata.json", HttpStatusCode.NotFound));

            var configManager = new ConfigurationManagerSync<OpenIdConnectConfiguration>(
                "OpenIdConnectMetadata.json",
                new OpenIdConnectConfigurationRetrieverSync(),
                documentRetriever);

            configManager.RefreshInterval = TimeSpan.FromSeconds(2);

            // ConfigurationManager._syncAfter is set to DateTimeOffset.MinValue on startup
            // If obtaining the metadata fails due to error, the value should not change
            try
            {
                var configuration = configManager.GetConfigurationSync();
            }
            catch (Exception firstFetchMetadataFailure)
            {
                // _syncAfter should not have been changed, because the fetch failed.
                var syncAfter = TestUtilities.GetField(configManager, "_syncAfter");
                if ((DateTimeOffset)syncAfter != DateTimeOffset.MinValue)
                    context.AddDiff($"ConfigurationManager._syncAfter: '{syncAfter}' should equal '{DateTimeOffset.MinValue}'.");

                if (firstFetchMetadataFailure.InnerException == null)
                    context.AddDiff($"Expected exception to contain inner exception for fetch metadata failure.");

                // Fetch metadata again during refresh interval, the exception should be same from above.
                try
                {
                    configManager.RequestRefresh();
                    var configuration = configManager.GetConfigurationSync();
                }
                catch (Exception secondFetchMetadataFailure)
                {
                    if (secondFetchMetadataFailure.InnerException == null)
                        context.AddDiff($"Expected exception to contain inner exception for fetch metadata failure.");

                    // _syncAfter should not have been changed, because the fetch failed.
                    syncAfter = TestUtilities.GetField(configManager, "_syncAfter");
                    if ((DateTimeOffset)syncAfter != DateTimeOffset.MinValue)
                        context.AddDiff($"ConfigurationManager._syncAfter: '{syncAfter}' should equal '{DateTimeOffset.MinValue}'.");

                    IdentityComparer.AreEqual(firstFetchMetadataFailure, secondFetchMetadataFailure, context);
                }
            }

            TestUtilities.AssertFailIfErrors(context);
        }

        [Fact]
        public void BootstrapRefreshIntervalTest_Blocking()
        {
            AppContext.SetSwitch(AppContextSwitches.UpdateConfigAsBlockingSwitch, true);

            var context = new CompareContext($"{this}.BootstrapRefreshIntervalTest_Blocking");

            var documentRetriever = new HttpDocumentRetriever(HttpResponseMessageUtils.SetupHttpClientThatReturns("OpenIdConnectMetadata.json", HttpStatusCode.NotFound));
            var configManager = new ConfigurationManagerSync<OpenIdConnectConfiguration>("OpenIdConnectMetadata.json", new OpenIdConnectConfigurationRetrieverSync(), documentRetriever);
            configManager.RefreshInterval = TimeSpan.FromSeconds(2);

            // First time to fetch metadata.
            try
            {
                var configuration = configManager.GetConfigurationSync();
            }
            catch (Exception firstFetchMetadataFailure)
            {
                // Refresh interval is BootstrapRefreshInterval
                var syncAfter = (DateTimeOffset)configManager.GetType().GetField("_syncAfter", BindingFlags.NonPublic | BindingFlags.Instance).GetValue(configManager);
                if (syncAfter > DateTime.UtcNow + TimeSpan.FromSeconds(2))
                    context.AddDiff($"Expected the refresh interval is longer than 2 seconds.");

                if (firstFetchMetadataFailure.InnerException == null)
                    context.AddDiff($"Expected exception to contain inner exception for fetch metadata failure.");

                // Fetch metadata again during refresh interval, the exception should be same from above.
                try
                {
                    configManager.RequestRefresh();
                    var configuration = configManager.GetConfigurationSync();
                }
                catch (Exception secondFetchMetadataFailure)
                {
                    if (secondFetchMetadataFailure.InnerException == null)
                        context.AddDiff($"Expected exception to contain inner exception for fetch metadata failure.");

                    syncAfter = (DateTimeOffset)configManager.GetType().GetField("_syncAfter", BindingFlags.NonPublic | BindingFlags.Instance).GetValue(configManager);

                    // Refresh interval is RefreshInterval
                    if (syncAfter > DateTime.UtcNow + configManager.RefreshInterval)
                        context.AddDiff($"Expected the refresh interval is longer than 2 seconds.");

                    IdentityComparer.AreEqual(firstFetchMetadataFailure, secondFetchMetadataFailure, context);
                }
            }
            TestUtilities.AssertFailIfErrors(context);
        }

        [Fact]
        public void GetSets()
        {
            TestUtilities.WriteHeader($"{this}.GetSets", "GetSets", true);

            int ExpectedPropertyCount = 8;
            var configManager = new ConfigurationManagerSync<OpenIdConnectConfiguration>("OpenIdConnectMetadata.json", new OpenIdConnectConfigurationRetrieverSync(), new FileDocumentRetriever());
            Type type = typeof(ConfigurationManagerSync<OpenIdConnectConfiguration>);
            PropertyInfo[] properties = type.GetProperties();
            if (properties.Length != ExpectedPropertyCount)
                Assert.Fail($"Number of properties has changed from {ExpectedPropertyCount} to: " + properties.Length + ", adjust tests");

            var defaultAutomaticRefreshInterval = ConfigurationManagerSync<OpenIdConnectConfiguration>.DefaultAutomaticRefreshInterval;
            var defaultRefreshInterval = ConfigurationManagerSync<OpenIdConnectConfiguration>.DefaultRefreshInterval;
            var context = new GetSetContext
            {
                PropertyNamesAndSetGetValue = new List<KeyValuePair<string, List<object>>>
                {
                    new KeyValuePair<string, List<object>>("RefreshInterval", new List<object>{defaultRefreshInterval, TimeSpan.FromHours(1), TimeSpan.FromHours(10)}),
                },
                Object = configManager,
            };

            TestUtilities.GetSet(context);
            TestUtilities.SetGet(configManager, "AutomaticRefreshInterval", TimeSpan.FromMilliseconds(1), ExpectedException.ArgumentOutOfRangeException(substringExpected: "IDX10108:"), context);
            TestUtilities.SetGet(configManager, "RefreshInterval", TimeSpan.FromMilliseconds(1), ExpectedException.ArgumentOutOfRangeException(substringExpected: "IDX10107:"), context);
            TestUtilities.SetGet(configManager, "RefreshInterval", Timeout.InfiniteTimeSpan, ExpectedException.ArgumentOutOfRangeException(substringExpected: "IDX10107:"), context);
            TestUtilities.SetGet(configManager, "LastKnownGoodConfiguration", new OpenIdConnectConfiguration(), ExpectedException.NoExceptionExpected, context);
            TestUtilities.SetGet(configManager, "UseLastKnownGoodConfiguration", true, ExpectedException.NoExceptionExpected, context);
            TestUtilities.SetGet(configManager, "MetadataAddress", "OpenIdConnectMetadata2.json", ExpectedException.NoExceptionExpected, context);
            TestUtilities.SetGet(configManager, "LastKnownGoodLifetime", TimeSpan.FromDays(5) - TimeSpan.FromDays(15), ExpectedException.ArgumentOutOfRangeException(substringExpected: "IDX10110:"), context);
            TestUtilities.AssertFailIfErrors("ConfigurationManager_GetSets", context.Errors);
        }

        [Theory, MemberData(nameof(CMTests.AutomaticIntervalTestCases), MemberType = typeof(CMTests), DisableDiscoveryEnumeration = true)]
        public void AutomaticRefreshInterval(ConfigurationManagerTests.ConfigurationManagerTheoryData<OpenIdConnectConfiguration> theoryData)
        {
            AutomaticRefreshIntervalBody(theoryData, false);
        }

        [Theory, MemberData(nameof(CMTests.AutomaticIntervalTestCases), MemberType = typeof(CMTests), DisableDiscoveryEnumeration = true)]
        public void AutomaticRefreshInterval_Blocking(ConfigurationManagerTests.ConfigurationManagerTheoryData<OpenIdConnectConfiguration> theoryData)
        {
            AppContext.SetSwitch(AppContextSwitches.UpdateConfigAsBlockingSwitch, true);
            AutomaticRefreshIntervalBody(theoryData, true);
        }

        private void AutomaticRefreshIntervalBody(ConfigurationManagerTests.ConfigurationManagerTheoryData<OpenIdConnectConfiguration> theoryData, bool blocking)
        {
            var context = new CompareContext($"{this}.AutomaticRefreshInterval");
            ConfigurationManagerSync<OpenIdConnectConfiguration> configurationManager = CreateSyncConfigurationManager(theoryData);

            AutoResetEvent resetEvent = ConfigurationManagerTests.SetupResetEvent(configurationManager);

            try
            {
                var configuration = configurationManager.GetConfigurationSync(CancellationToken.None);
                IdentityComparer.AreEqual(configuration, theoryData.ExpectedConfiguration, context);

                configurationManager.MetadataAddress = theoryData.UpdatedMetadataAddress;
                TestUtilities.SetField(configurationManager, "_syncAfter", theoryData.SyncAfter);
                var updatedConfiguration = configurationManager.GetConfigurationSync(CancellationToken.None);

                if (theoryData.WaitForEvent && !blocking)
                    ConfigurationManagerTests.WaitOrFail(resetEvent);

                updatedConfiguration = configurationManager.GetConfigurationSync(CancellationToken.None);
                IdentityComparer.AreEqual(updatedConfiguration, theoryData.ExpectedUpdatedConfiguration, context);

                theoryData.ExpectedException.ProcessNoException(context);
            }
            catch (Exception ex)
            {
                theoryData.ExpectedException.ProcessException(ex, context);
            }

            TestUtilities.AssertFailIfErrors(context);
        }

        [Theory, MemberData(nameof(CMTests.RequestRefreshTestCases), MemberType = typeof(CMTests), DisableDiscoveryEnumeration = true)]
        public void RequestRefresh(ConfigurationManagerTests.ConfigurationManagerTheoryData<OpenIdConnectConfiguration> theoryData)
        {
            RequestRefreshBody(theoryData, false);
        }

        [Theory, MemberData(nameof(CMTests.RequestRefreshTestCases), MemberType = typeof(CMTests), DisableDiscoveryEnumeration = true)]
        public void RequestRefresh_Blocking(ConfigurationManagerTests.ConfigurationManagerTheoryData<OpenIdConnectConfiguration> theoryData)
        {
            AppContext.SetSwitch(AppContextSwitches.UpdateConfigAsBlockingSwitch, true);
            RequestRefreshBody(theoryData, true);
        }

        private void RequestRefreshBody(ConfigurationManagerTests.ConfigurationManagerTheoryData<OpenIdConnectConfiguration> theoryData, bool blocking)
        {
            var context = new CompareContext($"{this}.RequestRefresh");
            ConfigurationManagerSync<OpenIdConnectConfiguration> configurationManager = CreateSyncConfigurationManager(theoryData);

            AutoResetEvent resetEvent = ConfigurationManagerTests.SetupResetEvent(configurationManager);

            var timeProvider = new FakeTimeProvider();
            configurationManager.TimeProvider = timeProvider;

            var configuration = configurationManager.GetConfigurationSync(CancellationToken.None);
            IdentityComparer.AreEqual(configuration, theoryData.ExpectedConfiguration, context);

            // the first call to RequestRefresh will trigger a refresh with ConfigurationManager.RefreshInterval being ignored.
            // Testing RefreshInterval requires a two calls, the second call will trigger a refresh with ConfigurationManager.RefreshInterval being used.
            if (theoryData.RequestRefresh)
            {
                configurationManager.RequestRefresh();

                if (theoryData.WaitForEvent && !blocking)
                    ConfigurationManagerTests.WaitOrFail(resetEvent);

                configuration = configurationManager.GetConfigurationSync(CancellationToken.None);
            }

            configurationManager.RefreshInterval = theoryData.RefreshInterval;
            configurationManager.MetadataAddress = theoryData.UpdatedMetadataAddress;

            timeProvider.Advance(TimeSpan.FromMilliseconds(theoryData.SleepTimeInMs));

            configurationManager.RequestRefresh();

            if (theoryData.WaitForEvent && !blocking)
                ConfigurationManagerTests.WaitOrFail(resetEvent);

            var updatedConfiguration = configurationManager.GetConfigurationSync(CancellationToken.None);

            IdentityComparer.AreEqual(updatedConfiguration, theoryData.ExpectedUpdatedConfiguration, context);

            TestUtilities.AssertFailIfErrors(context);
        }

        [Theory, MemberData(nameof(CMTests.HttpFailuresTestCases), MemberType = typeof(CMTests), DisableDiscoveryEnumeration = true)]
        public void HttpFailures(ConfigurationManagerTests.ConfigurationManagerTheoryData<OpenIdConnectConfiguration> theoryData)
        {
            var context = new CompareContext($"{this}.HttpFailures");
            ConfigurationManagerSync<OpenIdConnectConfiguration> configurationManager = CreateSyncConfigurationManager(theoryData);

            try
            {
                _ = configurationManager.GetConfigurationSync(CancellationToken.None);
                theoryData.ExpectedException.ProcessNoException(context);
            }
            catch (Exception ex)
            {
                theoryData.ExpectedException.ProcessException(ex, context);
            }

            TestUtilities.AssertFailIfErrors(context);
        }

        private static ConfigurationManagerSync<OpenIdConnectConfiguration> CreateSyncConfigurationManager(
            ConfigurationManagerTests.ConfigurationManagerTheoryData<OpenIdConnectConfiguration> theoryData)
        {
            return new ConfigurationManagerSync<OpenIdConnectConfiguration>(
                theoryData.MetadataAddress,
                theoryData.ConfigurationRetriever is null ? null : new OpenIdConnectConfigurationRetrieverSync(),
                (IDocumentRetrieverSync)theoryData.DocumentRetriever);
        }

        [Fact]
        public void CheckSyncAfter_Blocking()
        {
            AppContext.SetSwitch(AppContextSwitches.UpdateConfigAsBlockingSwitch, true);
            CheckSyncAfterBody(true);
        }

        [Fact]
        public void CheckSyncAfter()
        {
            CheckSyncAfterBody();
        }

        private void CheckSyncAfterBody(bool blocking = false)
        {
            // This test checks that the _syncAfter field is set correctly after a refresh.
            var context = new CompareContext($"{this}.CheckSyncAfterAndRefreshRequested");

            var docRetriever = new FileDocumentRetriever();
            var configManager = new ConfigurationManagerSync<OpenIdConnectConfiguration>(
                "OpenIdConnectMetadata.json",
                new OpenIdConnectConfigurationRetrieverSync(),
                docRetriever);

            AutoResetEvent resetEvent = ConfigurationManagerTests.SetupResetEvent(configManager);

            // This is the minimum time that should pass before an automatic refresh occurs
            // stored in advance to avoid any time drift issues.
            DateTimeOffset minimumRefreshInterval = DateTimeOffset.UtcNow + configManager.AutomaticRefreshInterval;

            // get the first configuration, internal _syncAfter should be set to a time greater than UtcNow + AutomaticRefreshInterval.
            var configuration = configManager.GetConfigurationSync(CancellationToken.None);

            // force a refresh by setting internal field
            TestUtilities.SetField(configManager, "_syncAfter", DateTimeOffset.UtcNow.Subtract(TimeSpan.FromHours(1)));
            configuration = configManager.GetConfigurationSync(CancellationToken.None);

            if (!blocking)
                ConfigurationManagerTests.WaitOrFail(resetEvent);

            // check that _syncAfter is greater than DateTimeOffset.UtcNow + AutomaticRefreshInterval
            DateTimeOffset syncAfter = (DateTimeOffset)TestUtilities.GetField(configManager, "_syncAfter");
            if (syncAfter < minimumRefreshInterval)
                context.Diffs.Add($"(AutomaticRefreshInterval) syncAfter '{syncAfter}' < DateTimeOffset.UtcNow + configManager.AutomaticRefreshInterval: '{minimumRefreshInterval}'.");

            // make same check for RequestRefresh
            // force a refresh by setting internal field
            TestUtilities.SetField(configManager, "_lastRequestRefresh", DateTimeOffset.UtcNow.Subtract(TimeSpan.FromHours(1)));

            configManager.RequestRefresh();

            if (blocking)
            {
                bool refreshRequested = (bool)TestUtilities.GetField(configManager, "_refreshRequested");
                if (!refreshRequested)
                    context.Diffs.Add("Refresh is expected to be requested after RequestRefresh is called");
            }

            configManager.GetConfigurationSync();

            if (blocking)
            {
                bool refreshRequested = (bool)TestUtilities.GetField(configManager, "_refreshRequested");
                if (refreshRequested)
                    context.Diffs.Add("Refresh is expected to be requested after RequestRefresh is called");
            }

            if (!blocking)
                ConfigurationManagerTests.WaitOrFail(resetEvent);

            // check that _syncAfter is greater than DateTimeOffset.UtcNow + AutomaticRefreshInterval
            syncAfter = (DateTimeOffset)TestUtilities.GetField(configManager, "_syncAfter");
            if (syncAfter < minimumRefreshInterval)
                context.Diffs.Add($"(RequestRefresh) syncAfter '{syncAfter}' < DateTimeOffset.UtcNow + configManager.AutomaticRefreshInterval: '{minimumRefreshInterval}'.");

            TestUtilities.AssertFailIfErrors(context);
        }

        [Fact]
        public void GetConfigurationSync()
        {
            GetConfigurationBody();
        }

        [Fact]
        public void GetConfigurationSync_Blocking()
        {
            AppContext.SetSwitch(AppContextSwitches.UpdateConfigAsBlockingSwitch, true);
            GetConfigurationBody();
        }

        private void GetConfigurationBody()
        {
            var context = new CompareContext($"{this}.GetConfiguration");

            var docRetriever = new FileDocumentRetriever();
            var configManager = new ConfigurationManagerSync<OpenIdConnectConfiguration>(
                "OpenIdConnectMetadata.json",
                new OpenIdConnectConfigurationRetrieverSync(),
                docRetriever);

            var configuration = configManager.GetConfigurationSync(CancellationToken.None);

            TestUtilities.SetField(configManager, "_lastRequestRefresh", DateTimeOffset.UtcNow.Subtract(TimeSpan.FromHours(1)));
            configManager.MetadataAddress = "http://127.0.0.1";
            configManager.RequestRefresh();

            // Unable to obtain a new configuration, but _currentConfiguration is not null so it should be returned.
            var configuration2 = configManager.GetConfigurationSync(CancellationToken.None);
            IdentityComparer.AreEqual(configuration, configuration2, context);
            if (!object.ReferenceEquals(configuration, configuration2))
                context.Diffs.Add("!object.ReferenceEquals(configuration, configuration2)");

            TestUtilities.AssertFailIfErrors(context);
        }

        // Test checks to make sure that the LastKnownGood (LKG) Configuration lifetime is properly reset at the time
        // a new LKG is set.
        [Fact]
        public void ResetLastKnownGoodLifetime()
        {
            ResetLastKnownGoodLifetimeBody();
        }

        [Fact]
        public void ResetLastKnownGoodLifetime_Blocking()
        {
            AppContext.SetSwitch(AppContextSwitches.UpdateConfigAsBlockingSwitch, true);
            ResetLastKnownGoodLifetimeBody();
        }

        private void ResetLastKnownGoodLifetimeBody()
        {
            TestUtilities.WriteHeader($"{this}.ResetLastKnownGoodLifetime");
            var context = new CompareContext();

            var validConfig = new OpenIdConnectConfiguration() { TokenEndpoint = Default.Issuer + "oauth/token", Issuer = Default.Issuer };
            var configurationManager = new MockConfigurationManager<OpenIdConnectConfiguration>(validConfig);

            // set and retrieve config in order to set the first access time
            configurationManager.LastKnownGoodConfiguration = validConfig;
            var lkg = configurationManager.LastKnownGoodConfiguration;
            var lkgConfigFirstUseField = typeof(BaseConfigurationManager).GetField("_lastKnownGoodConfigFirstUse", System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Instance);
            var lkgConfigFirstUse1 = lkgConfigFirstUseField.GetValue(configurationManager as BaseConfigurationManager);

            Thread.Sleep(1);

            // set and retrieve config again to reset first access time
            configurationManager.LastKnownGoodConfiguration = validConfig;
            lkg = configurationManager.LastKnownGoodConfiguration;
            var lkgConfigFirstUse2 = lkgConfigFirstUseField.GetValue(configurationManager as BaseConfigurationManager);

            if (lkgConfigFirstUse1 == null)
                context.AddDiff("Last known good first use time was not properly set for the first configuration.");

            if (lkgConfigFirstUse2 == null)
                context.AddDiff("Last known good first use time was not properly set for the second configuration.");

            //LKG config first use was not reset when a new configuration was set
            if (lkgConfigFirstUse1.Equals(lkgConfigFirstUse2))
                context.AddDiff("Last known good first use time was not reset when a new LKG configuration was set.");

            TestUtilities.AssertFailIfErrors(context);
        }

        [Fact]
        public void TestConfigurationComparer()
        {
            TestUtilities.WriteHeader($"{this}.TestConfigurationComparer", "TestConfigurationComparer", true);
            var context = new CompareContext();

            var config = new OpenIdConnectConfiguration() { TokenEndpoint = Default.Issuer + "/oauth/token", Issuer = Default.Issuer };
            config.SigningKeys.Add(KeyingMaterial.DefaultX509Key_2048);
            config.SigningKeys.Add(KeyingMaterial.DefaultRsaSecurityKey1);
            config.SigningKeys.Add(KeyingMaterial.DefaultRsaSecurityKey2);

            var configWithSameKeysDiffOrder = new OpenIdConnectConfiguration() { TokenEndpoint = Default.Issuer + "/oauth/token", Issuer = Default.Issuer };
            configWithSameKeysDiffOrder.SigningKeys.Add(KeyingMaterial.DefaultRsaSecurityKey1);
            configWithSameKeysDiffOrder.SigningKeys.Add(KeyingMaterial.DefaultX509Key_2048);
            configWithSameKeysDiffOrder.SigningKeys.Add(KeyingMaterial.DefaultRsaSecurityKey2);

            var configWithOverlappingKey = new OpenIdConnectConfiguration() { TokenEndpoint = Default.Issuer + "/oauth/token", Issuer = Default.Issuer };
            configWithOverlappingKey.SigningKeys.Add(Default.SymmetricSigningKey256);

            var configWithOverlappingKeyDiffissuer = new OpenIdConnectConfiguration() { TokenEndpoint = Default.Issuer + "/oauth/token", Issuer = Default.Issuer + "1" };
            configWithOverlappingKeyDiffissuer.SigningKeys.Add(Default.SymmetricSigningKey256);

            var configWithSameKidDiffKeyMaterial = new OpenIdConnectConfiguration() { TokenEndpoint = Default.Issuer + "/oauth/token", Issuer = Default.Issuer };
            configWithSameKidDiffKeyMaterial.SigningKeys.Add(new SymmetricSecurityKey(KeyingMaterial.DefaultSymmetricSecurityKey_128.Key) { KeyId = KeyingMaterial.DefaultSymmetricSecurityKey_256.KeyId });

            var configurationManager = new MockConfigurationManager<OpenIdConnectConfiguration>(config, config);
            IdentityComparer.AreEqual(configurationManager.GetValidLkgConfigurations().Length, 1, context);

            configurationManager.LastKnownGoodConfiguration = configWithSameKeysDiffOrder;
            IdentityComparer.AreEqual(configurationManager.GetValidLkgConfigurations().Length, 1, context);

            configurationManager.LastKnownGoodConfiguration = configWithOverlappingKey;
            IdentityComparer.AreEqual(configurationManager.GetValidLkgConfigurations().Length, 2, context);

            configurationManager.LastKnownGoodConfiguration = configWithOverlappingKeyDiffissuer;
            IdentityComparer.AreEqual(configurationManager.GetValidLkgConfigurations().Length, 3, context);

            configurationManager.LastKnownGoodConfiguration = configWithSameKidDiffKeyMaterial;
            IdentityComparer.AreEqual(configurationManager.GetValidLkgConfigurations().Length, 4, context);

            TestUtilities.AssertFailIfErrors(context);
        }

        [Theory, MemberData(nameof(CMTests.ValidateOpenIdConnectConfigurationTestCases), MemberType = typeof(CMTests), DisableDiscoveryEnumeration = true)]
        public void ValidateOpenIdConnectConfigurationTests_Blocking(ConfigurationManagerTests.ConfigurationManagerTheoryData<OpenIdConnectConfiguration> theoryData)
        {
            AppContext.SetSwitch(AppContextSwitches.UpdateConfigAsBlockingSwitch, true);
            ValidateOIDCConfigurationBody(theoryData, true);
        }

        [Theory, MemberData(nameof(CMTests.ValidateOpenIdConnectConfigurationTestCases), MemberType = typeof(CMTests), DisableDiscoveryEnumeration = true)]
        public void ValidateOpenIdConnectConfigurationTests(ConfigurationManagerTests.ConfigurationManagerTheoryData<OpenIdConnectConfiguration> theoryData)
        {
            ValidateOIDCConfigurationBody(theoryData);
        }

        private void ValidateOIDCConfigurationBody(ConfigurationManagerTests.ConfigurationManagerTheoryData<OpenIdConnectConfiguration> theoryData, bool blocking = false)
        {
            TestUtilities.WriteHeader($"{this}.ValidateOpenIdConnectConfigurationTests");
            var context = new CompareContext();
            OpenIdConnectConfiguration configuration;
            var configurationManager = new ConfigurationManagerSync<OpenIdConnectConfiguration>(
                theoryData.MetadataAddress,
                theoryData.ConfigurationRetriever is null ? null : new OpenIdConnectConfigurationRetrieverSync(),
                (IDocumentRetrieverSync)theoryData.DocumentRetriever,
                theoryData.ConfigurationValidator);

            var resetEvent = ConfigurationManagerTests.SetupResetEvent(configurationManager);

            if (theoryData.PresetCurrentConfiguration)
                TestUtilities.SetField(configurationManager, "_currentConfiguration", new OpenIdConnectConfiguration() { Issuer = Default.Issuer });

            try
            {
                //create a listener and enable it for logs
                using var listener = TestUtils.SampleListener.CreateLoggerListener(EventLevel.Warning);

                configuration = configurationManager.GetConfigurationSync();

                if (!blocking && theoryData.ExpectedException is null && string.IsNullOrEmpty(theoryData.ExpectedErrorMessage))
                    ConfigurationManagerTests.WaitOrFail(resetEvent);

                // Need to wait for the events on the listener to be processed.
                if (!string.IsNullOrEmpty(theoryData.ExpectedErrorMessage))
                {
                    _ = PollForCondition(
                        () => listener.TraceBuffer.Contains(theoryData.ExpectedErrorMessage),
                        TimeSpan.FromMilliseconds(100),
                        TimeSpan.FromSeconds(10));
                }

                if (!string.IsNullOrEmpty(theoryData.ExpectedErrorMessage) && !listener.TraceBuffer.Contains(theoryData.ExpectedErrorMessage))
                    context.AddDiff($"Expected exception to contain: '{theoryData.ExpectedErrorMessage}'.{Environment.NewLine}Log is:{Environment.NewLine}'{listener.TraceBuffer}'");

                theoryData.ExpectedException.ProcessNoException(context);
            }
            catch (Exception ex)
            {
                // this should throw, because last configuration retrieved was null
                Assert.Throws<InvalidOperationException>(() => configuration = configurationManager.GetConfigurationSync());

                theoryData.ExpectedException.ProcessException(ex, context);
            }

            TestUtilities.AssertFailIfErrors(context);
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

        private static InMemoryDocumentRetriever InMemoryDocumentRetrieverWithEvents(ManualResetEvent waitEvent, ManualResetEvent signalEvent)
        {
            return new InMemoryDocumentRetriever(
                new Dictionary<string, string>
                {
                    { "AADCommonV1Json", OpenIdConfigData.AADCommonV1Json },
                    { "https://login.microsoftonline.com/common/discovery/keys", OpenIdConfigData.AADCommonV1JwksString },
                    { "AADCommonV2Json", OpenIdConfigData.AADCommonV2Json },
                    { "https://login.microsoftonline.com/common/discovery/v2.0/keys", OpenIdConfigData.AADCommonV2JwksString }
                },
                waitEvent,
                signalEvent);
        }
    }
}

#endif // NET5_0_OR_GREATER
