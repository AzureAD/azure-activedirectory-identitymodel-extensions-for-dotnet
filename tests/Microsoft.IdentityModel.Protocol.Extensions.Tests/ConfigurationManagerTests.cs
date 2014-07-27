//-----------------------------------------------------------------------
// Copyright (c) Microsoft Open Technologies, Inc.
// All Rights Reserved
// Apache License 2.0
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
// 
// http://www.apache.org/licenses/LICENSE-2.0
// 
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//-----------------------------------------------------------------------

using Microsoft.VisualStudio.TestTools.UnitTesting;
using Microsoft.IdentityModel.Protocols;
using System;
using System.Threading;
using System.Reflection;
using System.Collections.Generic;
using System.IdentityModel.Test;

namespace Microsoft.IdentityModel.Test
{
    /// <summary>
    /// 
    /// </summary>
    [TestClass]
    public class ConfigurationManagerTests
    {
        public TestContext TestContext { get; set; }

        [ClassInitialize]
        public static void ClassSetup(TestContext testContext)
        {
        }

        [ClassCleanup]
        public static void ClassCleanup()
        {
        }

        [TestInitialize]
        public void Initialize()
        {
        }

        [TestMethod]
        [TestProperty("TestCaseID", "39792f21-e6cd-4b6a-bebd-fee9b86304d8")]
        [Description("Tests: Constructors")]
        public void ConfigurationManager_Constructors()
        {
        }

        [TestMethod]
        [TestProperty("TestCaseID", "2fa31653-3822-42a5-b87f-2c992df4f75e")]
        [Description("Tests: Defaults")]
        public void ConfigurationManager_Defaults()
        {
        }

        [TestMethod]
        [TestProperty("TestCaseID", "bce22318-a3a8-411f-9c39-84846ec16229")]
        [Description("Tests: GetSets")]
        [DeploymentItem("OpenIdConnectMetadata.json")]
        [DeploymentItem("OpenIdConnectMetadata2.json")]
        [DeploymentItem("JsonWebKeySet.json")]
        public void ConfigurationManager_GetSets()
        {
            ConfigurationManager<OpenIdConnectConfiguration> configManager = new ConfigurationManager<OpenIdConnectConfiguration>("OpenIdConnectMetadata.json");
            Type type = typeof(ConfigurationManager<OpenIdConnectConfiguration>);
            PropertyInfo[] properties = type.GetProperties();
            if (properties.Length != 2)
                Assert.Fail("Number of properties has changed from 2 to: " + properties.Length + ", adjust tests");

            TimeSpan defaultAutomaticRefreshInterval = ConfigurationManager<OpenIdConnectConfiguration>.DefaultAutomaticRefreshInterval;
            TimeSpan defaultRefreshInterval = ConfigurationManager<OpenIdConnectConfiguration>.DefaultRefreshInterval;

            GetSetContext context =
                new GetSetContext
                {
                    PropertyNamesAndSetGetValue = new List<KeyValuePair<string, List<object>>> 
                    { 
                        new KeyValuePair<string, List<object>>("AutomaticRefreshInterval", new List<object>{defaultAutomaticRefreshInterval, TimeSpan.FromHours(1), TimeSpan.FromHours(10)}),
                        new KeyValuePair<string, List<object>>("RefreshInterval", new List<object>{defaultRefreshInterval, TimeSpan.FromHours(1), TimeSpan.FromHours(10)}),
                    },
                    Object = configManager,
                };

            TestUtilities.GetSet(context);
            TestUtilities.AssertFailIfErrors(MethodInfo.GetCurrentMethod().Name, context.Errors);

            TestUtilities.SetGet(configManager, "AutomaticRefreshInterval", TimeSpan.FromMilliseconds(1), ExpectedException.ArgumentOutOfRangeException(substringExpected: "IDX10107:"));
            TestUtilities.SetGet(configManager, "RefreshInterval", TimeSpan.FromMilliseconds(1), ExpectedException.ArgumentOutOfRangeException(substringExpected: "IDX10106:"));
            TestUtilities.SetGet(configManager, "RefreshInterval", Timeout.InfiniteTimeSpan, ExpectedException.ArgumentOutOfRangeException(substringExpected: "IDX10106:"));

            // AutomaticRefreshInterval interval should return same config.
            OpenIdConnectConfiguration configuration = configManager.GetConfigurationAsync().Result;
            TestUtilities.SetField(configManager, "_metadataAddress", "OpenIdConnectMetadata2.json");
            OpenIdConnectConfiguration configuration2 = configManager.GetConfigurationAsync().Result;
            Assert.IsTrue(IdentityComparer.AreEqual<OpenIdConnectConfiguration>(configuration, configuration2));
            Assert.IsTrue(object.ReferenceEquals(configuration, configuration2));

            // AutomaticRefreshInterval should pick up new bits.
            configManager = new ConfigurationManager<OpenIdConnectConfiguration>("OpenIdConnectMetadata.json");
            TestUtilities.SetField(configManager, "_automaticRefreshInterval", TimeSpan.FromMilliseconds(1));
            configuration = configManager.GetConfigurationAsync().Result;
            Thread.Sleep(1);
            TestUtilities.SetField(configManager, "_metadataAddress", "OpenIdConnectMetadata2.json");
            configuration2 = configManager.GetConfigurationAsync().Result;
            Assert.IsFalse(IdentityComparer.AreEqual<OpenIdConnectConfiguration>(configuration, configuration2));
            Assert.IsFalse(object.ReferenceEquals(configuration, configuration2));

            // RefreshInterval is set to MaxValue
            configManager = new ConfigurationManager<OpenIdConnectConfiguration>("OpenIdConnectMetadata.json");
            configuration = configManager.GetConfigurationAsync().Result;
            configManager.RefreshInterval = TimeSpan.MaxValue;
            TestUtilities.SetField(configManager, "_metadataAddress", "OpenIdConnectMetadata2.json");
            configuration2 = configManager.GetConfigurationAsync().Result;
            Assert.IsTrue(IdentityComparer.AreEqual<OpenIdConnectConfiguration>(configuration, configuration2));
            Assert.IsTrue(object.ReferenceEquals(configuration, configuration2));

            // Refresh should have no effect
            configManager = new ConfigurationManager<OpenIdConnectConfiguration>("OpenIdConnectMetadata.json");
            configuration = configManager.GetConfigurationAsync().Result;
            configManager.RefreshInterval = TimeSpan.FromHours(10);
            configManager.RequestRefresh();
            configuration2 = configManager.GetConfigurationAsync().Result;
            Assert.IsTrue(IdentityComparer.AreEqual<OpenIdConnectConfiguration>(configuration, configuration2));
            Assert.IsTrue(object.ReferenceEquals(configuration, configuration2));

            // Refresh should force pickup of new config
            configManager = new ConfigurationManager<OpenIdConnectConfiguration>("OpenIdConnectMetadata.json");
            configuration = configManager.GetConfigurationAsync().Result;
            TestUtilities.SetField(configManager, "_refreshInterval", TimeSpan.FromMilliseconds(1));
            Thread.Sleep(1);
            configManager.RequestRefresh();
            TestUtilities.SetField(configManager, "_metadataAddress", "OpenIdConnectMetadata2.json");
            configuration2 = configManager.GetConfigurationAsync().Result;
            Assert.IsFalse(object.ReferenceEquals(configuration, configuration2));
            Assert.IsFalse(IdentityComparer.AreEqual<OpenIdConnectConfiguration>(configuration, configuration2));

            // Refresh set to MaxValue
            configManager.RefreshInterval = TimeSpan.MaxValue;
            configuration = configManager.GetConfigurationAsync().Result;
            Assert.IsTrue(object.ReferenceEquals(configuration, configuration2));
            Assert.IsTrue(IdentityComparer.AreEqual<OpenIdConnectConfiguration>(configuration, configuration2));
        }

        [TestMethod]
        [TestProperty("TestCaseID", "d8f4af92-e769-45f2-9347-62a1da348a04")]
        [Description("Tests: Publics")]
        public void ConfigurationManager_Publics()
        {
            ConfigurationManager<OpenIdConnectConfiguration> configManager = new ConfigurationManager<OpenIdConnectConfiguration>("OpenIdConnectMetadata.json");
            OpenIdConnectConfiguration config = configManager.GetConfigurationAsync(CancellationToken.None).Result;
        }

        private void RunConfigTest(ConfigurationManager<OpenIdConnectConfiguration> configManager, ExpectedException ee )
        {

        }
    }
}