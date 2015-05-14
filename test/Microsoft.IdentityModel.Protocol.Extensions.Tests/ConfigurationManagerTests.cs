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

using Microsoft.IdentityModel.Protocols;
using System;
using System.Collections.Generic;
using System.IdentityModel.Test;
using System.Reflection;
using System.Threading;
using Xunit;

namespace Microsoft.IdentityModel.Test
{
    /// <summary>
    /// 
    /// </summary>
    public class ConfigurationManagerTests
    {
        [Fact(DisplayName = "ConfigurationManagerTests: Constructors")]
        public void Constructors()
        {
        }

        [Fact(DisplayName = "ConfigurationManagerTests: Defaults")]
        public void Defaults()
        {
        }

        [Fact(DisplayName = "ConfigurationManagerTests: GetSets")]
        public void GetSets()
        {
            ConfigurationManager<OpenIdConnectConfiguration> configManager = new ConfigurationManager<OpenIdConnectConfiguration>("OpenIdConnectMetadata.json");
            Type type = typeof(ConfigurationManager<OpenIdConnectConfiguration>);
            PropertyInfo[] properties = type.GetProperties();
            if (properties.Length != 2)
                Assert.True(false, "Number of properties has changed from 2 to: " + properties.Length + ", adjust tests");

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
            TestUtilities.AssertFailIfErrors("ConfigurationManager_GetSets", context.Errors);

            TestUtilities.SetGet(configManager, "AutomaticRefreshInterval", TimeSpan.FromMilliseconds(1), ExpectedException.ArgumentOutOfRangeException(substringExpected: "IDX10107:"));
            TestUtilities.SetGet(configManager, "RefreshInterval", TimeSpan.FromMilliseconds(1), ExpectedException.ArgumentOutOfRangeException(substringExpected: "IDX10106:"));
            TestUtilities.SetGet(configManager, "RefreshInterval", Timeout.InfiniteTimeSpan, ExpectedException.ArgumentOutOfRangeException(substringExpected: "IDX10106:"));

            // AutomaticRefreshInterval interval should return same config.
            OpenIdConnectConfiguration configuration = configManager.GetConfigurationAsync().Result;
            TestUtilities.SetField(configManager, "_metadataAddress", "OpenIdConnectMetadata2.json");
            OpenIdConnectConfiguration configuration2 = configManager.GetConfigurationAsync().Result;
            Assert.True(IdentityComparer.AreEqual<OpenIdConnectConfiguration>(configuration, configuration2));
            Assert.True(object.ReferenceEquals(configuration, configuration2));

            // AutomaticRefreshInterval should pick up new bits.
            configManager = new ConfigurationManager<OpenIdConnectConfiguration>("OpenIdConnectMetadata.json");
            TestUtilities.SetField(configManager, "_automaticRefreshInterval", TimeSpan.FromMilliseconds(1));
            configuration = configManager.GetConfigurationAsync().Result;
            Thread.Sleep(1);
            TestUtilities.SetField(configManager, "_metadataAddress", "OpenIdConnectMetadata2.json");
            configuration2 = configManager.GetConfigurationAsync().Result;
            Assert.False(IdentityComparer.AreEqual<OpenIdConnectConfiguration>(configuration, configuration2));
            Assert.False(object.ReferenceEquals(configuration, configuration2));

            // RefreshInterval is set to MaxValue
            configManager = new ConfigurationManager<OpenIdConnectConfiguration>("OpenIdConnectMetadata.json");
            configuration = configManager.GetConfigurationAsync().Result;
            configManager.RefreshInterval = TimeSpan.MaxValue;
            TestUtilities.SetField(configManager, "_metadataAddress", "OpenIdConnectMetadata2.json");
            configuration2 = configManager.GetConfigurationAsync().Result;
            Assert.True(IdentityComparer.AreEqual<OpenIdConnectConfiguration>(configuration, configuration2));
            Assert.True(object.ReferenceEquals(configuration, configuration2));

            // Refresh should have no effect
            configManager = new ConfigurationManager<OpenIdConnectConfiguration>("OpenIdConnectMetadata.json");
            configuration = configManager.GetConfigurationAsync().Result;
            configManager.RefreshInterval = TimeSpan.FromHours(10);
            configManager.RequestRefresh();
            configuration2 = configManager.GetConfigurationAsync().Result;
            Assert.True(IdentityComparer.AreEqual<OpenIdConnectConfiguration>(configuration, configuration2));
            Assert.True(object.ReferenceEquals(configuration, configuration2));

            // Refresh should force pickup of new config
            configManager = new ConfigurationManager<OpenIdConnectConfiguration>("OpenIdConnectMetadata.json");
            configuration = configManager.GetConfigurationAsync().Result;
            TestUtilities.SetField(configManager, "_refreshInterval", TimeSpan.FromMilliseconds(1));
            Thread.Sleep(1);
            configManager.RequestRefresh();
            TestUtilities.SetField(configManager, "_metadataAddress", "OpenIdConnectMetadata2.json");
            configuration2 = configManager.GetConfigurationAsync().Result;
            Assert.False(object.ReferenceEquals(configuration, configuration2));
            Assert.False(IdentityComparer.AreEqual<OpenIdConnectConfiguration>(configuration, configuration2));

            // Refresh set to MaxValue
            configManager.RefreshInterval = TimeSpan.MaxValue;
            configuration = configManager.GetConfigurationAsync().Result;
            Assert.True(object.ReferenceEquals(configuration, configuration2));
            Assert.True(IdentityComparer.AreEqual<OpenIdConnectConfiguration>(configuration, configuration2));
        }

        [Fact(DisplayName = "ConfigurationManagerTests: Publics")]
        public void Publics()
        {
            ConfigurationManager<OpenIdConnectConfiguration> configManager = new ConfigurationManager<OpenIdConnectConfiguration>("OpenIdConnectMetadata.json");
            OpenIdConnectConfiguration config = configManager.GetConfigurationAsync(CancellationToken.None).Result;
        }

        private void RunConfigTest(ConfigurationManager<OpenIdConnectConfiguration> configManager, ExpectedException ee )
        {

        }
    }
}