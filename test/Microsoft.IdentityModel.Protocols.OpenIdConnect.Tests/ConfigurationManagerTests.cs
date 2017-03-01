//------------------------------------------------------------------------------
//
// Copyright (c) Microsoft Corporation.
// All rights reserved.
//
// This code is licensed under the MIT License.
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files(the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and / or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions :
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
// THE SOFTWARE.
//
//------------------------------------------------------------------------------

using System;
using System.Collections.Generic;
using System.Reflection;
using System.Threading;
using Microsoft.IdentityModel.Tokens.Tests;
using Xunit;

namespace Microsoft.IdentityModel.Protocols.OpenIdConnect.Tests
{
    /// <summary>
    /// 
    /// </summary>
    public class ConfigurationManagerTests
    {
        [Fact]
        public void Constructors()
        {
        }

        [Fact]
        public void Defaults()
        {
        }

        [Fact]
        public void GetSets()
        {
            FileDocumentRetriever docRetriever = new FileDocumentRetriever();
            ConfigurationManager<OpenIdConnectConfiguration> configManager = new ConfigurationManager<OpenIdConnectConfiguration>("OpenIdConnectMetadata.json", new OpenIdConnectConfigurationRetriever(), docRetriever);
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
        }

        [Fact]
        public void Publics()
        {
            ConfigurationManager<OpenIdConnectConfiguration> configManager = new ConfigurationManager<OpenIdConnectConfiguration>("OpenIdConnectMetadata.json", new OpenIdConnectConfigurationRetriever(), new FileDocumentRetriever());
            OpenIdConnectConfiguration config = configManager.GetConfigurationAsync(CancellationToken.None).Result;
        }

        [Fact]
        public void GetConfiguration()
        {
            FileDocumentRetriever docRetriever = new FileDocumentRetriever();
            ConfigurationManager<OpenIdConnectConfiguration> configManager = new ConfigurationManager<OpenIdConnectConfiguration>("OpenIdConnectMetadata.json", new OpenIdConnectConfigurationRetriever(), docRetriever);

            // AutomaticRefreshInterval interval should return same config.
            OpenIdConnectConfiguration configuration = configManager.GetConfigurationAsync().Result;
            TestUtilities.SetField(configManager, "_metadataAddress", "OpenIdConnectMetadata2.json");
            OpenIdConnectConfiguration configuration2 = configManager.GetConfigurationAsync().Result;
            Assert.True(IdentityComparer.AreEqual(configuration, configuration2));
            Assert.True(object.ReferenceEquals(configuration, configuration2));

            // AutomaticRefreshInterval should pick up new bits.
            configManager = new ConfigurationManager<OpenIdConnectConfiguration>("OpenIdConnectMetadata.json", new OpenIdConnectConfigurationRetriever(), docRetriever);
            TestUtilities.SetField(configManager, "_automaticRefreshInterval", TimeSpan.FromMilliseconds(1));
            configuration = configManager.GetConfigurationAsync().Result;
            TestUtilities.SetField(configManager, "_lastRefresh", DateTimeOffset.UtcNow - TimeSpan.FromHours(1));
            TestUtilities.SetField(configManager, "_metadataAddress", "OpenIdConnectMetadata2.json");
            configManager.RequestRefresh();
            configuration2 = configManager.GetConfigurationAsync().Result;
            Assert.False(IdentityComparer.AreEqual(configuration, configuration2));
            Assert.False(object.ReferenceEquals(configuration, configuration2));

            // RefreshInterval is set to MaxValue
            configManager = new ConfigurationManager<OpenIdConnectConfiguration>("OpenIdConnectMetadata.json", new OpenIdConnectConfigurationRetriever(), docRetriever);
            configuration = configManager.GetConfigurationAsync().Result;
            configManager.RefreshInterval = TimeSpan.MaxValue;
            TestUtilities.SetField(configManager, "_metadataAddress", "OpenIdConnectMetadata2.json");
            configuration2 = configManager.GetConfigurationAsync().Result;
            Assert.True(IdentityComparer.AreEqual(configuration, configuration2));
            Assert.True(object.ReferenceEquals(configuration, configuration2));

            // Refresh should have no effect
            configManager = new ConfigurationManager<OpenIdConnectConfiguration>("OpenIdConnectMetadata.json", new OpenIdConnectConfigurationRetriever(), docRetriever);
            configuration = configManager.GetConfigurationAsync().Result;
            configManager.RefreshInterval = TimeSpan.FromHours(10);
            configManager.RequestRefresh();
            configuration2 = configManager.GetConfigurationAsync().Result;
            Assert.True(IdentityComparer.AreEqual(configuration, configuration2));
            Assert.True(object.ReferenceEquals(configuration, configuration2));

            // Refresh should force pickup of new config
            configManager = new ConfigurationManager<OpenIdConnectConfiguration>("OpenIdConnectMetadata.json", new OpenIdConnectConfigurationRetriever(), docRetriever);
            configuration = configManager.GetConfigurationAsync().Result;
            TestUtilities.SetField(configManager, "_lastRefresh", DateTimeOffset.UtcNow - TimeSpan.FromHours(1));
            configManager.RequestRefresh();
            TestUtilities.SetField(configManager, "_metadataAddress", "OpenIdConnectMetadata2.json");
            configuration2 = configManager.GetConfigurationAsync().Result;
            Assert.False(object.ReferenceEquals(configuration, configuration2));
            Assert.False(IdentityComparer.AreEqual(configuration, configuration2));

            // Refresh set to MaxValue
            configManager.RefreshInterval = TimeSpan.MaxValue;
            configuration = configManager.GetConfigurationAsync().Result;
            Assert.True(object.ReferenceEquals(configuration, configuration2));
            Assert.True(IdentityComparer.AreEqual(configuration, configuration2));

            // get configuration from http address, should throw
            configManager = new ConfigurationManager<OpenIdConnectConfiguration>("http://someaddress.com", new OpenIdConnectConfigurationRetriever());
            ExpectedException ee = new ExpectedException(typeof(InvalidOperationException), "IDX10803:", typeof(ArgumentException));
            try
            {
                configuration = configManager.GetConfigurationAsync().Result;
                ee.ProcessNoException();
            }
            catch (AggregateException ex)
            {
                // this should throw, because last configuration retrived was null
                Assert.Throws<AggregateException>(() => configuration = configManager.GetConfigurationAsync().Result);

                ex.Handle((x) =>
                {
                    ee.ProcessException(x);
                    return true;
                });
            }
        }
    }
}
