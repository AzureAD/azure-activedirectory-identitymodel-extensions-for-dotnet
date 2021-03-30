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
using System.IO;
using System.Reflection;
using System.Threading;
using Microsoft.IdentityModel.TestUtils;
using Xunit;

#pragma warning disable CS3016 // Arrays as attribute arguments is not CLS-compliant

namespace Microsoft.IdentityModel.Protocols.OpenIdConnect.Tests
{
    /// <summary>
    /// 
    /// </summary>
    public class ConfigurationManagerTests
    {

        [Theory, MemberData(nameof(ConstructorTheoryData))]
        public void OpenIdConnectConstructor(ConfigurationManagerTheoryData<OpenIdConnectConfiguration> theoryData)
        {
            TestUtilities.WriteHeader($"{this}.OpenIdConnectConstructor", theoryData);
            try
            {
                var configurationManager = new ConfigurationManager<OpenIdConnectConfiguration>(theoryData.MetadataAddress, theoryData.ConfigurationRetreiver, theoryData.DocumentRetriever);
                theoryData.ExpectedException.ProcessNoException();
            }
            catch (Exception ex)
            {
                theoryData.ExpectedException.ProcessException(ex);
            }
        }

        public static TheoryData<ConfigurationManagerTheoryData<OpenIdConnectConfiguration>> ConstructorTheoryData
        {
            get
            {
                var theoryData = new TheoryData<ConfigurationManagerTheoryData<OpenIdConnectConfiguration>>();

                theoryData.Add(new ConfigurationManagerTheoryData<OpenIdConnectConfiguration>
                {
                    ConfigurationRetreiver = new OpenIdConnectConfigurationRetriever(),
                    DocumentRetriever = new HttpDocumentRetriever(),
                    ExpectedException = ExpectedException.ArgumentNullException("IDX10000:"),
                    First = true,
                    MetadataAddress = null,
                    TestId = "MetadataAddress: NULL"
                });

                theoryData.Add(new ConfigurationManagerTheoryData<OpenIdConnectConfiguration>
                {
                    ConfigurationRetreiver = null,
                    DocumentRetriever = new HttpDocumentRetriever(),
                    ExpectedException = ExpectedException.ArgumentNullException("IDX10000:"),
                    MetadataAddress = "OpenIdConnectMetadata.json",
                    TestId = "ConfigurationRetreiver: NULL"
                });

                theoryData.Add(new ConfigurationManagerTheoryData<OpenIdConnectConfiguration>
                {
                    ConfigurationRetreiver = new OpenIdConnectConfigurationRetriever(),
                    DocumentRetriever = null,
                    ExpectedException = ExpectedException.ArgumentNullException("IDX10000:"),
                    MetadataAddress = "OpenIdConnectMetadata.json",
                    TestId = "DocumentRetriever: NULL"
                });

                return theoryData;
            }
        }

        [Fact]
        public void Defaults()
        {
            TestUtilities.WriteHeader($"{this}.Defaults", "Defaults", true);

            Assert.Equal(ConfigurationManager<OpenIdConnectConfiguration>.DefaultAutomaticRefreshInterval, new TimeSpan(0, 12, 0, 0));
            Assert.Equal(ConfigurationManager<OpenIdConnectConfiguration>.DefaultRefreshInterval, new TimeSpan(0, 0, 5, 0));
            Assert.Equal(ConfigurationManager<OpenIdConnectConfiguration>.MinimumAutomaticRefreshInterval, new TimeSpan(0, 0, 5, 0));
            Assert.Equal(ConfigurationManager<OpenIdConnectConfiguration>.MinimumRefreshInterval, new TimeSpan(0, 0, 0, 1));
        }

        [Fact]
        public void GetSets()
        {
            TestUtilities.WriteHeader($"{this}.GetSets", "GetSets", true);

            var configManager = new ConfigurationManager<OpenIdConnectConfiguration>("OpenIdConnectMetadata.json", new OpenIdConnectConfigurationRetriever(), new FileDocumentRetriever());
            Type type = typeof(ConfigurationManager<OpenIdConnectConfiguration>);
            PropertyInfo[] properties = type.GetProperties();
            if (properties.Length != 2)
                Assert.True(false, "Number of properties has changed from 2 to: " + properties.Length + ", adjust tests");

            var defaultAutomaticRefreshInterval = ConfigurationManager<OpenIdConnectConfiguration>.DefaultAutomaticRefreshInterval;
            var defaultRefreshInterval = ConfigurationManager<OpenIdConnectConfiguration>.DefaultRefreshInterval;
            var context = new GetSetContext
            {
                PropertyNamesAndSetGetValue = new List<KeyValuePair<string, List<object>>>
                {
                    new KeyValuePair<string, List<object>>("AutomaticRefreshInterval", new List<object>{defaultAutomaticRefreshInterval, TimeSpan.FromHours(1), TimeSpan.FromHours(10)}),
                    new KeyValuePair<string, List<object>>("RefreshInterval", new List<object>{defaultRefreshInterval, TimeSpan.FromHours(1), TimeSpan.FromHours(10)}),
                },
                Object = configManager,
            };

            TestUtilities.GetSet(context);
            TestUtilities.SetGet(configManager, "AutomaticRefreshInterval", TimeSpan.FromMilliseconds(1), ExpectedException.ArgumentOutOfRangeException(substringExpected: "IDX20107:"), context);
            TestUtilities.SetGet(configManager, "RefreshInterval", TimeSpan.FromMilliseconds(1), ExpectedException.ArgumentOutOfRangeException(substringExpected: "IDX20106:"), context);
            TestUtilities.SetGet(configManager, "RefreshInterval", Timeout.InfiniteTimeSpan, ExpectedException.ArgumentOutOfRangeException(substringExpected: "IDX20106:"), context);
            TestUtilities.AssertFailIfErrors("ConfigurationManager_GetSets", context.Errors);
        }

        [Fact]
        public void GetConfiguration()
        {
            var docRetriever = new FileDocumentRetriever();
            var configManager = new ConfigurationManager<OpenIdConnectConfiguration>("OpenIdConnectMetadata.json", new OpenIdConnectConfigurationRetriever(), docRetriever);
            var context = new CompareContext($"{this}.GetConfiguration");

            // AutomaticRefreshInterval interval should return same config.
            var configuration = configManager.GetConfigurationAsync().Result;
            TestUtilities.SetField(configManager, "_metadataAddress", "OpenIdConnectMetadata2.json");
            var configuration2 = configManager.GetConfigurationAsync().Result;
            IdentityComparer.AreEqual(configuration, configuration2, context);
            if (!object.ReferenceEquals(configuration, configuration2))
                context.Diffs.Add("!object.ReferenceEquals(configuration, configuration2)");

            // AutomaticRefreshInterval should pick up new bits.
            configManager = new ConfigurationManager<OpenIdConnectConfiguration>("OpenIdConnectMetadata.json", new OpenIdConnectConfigurationRetriever(), docRetriever);
            TestUtilities.SetField(configManager, "_automaticRefreshInterval", TimeSpan.FromMilliseconds(1));
            configuration = configManager.GetConfigurationAsync().Result;
            TestUtilities.SetField(configManager, "_lastRefresh", DateTimeOffset.UtcNow - TimeSpan.FromHours(1));
            TestUtilities.SetField(configManager, "_metadataAddress", "OpenIdConnectMetadata2.json");
            configManager.RequestRefresh();
            configuration2 = configManager.GetConfigurationAsync().Result;
            if (IdentityComparer.AreEqual(configuration, configuration2))
                context.Diffs.Add("IdentityComparer.AreEqual(configuration, configuration2)");

            if (object.ReferenceEquals(configuration, configuration2))
                context.Diffs.Add("object.ReferenceEquals(configuration, configuration2) (2)");

            // RefreshInterval is set to MaxValue
            configManager = new ConfigurationManager<OpenIdConnectConfiguration>("OpenIdConnectMetadata.json", new OpenIdConnectConfigurationRetriever(), docRetriever);
            configuration = configManager.GetConfigurationAsync().Result;
            configManager.RefreshInterval = TimeSpan.MaxValue;
            TestUtilities.SetField(configManager, "_metadataAddress", "OpenIdConnectMetadata2.json");
            configuration2 = configManager.GetConfigurationAsync().Result;
            IdentityComparer.AreEqual(configuration, configuration2, context);
            if (!object.ReferenceEquals(configuration, configuration2))
                context.Diffs.Add("!object.ReferenceEquals(configuration, configuration2) (3)");

            // Refresh should have no effect
            configManager = new ConfigurationManager<OpenIdConnectConfiguration>("OpenIdConnectMetadata.json", new OpenIdConnectConfigurationRetriever(), docRetriever);
            configuration = configManager.GetConfigurationAsync().Result;
            configManager.RefreshInterval = TimeSpan.FromHours(10);
            configManager.RequestRefresh();
            configuration2 = configManager.GetConfigurationAsync().Result;
            IdentityComparer.AreEqual(configuration, configuration2, context);
            if (!object.ReferenceEquals(configuration, configuration2))
                context.Diffs.Add("!object.ReferenceEquals(configuration, configuration2) (4)");

            // Refresh should force pickup of new config
            configManager = new ConfigurationManager<OpenIdConnectConfiguration>("OpenIdConnectMetadata.json", new OpenIdConnectConfigurationRetriever(), docRetriever);
            configuration = configManager.GetConfigurationAsync().Result;
            TestUtilities.SetField(configManager, "_lastRefresh", DateTimeOffset.UtcNow - TimeSpan.FromHours(1));
            configManager.RequestRefresh();
            TestUtilities.SetField(configManager, "_metadataAddress", "OpenIdConnectMetadata2.json");
            configuration2 = configManager.GetConfigurationAsync().Result;
            if (IdentityComparer.AreEqual(configuration, configuration2))
                context.Diffs.Add("IdentityComparer.AreEqual(configuration, configuration2), should be different");

            if (object.ReferenceEquals(configuration, configuration2))
                context.Diffs.Add("object.ReferenceEquals(configuration, configuration2)");

            // Refresh set to MaxValue
            configManager.RefreshInterval = TimeSpan.MaxValue;
            configuration = configManager.GetConfigurationAsync().Result;
            IdentityComparer.AreEqual(configuration, configuration2, context);
            if (!object.ReferenceEquals(configuration, configuration2))
                context.Diffs.Add("!object.ReferenceEquals(configuration, configuration2)");

            // get configuration from http address, should throw
            configManager = new ConfigurationManager<OpenIdConnectConfiguration>("http://someaddress.com", new OpenIdConnectConfigurationRetriever());
            var ee = new ExpectedException(typeof(InvalidOperationException), "IDX20803:", typeof(ArgumentException));
            try
            {
                configuration = configManager.GetConfigurationAsync().Result;
                ee.ProcessNoException(context);
            }
            catch (AggregateException ex)
            {
                // this should throw, because last configuration retrived was null
                Assert.Throws<AggregateException>(() => configuration = configManager.GetConfigurationAsync().Result);

                ex.Handle((x) =>
                {
                    ee.ProcessException(x, context);
                    return true;
                });
            }

            // get configuration from https address, should throw
            configManager = new ConfigurationManager<OpenIdConnectConfiguration>("https://someaddress.com", new OpenIdConnectConfigurationRetriever());
            ee = new ExpectedException(typeof(InvalidOperationException), "IDX20803:", typeof(IOException));
            try
            {
                configuration = configManager.GetConfigurationAsync().Result;
                ee.ProcessNoException(context);
            }
            catch (AggregateException ex)
            {
                // this should throw, because last configuration retrived was null
                Assert.Throws<AggregateException>(() => configuration = configManager.GetConfigurationAsync().Result);

                ex.Handle((x) =>
                {
                    ee.ProcessException(x, context);
                    return true;
                });
            }

            // get configuration with unsuccessful HTTP response status code
            configManager = new ConfigurationManager<OpenIdConnectConfiguration>("https://httpstat.us/429", new OpenIdConnectConfigurationRetriever());
            ee = new ExpectedException(typeof(InvalidOperationException), "IDX20803:", typeof(IOException));
            try
            {
                configuration = configManager.GetConfigurationAsync().Result;
                ee.ProcessNoException(context);
            }
            catch (AggregateException ex)
            {
                // this should throw, because last configuration retrived was null
                Assert.Throws<AggregateException>(() => configuration = configManager.GetConfigurationAsync().Result);

                ex.Handle((x) =>
                {
                    ee.ProcessException(x, context);
                    return true;
                });
            }

            // Unable to obtain a new configuration, but _currentConfiguration is not null so it should be returned.
            configManager = new ConfigurationManager<OpenIdConnectConfiguration>("OpenIdConnectMetadata.json", new OpenIdConnectConfigurationRetriever(), docRetriever);
            configuration = configManager.GetConfigurationAsync().Result;
            TestUtilities.SetField(configManager, "_lastRefresh", DateTimeOffset.UtcNow - TimeSpan.FromHours(1));
            configManager.RequestRefresh();
            TestUtilities.SetField(configManager, "_metadataAddress", "http://someaddress.com");
            configuration2 = configManager.GetConfigurationAsync().Result;
            IdentityComparer.AreEqual(configuration, configuration2, context);
            if (!object.ReferenceEquals(configuration, configuration2))
                context.Diffs.Add("!object.ReferenceEquals(configuration, configuration2)");

            TestUtilities.AssertFailIfErrors(context);
        }

        public class ConfigurationManagerTheoryData<T> : TheoryDataBase
        {
            public TimeSpan AutomaticRefreshInterval { get; set; }

            public IConfigurationRetriever<T> ConfigurationRetreiver { get; set; }

            public IDocumentRetriever DocumentRetriever { get; set; }

            public string MetadataAddress { get; set; }

            public TimeSpan RefreshInterval { get; set; }

            public bool RequestRefresh { get; set; }

            public override string ToString()
            {
                return $"{TestId}, {MetadataAddress}, {ExpectedException}";
            }
        }
    }
}

#pragma warning restore CS3016 // Arrays as attribute arguments is not CLS-compliant
