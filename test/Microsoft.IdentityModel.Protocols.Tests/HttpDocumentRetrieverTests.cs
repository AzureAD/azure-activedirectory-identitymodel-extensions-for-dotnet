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

using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Tests;
using System.IO;
using System.Reflection;
using System.Threading;
using Xunit;

namespace Microsoft.IdentityModel.Protocols.Tests
{
    /// <summary>
    /// 
    /// </summary>
    public class HttpDocumentRetrieverTests
    {
        [Fact(DisplayName = "HttpDocumentRetrieverTests: Constructors")]
        public void Constructors()
        {
            HttpDocumentRetriever docRetriever = new HttpDocumentRetriever();
            Assert.Throws<ArgumentNullException>(() => new HttpDocumentRetriever(null));
        }

        [Fact(DisplayName = "HttpDocumentRetrieverTests: Defaults")]
        public void Defaults()
        {
        }

        [Fact(DisplayName = "HttpDocumentRetrieverTests: GetSets")]
        public void GetSets()
        {
            HttpDocumentRetriever docRetriever = new HttpDocumentRetriever();
            Type type = typeof(HttpDocumentRetriever);
            PropertyInfo[] properties = type.GetProperties();
            if (properties.Length != 1)
                Assert.True(true, "Number of properties has changed from 1 to: " + properties.Length + ", adjust tests");

            GetSetContext context =
                new GetSetContext
                {
                    PropertyNamesAndSetGetValue = new List<KeyValuePair<string, List<object>>>
                    {
                        new KeyValuePair<string, List<object>>("RequireHttps", new List<object>{true, false, true}),
                    },
                    Object = docRetriever,
                };

            TestUtilities.GetSet(context);
            TestUtilities.AssertFailIfErrors("HttpDocumentRetrieverTests_GetSets", context.Errors);
        }
        private void GetDocument(string address, IDocumentRetriever docRetriever, ExpectedException ee)
        {
            try
            {
                string doc = docRetriever.GetDocumentAsync(address, CancellationToken.None).Result;
                ee.ProcessNoException();
            }
            catch (AggregateException ex)
            {
                ex.Handle((x) =>
                {
                    ee.ProcessException(x);
                    return true;
                });
            }
        }

        [Fact(DisplayName = "HttpDocumentRetrieverTests: Publics")]
        public void Publics()
        {
            HttpDocumentRetriever docRetriever = new HttpDocumentRetriever();
            GetDocument(null, docRetriever, ExpectedException.ArgumentNullException());
            GetDocument("OpenIdConnectMetadata.json", docRetriever, new ExpectedException(typeof(ArgumentException), "IDX10108:"));
            GetDocument("httpss://OpenIdConnectMetadata.json", docRetriever, new ExpectedException(typeof(ArgumentException), "IDX10108:"));
            GetDocument("HTTPS://login.windows.net/common/.well-known/openid-configuration", docRetriever, ExpectedException.NoExceptionExpected);
            GetDocument("https://login.windows.net/common/.well-known/openid-configuration", docRetriever, ExpectedException.NoExceptionExpected);
            docRetriever.RequireHttps = false;
            GetDocument("OpenIdConnectMetadata.json", docRetriever, new ExpectedException(typeof(IOException), "IDX10804:", typeof(InvalidOperationException)));
        }
    }
}