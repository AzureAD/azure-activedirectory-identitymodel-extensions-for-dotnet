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
using Microsoft.IdentityModel.Tokens.Tests;
using Xunit;

namespace Microsoft.IdentityModel.Protocols.Tests
{
    /// <summary>
    /// 
    /// </summary>
    public class HttpDocumentRetrieverTests
    {
        [Fact]
        public void Constructors()
        {
            HttpDocumentRetriever docRetriever = new HttpDocumentRetriever();
            Assert.Throws<ArgumentNullException>(() => new HttpDocumentRetriever(null));
        }

        [Fact]
        public void Defaults()
        {
        }

        [Fact]
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

        [Fact]
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
