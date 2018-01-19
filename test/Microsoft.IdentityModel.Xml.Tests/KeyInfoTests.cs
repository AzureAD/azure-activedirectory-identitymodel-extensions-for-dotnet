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
using Microsoft.IdentityModel.Tests;
using Xunit;

namespace Microsoft.IdentityModel.Xml.Tests
{
    public class KeyInfoTests
    {
        [Fact]
        public void GetSets()
        {
            var type = typeof(KeyInfo);
            var properties = type.GetProperties();
            Assert.True(properties.Length == 6, $"Number of properties has changed from 6 to: {properties.Length}, adjust tests");

            var keyInfo = new KeyInfo();
            var context = new GetSetContext
            {
                PropertyNamesAndSetGetValue = new List<KeyValuePair<string, List<object>>>
                {
                    new KeyValuePair<string, List<object>>("Id", new List<object>{(string)null, Guid.NewGuid().ToString()}),
                    new KeyValuePair<string, List<object>>("Prefix", new List<object>{"", Guid.NewGuid().ToString()}),
                    new KeyValuePair<string, List<object>>("RetrievalMethodUri", new List<object>{(string)null, Guid.NewGuid().ToString()}),
                    new KeyValuePair<string, List<object>>("RSAKeyValue", new List<object>{(RSAKeyValue)null, new RSAKeyValue(Guid.NewGuid().ToString(), Guid.NewGuid().ToString())}),
                    new KeyValuePair<string, List<object>>("X509Data", new List<object>{keyInfo.X509Data, new List<X509Data>()}),
                    new KeyValuePair<string, List<object>>("KeyName", new List<object>{(string)null, Guid.NewGuid().ToString()}),

                },
                Object = keyInfo
            };

            TestUtilities.GetSet(context);
            TestUtilities.AssertFailIfErrors($"{this}.GetSets", context.Errors);
        }
    }

    public class KeyInfoTheoryData : TheoryDataBase
    {
        public DSigSerializer Serializer
        {
            get;
            set;
        } = new DSigSerializer();

        public KeyInfo KeyInfo
        {
            get;
            set;
        }

        public string Xml
        {
            get;
            set;
        }
    }
}
