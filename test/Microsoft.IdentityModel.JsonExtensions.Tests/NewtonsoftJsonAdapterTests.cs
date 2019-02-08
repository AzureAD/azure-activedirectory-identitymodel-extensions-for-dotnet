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

using Microsoft.IdentityModel.TestUtils;
using Microsoft.IdentityModel.Tokens;
using Xunit;

#pragma warning disable CS3016 // Arrays as attribute arguments is not CLS-compliant

namespace Microsoft.IdentityModel.JsonExtensions.Tests
{
    public class NewtonsoftJsonAdapterTests
    {
        [Fact]
        public void TryConvertTests()
        {
            var testContext = new CompareContext();
            IJsonConvertible jsonAdapter = new NewtonsoftJsonAdapter();

            var result = jsonAdapter.TryConvert(TestData.simpleJObject, out Newtonsoft.Json.Linq.JObject output1);
            IdentityComparer.AreBoolsEqual(result, true, testContext);

            result = jsonAdapter.TryConvert(TestData.complexJObject, out Newtonsoft.Json.Linq.JObject output2);
            IdentityComparer.AreBoolsEqual(result, true, testContext);

            result = jsonAdapter.TryConvert(TestData.simplejArray, out Newtonsoft.Json.Linq.JArray output3);
            IdentityComparer.AreBoolsEqual(result, true, testContext);

            result = jsonAdapter.TryConvert(TestData.complexjArray, out Newtonsoft.Json.Linq.JArray output4);
            IdentityComparer.AreBoolsEqual(result, true, testContext);

            result = jsonAdapter.TryConvert(TestData.plainString, out string output5);
            IdentityComparer.AreBoolsEqual(result, true, testContext);

            result = jsonAdapter.TryConvert(TestData.jValueString, out string output6);
            IdentityComparer.AreBoolsEqual(result, true, testContext);

            TestUtilities.AssertFailIfErrors(testContext);
        }
    }

    static class TestData
    {
         public static Microsoft.IdentityModel.Json.Linq.JObject simpleJObject = new Microsoft.IdentityModel.Json.Linq.JObject()
            {
                { "alg", "rsa" },
                { "kid", "123" },
                { "typ", "jwt" }
            };

        public static Microsoft.IdentityModel.Json.Linq.JObject complexJObject = new Microsoft.IdentityModel.Json.Linq.JObject
        {
            { "array_value", new Microsoft.IdentityModel.Json.Linq.JArray("1", 1) },
            { "plain_value", "test" },
            { "nested_object",
                new Microsoft.IdentityModel.Json.Linq.JObject
                {
                    {"nested_plain_value", "test2" }
                }
            }
        };

        public static Microsoft.IdentityModel.Json.Linq.JArray simplejArray = new Microsoft.IdentityModel.Json.Linq.JArray("1", 1, true, "True");

        public static Microsoft.IdentityModel.Json.Linq.JArray complexjArray = new Microsoft.IdentityModel.Json.Linq.JArray("1", new Microsoft.IdentityModel.Json.Linq.JObject( new Microsoft.IdentityModel.Json.Linq.JObject(new Microsoft.IdentityModel.Json.Linq.JProperty("key", "value"))));

        public static string plainString = "test";

        public static Microsoft.IdentityModel.Json.Linq.JValue jValueString = new Microsoft.IdentityModel.Json.Linq.JValue("test");
    }
}
