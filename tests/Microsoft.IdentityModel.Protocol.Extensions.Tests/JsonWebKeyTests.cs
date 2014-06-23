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
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.Collections;
using System.Collections.Generic;
using System.IdentityModel.Test;

namespace Microsoft.IdentityModel.Test
{
    /// <summary>
    /// 
    /// </summary>
    [TestClass]
    public class JsonWebKeyTests
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
        [TestProperty("TestCaseID", "5c9f0af7-b2cf-4baa-a73a-986574714a64")]
        [Description("Tests: Constructors")]
        public void JsonWebKey_Constructors()
        {
            JsonWebKey jsonWebKey = new JsonWebKey();
            Assert.IsTrue(IsDefaultJsonWebKey(jsonWebKey));
            string str = "hello";
            str = null;

            // null string, nothing to add
            RunJsonWebKeyTest(str, new JsonWebKey(), ExpectedException.NoExceptionExpected);

            // null dictionary, nothing to add
            RunJsonWebKeyTest(null, new JsonWebKey(), ExpectedException.NoExceptionExpected, false);

            // valid json, JsonWebKey1
            RunJsonWebKeyTest(OpenIdConfigData.JsonWebKeyFromPing, OpenIdConfigData.JsonWebKeyFromPingExpected1, ExpectedException.NoExceptionExpected);

            // valid json, JsonWebKey1
            RunJsonWebKeyTest(OpenIdConfigData.JsonWebKeyString1, OpenIdConfigData.JsonWebKeyExpected1, ExpectedException.NoExceptionExpected);

            // valid dictionary, JsonWebKey1
            RunJsonWebKeyTest(OpenIdConfigData.JsonWebKeyDictionary1, OpenIdConfigData.JsonWebKeyExpected1, ExpectedException.NoExceptionExpected);

            // valid json, JsonWebKey2
            jsonWebKey = RunJsonWebKeyTest(OpenIdConfigData.JsonWebKeyString2, OpenIdConfigData.JsonWebKeyExpected2, ExpectedException.NoExceptionExpected);
            Assert.IsTrue(!IdentityComparer.AreEqual(jsonWebKey, OpenIdConfigData.JsonWebKeyExpected1));

            // invalid json, JsonWebKeyBadFormatString1
            RunJsonWebKeyTest(OpenIdConfigData.JsonWebKeyBadFormatString1, null, ExpectedException.ArgumentException());

            // invalid json, JsonWebKeyBadFormatString2
            RunJsonWebKeyTest(OpenIdConfigData.JsonWebKeyBadFormatString2, null, ExpectedException.ArgumentException());

            // invalid json, JsonWebKeyBadx509String1
            RunJsonWebKeyTest(OpenIdConfigData.JsonWebKeyBadX509String, OpenIdConfigData.JsonWebKeyExpectedBadX509Data, ExpectedException.NoExceptionExpected);

        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="obj"></param>
        /// <param name="compareTo"></param>
        /// <param name="expectedException"></param>
        /// <param name="asString"> this is useful when passing null for parameter 'is' and 'as' don't contain type info.</param>
        /// <returns></returns>
        private JsonWebKey RunJsonWebKeyTest(object obj, JsonWebKey compareTo, ExpectedException expectedException, bool asString = true)
        {
            JsonWebKey jsonWebKey = null;
            try
            {
                if (obj is string)
                {
                    jsonWebKey = new JsonWebKey(obj as string);
                }
                else if (obj is IDictionary<string, object>)
                {
                    jsonWebKey = new JsonWebKey(obj as IDictionary<string, object>);
                }
                else
                {
                    if (asString)
                    {
                        jsonWebKey = new JsonWebKey(obj as string);
                    }
                    else
                    {
                        jsonWebKey = new JsonWebKey(obj as IDictionary<string, object>);
                    }
                }
                expectedException.ProcessNoException();
            }
            catch (Exception ex)
            {
                expectedException.ProcessException(ex);
            }

            if (compareTo != null)
            {
                Assert.IsTrue(IdentityComparer.AreEqual(jsonWebKey, compareTo), "jsonWebKey created from: " + ( obj == null ? "NULL" : obj.ToString() + " did not match expected."));
            }

            return jsonWebKey;
        }

        [TestMethod]
        [TestProperty("TestCaseID", "54fa205b-5a50-4d29-9ff0-9c38c397106a")]
        [Description("Tests: Defaults")]
        public void JsonWebKey_Defaults()
        {
        }

        [TestMethod]
        [TestProperty("TestCaseID", "4642e46f-72cd-4ffe-80ea-1006036986a1")]
        [Description("Tests: GetSets")]
        public void JsonWebKey_GetSets()
        {
            JsonWebKey jsonWebKey = new JsonWebKey();
            TestUtilities.CallAllPublicInstanceAndStaticPropertyGets(jsonWebKey, "JsonWebKey_GetSets");
            List<string> methods = new List<string>{"Alg", "KeyOps", "Kid", "Kty", "X5t", "X5u", "Use"};
            foreach(string method in methods)
            {
                TestUtilities.GetSet(jsonWebKey, method, null, new object[] { Guid.NewGuid().ToString(), null, Guid.NewGuid().ToString() });
                jsonWebKey.X5c.Add(method);
            }

            Assert.IsTrue(IdentityComparer.AreEqual<IEnumerable<string>>(jsonWebKey.X5c, methods, CompareContext.Default));
        }

        [TestMethod]
        [TestProperty("TestCaseID", "ee45364b-0792-4fea-8485-e36fc6381319")]
        [Description("Tests: Publics")]
        public void JsonWebKey_Publics()
        {
        }

        private bool IsDefaultJsonWebKey(JsonWebKey jsonWebKey)
        {
            if (jsonWebKey.Alg != null)
                return false;

            if (jsonWebKey.KeyOps != null)
                return false;

            if (jsonWebKey.Kid != null)
                return false;

            if (jsonWebKey.Kty != null)
                return false;

            if (jsonWebKey.X5c == null)
                return false;

            if (jsonWebKey.X5c.Count != 0)
                return false;

            if (jsonWebKey.X5t != null)
                return false;

            if (jsonWebKey.X5u != null)
                return false;

            if (jsonWebKey.Use != null)
                return false;

            return true;
        }
    }
}