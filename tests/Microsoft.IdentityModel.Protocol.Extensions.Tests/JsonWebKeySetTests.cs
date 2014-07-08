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
using System.Collections.Generic;
using System.Globalization;
using System.IdentityModel.Test;
using System.IdentityModel.Tokens;
using System.IO;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace Microsoft.IdentityModel.Test
{
    /// <summary>
    /// 
    /// </summary>
    [TestClass]
    public class JsonWebKeySetTests
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
        [TestProperty("TestCaseID", "6dc1a5b5-d458-44ba-aa29-50ada648d191")]
        [Description("Tests: Constructors")]
        public void JsonWebKeySet_Constructors()
        {
            JsonWebKeySet jsonWebKeys = new JsonWebKeySet();
            Assert.IsTrue(IsDefaultJsonWebKeySet(jsonWebKeys));

            // null string, nothing to add
            RunJsonWebKeySetTest((string)null, null, ExpectedException.ArgumentNullException());

            // null dictionary, nothing to add
            RunJsonWebKeySetTest((IDictionary<string, object>)null, null, ExpectedException.ArgumentNullException(), false);

            RunJsonWebKeySetTest(OpenIdConfigData.JsonWebKeySetString1,  OpenIdConfigData.JsonWebKeySetExpected1, ExpectedException.NoExceptionExpected);
            RunJsonWebKeySetTest(OpenIdConfigData.JsonWebKeySetBadFormatingString, null, ExpectedException.ArgumentException());
        }

        [TestMethod]
        [TestProperty("TestCaseID", "C6A4AFA6-25A2-44F4-A8FB-83BBEC4DB9A1")]
        [Description("Tests: Interop")]
        [DeploymentItem("google-certs.json")]
        public void JsonWebKeySet_Interop()
        {
            string certsData = File.ReadAllText(OpenIdConfigData.GoogleCertsFile);
            RunJsonWebKeySetTest(certsData, OpenIdConfigData.GoogleCertsExpected, ExpectedException.NoExceptionExpected);

            GetSigningTokens(OpenIdConfigData.JsonWebKeySetBadRsaExponentString, null, ExpectedException.InvalidOperationException(substringExpected: "IDX10801:", inner: typeof(FormatException)));
            GetSigningTokens(OpenIdConfigData.JsonWebKeySetBadRsaModulusString, null, ExpectedException.InvalidOperationException(substringExpected: "IDX10801:", inner: typeof(FormatException)));
            GetSigningTokens(OpenIdConfigData.JsonWebKeySetKtyNotRsaString, null, ExpectedException.NoExceptionExpected);
            GetSigningTokens(OpenIdConfigData.JsonWebKeySetUseNotSigString, null, ExpectedException.NoExceptionExpected);
            GetSigningTokens(OpenIdConfigData.JsonWebKeySetBadX509String, null, ExpectedException.InvalidOperationException(substringExpected: "IDX10802:", inner: typeof(FormatException)));
        }

        private void GetSigningTokens(string webKeySetString, List<SecurityToken> expectedTokens, ExpectedException expectedException)
        {

            JsonWebKeySet webKeySet = new JsonWebKeySet(webKeySetString);
            try
            {
                IList<SecurityToken> tokens = webKeySet.GetSigningTokens();
                expectedException.ProcessNoException();
                if (expectedTokens != null)
                {
                    Assert.IsTrue(IdentityComparer.AreEqual<IEnumerable<SecurityToken>>(tokens, expectedTokens));
                }
            }
            catch (Exception ex)
            {
                expectedException.ProcessException(ex);
            }
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="obj"></param>
        /// <param name="compareTo"></param>
        /// <param name="expectedException"></param>
        /// <param name="asString"> this is useful when passing null for parameter 'is' and 'as' don't contain type info.</param>
        /// <returns></returns>
        private JsonWebKeySet RunJsonWebKeySetTest(object obj, JsonWebKeySet compareTo, ExpectedException expectedException, bool asString = true)
        {
            JsonWebKeySet jsonWebKeys = null;
            try
            {
                if (obj is string)
                {
                    jsonWebKeys = new JsonWebKeySet(obj as string);
                }
                else if (obj is IDictionary<string, object>)
                {
                    jsonWebKeys = new JsonWebKeySet(obj as IDictionary<string, object>);
                }
                else
                {
                    if (asString)
                    {
                        jsonWebKeys = new JsonWebKeySet(obj as string);
                    }
                    else
                    {
                        jsonWebKeys = new JsonWebKeySet(obj as IDictionary<string, object>);
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
                Assert.IsTrue(IdentityComparer.AreEqual<JsonWebKeySet>(jsonWebKeys, compareTo, CompareContext.Default), "jsonWebKeys created from: " + (obj == null ? "NULL" : obj.ToString() + " did not match expected."));
            }

            return jsonWebKeys;
        }

        [TestMethod]
        [TestProperty("TestCaseID", "ae4aac50-6410-49c3-8cd1-92d81681e8b9")]
        [Description("Tests: Defaults")]
        public void JsonWebKeySet_Defaults()
        {
        }

        [TestMethod]
        [TestProperty("TestCaseID", "bffd5933-f161-4fb1-aaae-bb6ad8787972")]
        [Description("Tests: GetSets")]
        public void JsonWebKeySet_GetSets()
        {
        }

        [TestMethod]
        [TestProperty("TestCaseID", "c8d70600-a3ac-4c88-bd9d-2140481d4cf7")]
        [Description("Tests: Publics")]
        public void JsonWebKeySet_Publics()
        {
        }

        private bool IsDefaultJsonWebKeySet(JsonWebKeySet jsonWebKeys)
        {
            if (jsonWebKeys.Keys == null)
                return false;

            if (jsonWebKeys.Keys.Count != 0)
                return false;

            return true;
        }
    }
}