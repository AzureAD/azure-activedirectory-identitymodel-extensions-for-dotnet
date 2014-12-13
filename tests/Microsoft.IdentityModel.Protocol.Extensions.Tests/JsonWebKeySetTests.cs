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
using Xunit;
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
    public class JsonWebKeySetTests
    {
        [Fact(DisplayName = "Tests: Constructors")]
        public void JsonWebKeySet_Constructors()
        {
            JsonWebKeySet jsonWebKeys = new JsonWebKeySet();
            Assert.True(IsDefaultJsonWebKeySet(jsonWebKeys));

            // null string, nothing to add
            RunJsonWebKeySetTest((string)null, null, ExpectedException.ArgumentNullException());

            // null dictionary, nothing to add
            RunJsonWebKeySetTest((IDictionary<string, object>)null, null, ExpectedException.ArgumentNullException(), false);

            RunJsonWebKeySetTest(OpenIdConfigData.JsonWebKeySetString1,  OpenIdConfigData.JsonWebKeySetExpected1, ExpectedException.NoExceptionExpected);
            RunJsonWebKeySetTest(OpenIdConfigData.JsonWebKeySetBadFormatingString, null, ExpectedException.ArgumentException());
        }

        [Fact(DisplayName = "Tests: Interop")]
        public void JsonWebKeySet_Interop()
        {
            string certsData = File.ReadAllText(OpenIdConfigData.GoogleCertsFile);
            RunJsonWebKeySetTest(certsData, OpenIdConfigData.GoogleCertsExpected, ExpectedException.NoExceptionExpected);

            GetSigningKeys(OpenIdConfigData.JsonWebKeySetBadRsaExponentString, null, ExpectedException.InvalidOperationException(substringExpected: "IDX10801:", inner: typeof(FormatException)));
            GetSigningKeys(OpenIdConfigData.JsonWebKeySetBadRsaModulusString, null, ExpectedException.InvalidOperationException(substringExpected: "IDX10801:", inner: typeof(FormatException)));
            GetSigningKeys(OpenIdConfigData.JsonWebKeySetKtyNotRsaString, null, ExpectedException.NoExceptionExpected);
            GetSigningKeys(OpenIdConfigData.JsonWebKeySetUseNotSigString, null, ExpectedException.NoExceptionExpected);
            GetSigningKeys(OpenIdConfigData.JsonWebKeySetBadX509String, null, ExpectedException.InvalidOperationException(substringExpected: "IDX10802:", inner: typeof(FormatException)));
        }

        private void GetSigningKeys(string webKeySetString, List<SecurityKey> expectedKeys, ExpectedException expectedException)
        {

            JsonWebKeySet webKeySet = new JsonWebKeySet(webKeySetString);
            try
            {
                IList<SecurityKey> keys = webKeySet.GetSigningKeys();
                expectedException.ProcessNoException();
                if (expectedKeys != null)
                {
                    Assert.True(IdentityComparer.AreEqual<IEnumerable<SecurityKey>>(keys, expectedKeys));
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
                Assert.True(IdentityComparer.AreEqual<JsonWebKeySet>(jsonWebKeys, compareTo, CompareContext.Default), "jsonWebKeys created from: " + (obj == null ? "NULL" : obj.ToString() + " did not match expected."));
            }

            return jsonWebKeys;
        }

        [Fact(DisplayName = "Tests: Defaults")]
        public void JsonWebKeySet_Defaults()
        {
        }

        [Fact(DisplayName = "Tests: GetSets")]
        public void JsonWebKeySet_GetSets()
        {
        }

        [Fact(DisplayName = "Tests: Publics")]
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