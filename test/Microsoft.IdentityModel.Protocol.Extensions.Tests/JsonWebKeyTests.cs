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
using Xunit;

namespace Microsoft.IdentityModel.Test
{
    /// <summary>
    /// 
    /// </summary>
    public class JsonWebKeyTests
    {
        [Fact(DisplayName = "JsonWebKeyTests: Constructors")]
        public void Constructors()
        {
            JsonWebKey jsonWebKey = new JsonWebKey();
            Assert.True(IsDefaultJsonWebKey(jsonWebKey));

            List<string> errors = new List<string>();
            // null string, nothing to add
            RunJsonWebKeyTest("JsonWebKey_Constructors: 1", null, null, ExpectedException.ArgumentNullException(substringExpected: "json"), true, errors);

            // null dictionary, nothing to add
            RunJsonWebKeyTest("JsonWebKey_Constructors: 2", null, null, ExpectedException.ArgumentNullException(substringExpected: "dictionary"), false, errors);

            // valid json, JsonWebKey1
            RunJsonWebKeyTest("JsonWebKey_Constructors: 3", OpenIdConfigData.JsonWebKeyFromPing, OpenIdConfigData.JsonWebKeyFromPingExpected1, ExpectedException.NoExceptionExpected, false, errors);

            // valid json, JsonWebKey1
            RunJsonWebKeyTest("JsonWebKey_Constructors: 4", OpenIdConfigData.JsonWebKeyString1, OpenIdConfigData.JsonWebKeyExpected1, ExpectedException.NoExceptionExpected, false, errors);

            // valid dictionary, JsonWebKey1
            RunJsonWebKeyTest("JsonWebKey_Constructors: 5", OpenIdConfigData.JsonWebKeyDictionary1, OpenIdConfigData.JsonWebKeyExpected1, ExpectedException.NoExceptionExpected, false, errors);

            // valid json, JsonWebKey2
            jsonWebKey = RunJsonWebKeyTest("JsonWebKey_Constructors: 6", OpenIdConfigData.JsonWebKeyString2, OpenIdConfigData.JsonWebKeyExpected2, ExpectedException.NoExceptionExpected, false, errors);
            CompareContext context = new CompareContext();
            if (IdentityComparer.AreEqual(jsonWebKey, OpenIdConfigData.JsonWebKeyExpected1, context))
            {
                errors.Add("IdentityComparer.AreEqual(jsonWebKey, OpenIdConfigData.JsonWebKeyExpected1)");
                errors.AddRange(context.Diffs);
            }

            // invalid json, JsonWebKeyBadFormatString1
            RunJsonWebKeyTest("JsonWebKey_Constructors: 7", OpenIdConfigData.JsonWebKeyBadFormatString1, null, new ExpectedException(typeExpected: typeof(Newtonsoft.Json.JsonReaderException)), false, errors);

            // invalid json, JsonWebKeyBadFormatString2
            RunJsonWebKeyTest("JsonWebKey_Constructors: 8", OpenIdConfigData.JsonWebKeyBadFormatString2, null, new ExpectedException(typeExpected: typeof(Newtonsoft.Json.JsonSerializationException), innerTypeExpected: typeof(ArgumentException)), false, errors);

            // invalid json, JsonWebKeyBadx509String1
            RunJsonWebKeyTest("JsonWebKey_Constructors: 9", OpenIdConfigData.JsonWebKeyBadX509String, OpenIdConfigData.JsonWebKeyExpectedBadX509Data, ExpectedException.NoExceptionExpected, false, errors);

            TestUtilities.AssertFailIfErrors("JsonWebKey_Constructors", errors);
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="obj"></param>
        /// <param name="compareTo"></param>
        /// <param name="expectedException"></param>
        /// <param name="asString"> this is useful when passing null for parameter 'is' and 'as' don't contain type info.</param>
        /// <returns></returns>
        private JsonWebKey RunJsonWebKeyTest(string testId, object obj, JsonWebKey compareTo, ExpectedException expectedException, bool asString, List<string> errors)
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
                expectedException.ProcessNoException(errors);
            }
            catch (Exception ex)
            {
                expectedException.ProcessException(ex, errors);
            }

            if (compareTo != null)
            {
                CompareContext context = new CompareContext();
                if (!IdentityComparer.AreEqual(jsonWebKey, compareTo, context))
                {
                    errors.Add(testId + "\n!IdentityComparer.AreEqual(jsonWebKey, compareTo, context)\n" + jsonWebKey.ToString() + "\n" + compareTo.ToString() + "\n");
                    errors.AddRange(context.Diffs);
                    errors.Add("\n");
                }
            }

            return jsonWebKey;
        }

        [Fact(DisplayName = "JsonWebKeyTests: Defaults")]
        public void Defaults()
        {
        }

        [Fact(DisplayName = "JsonWebKeyTests: GetSets")]
        public void GetSets()
        {
            JsonWebKey jsonWebKey = new JsonWebKey();
            TestUtilities.CallAllPublicInstanceAndStaticPropertyGets(jsonWebKey, "JsonWebKey_GetSets");
            List<string> methods = new List<string>{"Alg", "Kid", "Kty", "X5t", "X5u", "Use"};
            List<string> errors = new List<string>();
            foreach(string method in methods)
            {
                TestUtilities.GetSet(jsonWebKey, method, null, new object[] { Guid.NewGuid().ToString(), null, Guid.NewGuid().ToString()}, errors);
                jsonWebKey.X5c.Add(method);
            }

            CompareContext context = new CompareContext();
            if (IdentityComparer.AreEqual<IEnumerable<string>>(jsonWebKey.X5c, methods, context))
            {
                errors.AddRange(context.Diffs);
            }

            TestUtilities.AssertFailIfErrors("JsonWebKey_GetSets", errors);
        }

        [Fact(DisplayName = "JsonWebKeyTests: Publics")]
        public void Publics()
        {
        }

        private bool IsDefaultJsonWebKey(JsonWebKey jsonWebKey)
        {
            if (jsonWebKey.Alg != null)
                return false;

            if (jsonWebKey.KeyOps.Count != 0)
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