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
using Xunit;

namespace Microsoft.IdentityModel.Tokens.Tests
{
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

            // valid json, JsonWebKey1
            RunJsonWebKeyTest("JsonWebKey_Constructors: 3", DataSets.JsonWebKeyFromPing, DataSets.JsonWebKeyFromPingExpected1, ExpectedException.NoExceptionExpected, false, errors);

            // valid json, JsonWebKey1
            RunJsonWebKeyTest("JsonWebKey_Constructors: 4", DataSets.JsonWebKeyString1, DataSets.JsonWebKeyExpected1, ExpectedException.NoExceptionExpected, false, errors);

            // valid json, JsonWebKey2
            jsonWebKey = RunJsonWebKeyTest("JsonWebKey_Constructors: 6", DataSets.JsonWebKeyString2, DataSets.JsonWebKeyExpected2, ExpectedException.NoExceptionExpected, false, errors);
            CompareContext context = new CompareContext();
            if (IdentityComparer.AreEqual(jsonWebKey, DataSets.JsonWebKeyExpected1, context))
            {
                errors.Add("IdentityComparer.AreEqual(jsonWebKey, DataSets.JsonWebKeyExpected1)");
                errors.AddRange(context.Diffs);
            }

            //invalid json, JsonWebKeyBadFormatString1
            RunJsonWebKeyTest("JsonWebKey_Constructors: 7", DataSets.JsonWebKeyBadFormatString1, null, new ExpectedException(typeExpected: typeof(Newtonsoft.Json.JsonReaderException)), false, errors);

            // invalid json, JsonWebKeyBadFormatString2
            RunJsonWebKeyTest("JsonWebKey_Constructors: 8", DataSets.JsonWebKeyBadFormatString2, null, new ExpectedException(typeExpected: typeof(Newtonsoft.Json.JsonSerializationException), innerTypeExpected: typeof(System.ArgumentException)), false, errors);

            // invalid json, JsonWebKeyBadx509String1
            RunJsonWebKeyTest("JsonWebKey_Constructors: 9", DataSets.JsonWebKeyBadX509String, DataSets.JsonWebKeyExpectedBadX509Data, ExpectedException.NoExceptionExpected, false, errors);

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
                if (obj is string || asString)
                {
                    jsonWebKey = new JsonWebKey(obj as string);
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
            if (IdentityComparer.AreEqual(jsonWebKey.X5c, methods, context))
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

        [Fact(DisplayName = "RsaSecurityKeyTests: IsSupportedAlgorithm")]
        public void IsSupportedAlgorithm()
        {
            Assert.True(KeyingMaterial.JsonWebKeyEcdsa256.IsSupportedAlgorithm(SecurityAlgorithms.EcdsaSha256), "KeyingMaterial.JsonWebKeyEcdsa256.IsSupportedAlgorithm returned false for ecdsasha256");
            Assert.True(!KeyingMaterial.JsonWebKeyEcdsa256.IsSupportedAlgorithm(SecurityAlgorithms.RsaSha256Signature), "KeyingMaterial.JsonWebKeyEcdsa256.IsSupportedAlgorithm returned true for rsasha256");
            Assert.True(KeyingMaterial.JsonWebKeyRsa256.IsSupportedAlgorithm(SecurityAlgorithms.RsaSha256), "KeyingMaterial.JsonWebKeyRsa256.IsSupportedAlgorithm returned false for rsasha256");
            Assert.True(!KeyingMaterial.JsonWebKeyRsa256.IsSupportedAlgorithm(SecurityAlgorithms.EcdsaSha256), "KeyingMaterial.JsonWebKeyRsa256.IsSupportedAlgorithm returned true for ecdsasha256");
            Assert.True(KeyingMaterial.JsonWebKeySymmetric256.IsSupportedAlgorithm(SecurityAlgorithms.HmacSha256), "KeyingMaterial.JsonWebKeySymmetric256.IsSupportedAlgorithm returned false for hmacsha256");
            Assert.True(!KeyingMaterial.JsonWebKeySymmetric256.IsSupportedAlgorithm(SecurityAlgorithms.RsaSha256Signature), "KeyingMaterial.JsonWebKeySymmetric256.IsSupportedAlgorithm returned true for RsaSha256Signature");
        }
    }
}
