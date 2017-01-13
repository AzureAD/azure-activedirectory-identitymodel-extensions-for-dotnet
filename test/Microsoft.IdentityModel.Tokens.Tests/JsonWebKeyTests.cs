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
using System.Security.Cryptography;
using Xunit;

namespace Microsoft.IdentityModel.Tokens.Tests
{
    public class JsonWebKeyTests
    {
#pragma warning disable CS3016 // Arrays as attribute arguments is not CLS-compliant
        [Theory, MemberData("JsonWebKeyDataSet")]
#pragma warning restore CS3016 // Arrays as attribute arguments is not CLS-compliant
        public void Constructors(string json, JsonWebKey compareTo, ExpectedException ee)
        {
            var context = new CompareContext();
            try
            {
                var jsonWebKey = new JsonWebKey(json);
                ee.ProcessNoException(context);
                if (compareTo != null)
                    IdentityComparer.AreEqual(jsonWebKey, compareTo, context);
            }
            catch (Exception ex)
            {
                ee.ProcessException(ex, context.Diffs);
            }

            TestUtilities.AssertFailIfErrors(context);
        }

        public static TheoryData<string, JsonWebKey, ExpectedException> JsonWebKeyDataSet
        {
            get
            {
                var dataset = new TheoryData<string, JsonWebKey, ExpectedException>();

                dataset.Add(null, null, ExpectedException.ArgumentNullException(substringExpected: "json"));
                dataset.Add(DataSets.JsonWebKeyFromPingString1, DataSets.JsonWebKeyFromPing1, ExpectedException.NoExceptionExpected);
                dataset.Add(DataSets.JsonWebKeyString1, DataSets.JsonWebKey1, ExpectedException.NoExceptionExpected);
                dataset.Add(DataSets.JsonWebKeyString2, DataSets.JsonWebKey2, ExpectedException.NoExceptionExpected);
                dataset.Add(DataSets.JsonWebKeyBadFormatString1, null, ExpectedException.ArgumentException(inner: typeof(Newtonsoft.Json.JsonReaderException)));
                dataset.Add(DataSets.JsonWebKeyBadFormatString2, null, ExpectedException.ArgumentException(inner: typeof(Newtonsoft.Json.JsonSerializationException)));
                dataset.Add(DataSets.JsonWebKeyBadX509String, DataSets.JsonWebKeyBadX509Data, ExpectedException.NoExceptionExpected);

                return dataset;
            }
        }

        [Fact]
        public void Defaults()
        {
            var context = new CompareContext();
            JsonWebKey jsonWebKey = new JsonWebKey();

            if (jsonWebKey.Alg != null)
                context.Diffs.Add("jsonWebKey.Alg != null");

            if (jsonWebKey.KeyOps.Count != 0)
                context.Diffs.Add("jsonWebKey.KeyOps.Count != 0");

            if (jsonWebKey.Kid != null)
                context.Diffs.Add("jsonWebKey.Kid != null");

            if (jsonWebKey.Kty != null)
                context.Diffs.Add("jsonWebKey.Kty != null");

            if (jsonWebKey.X5c == null)
                context.Diffs.Add("jsonWebKey.X5c == null");

            if (jsonWebKey.X5c.Count != 0)
                context.Diffs.Add("jsonWebKey.X5c.Count != 0");

            if (jsonWebKey.X5t != null)
                context.Diffs.Add("jsonWebKey.X5t != null");

            if (jsonWebKey.X5u != null)
                context.Diffs.Add("jsonWebKey.X5u != null");

            if (jsonWebKey.Use != null)
                context.Diffs.Add("jsonWebKey.Use != null");

            if (jsonWebKey.AdditionalData == null)
                context.Diffs.Add("jsonWebKey.AdditionalData == null");
            else if (jsonWebKey.AdditionalData.Count != 0)
                context.Diffs.Add("jsonWebKey.AdditionalData.Count != 0");

            TestUtilities.AssertFailIfErrors(context);
        }

        [Fact]
        public void GetSets()
        {
            JsonWebKey jsonWebKey = new JsonWebKey();
            TestUtilities.CallAllPublicInstanceAndStaticPropertyGets(jsonWebKey, "JsonWebKey_GetSets");
            List<string> methods = new List<string> { "Alg", "Kid", "Kty", "X5t", "X5u", "Use" };
            List<string> errors = new List<string>();
            foreach (string method in methods)
            {
                TestUtilities.GetSet(jsonWebKey, method, null, new object[] { Guid.NewGuid().ToString(), null, Guid.NewGuid().ToString() }, errors);
                jsonWebKey.X5c.Add(method);
            }

            CompareContext context = new CompareContext();
            if (IdentityComparer.AreEqual(jsonWebKey.X5c, methods, context))
            {
                errors.AddRange(context.Diffs);
            }

            TestUtilities.AssertFailIfErrors("JsonWebKey_GetSets", errors);
        }

        [Fact]
        public void Publics()
        {
        }

        #pragma warning disable CS3016 // Arrays as attribute arguments is not CLS-compliant
        [Theory, MemberData("IsSupportedAlgDataSet")]
#pragma warning restore CS3016 // Arrays as attribute arguments is not CLS-compliant
        public void IsSupportedAlgorithm(JsonWebKey key, string alg, bool isPrivateKey, bool expectedResult)
        {
            if (key.CryptoProviderFactory.IsSupportedAlgorithm(alg, key) != expectedResult)
                Assert.True(false, string.Format("{0} failed with alg: {1}. ExpectedResult: {2}", key, alg, expectedResult));
        }

        public static TheoryData<JsonWebKey, string, bool, bool> IsSupportedAlgDataSet
        {
            get
            {
                var dataset = new TheoryData<JsonWebKey, string, bool, bool>();
                dataset.Add(KeyingMaterial.JsonWebKeyEcdsa256, SecurityAlgorithms.EcdsaSha256, KeyingMaterial.JsonWebKeyEcdsa256.HasPrivateKey, true);
                dataset.Add(KeyingMaterial.JsonWebKeyEcdsa256, SecurityAlgorithms.RsaSha256Signature, KeyingMaterial.JsonWebKeyEcdsa256.HasPrivateKey, false);
                dataset.Add(KeyingMaterial.JsonWebKeyRsa256, SecurityAlgorithms.RsaSha256, KeyingMaterial.JsonWebKeyRsa256.HasPrivateKey, true);
                dataset.Add(KeyingMaterial.JsonWebKeyRsa256, SecurityAlgorithms.EcdsaSha256, KeyingMaterial.JsonWebKeyRsa256.HasPrivateKey, false);
                dataset.Add(KeyingMaterial.JsonWebKeySymmetric256, SecurityAlgorithms.HmacSha256, false, true);
                dataset.Add(KeyingMaterial.JsonWebKeySymmetric256, SecurityAlgorithms.RsaSha256Signature, false, false);
                JsonWebKey testKey = new JsonWebKey
                {
                    Kty = JsonWebAlgorithmsKeyTypes.Octet,
                    K = "Vbxq2mlbGJw8XH+ZoYBnUHmHga8/o/IduvU/Tht70iE="
                };
                testKey.CryptoProviderFactory = new CustomCryptoProviderFactory(new string[] { SecurityAlgorithms.RsaSha256Signature });
                dataset.Add(testKey, SecurityAlgorithms.RsaSha256Signature, testKey.HasPrivateKey, true);
                return dataset;
            }
        }
    }
}
