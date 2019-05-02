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
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Microsoft.IdentityModel.TestUtils;
using Newtonsoft.Json;
using Xunit;

#pragma warning disable CS3016 // Arrays as attribute arguments is not CLS-compliant

namespace Microsoft.IdentityModel.Tokens.Tests
{
    public class JsonWebKeySetTests
    {
        private static readonly JsonSerializerSettings _jsonSerializerSettingsForRegressionTest = new JsonSerializerSettings
        {
            ObjectCreationHandling = ObjectCreationHandling.Replace,
        };

        [Theory, MemberData(nameof(JsonWebKeySetDataSet))]
        public void Constructors(
            string json,
            JsonWebKeySet compareTo,
            JsonSerializerSettings settings,
            ExpectedException ee)
        {
            var context = new CompareContext();
            try
            {
#pragma warning disable CS0618 // Type or member is obsolete
                var jsonWebKeys = new JsonWebKeySet(json, settings);
#pragma warning restore CS0618 // Type or member is obsolete
                var keys = jsonWebKeys.GetSigningKeys();
                ee.ProcessNoException(context);
                if (compareTo != null)
                    IdentityComparer.AreEqual(jsonWebKeys, compareTo, context);

            }
            catch (Exception ex)
            {
                ee.ProcessException(ex, context.Diffs);
            }

            TestUtilities.AssertFailIfErrors(context);
        }

        public static TheoryData<string, JsonWebKeySet, JsonSerializerSettings, ExpectedException> JsonWebKeySetDataSet
        {
            get
            {
                var dataset = new TheoryData<string, JsonWebKeySet, JsonSerializerSettings, ExpectedException>();

                foreach (var setting in new[] { _jsonSerializerSettingsForRegressionTest, null })
                {
                    dataset.Add(DataSets.JsonWebKeySetAdditionalDataString1, DataSets.JsonWebKeySetAdditionalData1, setting, ExpectedException.NoExceptionExpected);
                    dataset.Add(null, null, setting, ExpectedException.ArgumentNullException());
                    dataset.Add(DataSets.JsonWebKeySetString1, DataSets.JsonWebKeySet1, setting, ExpectedException.NoExceptionExpected);
                    dataset.Add(DataSets.JsonWebKeySetBadFormatingString, null, setting, ExpectedException.ArgumentException(substringExpected: "IDX10805:", inner: typeof(JsonReaderException)));
                    dataset.Add(File.ReadAllText(DataSets.GoogleCertsFile), DataSets.GoogleCertsExpected, setting, ExpectedException.NoExceptionExpected);
                    dataset.Add(DataSets.JsonWebKeySetBadRsaExponentString, null, setting, ExpectedException.InvalidOperationException(substringExpected: "IDX10801:", inner: typeof(FormatException)));
                    dataset.Add(DataSets.JsonWebKeySetBadRsaModulusString, null, setting, ExpectedException.InvalidOperationException(substringExpected: "IDX10801:", inner: typeof(FormatException)));
                    dataset.Add(DataSets.JsonWebKeySetKtyNotRsaString, null, setting, ExpectedException.NoExceptionExpected);
                    dataset.Add(DataSets.JsonWebKeySetUseNotSigString, null, setting, ExpectedException.NoExceptionExpected);
                    dataset.Add(DataSets.JsonWebKeySetBadX509String, null, setting, ExpectedException.InvalidOperationException(substringExpected: "IDX10802:", inner: typeof(FormatException)));
                    dataset.Add(DataSets.JsonWebKeySetECCString, DataSets.JsonWebKeySetEC, setting, ExpectedException.NoExceptionExpected);
                    dataset.Add(DataSets.JsonWebKeySetBadECCurveString, null, setting, ExpectedException.InvalidOperationException(substringExpected: "IDX10807:", inner: typeof(CryptographicException)));
                    dataset.Add(DataSets.JsonWebKeySetOnlyX5tString, DataSets.JsonWebKeySetOnlyX5t, setting, ExpectedException.NoExceptionExpected);
                }

                return dataset;
            }
        }

        [Fact]
        public void Defaults()
        {
            var context = new CompareContext();
            JsonWebKeySet jsonWebKeys = new JsonWebKeySet();

            if (jsonWebKeys.Keys == null)
                context.Diffs.Add("jsonWebKeys.Keys == null");
            else if (jsonWebKeys.Keys.Count != 0)
                context.Diffs.Add("jsonWebKeys.Keys.Count != 0");

            if (jsonWebKeys.AdditionalData == null)
                context.Diffs.Add("jsonWebKeys.AdditionalData == null");
            else if (jsonWebKeys.AdditionalData.Count != 0)
                context.Diffs.Add("jsonWebKeys.AdditionalData.Count != 0");

            TestUtilities.AssertFailIfErrors(context);
        }

        [Fact]
        public void GetSets()
        {
        }

        [Fact]
        public void Publics()
        {
        }

        [Theory, MemberData(nameof(GetSigningKeysTheoryData))]
        public void GetSigningKeys(JsonWebKeySetTheoryData theoryData)
        {
            var context = TestUtilities.WriteHeader($"{this}.GetSigningKeys", theoryData);
            try
            {
                JsonWebKeySet.IgnoreInvalidSigningKeys = theoryData.IgnoreInvalidSigningKeys;
                var signingKeys = theoryData.JsonWebKeySet.GetSigningKeys();

                IdentityComparer.AreEqual(signingKeys, theoryData.ExpectedSigningKeys, context);

                theoryData.ExpectedException.ProcessNoException(context);
            }
            catch (Exception ex)
            {
                theoryData.ExpectedException.ProcessException(ex, context);
            }

            // revert to default
            JsonWebKeySet.IgnoreInvalidSigningKeys = false;

            TestUtilities.AssertFailIfErrors(context);
        }

        public static TheoryData<JsonWebKeySetTheoryData> GetSigningKeysTheoryData
        {
            get
            {
                var ecdsaAdapter = new ECDsaAdapter();
                var theoryData = new TheoryData<JsonWebKeySetTheoryData>();

                var jsonWebKeySet = new JsonWebKeySet(DataSets.JsonWebKeySetUseNotSigString);
                theoryData.Add(new JsonWebKeySetTheoryData
                {
                    First = true,
                    JsonWebKeySet = jsonWebKeySet,
                    ExpectedSigningKeys = new List<SecurityKey>(),
                    ExpectedException = ExpectedException.NoExceptionExpected,
                    TestId = "ZeroKeysWithSigAsUse",
                });

                jsonWebKeySet = new JsonWebKeySet(DataSets.JsonWebKeySetUseNoKtyString);
                theoryData.Add(new JsonWebKeySetTheoryData
                {
                    First = true,
                    JsonWebKeySet = jsonWebKeySet,
                    ExpectedSigningKeys = new List<SecurityKey>() { (jsonWebKeySet.Keys as List<JsonWebKey>)[0] },
                    TestId = "KeysWithoutKty",
                });

                jsonWebKeySet = new JsonWebKeySet(DataSets.JsonWebKeySetEvoString);
                theoryData.Add(new JsonWebKeySetTheoryData
                {
                    JsonWebKeySet = jsonWebKeySet,
                    IgnoreInvalidSigningKeys = false,
                    ExpectedSigningKeys = new List<SecurityKey>() { CreateRsaSecurityKey(jsonWebKeySet, 0), CreateX509SecurityKey(jsonWebKeySet, 0) },
                    ExpectedException = ExpectedException.NoExceptionExpected,
                    TestId = "EvoSigningKey",
                });

                jsonWebKeySet = new JsonWebKeySet(DataSets.JsonWebKeySetKtyNotRsaString);
                theoryData.Add(new JsonWebKeySetTheoryData
                {
                    JsonWebKeySet = jsonWebKeySet,
                    IgnoreInvalidSigningKeys = false,
                    ExpectedSigningKeys = new List<SecurityKey>() { (jsonWebKeySet.Keys as List<JsonWebKey>)[0] },
                    ExpectedException = ExpectedException.NoExceptionExpected,
                    TestId = "NonRsaNonEcKey",
                });

                jsonWebKeySet = DataSets.JsonWebKeySetOnlyX5t;
                theoryData.Add(new JsonWebKeySetTheoryData
                {
                    JsonWebKeySet = jsonWebKeySet,
                    ExpectedSigningKeys = new List<SecurityKey>() { (jsonWebKeySet.Keys as List<JsonWebKey>)[0] },
                    ExpectedException = ExpectedException.NoExceptionExpected,
                    TestId = "JsonWebKeyNotInvalidNotResolved"
                });

                jsonWebKeySet = new JsonWebKeySet(DataSets.JsonWebKeySetOneValidRsaOneInvalidRsaString);
                theoryData.Add(new JsonWebKeySetTheoryData
                {
                    JsonWebKeySet = jsonWebKeySet,
                    IgnoreInvalidSigningKeys = false,
                    ExpectedException = ExpectedException.InvalidOperationException(substringExpected: "IDX10801:", inner: typeof(FormatException)),
                    TestId = "OneValidAndOneInvalidRsa",
                });

                jsonWebKeySet = new JsonWebKeySet(DataSets.JsonWebKeySetOneValidRsaOneInvalidRsaString);
                theoryData.Add(new JsonWebKeySetTheoryData
                {
                    JsonWebKeySet = jsonWebKeySet,
                    IgnoreInvalidSigningKeys = true,
                    ExpectedSigningKeys = new List<SecurityKey>() { CreateRsaSecurityKey(jsonWebKeySet, 0) },
                    ExpectedException = ExpectedException.NoExceptionExpected,
                    TestId = "OneValidAndOneInvalidRsaIgnoreInvalid",
                });

                jsonWebKeySet = new JsonWebKeySet(DataSets.JsonWebKeySetOneInvalidEcOneValidEcString);
                theoryData.Add(new JsonWebKeySetTheoryData
                {
                    JsonWebKeySet = jsonWebKeySet,
                    IgnoreInvalidSigningKeys = false,
                    ExpectedException = new ExpectedException(typeof(InvalidOperationException), substringExpected: "IDX10807:", ignoreInnerException: true),
                    TestId = "OneValidAndOneInvalidEc",
                });

                jsonWebKeySet = new JsonWebKeySet(DataSets.JsonWebKeySetOneInvalidEcOneValidEcString);
                theoryData.Add(new JsonWebKeySetTheoryData
                {
                    JsonWebKeySet = jsonWebKeySet,
                    IgnoreInvalidSigningKeys = true,
                    ExpectedSigningKeys = new List<SecurityKey>() { CreateEcdsaSecurityKey(jsonWebKeySet, 1, ecdsaAdapter) },
                    ExpectedException = ExpectedException.NoExceptionExpected,
                    TestId = "OneValidAndOneInvalidECIgnoreInvalid",
                });

                jsonWebKeySet = new JsonWebKeySet(DataSets.JsonWebKeySetOneValidRsaOneInvalidEcString);
                theoryData.Add(new JsonWebKeySetTheoryData
                {
                    JsonWebKeySet = jsonWebKeySet,
                    IgnoreInvalidSigningKeys = false,
                    ExpectedException = new ExpectedException(typeof(InvalidOperationException), substringExpected: "IDX10807:", ignoreInnerException: true),
                    TestId = "ValidRsaInvalidEc",
                });

                jsonWebKeySet = new JsonWebKeySet(DataSets.JsonWebKeySetOneValidRsaOneInvalidEcString);
                theoryData.Add(new JsonWebKeySetTheoryData
                {
                    JsonWebKeySet = jsonWebKeySet,
                    IgnoreInvalidSigningKeys = true,
                    ExpectedSigningKeys = new List<SecurityKey>() { CreateRsaSecurityKey(jsonWebKeySet, 0) },
                    ExpectedException = ExpectedException.NoExceptionExpected,
                    TestId = "ValidRsaInvalidEcIgnoreInvalid",
                });

                jsonWebKeySet = DataSets.JsonWebKeySetX509Data;
                theoryData.Add(new JsonWebKeySetTheoryData
                {
                    JsonWebKeySet = jsonWebKeySet,
                    IgnoreInvalidSigningKeys = false,
                    ExpectedSigningKeys = new List<SecurityKey>() { CreateX509SecurityKey(jsonWebKeySet, 0) },
                    ExpectedException = ExpectedException.NoExceptionExpected,
                    TestId = "ValidX5c",
                });

                jsonWebKeySet = new JsonWebKeySet(DataSets.JsonWebKeySetBadX509String);
                theoryData.Add(new JsonWebKeySetTheoryData
                {
                    JsonWebKeySet = jsonWebKeySet,
                    IgnoreInvalidSigningKeys = false,
                    ExpectedException = ExpectedException.InvalidOperationException(substringExpected: "IDX10802:", inner: typeof(FormatException)),
                    TestId = "InvalidX5c",
                });

                jsonWebKeySet = new JsonWebKeySet(DataSets.JsonWebKeySetBadX509String);
                theoryData.Add(new JsonWebKeySetTheoryData
                {
                    JsonWebKeySet = jsonWebKeySet,
                    IgnoreInvalidSigningKeys = true,
                    ExpectedSigningKeys = new List<SecurityKey>() { CreateRsaSecurityKey(jsonWebKeySet, 0) },
                    ExpectedException = ExpectedException.NoExceptionExpected,
                    TestId = "InvalidX5cIgnoreInvalidAddRsa",
                });

                return theoryData;
            }
        }

        private static X509SecurityKey CreateX509SecurityKey(JsonWebKeySet webKeySet, int keyIndex)
        {
            var webKey = (webKeySet.Keys as List<JsonWebKey>)[keyIndex];

            return new X509SecurityKey(new X509Certificate2(Convert.FromBase64String(webKey.X5c[0])))
            {
                KeyId = webKey.KeyId
            };
        }

        private static RsaSecurityKey CreateRsaSecurityKey(JsonWebKeySet webKeySet, int keyIndex)
        {
            var webKey = (webKeySet.Keys as List<JsonWebKey>)[keyIndex];

            var rsaParams = new RSAParameters()
            {
                Exponent = Base64UrlEncoder.DecodeBytes(webKey.E),
                Modulus = Base64UrlEncoder.DecodeBytes(webKey.N),
            };

            return new RsaSecurityKey(rsaParams)
            {
                KeyId = webKey.KeyId,
            };
        }

        private static ECDsaSecurityKey CreateEcdsaSecurityKey(JsonWebKeySet webKeySet, int keyIndex, ECDsaAdapter ecdsaAdapter)
        {
            var webKey = (webKeySet.Keys as List<JsonWebKey>)[keyIndex];

            return new ECDsaSecurityKey(ecdsaAdapter.CreateECDsa(webKey, false))
            {
                KeyId = webKey.KeyId
            };
        }

        public class JsonWebKeySetTheoryData : TheoryDataBase
        {
            public JsonWebKeySet JsonWebKeySet { get; set; }

            public bool IgnoreInvalidSigningKeys { get; set; } = false;

            public List<SecurityKey> ExpectedSigningKeys { get; set; }
        }
    }
}

#pragma warning restore CS3016 // Arrays as attribute arguments is not CLS-compliant
