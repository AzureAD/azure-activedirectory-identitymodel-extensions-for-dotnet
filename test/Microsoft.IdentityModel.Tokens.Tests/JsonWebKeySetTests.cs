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
using System.Linq;
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
                    dataset.Add(DataSets.JsonWebKeySetBadRsaExponentString, null, setting, ExpectedException.NoExceptionExpected);
                    dataset.Add(DataSets.JsonWebKeySetBadRsaModulusString, null, setting, ExpectedException.NoExceptionExpected);
                    dataset.Add(DataSets.JsonWebKeySetKtyNotRsaString, null, setting, ExpectedException.NoExceptionExpected);
                    dataset.Add(DataSets.JsonWebKeySetUseNotSigString, null, setting, ExpectedException.NoExceptionExpected);
                    dataset.Add(DataSets.JsonWebKeySetBadX509String, null, setting, ExpectedException.NoExceptionExpected);
                    dataset.Add(DataSets.JsonWebKeySetECCString, DataSets.JsonWebKeySetEC, setting, ExpectedException.NoExceptionExpected);
                    dataset.Add(DataSets.JsonWebKeySetBadECCurveString, null, setting, ExpectedException.NoExceptionExpected);
                    dataset.Add(DataSets.JsonWebKeySetOnlyX5tString, DataSets.JsonWebKeySetOnlyX5t, setting, ExpectedException.NoExceptionExpected);
                    dataset.Add(DataSets.JsonWebKeySetX509DataString, DataSets.JsonWebKeySetX509Data, setting, ExpectedException.NoExceptionExpected);
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

        [Fact]
        public void SigningKeysExtensibility()
        {
            var context = new CompareContext($"{this}.SigningKeysExtensibility");
            TestUtilities.WriteHeader($"{this}.SigningKeysExtensibility");

            try
            {
                // Received json web key only has an x5t property and it can't be used for signature validation as it can't be resolved into a SecurityKey, without user's custom code.
                // This test proves that the scenario described above is possible using extensibility.
                JsonWebKeySet.DefaultSkipUnresolvedJsonWebKeys = false;
                var signingKeys = new JsonWebKeySet(DataSets.JsonWebKeySetOnlyX5tString).GetSigningKeys();

                var tokenValidationParameters = new TokenValidationParameters()
                {
                    IssuerSigningKeys = signingKeys,
                    IssuerSigningKeyResolver = (token, securityToken, keyIdentifier, tvp) => { return new List<SecurityKey> { ResolveX509Certificate(token, securityToken, keyIdentifier, tvp) }; },
                    ValidateIssuer = false,
                    ValidateAudience = false,
                    ValidateLifetime = false,
                };

                var tokenValidationResult = new JsonWebTokens.JsonWebTokenHandler().ValidateToken(Default.AsymmetricJwt, tokenValidationParameters);

                if (tokenValidationResult.IsValid != true)
                    context.Diffs.Add("tokenValidationResult.IsValid != true");
            }
            catch (Exception ex)
            {
                context.Diffs.Add($"TokenValidationFailed: {ex}");
            }

            finally
            {
                // revert back to default
                JsonWebKeySet.DefaultSkipUnresolvedJsonWebKeys = true;
            }

            TestUtilities.AssertFailIfErrors(context);
        }

        private SecurityKey ResolveX509Certificate(string token, SecurityToken securityToken, string keyIdentifier, TokenValidationParameters tvp)
        {
            // example: get a certificate from a cert store

            if (tvp.IssuerSigningKeys.First() is JsonWebKey jsonWebKey)
            {
                if (!string.IsNullOrEmpty(jsonWebKey.X5t))
                {
                    // X509Store store = new X509Store(StoreLocation.CurrentUser);
                    // store.Open(OpenFlags.ReadOnly);
                    // X509Certificate2Collection certs = store.Certificates.Find(X509FindType.FindByThumbprint, Base64UrlEncoder.Decode(jsonWebKey.X5t), true);
                    // return new X509SecurityKey(certs[0]);

                    return new X509SecurityKey(KeyingMaterial.DefaultCert_2048);
                }
            }

            return null;
        }

        [Theory, MemberData(nameof(GetSigningKeysTheoryData))]
        public void GetSigningKeys(JsonWebKeySetTheoryData theoryData)
        {
            var context = TestUtilities.WriteHeader($"{this}.GetSigningKeys", theoryData);
            try
            {
                if (theoryData.SetEcdsaAdapterToNull)
                    JsonWebKeySet.ECDsaAdapter = null;

                var signingKeys = theoryData.JsonWebKeySet.GetSigningKeys();

                IdentityComparer.AreEqual(signingKeys, theoryData.ExpectedSigningKeys, context);

                theoryData.ExpectedException.ProcessNoException(context);
            }
            catch (Exception ex)
            {
                theoryData.ExpectedException.ProcessException(ex, context);
            }

            // revert to default
            if (theoryData.SetEcdsaAdapterToNull)
            {
                try
                {
                    JsonWebKeySet.ECDsaAdapter = new ECDsaAdapter();
                }
                catch
                {
                    // ECDsaAdapter is not supported by NETSTANDARD1.4, when running on platforms other than Windows
                }
            }

            TestUtilities.AssertFailIfErrors(context);
        }

        public static TheoryData<JsonWebKeySetTheoryData> GetSigningKeysTheoryData
        {
            get
            {
                var ecdsaAdapter = new ECDsaAdapter();
                var theoryData = new TheoryData<JsonWebKeySetTheoryData>();

                var jsonWebKeySet = new JsonWebKeySet(DataSets.JsonWebKeySetUseNotSigString) { SkipUnresolvedJsonWebKeys = true };
                theoryData.Add(new JsonWebKeySetTheoryData
                {
                    First = true,
                    JsonWebKeySet = jsonWebKeySet,
                    ExpectedSigningKeys = new List<SecurityKey>(),
                    TestId = "ZeroKeysWithSigAsUseSkipUnresolved",
                });

                jsonWebKeySet = new JsonWebKeySet(DataSets.JsonWebKeySetUseNotSigString) { SkipUnresolvedJsonWebKeys = false };
                theoryData.Add(new JsonWebKeySetTheoryData
                {
                    JsonWebKeySet = jsonWebKeySet,
                    ExpectedSigningKeys = new List<SecurityKey>() { (jsonWebKeySet.Keys as List<JsonWebKey>)[0] },
                    TestId = "ZeroKeysWithSigAsUse",
                });

                jsonWebKeySet = new JsonWebKeySet(DataSets.JsonWebKeySetUseNoKtyString) { SkipUnresolvedJsonWebKeys = true };
                theoryData.Add(new JsonWebKeySetTheoryData
                {
                    JsonWebKeySet = jsonWebKeySet,
                    ExpectedSigningKeys = new List<SecurityKey>(),
                    TestId = "KeysWithoutKtySkipUnresolved",
                });

                jsonWebKeySet = new JsonWebKeySet(DataSets.JsonWebKeySetUseNoKtyString) { SkipUnresolvedJsonWebKeys = false };
                theoryData.Add(new JsonWebKeySetTheoryData
                {
                    JsonWebKeySet = jsonWebKeySet,
                    ExpectedSigningKeys = new List<SecurityKey>() { (jsonWebKeySet.Keys as List<JsonWebKey>)[0] },
                    TestId = "KeysWithoutKty",
                });

                jsonWebKeySet = new JsonWebKeySet(DataSets.JsonWebKeySetEvoString) { SkipUnresolvedJsonWebKeys = false };
                theoryData.Add(new JsonWebKeySetTheoryData
                {
                    JsonWebKeySet = jsonWebKeySet,
                    ExpectedSigningKeys = new List<SecurityKey>() { CreateRsaSecurityKey(jsonWebKeySet, 0), CreateX509SecurityKey(jsonWebKeySet, 0) },
                    TestId = "EvoSigningKey",
                });

                jsonWebKeySet = new JsonWebKeySet(DataSets.JsonWebKeySetKtyNotRsaString) { SkipUnresolvedJsonWebKeys = true };
                theoryData.Add(new JsonWebKeySetTheoryData
                {
                    JsonWebKeySet = jsonWebKeySet,
                    ExpectedSigningKeys = new List<SecurityKey>(),
                    TestId = "NonRsaNonEcKeySkipUnresolved",
                });

                jsonWebKeySet = new JsonWebKeySet(DataSets.JsonWebKeySetKtyNotRsaString) { SkipUnresolvedJsonWebKeys = false };
                theoryData.Add(new JsonWebKeySetTheoryData
                {
                    JsonWebKeySet = jsonWebKeySet,
                    ExpectedSigningKeys = new List<SecurityKey>() { (jsonWebKeySet.Keys as List<JsonWebKey>)[0] },
                    TestId = "NonRsaNonEcKey",
                });

                jsonWebKeySet = new JsonWebKeySet(DataSets.JsonWebKeySetOnlyX5tString) { SkipUnresolvedJsonWebKeys = true };
                theoryData.Add(new JsonWebKeySetTheoryData
                {
                    JsonWebKeySet = jsonWebKeySet,
                    ExpectedSigningKeys = new List<SecurityKey>(),
                    TestId = "JsonWebKeyNotInvalidNotResolvedSkipUnresolved"
                });

                jsonWebKeySet = new JsonWebKeySet(DataSets.JsonWebKeySetOnlyX5tString) { SkipUnresolvedJsonWebKeys = false };
                theoryData.Add(new JsonWebKeySetTheoryData
                {
                    JsonWebKeySet = jsonWebKeySet,
                    ExpectedSigningKeys = new List<SecurityKey>() { (jsonWebKeySet.Keys as List<JsonWebKey>)[0] },
                    TestId = "JsonWebKeyNotInvalidNotResolved"
                });

                jsonWebKeySet = new JsonWebKeySet(DataSets.JsonWebKeySetOneValidRsaOneInvalidRsaString) { SkipUnresolvedJsonWebKeys = true };
                theoryData.Add(new JsonWebKeySetTheoryData
                {
                    JsonWebKeySet = jsonWebKeySet,
                    ExpectedSigningKeys = new List<SecurityKey>() { CreateRsaSecurityKey(jsonWebKeySet, 0) },
                    TestId = "OneValidAndOneInvalidRsaSkipUnresolved",
                });

                jsonWebKeySet = new JsonWebKeySet(DataSets.JsonWebKeySetOneValidRsaOneInvalidRsaString) { SkipUnresolvedJsonWebKeys = false };
                theoryData.Add(new JsonWebKeySetTheoryData
                {
                    JsonWebKeySet = jsonWebKeySet,
                    ExpectedSigningKeys = new List<SecurityKey>() { (jsonWebKeySet.Keys as List<JsonWebKey>)[0], (jsonWebKeySet.Keys as List<JsonWebKey>)[1] },
                    TestId = "OneValidAndOneInvalidRsa",
                });

                jsonWebKeySet = new JsonWebKeySet(DataSets.JsonWebKeySetOneInvalidEcOneValidEcString) { SkipUnresolvedJsonWebKeys = true };
                theoryData.Add(new JsonWebKeySetTheoryData
                {
                    JsonWebKeySet = jsonWebKeySet,
                    ExpectedSigningKeys = new List<SecurityKey>() { CreateEcdsaSecurityKey(jsonWebKeySet, 1, ecdsaAdapter) },
                    TestId = "OneValidAndOneInvalidEcSkipUnresolved",
                });

                jsonWebKeySet = new JsonWebKeySet(DataSets.JsonWebKeySetOneInvalidEcOneValidEcString) { SkipUnresolvedJsonWebKeys = false };
                theoryData.Add(new JsonWebKeySetTheoryData
                {
                    JsonWebKeySet = jsonWebKeySet,
                    ExpectedSigningKeys = new List<SecurityKey>() { (jsonWebKeySet.Keys as List<JsonWebKey>)[0], CreateEcdsaSecurityKey(jsonWebKeySet, 1, ecdsaAdapter) },
                    TestId = "OneValidAndOneInvalidEC",
                });

                jsonWebKeySet = new JsonWebKeySet(DataSets.JsonWebKeySetOneValidRsaOneInvalidEcString) { SkipUnresolvedJsonWebKeys = true };
                theoryData.Add(new JsonWebKeySetTheoryData
                {
                    JsonWebKeySet = jsonWebKeySet,
                    ExpectedSigningKeys = new List<SecurityKey>() { CreateRsaSecurityKey(jsonWebKeySet, 0) },
                    TestId = "ValidRsaInvalidEcSkipUnresolved",
                });

                jsonWebKeySet = new JsonWebKeySet(DataSets.JsonWebKeySetOneValidRsaOneInvalidEcString) { SkipUnresolvedJsonWebKeys = false };
                theoryData.Add(new JsonWebKeySetTheoryData
                {
                    JsonWebKeySet = jsonWebKeySet,
                    ExpectedSigningKeys = new List<SecurityKey>() { CreateRsaSecurityKey(jsonWebKeySet, 0), (jsonWebKeySet.Keys as List<JsonWebKey>)[1] },
                    TestId = "ValidRsaInvalidEc",
                });

                jsonWebKeySet = new JsonWebKeySet(DataSets.JsonWebKeySetX509DataString) { SkipUnresolvedJsonWebKeys = false };
                theoryData.Add(new JsonWebKeySetTheoryData
                {
                    JsonWebKeySet = jsonWebKeySet,
                    ExpectedSigningKeys = new List<SecurityKey>() { CreateX509SecurityKey(jsonWebKeySet, 0) },
                    TestId = "ValidX5c",
                });

                jsonWebKeySet = new JsonWebKeySet(DataSets.JsonWebKeySetBadX509String) { SkipUnresolvedJsonWebKeys = true };
                theoryData.Add(new JsonWebKeySetTheoryData
                {
                    JsonWebKeySet = jsonWebKeySet,
                    ExpectedSigningKeys = new List<SecurityKey>() { CreateRsaSecurityKey(jsonWebKeySet, 0) },
                    TestId = "InvalidX5cSkipUnresolvedAddRsa",
                });

                jsonWebKeySet = new JsonWebKeySet(DataSets.JsonWebKeySetBadX509String) { SkipUnresolvedJsonWebKeys = false };
                theoryData.Add(new JsonWebKeySetTheoryData
                {
                    JsonWebKeySet = jsonWebKeySet,
                    ExpectedSigningKeys = new List<SecurityKey>() { CreateRsaSecurityKey(jsonWebKeySet, 0), (jsonWebKeySet.Keys as List<JsonWebKey>)[0] },
                    TestId = "InvalidX5c",
                });

                jsonWebKeySet = new JsonWebKeySet(DataSets.JsonWebKeySetOneInvalidEcOneValidEcString) { SkipUnresolvedJsonWebKeys = true };
                theoryData.Add(new JsonWebKeySetTheoryData
                {
                    JsonWebKeySet = jsonWebKeySet,
                    ExpectedSigningKeys = new List<SecurityKey>(),
                    SetEcdsaAdapterToNull = true,
                    TestId = "ECDsaAdapterIsNotSupportedSkipUnresolved",
                });

                jsonWebKeySet = new JsonWebKeySet(DataSets.JsonWebKeySetOneInvalidEcOneValidEcString) { SkipUnresolvedJsonWebKeys = false };
                theoryData.Add(new JsonWebKeySetTheoryData
                {
                    JsonWebKeySet = jsonWebKeySet,
                    ExpectedSigningKeys = new List<SecurityKey>() { (jsonWebKeySet.Keys as List<JsonWebKey>)[0], (jsonWebKeySet.Keys as List<JsonWebKey>)[1] },
                    SetEcdsaAdapterToNull = true,
                    TestId = "ECDsaAdapterIsNotSupported",
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

            public List<SecurityKey> ExpectedSigningKeys { get; set; }

            public bool SetEcdsaAdapterToNull { get; set; } = false;
         }
    }
}

#pragma warning restore CS3016 // Arrays as attribute arguments is not CLS-compliant
