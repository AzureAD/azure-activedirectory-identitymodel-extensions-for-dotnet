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

using System.Collections.Generic;
using System.Globalization;
using System.Reflection;
using System.Security.Claims;
using Microsoft.IdentityModel.Tokens;
using Microsoft.IdentityModel.Tokens.Tests;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using Xunit;

namespace System.IdentityModel.Tokens.Jwt.Tests
{
    public class JwtPayloadTests
    {
        /// <summary>
        /// Test Context Wrapper instance on top of TestContext. Provides better accessor functions
        /// </summary>
        [Fact(DisplayName = "JwtPayloadTests: Ensures that JwtPayload defaults are as expected")]
        public void Defaults()
        {
            JwtPayload jwtPayload = new JwtPayload();
            List<Claim> claims = jwtPayload.Claims as List<Claim>;
            Assert.True(claims != null, "claims as List<Claim> == null");

            foreach (Claim c in jwtPayload.Claims)
            {
                Assert.True(false, "jwtPayload.Claims should be empty");
            }

            Assert.True(jwtPayload.Aud != null, "jwtPayload.Aud should not be null");
            foreach (string audience in jwtPayload.Aud)
            {
                Assert.True(false, "jwtPayload.Aud should be empty");
            }

            Assert.True(jwtPayload.Amr != null, "jwtPayload.Amr should not be null");
            foreach (string audience in jwtPayload.Amr)
            {
                Assert.True(false, "jwtPayload.Amr should be empty");
            }

            Assert.True(jwtPayload.ValidFrom == DateTime.MinValue, "jwtPayload.ValidFrom != DateTime.MinValue");
            Assert.True(jwtPayload.ValidTo == DateTime.MinValue, "jwtPayload.ValidTo != DateTime.MinValue");
        }

        [Fact(DisplayName = "JwtPayloadTests: GetSets, covers defaults")]
        public void GetSets()
        {
            // Aud, Claims, ValidFrom, ValidTo handled in Defaults.

            JwtPayload jwtPayload = new JwtPayload();
            Type type = typeof(JwtPayload);
            PropertyInfo[] properties = type.GetProperties();
            if (properties.Length != 22)
                Assert.True(false, "Number of properties has changed from 22 to: " + properties.Length + ", adjust tests");

            GetSetContext context =
                new GetSetContext
                {
                    PropertyNamesAndSetGetValue = new List<KeyValuePair<string, List<object>>>
                    {
                        new KeyValuePair<string, List<object>>("Actort", new List<object>{(string)null, Guid.NewGuid().ToString(), Guid.NewGuid().ToString()}),
                        new KeyValuePair<string, List<object>>("Acr", new List<object>{(string)null, Guid.NewGuid().ToString(), Guid.NewGuid().ToString()}),
                        new KeyValuePair<string, List<object>>("AuthTime", new List<object>{(string)null, 10, 12 }),
                        new KeyValuePair<string, List<object>>("Azp", new List<object>{(string)null, Guid.NewGuid().ToString(), Guid.NewGuid().ToString()}),
                        new KeyValuePair<string, List<object>>("CHash", new List<object>{(string)null, Guid.NewGuid().ToString(), Guid.NewGuid().ToString()}),
                        new KeyValuePair<string, List<object>>("Exp", new List<object>{(string)null, 1, 0 }),
                        new KeyValuePair<string, List<object>>("Jti", new List<object>{(string)null, Guid.NewGuid().ToString(), Guid.NewGuid().ToString()}),
                        new KeyValuePair<string, List<object>>("Iat", new List<object>{(string)null, 10, 0}),
                        new KeyValuePair<string, List<object>>("Iss", new List<object>{(string)null, Guid.NewGuid().ToString(), Guid.NewGuid().ToString()}),
                        new KeyValuePair<string, List<object>>("Nbf", new List<object>{(string)null, 1, 0 }),
                        new KeyValuePair<string, List<object>>("Nonce", new List<object>{(string)null, Guid.NewGuid().ToString(), Guid.NewGuid().ToString()}),
                        new KeyValuePair<string, List<object>>("Sub", new List<object>{(string)null, Guid.NewGuid().ToString(), Guid.NewGuid().ToString()}),
                    },
                    Object = jwtPayload,
                };
            TestUtilities.GetSet(context);
            TestUtilities.AssertFailIfErrors("JwtPayload_GetSets", context.Errors);
        }

        [Fact]
        public void JwtPayloadEncoding()
        {
            var context = new CompareContext();
            RunEncodingVariation(JwtPayloadTestData.ClaimForEachProperty, JwtPayloadTestData.ObjectForEachProperty, context);
            RunEncodingVariation(JwtPayloadTestData.Multiples.Key, JwtPayloadTestData.Multiples.Value, context);

            TestUtilities.AssertFailIfErrors(context.Diffs);
        }

        [Fact]
        public void FirstClassProperties()
        {
            var context = new CompareContext();

            JwtPayload jwtPayload = new JwtPayload();
            int? time = 10000;
            jwtPayload.Add("exp", time);
            DateTime payloadTime = EpochTime.DateTime(time.Value);
            DateTime payloadValidTo = jwtPayload.ValidTo;

            Assert.True(EpochTime.DateTime(time.Value) == jwtPayload.ValidTo, "EpochTime.DateTime( time ) != jwtPayload.ValidTo");

            int? expirationTime = jwtPayload.Exp;
            Assert.True(expirationTime == time, "expirationTime != time");

            TestUtilities.AssertFailIfErrors(GetType().ToString() + ".Claims", context.Diffs);
        }

        [Fact]
        public void TestClaimWithNullValue()
        {
            JwtPayload jwtPayload = new JwtPayload();
            jwtPayload.Add("testClaim", null);
            List<Claim> claims = jwtPayload.Claims as List<Claim>;   // this should not throw
        }

#pragma warning disable CS3016 // Arrays as attribute arguments is not CLS-compliant
        [Theory, MemberData("JsonDataSet")]
#pragma warning restore CS3016 // Arrays as attribute arguments is not CLS-compliant

        public void JsonClaims(List<Claim> claims, string json)
        {
            var context = new CompareContext();
            var payload = new JwtPayload(claims);
            var encodedPayload = payload.SerializeToJson();
            var payloadDecoded = JwtPayload.Deserialize(encodedPayload);

            IdentityComparer.AreEqual(payload, payloadDecoded, context);
            IdentityComparer.AreEqual(payload.Claims, claims, context);
            IdentityComparer.AreEqual(payload.Claims, payloadDecoded.Claims, context);

            CheckClaimsTypeParsing(payload.Claims, context);
            CheckClaimsTypeParsing(payloadDecoded.Claims, context);

            TestUtilities.AssertFailIfErrors(context);
        }

        public static TheoryData<List<Claim>, string> JsonDataSet
        {
            get
            {
                var dataset = new TheoryData<List<Claim>, string>();
                var claims = new List<Claim>
                {
                    new Claim("json3", @"{""name3.1"":""value3.1""}", JsonClaimValueTypes.Json),
                    new Claim("json3", @"{""name3.2"":""value3.2""}", JsonClaimValueTypes.Json),
                    new Claim("json3", @"{""name3.3"":[1,2,3]}", JsonClaimValueTypes.Json),
                    new Claim("json3", "name3.4")
                };

                dataset.Add(claims, "");

                claims = new List<Claim>
                {
                    new Claim("may_act", @"""sub"": ""admin@example.net""", @"""name"": ""Admin""", JsonClaimValueTypes.Json),
                    new Claim("may_act", @"""sub"": ""admin@example.net""", @"""name"": ""Admin""", JsonClaimValueTypes.Json),
                    new Claim("may_act2", @"""sub"": ""admin@example.net""", @"""name"": ""Admin""", JsonClaimValueTypes.Json)
                };

                dataset.Add(claims, "");

                claims = new List<Claim>
                {
                    new Claim("scp", "status"),
                    new Claim("scp", "feed"),
                    new Claim("scp", @"[""status"",""feed""]", JsonClaimValueTypes.JsonArray),
                    new Claim("scp", "12", ClaimValueTypes.Integer)
                };

                dataset.Add(claims, "");

                claims = new List<Claim>
                {
                    new Claim("ClaimValueTypes", "100", ClaimValueTypes.Integer),
                    new Claim("ClaimValueTypes", "132", ClaimValueTypes.Integer32),
                    new Claim("ClaimValueTypes", "164", ClaimValueTypes.Integer64),
                    new Claim("ClaimValueTypes", "-100", ClaimValueTypes.Integer),
                    new Claim("ClaimValueTypes", "-132", ClaimValueTypes.Integer32),
                    new Claim("ClaimValueTypes", "-164", ClaimValueTypes.Integer64),
                    new Claim("ClaimValueTypes", "132..64", ClaimValueTypes.Double),
                    new Claim("ClaimValueTypes", "-132.64", ClaimValueTypes.Double),
                    new Claim("ClaimValueTypes", "true", ClaimValueTypes.Boolean),
                    new Claim("ClaimValueTypes", "false", ClaimValueTypes.Boolean),
                    new Claim("ClaimValueTypes", @"{""name3.1"":""value3.1""}", JsonClaimValueTypes.Json),
                    new Claim("ClaimValueTypes", @"[""status"",""feed""]", JsonClaimValueTypes.JsonArray),
                };

                dataset.Add(claims, "");

                return dataset;
            }
        }

        private void CheckClaimsTypeParsing(IEnumerable<Claim> claims, CompareContext context)
        {
            if (claims == null)
                return;

            foreach (var claim in claims)
            {
                switch (claim.ValueType)
                {
                    case ClaimValueTypes.Boolean:
                        bool boolRet;
                        if (!bool.TryParse(claim.Value, out boolRet))
                            context.Diffs.Add(string.Format(CultureInfo.InvariantCulture, "bool.TryParse(claim.Value, out boolRet), value: '{0}'", claim.Value));

                        break;

                    case ClaimValueTypes.Double:
                        double doubleRet;
                        if (!double.TryParse(claim.Value, out doubleRet))
                            context.Diffs.Add(string.Format(CultureInfo.InvariantCulture, "double.TryParse(claim.Value, out doubleRet), value: '{0}'", claim.Value));

                        break;

                    case ClaimValueTypes.Integer:
                        int intRet;
                        if (!int.TryParse(claim.Value, out intRet))
                            context.Diffs.Add(string.Format(CultureInfo.InvariantCulture, "int.TryParse(claim.Value, out intRet), value: '{0}'", claim.Value));

                        break;

                    case ClaimValueTypes.Integer32:
                        int intRet32;
                        if (!int.TryParse(claim.Value, out intRet32))
                            context.Diffs.Add(string.Format(CultureInfo.InvariantCulture, "int.TryParse(claim.Value, out intRet32), value: '{0}'", claim.Value));

                        break;

                    case ClaimValueTypes.Integer64:
                        long long64;
                        if (!long.TryParse(claim.Value, out long64))
                            context.Diffs.Add(string.Format(CultureInfo.InvariantCulture, "long.TryParse(claim.Value, out long64), value: '{0}'", claim.Value));

                        break;

                    case JsonClaimValueTypes.Json:
                        try
                        {
                            JObject.Parse(claim.Value);
                        }
                        catch (Exception ex)
                        {
                            context.Diffs.Add(string.Format(CultureInfo.InvariantCulture, "JObject.Parse(claim.Value) threw: '{0}', value: '{1}'", ex, claim.Value));
                        }

                        break;

                    case JsonClaimValueTypes.JsonArray:
                        try
                        {
                            JArray.Parse(claim.Value);
                        }
                        catch (Exception ex)
                        {
                            context.Diffs.Add(string.Format(CultureInfo.InvariantCulture, "JArray.Parse(claim.Value) threw: '{0}', value: '{1}'", ex, claim.Value));
                        }
                        break;
                }
            }
        }


        private void RunEncodingVariation(List<Claim> claims, Dictionary<string, object> values, CompareContext context)
        {
            var jwtPayload1 = new JwtPayload(claims);
            var jwtPayload2 = new JwtPayload();
            foreach (var kv in values)
            {
                jwtPayload2[kv.Key] = kv.Value;
            }

            IdentityComparer.AreEqual(jwtPayload1, jwtPayload2, context);

            jwtPayload1 = JwtPayload.Base64UrlDeserialize(jwtPayload1.Base64UrlEncode());
            jwtPayload2 = JwtPayload.Base64UrlDeserialize(jwtPayload2.Base64UrlEncode());
            IdentityComparer.AreEqual(jwtPayload1, jwtPayload2, context);
        }
    }
}
