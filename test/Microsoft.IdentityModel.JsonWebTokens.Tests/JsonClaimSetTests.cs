// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System;
using System.Collections.Generic;
using System.Globalization;
using System.Reflection;
using System.Security.Claims;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.IdentityModel.TestUtils;
using Microsoft.IdentityModel.Tokens;
using Microsoft.IdentityModel.Tokens.Json.Tests;
using Xunit;

namespace Microsoft.IdentityModel.JsonWebTokens.Tests
{
    public class JsonClaimSetTests
    {
        private static DateTime _dateTime = new DateTime(2000, 01, 01, 0, 0, 0);
        private static string _dateTimePropertyName = "dateTime";
        private static string _jsonPayload = $@"{{""intarray"":[1,2,3], ""array"":[1,""2"",3], ""jobject"": {{""string1"":""string1value"",""string2"":""string2value""}},""string"":""bob"", ""float"":42.0, ""integer"":42, ""nill"": null, ""bool"" : true, ""{_dateTimePropertyName}"": ""{_dateTime}"", ""dateTimeIso8061"": ""{_dateTime.ToUniversalTime().ToString("o", CultureInfo.InvariantCulture)}"" }}";
        private List<Claim> _payloadClaims = new List<Claim>()
        {
            new Claim("intarray", @"[1,2,3]", JsonClaimValueTypes.JsonArray, "LOCAL AUTHORITY", "LOCAL AUTHORITY"),
            new Claim("array", @"[1,""2"",3]", JsonClaimValueTypes.JsonArray, "LOCAL AUTHORITY", "LOCAL AUTHORITY"),
            new Claim("jobject", @"{""string1"":""string1value"",""string2"":""string2value""}", JsonClaimValueTypes.Json, "LOCAL AUTHORITY", "LOCAL AUTHORITY"),
            new Claim("string", "bob", ClaimValueTypes.String, "LOCAL AUTHORITY", "LOCAL AUTHORITY"),
            new Claim("float", "42.0", ClaimValueTypes.Double, "LOCAL AUTHORITY", "LOCAL AUTHORITY"),
            new Claim("integer", "42", ClaimValueTypes.Integer, "LOCAL AUTHORITY", "LOCAL AUTHORITY"),
            new Claim("nill", "", JsonClaimValueTypes.JsonNull, "LOCAL AUTHORITY", "LOCAL AUTHORITY"),
            new Claim("bool", "true", ClaimValueTypes.Boolean, "LOCAL AUTHORITY", "LOCAL AUTHORITY"),
            new Claim("dateTime", _dateTime.ToString(), ClaimValueTypes.String, "LOCAL AUTHORITY", "LOCAL AUTHORITY"),
            new Claim("dateTimeIso8061", _dateTime.ToUniversalTime().ToString("o", CultureInfo.InvariantCulture), ClaimValueTypes.DateTime, "LOCAL AUTHORITY", "LOCAL AUTHORITY"),
        };

        [Theory, MemberData(nameof(DirectClaimSetTestCases), DisableDiscoveryEnumeration = true)]
        public void DirectClaimSetTests(JsonClaimSetTheoryData theoryData)
        {
            CompareContext context = TestUtilities.WriteHeader($"{this}.ClaimSetTests", theoryData);
            context.IgnoreType = false;

            try
            {
                JsonWebToken jwt = new JsonWebToken("{}", $@"{{""true"":true}}");
                JsonClaimSet claimSet = jwt.CreatePayloadClaimSet(theoryData.Utf8Bytes, theoryData.Utf8Bytes.Length);
                theoryData.ExpectedException.ProcessNoException(context);
            }
            catch (JsonException ex)
            {
                theoryData.ExpectedException.ProcessException(ex, context);
            }
            catch (Exception ex)
            {
                theoryData.ExpectedException.ProcessException(ex, context);
            }

            TestUtilities.AssertFailIfErrors(context);
        }

        public static TheoryData<JsonClaimSetTheoryData> DirectClaimSetTestCases()
        {
            var theoryData = new TheoryData<JsonClaimSetTheoryData>();
            theoryData.Add(new JsonClaimSetTheoryData("NotOnStartObject")
            {
                ExpectedException = new ExpectedException(typeof(JsonException)),
                Utf8Bytes = Encoding.UTF8.GetBytes($@"[""a""]")
            });

            // ignore exception as a System.Text.Json.JsonReaderException is thrown
            // which is internal to System.Text.Json so we can't define it.
            theoryData.Add(new JsonClaimSetTheoryData("badJson")
            {
                ExpectedException = new ExpectedException(typeof(JsonException)) { IgnoreExceptionType = true },
                Utf8Bytes = Encoding.UTF8.GetBytes("badJson")
            });

            return theoryData;
        }

        // Exercises the claims dictionary presizing (capacity == byteSpan.Length / AverageJsonClaimLengthInBytes).
        // The seeded capacity is a performance hint only and must never change the parsed result, so these cases
        // cover the different capacity regimes: capacity 0 (payload smaller than one average claim), the boundary
        // around AverageJsonClaimLengthInBytes, an under-estimate (many small claims forcing growth beyond the seed)
        // and an over-estimate (few large claims). Each case asserts every expected claim is parsed.
        [Theory, MemberData(nameof(PresizedClaimSetTestCases), DisableDiscoveryEnumeration = true)]
        public void PresizedClaimSet_ParsesAllClaims(JsonClaimSetTheoryData theoryData)
        {
            CompareContext context = TestUtilities.WriteHeader($"{this}.PresizedClaimSet_ParsesAllClaims", theoryData);

            JsonWebToken jwt = new JsonWebToken("{}", $@"{{""true"":true}}");

            // Act
            JsonClaimSet claimSet = jwt.CreatePayloadClaimSet(theoryData.Utf8Bytes, theoryData.Utf8Bytes.Length);

            // Assert
            if (claimSet._jsonClaims.Count != theoryData.ExpectedClaimNames.Count)
                context.AddDiff($"Expected {theoryData.ExpectedClaimNames.Count} claims, found {claimSet._jsonClaims.Count}.");

            foreach (string claimName in theoryData.ExpectedClaimNames)
            {
                if (!claimSet._jsonClaims.ContainsKey(claimName))
                    context.AddDiff($"Expected claim '{claimName}' was not found in the parsed claim set.");
            }

            TestUtilities.AssertFailIfErrors(context);
        }

        public static TheoryData<JsonClaimSetTheoryData> PresizedClaimSetTestCases()
        {
            var theoryData = new TheoryData<JsonClaimSetTheoryData>();

            // Empty object: length 2 => capacity 0, no claims.
            theoryData.Add(new JsonClaimSetTheoryData("EmptyObject")
            {
                Utf8Bytes = Encoding.UTF8.GetBytes("{}"),
                ExpectedClaimNames = new List<string>()
            });

            // Tiny single claim, well under AverageJsonClaimLengthInBytes => capacity 0.
            theoryData.Add(new JsonClaimSetTheoryData("SingleClaimCapacityZero")
            {
                Utf8Bytes = Encoding.UTF8.GetBytes(@"{""a"":""b""}"),
                ExpectedClaimNames = new List<string> { "a" }
            });

            // Payload sized right around AverageJsonClaimLengthInBytes (32 bytes) => capacity ~1.
            theoryData.Add(new JsonClaimSetTheoryData("PayloadAtCapacityBoundary")
            {
                Utf8Bytes = Encoding.UTF8.GetBytes(@"{""iss"":""abc"",""sub"":""1234567""}"),
                ExpectedClaimNames = new List<string> { "iss", "sub" }
            });

            // Many small claims: the byte-length estimate under-counts the claims, forcing growth
            // beyond the seeded capacity.
            var manyClaims = new List<string>();
            var manyClaimsBuilder = new StringBuilder("{");
            for (int i = 0; i < 20; i++)
            {
                string name = "c" + i;
                manyClaims.Add(name);
                if (i > 0)
                    manyClaimsBuilder.Append(',');

                manyClaimsBuilder.Append($@"""{name}"":{i}");
            }

            manyClaimsBuilder.Append('}');
            theoryData.Add(new JsonClaimSetTheoryData("ManySmallClaimsUnderEstimate")
            {
                Utf8Bytes = Encoding.UTF8.GetBytes(manyClaimsBuilder.ToString()),
                ExpectedClaimNames = manyClaims
            });

            // Few large claims: the byte-length estimate over-counts the claims, over-sizing the dictionary.
            theoryData.Add(new JsonClaimSetTheoryData("FewLargeClaimsOverEstimate")
            {
                Utf8Bytes = Encoding.UTF8.GetBytes($@"{{""big"":""{new string('x', 512)}""}}"),
                ExpectedClaimNames = new List<string> { "big" }
            });

            return theoryData;
        }

        [Theory, MemberData(nameof(GetClaimAsTypeTheoryData), DisableDiscoveryEnumeration = true)]
        public void GetClaimAsType(JsonClaimSetTheoryData theoryData)
        {
            CompareContext context = TestUtilities.WriteHeader($"{this}.GetClaimAsType", theoryData);
            try
            {
                JsonWebToken token = new JsonWebToken(theoryData.Json);

                var methods = typeof(JsonWebToken).GetMethods(BindingFlags.NonPublic | BindingFlags.Public | BindingFlags.Instance);
                var method = typeof(JsonWebToken).GetMethod("GetPayloadValue", BindingFlags.NonPublic | BindingFlags.Public | BindingFlags.Instance, null, CallingConventions.Standard, new Type[] { typeof(string) }, null);
                var retval = method.MakeGenericMethod(theoryData.PropertyType).Invoke(token, new object[] { theoryData.PropertyName });
                theoryData.ExpectedException.ProcessNoException(context);
                IdentityComparer.AreEqual(retval, theoryData.PropertyValue, context);
            }
            catch (Exception ex)
            {
                theoryData.ExpectedException.ProcessException(ex, context);
            }

            TestUtilities.AssertFailIfErrors(context);
        }

        // Tests a JsonClaimSet, to ensure the same List object is returned for concurrent calls to the Claims member.
        [Fact]
        public async Task ValidJsonClaimSet_ConcurrencyTest()
        {
            // Arrange
            var numThreads = 10;
            var barrier = new Barrier(numThreads);
            var jsonClaims = new Dictionary<string, object>
            {
                { "claim1", "value1" },
                { "claim2", "value2" }
            };
            var jsonClaimSet = new JsonClaimSet(jsonClaims);
            List<Claim>[] allClaims = new List<Claim>[numThreads];
            Task[] tasks = new Task[numThreads];

            for (var i = 0; i < numThreads; i++)
            {
                var index = i;
                tasks[i] = (Task.Run(() =>
                {
                    barrier.SignalAndWait();
                    allClaims[index] = jsonClaimSet.Claims("claim1");
                }));
            }

            // Act
            await Task.WhenAll(tasks);

            // Assert
            Assert.All(allClaims, claims => Assert.NotNull(claims));
            var firstClaims = allClaims[0];
            for (var i = 1; i < numThreads; i++)
            {
                Assert.Same(firstClaims, allClaims[i]);
            }
        }

        public static TheoryData<JsonClaimSetTheoryData> GetClaimAsTypeTheoryData()
        {
            var theoryData = new TheoryData<JsonClaimSetTheoryData>();

            string header = Base64UrlEncoder.Encode("{}");
            string payload = Base64UrlEncoder.Encode(@"{""a"":{""prop1"":""value1""},""b"":{""prop1"":[""value1"",""value2""]}, ""exp"": 1692706803,""iat"": 1692703203,""nbf"": 1692703203}");

            theoryData.Add(
                new JsonClaimSetTheoryData("DictionaryWithListOfStrings")
                {
                    Json = header + "." + payload + ".",
                    PropertyName = "b",
                    PropertyType = typeof(Dictionary<string, List<string>>),
                    PropertyValue = new Dictionary<string, List<string>> { { "prop1", new List<string> { "value1", "value2" } } }
                });

            theoryData.Add(
                new JsonClaimSetTheoryData("DictionaryWithArrayOfStrings")
                {
                    Json = header + "." + payload + ".",
                    PropertyName = "b",
                    PropertyType = typeof(Dictionary<string, string[]>),
                    PropertyValue = new Dictionary<string, string[]> { { "prop1", new string[] { "value1", "value2" } } }
                });

            theoryData.Add(
                new JsonClaimSetTheoryData("DictionaryOfStrings")
                {
                    Json = header + "." + payload + ".",
                    PropertyName = "a",
                    PropertyType = typeof(Dictionary<string, string>),
                    PropertyValue = new Dictionary<string, string> { { "prop1", "value1" } }
                });

            theoryData.Add(
                new JsonClaimSetTheoryData("ArrayOfObjects")
                {
                    Json = header + "." + Base64UrlEncoder.Encode(JsonData.ArrayOfObjectsObject) + ".",
                    PropertyName = JsonData.ArrayProperty,
                    PropertyType = typeof(JsonElement),
                    PropertyValue = JsonUtilities.CreateJsonElement(JsonData.ArrayOfObjectsValue)
                });

            theoryData.Add(
                new JsonClaimSetTheoryData("ObjectOfObjects")
                {
                    Json = header + "." + Base64UrlEncoder.Encode("{" + JsonData.ObjectClaim + "}") + ".",
                    PropertyName = JsonData.ObjectProperty,
                    PropertyType = typeof(JsonElement),
                    PropertyValue = JsonUtilities.CreateJsonElement(JsonData.ObjectValue)
                });

            return theoryData;
        }

        public class JsonClaimSetTheoryData : TheoryDataBase
        {
            public JsonClaimSetTheoryData(string id) : base(id) { }

            public List<string> ExpectedClaimNames { get; set; }

            public string Json { get; set; }

            public JsonWebToken JsonWebToken { get; set; }

            public string PropertyName { get; set; }

            public Type PropertyOut { get; set; }

            public Type PropertyType { get; set; }

            public object PropertyValue { get; set; }

            public bool ShouldFind { get; set; }

            public byte[] Utf8Bytes { get; set; }
        }
    }
}
