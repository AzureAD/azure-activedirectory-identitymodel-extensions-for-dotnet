// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System;
using System.Collections.Generic;
using System.Globalization;
using System.Reflection;
using System.Security.Claims;
using System.Text;
using System.Text.Json;
using Microsoft.IdentityModel.TestUtils;
using Microsoft.IdentityModel.Tokens.Json.Tests;
using Microsoft.IdentityModel.Tokens;
using Xunit;
using System.Threading.Tasks;
using static System.Net.WebRequestMethods;

namespace Microsoft.IdentityModel.JsonWebTokens.Tests
{
    [Collection(nameof(JsonClaimSetTests))]
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

        public JsonClaimSetTests()
        {
            AppContextSwitches.ResetAllSwitches();
        }

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

            public string Json { get; set; }

            public JsonWebToken JsonWebToken { get; set; }

            public string PropertyName { get; set; }

            public Type PropertyOut { get; set; }

            public Type PropertyType { get; set; }

            public object PropertyValue { get; set; }

            public bool ShouldFind { get; set; }

            public byte[] Utf8Bytes { get; set; }
        }

        [Fact]
        public void CreateClaimFromObject_ListOfStrings_AppContextSwitchOn()
        {
            AppContext.SetSwitch(AppContextSwitches.StoreArrayClaimsAsJsonStringSwitch, true);
            var claims = new List<Claim>();
            var value = new List<string> { "value1", "value2" };
            JsonClaimSet.CreateClaimFromObject(claims, "claimType", value, "issuer");

            Assert.Single(claims);
            Assert.Equal(JsonClaimValueTypes.JsonArray, claims[0].ValueType);
        }

        [Fact]
        public void CreateClaimFromObject_ListOfStrings_AppContextSwitchOff()
        {
            AppContext.SetSwitch(AppContextSwitches.StoreArrayClaimsAsJsonStringSwitch, false);
            var claims = new List<Claim>();
            var value = new List<string> { "value1", "value2" };
            JsonClaimSet.CreateClaimFromObject(claims, "claimType", value, "issuer");

            Assert.Equal(2, claims.Count);
            Assert.Equal("value1", claims[0].Value);
            Assert.Equal("value2", claims[1].Value);
        }

        [Fact]
        public void CreateClaimFromObject_ArrayOfInts_AppContextSwitchOn()
        {
            AppContext.SetSwitch(AppContextSwitches.StoreArrayClaimsAsJsonStringSwitch, true);
            var claims = new List<Claim>();
            var value = new int[] { 1, 2, 3 };
            JsonClaimSet.CreateClaimFromObject(claims, "claimType", value, "issuer");

            Assert.Single(claims);
            Assert.Equal(JsonClaimValueTypes.JsonArray, claims[0].ValueType);
        }

        [Fact]
        public void CreateClaimFromObject_ArrayOfInts_AppContextSwitchOff()
        {
            AppContext.SetSwitch(AppContextSwitches.StoreArrayClaimsAsJsonStringSwitch, false);
            var claims = new List<Claim>();
            var value = new int[] { 1, 2, 3 };
            JsonClaimSet.CreateClaimFromObject(claims, "claimType", value, "issuer");

            Assert.Equal(3, claims.Count);
            Assert.Equal("1", claims[0].Value);
            Assert.Equal("2", claims[1].Value);
            Assert.Equal("3", claims[2].Value);
        }

        [Fact]
        public void CreateClaimFromObject_ListOfLists_AppContextSwitchOn()
        {
            AppContext.SetSwitch(AppContextSwitches.StoreArrayClaimsAsJsonStringSwitch, true);
            var claims = new List<Claim>();
            var value = new List<List<string>> { new List<string> { "value1" }, new List<string> { "value2" } };
            JsonClaimSet.CreateClaimFromObject(claims, "claimType", value, "issuer");

            Assert.Single(claims);
            Assert.Equal(JsonClaimValueTypes.JsonArray, claims[0].ValueType);
        }

        [Fact]
        public void CreateClaimFromObject_ListOfLists_AppContextSwitchOff()
        {
            AppContext.SetSwitch(AppContextSwitches.StoreArrayClaimsAsJsonStringSwitch, false);
            var claims = new List<Claim>();
            var value = new List<List<string>> { new List<string> { "value1" }, new List<string> { "value2" } };
            JsonClaimSet.CreateClaimFromObject(claims, "claimType", value, "issuer");

            Assert.Equal(2, claims.Count);
            Assert.Equal("value1", claims[0].Value);
            Assert.Equal("value2", claims[1].Value);
        }

        [Fact]
        public void CreateClaimFromObject_ArrayOfArrays_AppContextSwitchOn()
        {
            AppContext.SetSwitch(AppContextSwitches.StoreArrayClaimsAsJsonStringSwitch, true);
            var claims = new List<Claim>();
            var value = new int[][] { new int[] { 1, 2 }, new int[] { 3, 4 } };
            JsonClaimSet.CreateClaimFromObject(claims, JsonClaimValueTypes.JsonArray, value, "issuer");

            Assert.Single(claims);
            Assert.Equal(JsonClaimValueTypes.JsonArray, claims[0].ValueType);
        }

        [Fact]
        public void CreateClaimFromObject_ArrayOfArrays_AppContextSwitchOff()
        {
            AppContext.SetSwitch(AppContextSwitches.StoreArrayClaimsAsJsonStringSwitch, false);
            var claims = new List<Claim>();
            var value = new int[][] { new int[] { 1, 2 }, new int[] { 3, 4 } };
            JsonClaimSet.CreateClaimFromObject(claims, JsonClaimValueTypes.JsonArray, value, "issuer");

            Assert.Equal(4, claims.Count);
            Assert.Equal("1", claims[0].Value);
            Assert.Equal("2", claims[1].Value);
            Assert.Equal("3", claims[2].Value);
            Assert.Equal("4", claims[3].Value);

        }

        [Fact]
        public async Task TryGetPayloadValueOnArrayClaims_AppContextSwitchOn_ReturnsList()
        {
            // Setup
            AppContext.SetSwitch(AppContextSwitches.StoreArrayClaimsAsJsonStringSwitch, true);
            SigningCredentials signingCredentials = new SigningCredentials(KeyingMaterial.DefaultSymmetricSecurityKey_256, SecurityAlgorithms.HmacSha256, SecurityAlgorithms.Sha256);

            var claims = new Dictionary<string, object>
            {
                { JwtRegisteredClaimNames.Iss, "http://Default.Issuer.com" },
                { JwtRegisteredClaimNames.Aud, new List<string>() { "http://Default.AudienceOne.com", "http://Default.AudienceTwo.com" } },
                { JwtRegisteredClaimNames.Exp, EpochTime.GetIntDate(DateTime.UtcNow.AddDays(1)) },
                { JwtRegisteredClaimNames.Iat, EpochTime.GetIntDate(DateTime.UtcNow.AddDays(-1)) },
                { JwtRegisteredClaimNames.Nbf, EpochTime.GetIntDate(DateTime.UtcNow.AddDays(-1)) },
                { JwtRegisteredClaimNames.Email, "Alice@contoso.com" },
                { JwtRegisteredClaimNames.GivenName, "Alice" }
            };

            var tokenDescriptor = new SecurityTokenDescriptor
            {
                SigningCredentials = signingCredentials,
                Claims = claims
            };

            var validationParameters = new TokenValidationParameters()
            {
                ValidAudiences = ["http://Default.AudienceOne.com"],
                ValidIssuers = ["http://Default.Issuer.com"],
                IssuerSigningKeys = [KeyingMaterial.DefaultSymmetricSecurityKey_256]
            };

            var jwtHandler = new JsonWebTokenHandler();
            var encodedToken = jwtHandler.CreateToken(tokenDescriptor);
            var jwt = new JsonWebToken(encodedToken);

            var result = await jwtHandler.ValidateTokenAsync(jwt, validationParameters);
            Assert.True(result.IsValid);
            Assert.True(result.ClaimsIdentity.FindFirst(JwtRegisteredClaimNames.Aud).ValueType == JsonClaimValueTypes.JsonArray);
            Assert.True(result.ClaimsIdentity.FindFirst(JwtRegisteredClaimNames.Aud).Value == @"[""http://Default.AudienceOne.com"",""http://Default.AudienceTwo.com""]");
            Assert.True(jwt.TryGetPayloadValue<List<string>>(JwtRegisteredClaimNames.Aud, out var audiences));
            Assert.True(audiences.Count == 2);
        }
    }
}
