﻿// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System;
using System.Collections.Generic;
using System.Globalization;
using System.IdentityModel.Tokens.Jwt;
using System.IdentityModel.Tokens.Jwt.Tests;
using System.Linq;
using System.Security.Claims;
using Microsoft.IdentityModel.TestUtils;
using Microsoft.IdentityModel.Tokens;
using Xunit;
using Microsoft.IdentityModel.Json;
using Microsoft.IdentityModel.Json.Linq;

#if NET452
using JsonReaderException = Microsoft.IdentityModel.Json.JsonReaderException;
#else
using System.Text.Json;
using System.Threading.Tasks;
using JsonReaderException = System.Text.Json.JsonException;
#endif

#pragma warning disable CS3016 // Arrays as attribute arguments is not CLS-compliant

namespace Microsoft.IdentityModel.JsonWebTokens.Tests
{
    public class JsonWebTokenTests
    {
        private static DateTime dateTime = new DateTime(2000, 01, 01, 0, 0, 0);
        private string jsonString = $@"{{""intarray"":[1,2,3], ""array"":[1,""2"",3], ""jobject"": {{""string1"":""string1value"",""string2"":""string2value""}},""string"":""bob"", ""float"":42.0, ""integer"":42, ""nill"": null, ""bool"" : true, ""dateTime"": ""{dateTime}"", ""dateTimeIso8061"": ""{dateTime.ToUniversalTime().ToString("o", CultureInfo.InvariantCulture)}"" }}";
        private List<Claim> payloadClaims = new List<Claim>()
        {
            new Claim("intarray", @"[1,2,3]", JsonClaimValueTypes.JsonArray, "LOCAL AUTHORITY", "LOCAL AUTHORITY"),
            new Claim("array", @"[1,""2"",3]", JsonClaimValueTypes.JsonArray, "LOCAL AUTHORITY", "LOCAL AUTHORITY"),
            new Claim("jobject", @"{""string1"":""string1value"",""string2"":""string2value""}", JsonClaimValueTypes.Json, "LOCAL AUTHORITY", "LOCAL AUTHORITY"),
            new Claim("string", "bob", ClaimValueTypes.String, "LOCAL AUTHORITY", "LOCAL AUTHORITY"),
            new Claim("float", "42.0", ClaimValueTypes.Double, "LOCAL AUTHORITY", "LOCAL AUTHORITY"),
            new Claim("integer", "42", ClaimValueTypes.Integer, "LOCAL AUTHORITY", "LOCAL AUTHORITY"),
            new Claim("nill", "", JsonClaimValueTypes.JsonNull, "LOCAL AUTHORITY", "LOCAL AUTHORITY"),
            new Claim("bool", "true", ClaimValueTypes.Boolean, "LOCAL AUTHORITY", "LOCAL AUTHORITY"),
            new Claim("dateTime", dateTime.ToString(), ClaimValueTypes.String, "LOCAL AUTHORITY", "LOCAL AUTHORITY"),
            new Claim("dateTimeIso8061", dateTime.ToUniversalTime().ToString("o", CultureInfo.InvariantCulture), ClaimValueTypes.DateTime, "LOCAL AUTHORITY", "LOCAL AUTHORITY"),
        };

#if !NET452
        static string app_displayname = "sdtest-AllAccess";
        static string appid = "C9977FDF-DBB9-4E26-921B-639552F0F810";
        static string aud = "https://graph.microsoft.com";
        static string iss = "https://sts.windows.net/80165B57-9098-4710-B4AC-98E5D08DF51D/";
        static string given_name = "given_name";
        static string scp = "Calendars.Read Calendars.ReadWrite Contacts.Read Contacts.ReadWrite Directory.AccessAsUser.All Directory.Read.All Directory.ReadWrite.All email Files.Read Files.Read.All Files.Read.Selected Files.ReadWrite Files.ReadWrite.All Files.ReadWrite.AppFolder Files.ReadWrite.Selected Group.Read.All Group.ReadWrite.All IdentityRiskEvent.Read.All Mail.Read Mail.ReadWrite Mail.Send MailboxSettings.ReadWrite Notes.Create Notes.Read Notes.Read.All Notes.ReadWrite Notes.ReadWrite.All Notes.ReadWrite.CreatedByApp offline_access openid People.Read People.ReadWrite profile recipient.manage Sites.Read.All Tasks.ReadWrite User.Read User.Read.All User.ReadBasic.All User.ReadWrite User.ReadWrite.All";

        [Fact]
        public async Task JsonClaimSetThreading()
        {
            var document = JsonDocument.Parse(Payload, new JsonDocumentOptions { AllowTrailingCommas = true });
            JsonClaimSet jsonClaimSet = new JsonClaimSet(document);

            var taskList = new List<Task>();
            for (var i = 0; i < 1000000; i++)
            {
                var task = new Task(() =>
                {
                    CheckElement(jsonClaimSet, "app_displayname", app_displayname);
                    CheckElement(jsonClaimSet, "appid", appid);
                    CheckElement(jsonClaimSet, "aud", aud);
                    CheckElement(jsonClaimSet, "iss", iss);
                    CheckElement(jsonClaimSet, "scp", scp);
                });

                task.Start();
                taskList.Add(task);
            }

            await Task.WhenAll(taskList).ConfigureAwait(false);
            document.Dispose();
        }

        [Fact]
        public async Task JsonWebTokenThreading()
        {
            JsonWebToken jwt = new JsonWebToken("{}", Payload);

            var taskList = new List<Task>();
            for (var i = 0; i < 1000000; i++)
            {
                var task = new Task(() =>
                {
                    CheckClaimValue(jwt, "app_displayname", app_displayname);
                    CheckClaimValue(jwt, "appid", appid);
                    CheckClaimValue(jwt, "aud", aud);
                    CheckClaimValue(jwt, "iss", iss);
                    CheckClaimValue(jwt, "scp", scp);
                });

                task.Start();
                taskList.Add(task);
            }

            await Task.WhenAll(taskList).ConfigureAwait(false);
        }

        internal void CheckClaimValue(JsonWebToken jwt, string claim, string expectedClaim)
        {
            bool success = jwt.TryGetPayloadValue(claim, out string strValue);

            Assert.True(success);
            Assert.Equal(strValue, expectedClaim);
            Assert.NotEqual(given_name, strValue);
        }

        internal void CheckElement(JsonClaimSet jsonClaimSet, string claim, string expectedValue)
        {
            bool success = jsonClaimSet.TryGetValue(claim, out JsonElement jsonElement);

            Assert.True(success);
            Assert.Equal(JsonValueKind.String, jsonElement.ValueKind);
            Assert.Equal(expectedValue, jsonElement.GetString());
            Assert.NotEqual(given_name, jsonElement.GetString());
        }

        public static string Payload =>
            $@"{{
              ""aud"": ""{aud}"",
              ""iss"": ""{iss}"",
              ""iat"": 1506034341,
              ""nbf"": 1506034341,
              ""exp"": 1506038241,
              ""acr"": ""1"",
              ""aio"": ""80165B57-9098-4710-B4AC-98E5D08DF51D="",
              ""amr"": [
                ""pwd""
              ],
              ""app_displayname"": ""{app_displayname}"",
              ""appid"": ""{appid}"",
              ""appidacr"": ""1"",
              ""family_name"": ""Doe"",
              ""given_name"": ""{given_name}"",
              ""ipaddr"": ""0.0.0.127"",
              ""name"": ""TEST_TEST_NAME"",
              ""oid"": ""462AAB4E-E470-4331-9B9F-2507319916A5"",
              ""platf"": ""14"",
              ""puid"": ""123456789ABC"",
              ""scp"": ""{scp}"",
              ""sub"": ""CA3F3BA1-14DA-4040-9408-FCDC5E4F714C"",
              ""tid"": ""55C25696-89F7-42A6-8B31-6294BFDB377C"",
              ""unique_name"": ""admin@A49052AB-06C5-4BC4-8263-67865A8267CB.net"",
              ""upn"": ""A49052AB-06C5-4BC4-8263-67865A8267CB.net"",
              ""uti"": ""80165B57-9098-4710-B4AC-98E5D08DF51D"",
              ""ver"": ""1.0"",
              ""wids"": [
                ""80165B57-9098-4710-B4AC-98E5D08DF51D""
              ]
            }}";
#endif

        // This test is designed to test that all properties of a JWE can be accessed.
        // Some properties rely on an inner token and the Payload can be null.
        [Fact]
        public void JWETouchAllProperties()
        {
            var context = new CompareContext();
            var jsonWebTokenHandler = new JsonWebTokenHandler();
            SecurityTokenDescriptor tokenDescriptor = new SecurityTokenDescriptor
            {
                SigningCredentials = KeyingMaterial.JsonWebKeyRsa256SigningCredentials,
                EncryptingCredentials = KeyingMaterial.DefaultSymmetricEncryptingCreds_Aes256_Sha512_512,
                Subject = new CaseSensitiveClaimsIdentity(Default.PayloadClaims),
                TokenType = "TokenType"
            };

            string jwe = jsonWebTokenHandler.CreateToken(tokenDescriptor);
            JsonWebToken jsonWebToken = new JsonWebToken(jwe);
            JsonWebToken jsonWebToken2 = new JsonWebToken(jwe);

            IdentityComparer.AreEqual(jsonWebToken, jsonWebToken2, context);

            TestUtilities.AssertFailIfErrors(context);
        }

        // Test checks to make sure that the JsonWebToken.GetClaim() method is able to retrieve every Claim returned by the Claims property (with the exception 
        // of Claims that are JObjects or arrays, as those are converted to strings by the GetClaim() method).
        [Fact]
        public void CompareGetClaimAndClaims()
        {
            var context = new CompareContext();
            var jsonWebTokenHandler = new JsonWebTokenHandler();
            var jsonWebTokenString = jsonWebTokenHandler.CreateToken(Default.PayloadString, KeyingMaterial.JsonWebKeyRsa256SigningCredentials);
            var jsonWebToken = new JsonWebToken(jsonWebTokenString);
            var claims = jsonWebToken.Claims;

            foreach (var claim in claims)
            {
                var claimFromGetClaim = jsonWebToken.GetClaim(claim.Type);
                IdentityComparer.AreEqual(claim, claimFromGetClaim, context);
            }

            TestUtilities.AssertFailIfErrors(context);
        }

        // Test checks to make sure that GetPayloadValue<Claim>() returns the same vaue as GetClaim() for every { key, 'value' } pair in the payload.
        [Fact]
        public void CompareGetClaimAndGetPayloadValue()
        {
            var context = new CompareContext();
            var jsonWebTokenHandler = new JsonWebTokenHandler();
            var jsonWebTokenString = jsonWebTokenHandler.CreateToken(Default.PayloadString, KeyingMaterial.JsonWebKeyRsa256SigningCredentials);
            var jsonWebToken = new JsonWebToken(jsonWebTokenString);
            var claims = jsonWebToken.Claims;

            foreach (var claim in claims)
            {
                var claimFromGetClaim = jsonWebToken.GetClaim(claim.Type);
                var claimFromGetPayloadValue = jsonWebToken.GetPayloadValue<Claim>(claim.Type);
                IdentityComparer.AreEqual(claimFromGetClaim, claimFromGetPayloadValue, context);
            }

            TestUtilities.AssertFailIfErrors(context);
        }

        // Test checks to make sure that TryGetPayloadValue<Claim>() returns the same vaue as TryGetClaim() for every { key, 'value' } pair in the payload.
        [Fact]
        public void CompareTryGetClaimAndTryGetPayloadValue()
        {
            var context = new CompareContext();
            var jsonWebTokenHandler = new JsonWebTokenHandler();
            var jsonWebTokenString = jsonWebTokenHandler.CreateToken(Default.PayloadString, KeyingMaterial.JsonWebKeyRsa256SigningCredentials);
            var jsonWebToken = new JsonWebToken(jsonWebTokenString);
            var claims = jsonWebToken.Claims;

            var tryGetClaimSucceeded = jsonWebToken.TryGetPayloadValue<Claim>("doesnotexist", out var claimFromTryGetPayloadValue);
            var tryGetPayloadSucceeded = jsonWebToken.TryGetClaim("doesnotexist", out var claimFromTryGetClaim);
            IdentityComparer.AreEqual(tryGetClaimSucceeded, tryGetPayloadSucceeded, context);
            IdentityComparer.AreEqual(claimFromTryGetClaim, claimFromTryGetPayloadValue, context);

            foreach (var claim in claims)
            {
                tryGetClaimSucceeded = jsonWebToken.TryGetPayloadValue(claim.Type, out claimFromTryGetPayloadValue);
                tryGetPayloadSucceeded = jsonWebToken.TryGetClaim(claim.Type, out claimFromTryGetClaim);
                IdentityComparer.AreEqual(tryGetClaimSucceeded, tryGetPayloadSucceeded, context);
                IdentityComparer.AreEqual(claimFromTryGetClaim, claimFromTryGetPayloadValue, context);
            }

            TestUtilities.AssertFailIfErrors(context);
        }

        // Test checks to make sure that the Claim values returned by GetClaim() are what we expect.
        // This includes JArrays and JObjects, which are converted to strings.
        [Fact]
        public void GetClaim()
        {
            var context = new CompareContext();
            var jsonWebToken = new JsonWebToken("{}", jsonString);

            foreach (var claim in payloadClaims)
            {
                var claimToCompare = jsonWebToken.GetClaim(claim.Type);
                IdentityComparer.AreEqual(claim, claimToCompare, context);
            }

            try // Try to retrieve a value that doesn't exist in the payload.
            {
                jsonWebToken.GetClaim("doesnotexist");
            }
            catch (Exception ex)
            {
                ExpectedException.ArgumentException("IDX14304:").ProcessException(ex, context);
            }

            TestUtilities.AssertFailIfErrors(context);
        }

        // Test checks to make sure that the Claim values returned by TryGetClaim() are what we expect.
        // This includes JArrays and JObjects, which are converted to strings.
        [Fact]
        public void TryGetClaim()
        {
            var context = new CompareContext();
            var jsonWebToken = new JsonWebToken("{}", jsonString);

            // Tries to retrieve a value that does not exist in the payload.
            var success = jsonWebToken.TryGetClaim("doesnotexist", out Claim doesNotExist);
            IdentityComparer.AreEqual(null, doesNotExist, context);
            IdentityComparer.AreEqual(false, success, context);

            foreach (var claim in payloadClaims)
            {
                success = jsonWebToken.TryGetClaim(claim.Type, out var claimToCompare);
                IdentityComparer.AreEqual(claim, claimToCompare, context);
                IdentityComparer.AreEqual(true, success, context);
            }

            TestUtilities.AssertFailIfErrors(context);
        }

        // Test checks to make sure that the JsonWebToken payload is correctly converted to IEnumerable<Claim>.
        [Fact]
        public void GetClaimsFromJObject()
        {
            var context = new CompareContext();
            var jsonWebTokenHandler = new JsonWebTokenHandler();
            var jsonWebTokenString = jsonWebTokenHandler.CreateToken(Default.PayloadString, KeyingMaterial.JsonWebKeyRsa256SigningCredentials);
            var jsonWebToken = new JsonWebToken(jsonWebTokenString);
            var claims = jsonWebToken.Claims;
            IdentityComparer.AreEqual(Default.PayloadClaims, claims, context);
            TestUtilities.AssertFailIfErrors(context);
        }

        // Test checks to make sure that the 'Audiences' claim can be successfully retrieved when multiple audiences are present.
        // It also checks that the rest of the claims match up as well
        [Fact]
        public void CompareJwtSecurityTokenWithJsonSecurityTokenMultipleAudiences()
        {
            var context = new CompareContext();
            string payload = @"{""aud"":[""http://Default.Audience.com"", ""http://Default.Audience1.com"", ""http://Default.Audience2.com"", ""http://Default.Audience3.com"", ""http://Default.Audience4.com""]}";
            string header = "{}";
            var jsonWebToken = new JsonWebToken(header, payload);
            var jwtSecurityToken = new JwtSecurityToken($"{Base64UrlEncoder.Encode(header)}.{Base64UrlEncoder.Encode(payload)}.");
            IdentityComparer.AreEqual(jsonWebToken.Claims, jwtSecurityToken.Claims);
            IdentityComparer.AreEqual(jsonWebToken.Audiences, jwtSecurityToken.Audiences, context);
            TestUtilities.AssertFailIfErrors(context);
        }

        // Test checks to make sure that claim values of various types can be successfully retrieved from the header.
        [Fact]
        public void TryGetHeaderValues()
        {
            var context = new CompareContext();
            TestUtilities.WriteHeader($"{this}.TryGetHeaderValues");

            var token = new JsonWebToken(jsonString, "{}");

            var success = token.TryGetHeaderValue("intarray", out int[] intarray);
            IdentityComparer.AreEqual(new int[] { 1, 2, 3 }, intarray, context);
            IdentityComparer.AreEqual(true, success, context);

            success = token.TryGetHeaderValue("array", out object[] array);
            IdentityComparer.AreEqual(new object[] { 1L, "2", 3L }, array, context);
            IdentityComparer.AreEqual(true, success, context);

#if NET452
            // only possible internally within the library since we're using Microsoft.IdentityModel.Json.Linq.JObject
            success = token.TryGetHeaderValue("jobject", out JObject jobject);
            IdentityComparer.AreEqual(JObject.Parse(@"{ ""string1"":""string1value"", ""string2"":""string2value"" }"), jobject, context);
            IdentityComparer.AreEqual(true, success, context);
#endif
            success = token.TryGetHeaderValue("string", out string name);
            IdentityComparer.AreEqual("bob", name, context);
            IdentityComparer.AreEqual(true, success, context);

            success = token.TryGetHeaderValue("float", out float floatingPoint);
            IdentityComparer.AreEqual(42.0, floatingPoint, context);
            IdentityComparer.AreEqual(true, success, context);

            success = token.TryGetHeaderValue("integer", out int integer);
            IdentityComparer.AreEqual(42, integer, context);
            IdentityComparer.AreEqual(true, success, context);

            success = token.TryGetHeaderValue("nill", out object nill);
            IdentityComparer.AreEqual(nill, null, context);
            IdentityComparer.AreEqual(true, success, context);

            success = token.TryGetHeaderValue("bool", out bool boolean);
            IdentityComparer.AreEqual(boolean, true, context);
            IdentityComparer.AreEqual(true, success, context);

            success = token.TryGetHeaderValue("doesnotexist", out int doesNotExist);
            IdentityComparer.AreEqual(0, doesNotExist, context);
            IdentityComparer.AreEqual(false, success, context);

            success = token.TryGetHeaderValue("string", out int cannotConvert);
            IdentityComparer.AreEqual(0, cannotConvert, context);
            IdentityComparer.AreEqual(false, success, context);

            TestUtilities.AssertFailIfErrors(context);
        }

        // Test checks to make sure that claim values of various types can be successfully retrieved from the payload.
        [Fact]
        public void GetPayloadValues()
        {
            var context = new CompareContext();
            TestUtilities.WriteHeader($"{this}.GetPayloadValues");

            var token = new JsonWebToken("{}", jsonString);

//        private string jsonString = $@"{""array"":[1,""2"",3], ""jobject"": {{""string1"":""string1value"",""string2"":""string2value""}},""string"":""bob"", ""float"":42.0, ""integer"":42, ""nill"": null, ""bool"" : true, ""dateTime"": ""{dateTime}"", ""dateTimeIso8061"": ""{dateTime.ToUniversalTime().ToString("o", CultureInfo.InvariantCulture)}"" }}";


            try // Try to retrieve a value that doesn't exist in the header.
            {
                token.GetPayloadValue<int>("doesnotexist");
            }
            catch (Exception ex)
            {
                ExpectedException.ArgumentException("IDX14304:").ProcessException(ex, context);
            }

            try // Try to retrieve an integer when the value is actually a string.
            {
                token.GetPayloadValue<int>("string");
            }
            catch (Exception ex)
            {
#if NET452
                ExpectedException.ArgumentException("IDX14305:", typeof(System.FormatException)).ProcessException(ex, context);
#else
                ExpectedException.ArgumentException("IDX14305:", typeof(System.Text.Json.JsonException)).ProcessException(ex, context);
#endif
            }

            TestUtilities.AssertFailIfErrors(context);
        }

        // Test checks to make sure that claim values of various types can be successfully retrieved from the payload.
        [Fact]
        public void TryGetPayloadValues()
        {
            var context = new CompareContext();
            TestUtilities.WriteHeader($"{this}.TryGetPayloadValues");

            var token = new JsonWebToken("{}", jsonString);

            var success = token.TryGetPayloadValue("intarray", out int[] intarray);
            IdentityComparer.AreEqual(new int[] { 1, 2, 3 }, intarray, context);
            IdentityComparer.AreEqual(true, success, context);

            success = token.TryGetPayloadValue("array", out object[] array);
            IdentityComparer.AreEqual(new object[] { 1L, "2", 3L }, array, context);
            IdentityComparer.AreEqual(true, success, context);

#if NET452
            // only possible internally within the library since we're using Microsoft.IdentityModel.Json.Linq.JObject
            success = token.TryGetPayloadValue("jobject", out JObject jobject);
            IdentityComparer.AreEqual(JObject.Parse(@"{ ""string1"":""string1value"", ""string2"":""string2value"" }"), jobject, context);
            IdentityComparer.AreEqual(true, success, context);
#endif
            success = token.TryGetPayloadValue("string", out string name);
            IdentityComparer.AreEqual("bob", name, context);
            IdentityComparer.AreEqual(true, success, context);

            success = token.TryGetPayloadValue("float", out float floatingPoint);
            IdentityComparer.AreEqual(42.0, floatingPoint, context);
            IdentityComparer.AreEqual(true, success, context);

            success = token.TryGetPayloadValue("integer", out int integer);
            IdentityComparer.AreEqual(42, integer, context);
            IdentityComparer.AreEqual(true, success, context);

            success = token.TryGetPayloadValue("nill", out object nill);
            IdentityComparer.AreEqual(nill, null, context);
            IdentityComparer.AreEqual(true, success, context);

            success = token.TryGetPayloadValue("bool", out bool boolean);
            IdentityComparer.AreEqual(boolean, true, context);
            IdentityComparer.AreEqual(true, success, context);

            var dateTimeValue = token.GetPayloadValue<string>("dateTime");
            IdentityComparer.AreEqual(dateTimeValue, dateTime.ToString(), context);
            IdentityComparer.AreEqual(true, success, context);

            var dateTimeIso8061Value = token.GetPayloadValue<DateTime>("dateTimeIso8061");
            IdentityComparer.AreEqual(dateTimeIso8061Value, dateTime.ToUniversalTime(), context);
            IdentityComparer.AreEqual(true, success, context);

            success = token.TryGetPayloadValue("doesnotexist", out int doesNotExist);
            IdentityComparer.AreEqual(0, doesNotExist, context);
            IdentityComparer.AreEqual(false, success, context);

            success = token.TryGetPayloadValue("string", out int cannotConvert);
            IdentityComparer.AreEqual(0, cannotConvert, context);
            IdentityComparer.AreEqual(false, success, context);

            TestUtilities.AssertFailIfErrors(context);
        }

        // Time values can be floats, ints, or strings.
        // This test checks to make sure that parsing does not fault in any of the above cases.
        [Theory, MemberData(nameof(ParseTimeValuesTheoryData))]
        public void ParseTimeValues(ParseTimeValuesTheoryData theoryData)
        {
            var context = TestUtilities.WriteHeader($"{this}.ParseTimeValues", theoryData);
            var jsonWebTokenHandler = new JsonWebTokenHandler();
            try
            {
                var token = new JsonWebToken(theoryData.Header, theoryData.Payload);
                var validFrom = token.ValidFrom;
                var validTo = token.ValidTo;
            }
            catch (Exception ex)
            {
                theoryData.ExpectedException.ProcessException(ex, context);
            }

            TestUtilities.AssertFailIfErrors(context);
        }

        public static TheoryData<ParseTimeValuesTheoryData> ParseTimeValuesTheoryData
        {
            get
            {
                return new TheoryData<ParseTimeValuesTheoryData>
                {
                    new ParseTimeValuesTheoryData("DatesAsStrings")
                    {
                        Payload = Default.PayloadString,
                        Header = new JObject
                        {
                            { JwtHeaderParameterNames.Alg, SecurityAlgorithms.Sha512  },
                            { JwtHeaderParameterNames.Kid, Default.AsymmetricSigningKey.KeyId },
                            { JwtHeaderParameterNames.Typ, JwtConstants.HeaderType }
                        }.ToString(Formatting.None)
                    },
                    new ParseTimeValuesTheoryData("DatesAsLongs")
                    {
                        Payload = new JObject()
                        {
                            { JwtRegisteredClaimNames.Email, "Bob@contoso.com" },
                            { JwtRegisteredClaimNames.GivenName, "Bob" },
                            { JwtRegisteredClaimNames.Iss, Default.Issuer },
                            { JwtRegisteredClaimNames.Aud, Default.Audience },
                            { JwtRegisteredClaimNames.Nbf, EpochTime.GetIntDate(Default.NotBefore)},
                            { JwtRegisteredClaimNames.Exp, EpochTime.GetIntDate(Default.Expires) }
                        }.ToString(Formatting.None),
                        Header = new JObject
                        {
                            { JwtHeaderParameterNames.Alg, SecurityAlgorithms.Sha512  },
                            { JwtHeaderParameterNames.Kid, Default.AsymmetricSigningKey.KeyId },
                            { JwtHeaderParameterNames.Typ, JwtConstants.HeaderType }
                        }.ToString(Formatting.None)
                    },
                    new ParseTimeValuesTheoryData("DatesAsFloats")
                    {
                        Payload = new JObject()
                        {
                            { JwtRegisteredClaimNames.Email, "Bob@contoso.com" },
                            { JwtRegisteredClaimNames.GivenName, "Bob" },
                            { JwtRegisteredClaimNames.Iss, Default.Issuer },
                            { JwtRegisteredClaimNames.Aud, Default.Audience },
                            { JwtRegisteredClaimNames.Nbf, (float) EpochTime.GetIntDate(Default.NotBefore)},
                            { JwtRegisteredClaimNames.Exp, (float) EpochTime.GetIntDate(Default.Expires) }
                        }.ToString(Formatting.None),
                        Header = new JObject
                        {
                            { JwtHeaderParameterNames.Alg, SecurityAlgorithms.Sha512  },
                            { JwtHeaderParameterNames.Kid, Default.AsymmetricSigningKey.KeyId },
                            { JwtHeaderParameterNames.Typ, JwtConstants.HeaderType }
                        }.ToString(Formatting.None)
                    },
                };
            }
        }

        // Test ensures that we only try to populate a JsonWebToken from a string if it is a properly formatted JWT.
        // More specifically, we only want to try and decode
        // a JWT token if it has the correct number of (JWE or JWS) token parts.
        [Theory, MemberData(nameof(ParseTokenTheoryData))]
        public void ParseToken(JwtTheoryData theoryData)
        {
            var context = TestUtilities.WriteHeader($"{this}.ParseToken", theoryData);
            try
            {
                var tokenFromEncodedString = new JsonWebToken(theoryData.Token);
                theoryData.ExpectedException.ProcessNoException(context);
            }
            catch (Exception ex)
            {
                theoryData.ExpectedException.ProcessException(ex, context);
            }

            TestUtilities.AssertFailIfErrors(context);
        }

        public static TheoryData<JwtTheoryData> ParseTokenTheoryData
        {
            get
            {
                var theoryData = new TheoryData<JwtTheoryData>();

                JwtTestData.InvalidNumberOfSegmentsData(
                    new List<string>
                    {
                        "IDX14100:",
                        "IDX14120",
                        "IDX14121",
                        "IDX14121",
                        "IDX14310",
                        "IDX14122"
                    },
                    theoryData
                );
                JwtTestData.ValidEncodedSegmentsData(theoryData);

                theoryData.Add(new JwtTheoryData(nameof(EncodedJwts.InvalidHeader))
                {
                    Token = EncodedJwts.InvalidHeader,
#if NET452
                    ExpectedException = new ExpectedException(typeof(ArgumentException), "IDX14102:", typeof(JsonReaderException), false ),
#else
                    ExpectedException = new ExpectedException(typeof(ArgumentException), "IDX14102:", typeof(JsonReaderException), true),
#endif
                });

                theoryData.Add(new JwtTheoryData(nameof(EncodedJwts.InvalidPayload))
                {
                    Token = EncodedJwts.InvalidPayload,
#if NET452
                    ExpectedException = new ExpectedException(typeof(ArgumentException), "IDX14101:", typeof(JsonReaderException), false ),
#else
                    ExpectedException = new ExpectedException(typeof(ArgumentException), "IDX14101:", typeof(JsonReaderException), true),
#endif
                });

                theoryData.Add(new JwtTheoryData(nameof(EncodedJwts.JWSEmptyHeader))
                {
                    Token = EncodedJwts.JWSEmptyHeader,
#if NET452
                    ExpectedException = new ExpectedException(typeof(ArgumentException), "IDX14102:", typeof(JsonReaderException), false ),
#else
                    ExpectedException = new ExpectedException(typeof(ArgumentException), "IDX14102:", typeof(JsonReaderException), true),
#endif
                });

                theoryData.Add(new JwtTheoryData(nameof(EncodedJwts.JWSEmptyPayload))
                {
                    Token = EncodedJwts.JWSEmptyPayload,
#if NET452
                    ExpectedException = new ExpectedException(typeof(ArgumentException), "IDX14101:", typeof(JsonReaderException), false ),
#else
                    ExpectedException = new ExpectedException(typeof(ArgumentException), "IDX14101:", typeof(JsonReaderException), true),
#endif
                });

                theoryData.Add(new JwtTheoryData(nameof(EncodedJwts.JWEEmptyHeader))
                {
                    Token = EncodedJwts.JWEEmptyHeader,
                    ExpectedException = new ExpectedException(typeof(ArgumentException), "IDX14307:"),
                });

                theoryData.Add(new JwtTheoryData(nameof(EncodedJwts.JWEEmptyEncryptedKey))
                {
                    Token = EncodedJwts.JWEEmptyEncryptedKey,
                });

                theoryData.Add(new JwtTheoryData(nameof(EncodedJwts.JWEEmptyIV))
                {
                    ExpectedException = new ExpectedException(typeof(ArgumentException), "IDX14308:"),
                    Token = EncodedJwts.JWEEmptyIV,
                });

                theoryData.Add(new JwtTheoryData(nameof(EncodedJwts.JWEEmptyCiphertext))
                {
                    Token = EncodedJwts.JWEEmptyCiphertext,
                    ExpectedException = ExpectedException.ArgumentException(substringExpected: "IDX14306:")
                });

                theoryData.Add(new JwtTheoryData(nameof(EncodedJwts.JWEEmptyAuthenticationTag))
                {
                    ExpectedException = ExpectedException.SecurityTokenMalformedTokenException(substringExpected: "IDX14310:"),
                    Token = EncodedJwts.JWEEmptyAuthenticationTag,
                });

                return theoryData;
            }
        }

        [Fact]
        public void DateTimeISO8061Claim()
        {
            var context = new CompareContext();
            TestUtilities.WriteHeader($"{this}.DateTimeISO8061Claim");

            var encodedTokenWithDateTimeISO8061Claim = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJjbGFpbV9hc19kYXRldGltZSI6IjIwMTktMTEtMTVUMTQ6MzE6MjEuNjEwMTMyNloifQ.yYcHSl-rNT2nHe8Nb0aWe6Qu3E0ZOn2_OUidpxuw0wk";
            var claimA = new JwtSecurityTokenHandler().ReadJwtToken(encodedTokenWithDateTimeISO8061Claim).Claims.First();
            var claimB = new JsonWebTokenHandler().ReadJsonWebToken(encodedTokenWithDateTimeISO8061Claim).Claims.First();

            // both claims should be equal
            IdentityComparer.AreClaimsEqual(claimA, claimB, context);
            TestUtilities.AssertFailIfErrors(context);

            // both claim value types should be DateTime
            Assert.True(string.Equals(claimA.ValueType, ClaimValueTypes.DateTime), "ClaimValueType is not DateTime.");
            // claim value shouldn't contain any quotes
            Assert.DoesNotContain("\"", claimA.Value);
        }

        [Fact]
        public void EscapedClaims()
        {
            string json = @"{""family_name"":""\u0027\u0027"",""given_name"":""\u0027\u0027"",""name"":""謝京螢""}";
            string jsonEncoded = Base64UrlEncoder.Encode("{}") + "." + Base64UrlEncoder.Encode(json) + ".";
            JsonWebToken encodedToken = new JsonWebToken(jsonEncoded);
            _ = encodedToken.Claims;
        }
    }

    public class ParseTimeValuesTheoryData : TheoryDataBase
    {
        public ParseTimeValuesTheoryData(string testId) : base(testId) { }

        public string Payload { get; set; }

        public string Header { get; set; }
    }
}
